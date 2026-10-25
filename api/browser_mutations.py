"""Replay and optimistic-concurrency boundary for Address Book HTML forms."""

import json
from functools import wraps
from urllib.parse import urlsplit

from django.contrib import messages
from django.db import transaction
from django.http import HttpResponseRedirect

from api.address_book_authorization import MAX_AUTHORIZATION_GENERATION
from api.identifiers import InvalidIdentifier
from api.management_operations import (
    ManagementMutation,
    ManagementOperationConflict,
    document_digest,
    execute_management_operation,
    parse_operation_id,
)
from api.models import AddressBookProfile, AddressBookRule, AddressBookShare

_SURFACE_ACTIONS = {
    "ab_book": {
        "bulk_tag_add",
        "bulk_tag_remove",
        "bulk_tag_replace",
        "bulk_note_update",
        "bulk_peer_delete",
        "add_tag",
        "rename_tag",
        "update_tag",
        "delete_tag",
        "add_peer",
        "update_peer",
        "delete_peer",
    },
    "tag_manage": {"add_tag", "update_tag", "rename_tag", "delete_tag"},
    "ab_manage": {
        "update_rule",
        "delete_rule",
        "add_user_share",
        "add_group_rule",
        "add_everyone_rule",
    },
    "ab_rules": {"update_rule", "delete_rule", "bulk_update", "bulk_delete"},
}
_REDIRECTS = {
    "ab_book": "/api/ab_books",
    "tag_manage": "/api/tag_manage",
    "ab_manage": "/api/ab_manage",
    "ab_rules": "/api/ab_rules",
}
_EXCLUDED_FORM_FIELDS = {"csrfmiddlewaretoken", "idempotency_key"}
_SENSITIVE_FORM_FIELDS = {"password", "default_password"}


class _UnrecordableBrowserMutation(RuntimeError):
    def __init__(self, response):
        super().__init__("Browser mutation response cannot be persisted")
        self.response = response


def _operation_id(request):
    value = request.META.get("HTTP_IDEMPOTENCY_KEY") or request.POST.get("idempotency_key")
    if value is None or not str(value).strip():
        raise InvalidIdentifier("A canonical Idempotency-Key UUID is required")
    return parse_operation_id(str(value))


def _request_document(request, *, operation):
    fields = {}
    for key, values in sorted(request.POST.lists()):
        if key in _EXCLUDED_FORM_FIELDS:
            continue
        if key in _SENSITIVE_FORM_FIELDS:
            fields[key] = [document_digest(value) for value in values]
        else:
            fields[key] = list(values)
    return {
        "operation": operation,
        "method": request.method,
        "path": request.path,
        "fields": fields,
    }


def _rule_profile_ids(references):
    references = [str(reference) for reference in references if str(reference).strip()]
    if not references:
        return set()
    profile_ids = set(
        AddressBookShare.objects.filter(guid__in=references).values_list("profile_id", flat=True)
    )
    profile_ids.update(
        AddressBookRule.objects.filter(guid__in=references).values_list("profile_id", flat=True)
    )
    return profile_ids


def _referenced_profile_ids(request, surface):
    if surface in {"ab_book", "tag_manage"}:
        guid_field = "guid" if surface == "ab_book" else "profile_guid"
        guid = str(request.POST.get(guid_field, "")).strip()
        if not guid:
            return set()
        return set(AddressBookProfile.objects.filter(guid=guid).values_list("pk", flat=True))
    if surface == "ab_manage":
        profile_guid = str(request.POST.get("profile_guid", "")).strip()
        if profile_guid:
            return set(
                AddressBookProfile.objects.filter(guid=profile_guid).values_list("pk", flat=True)
            )
        return _rule_profile_ids([request.POST.get("rule_guid", "")])
    if surface == "ab_rules":
        references = request.POST.getlist("selected")
        if not references:
            references = [request.POST.get("rule_guid", "")]
        return _rule_profile_ids(references)
    raise ValueError("Unsupported browser mutation surface")


def _lock_profiles(profile_ids):
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Browser Address Book mutation requires a transaction")
    return {
        profile.pk: profile
        for profile in AddressBookProfile.objects.select_for_update()
        .filter(pk__in=profile_ids)
        .order_by("pk")
    }


def _expected_generations(request, profiles):
    singular = str(request.POST.get("expected_generation", "")).strip()
    encoded_map = str(request.POST.get("expected_generations", "")).strip()
    if singular and encoded_map:
        raise ValueError("Only one generation precondition format is allowed")
    if singular:
        if (
            len(profiles) != 1
            or not singular.isascii()
            or not singular.isdigit()
            or int(singular) > MAX_AUTHORIZATION_GENERATION
        ):
            raise ValueError("Invalid resource generation")
        profile = next(iter(profiles.values()))
        return {str(profile.guid): int(singular)}
    if encoded_map:
        try:
            values = json.loads(encoded_map)
        except (TypeError, ValueError) as exc:
            raise ValueError("Invalid resource generation map") from exc
        if not isinstance(values, dict):
            raise ValueError("Invalid resource generation map")
        normalized = {}
        for key, value in values.items():
            if (
                not isinstance(key, str)
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > MAX_AUTHORIZATION_GENERATION
            ):
                raise ValueError("Invalid resource generation map")
            normalized[key] = value
        expected_keys = {str(profile.guid) for profile in profiles.values()}
        if set(normalized) != expected_keys:
            raise ValueError("Resource generation map must match the complete target set")
        return normalized
    raise ValueError("Resource generation is required")


def _feedback_from_request(request):
    feedback = []
    for message in messages.get_messages(request):
        feedback.append(
            {
                "level": int(message.level),
                "message": str(message)[:512],
                "extra_tags": str(message.extra_tags or "")[:128],
            }
        )
    return feedback


def _restore_feedback(request, feedback):
    if not isinstance(feedback, list):
        return
    valid_levels = {messages.DEBUG, messages.INFO, messages.SUCCESS, messages.WARNING, messages.ERROR}
    for item in feedback[:16]:
        if not isinstance(item, dict):
            continue
        level = item.get("level")
        message = item.get("message")
        extra_tags = item.get("extra_tags", "")
        if level not in valid_levels or not isinstance(message, str) or not isinstance(extra_tags, str):
            continue
        messages.add_message(request, level, message[:512], extra_tags=extra_tags[:128])


def _merge_feedback(*groups):
    merged = []
    seen = set()
    for group in groups:
        if not isinstance(group, list):
            continue
        for item in group:
            if not isinstance(item, dict):
                continue
            marker = (item.get("level"), item.get("message"), item.get("extra_tags", ""))
            if marker in seen:
                continue
            seen.add(marker)
            merged.append(item)
    return merged


def _local_redirect(response):
    if response.status_code < 300 or response.status_code >= 400:
        raise _UnrecordableBrowserMutation(response)
    location = str(response.get("Location", ""))
    parsed = urlsplit(location)
    if not location.startswith("/") or parsed.scheme or parsed.netloc:
        raise _UnrecordableBrowserMutation(response)
    return location


def replayable_address_book_form(surface):
    """Make a known Address Book form action replay-safe and generation-aware."""

    if surface not in _SURFACE_ACTIONS:
        raise ValueError("Unsupported browser mutation surface")

    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            action = str(request.POST.get("action", "")) if request.method == "POST" else ""
            if request.method != "POST" or action not in _SURFACE_ACTIONS[surface]:
                return view(request, *args, **kwargs)
            actor = request.user
            redirect_fallback = _REDIRECTS[surface]
            try:
                operation_id = _operation_id(request)
            except InvalidIdentifier:
                messages.error(request, "操作标识无效，请刷新页面后重试。")
                return HttpResponseRedirect(redirect_fallback)
            prior_feedback = _feedback_from_request(request)

            operation = f"browser_{surface}_{action}"
            request_document = _request_document(request, operation=operation)

            def mutate():
                profile_ids = _referenced_profile_ids(request, surface)
                profiles = _lock_profiles(profile_ids)
                before = {
                    profile.pk: profile.authorization_generation for profile in profiles.values()
                }
                try:
                    expected = _expected_generations(request, profiles)
                except ValueError:
                    return ManagementMutation(
                        status_code=400,
                        body={
                            "code": "invalid_resource_generation",
                            "redirect": redirect_fallback,
                            "feedback": [
                                {
                                    "level": messages.ERROR,
                                    "message": "资源版本无效，请刷新页面后重试。",
                                    "extra_tags": "",
                                }
                            ],
                        },
                        applied={"mutations": 0},
                        result_state={"error": "invalid_resource_generation"},
                    )
                stale = {
                    str(profile.guid): profile.authorization_generation
                    for profile in profiles.values()
                    if str(profile.guid) in expected
                    and profile.authorization_generation != expected[str(profile.guid)]
                }
                if stale:
                    return ManagementMutation(
                        status_code=409,
                        body={
                            "code": "resource_generation_conflict",
                            "redirect": redirect_fallback,
                            "current_generations": stale,
                            "feedback": [
                                {
                                    "level": messages.ERROR,
                                    "message": "地址簿已变化，请刷新页面后重试。",
                                    "extra_tags": "",
                                }
                            ],
                        },
                        applied={"mutations": 0},
                        result_state={"current_generations": stale},
                    )

                response = view(request, *args, **kwargs)
                redirect = _local_redirect(response)
                feedback = _feedback_from_request(request)
                profile_ids.update(_referenced_profile_ids(request, surface))
                current = _lock_profiles(profile_ids)
                generations = {}
                changed = False
                for profile in current.values():
                    profile.refresh_from_db(fields=("guid", "authorization_generation"))
                    generations[str(profile.guid)] = profile.authorization_generation
                    previous = before.get(profile.pk)
                    if previous is None or previous != profile.authorization_generation:
                        changed = True
                return ManagementMutation(
                    status_code=200,
                    body={
                        "redirect": redirect,
                        "feedback": feedback,
                        "mutation_generations": generations,
                    },
                    applied={"mutations": int(changed)},
                    result_state={
                        "redirect": redirect,
                        "feedback": feedback,
                        "mutation_generations": generations,
                        "applied": changed,
                    },
                )

            try:
                result = execute_management_operation(
                    actor=actor,
                    operation_id=operation_id,
                    operation=operation,
                    request_document=request_document,
                    requested={"mutations": 1},
                    mutation=mutate,
                )
            except ManagementOperationConflict:
                _restore_feedback(request, prior_feedback)
                messages.error(request, "操作标识已被其他请求使用。")
                return HttpResponseRedirect(redirect_fallback)
            except _UnrecordableBrowserMutation as exc:
                _restore_feedback(request, prior_feedback)
                return exc.response

            _restore_feedback(
                request,
                _merge_feedback(prior_feedback, result.body.get("feedback")),
            )
            redirect = result.body.get("redirect")
            if not isinstance(redirect, str) or not redirect.startswith("/"):
                raise RuntimeError("Stored browser mutation redirect is invalid")
            return HttpResponseRedirect(redirect)

        return wrapped

    return decorate
