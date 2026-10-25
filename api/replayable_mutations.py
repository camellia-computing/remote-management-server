"""Idempotency and generation boundary for Address Book JSON mutations."""

import hashlib
import json
import re

from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from api.address_book_authorization import MAX_AUTHORIZATION_GENERATION, bump_locked_authorization_generation
from api.identifiers import InvalidIdentifier
from api.management_operations import (
    ManagementMutation,
    ManagementOperationConflict,
    execute_management_operation,
    operation_id_from_request,
)
from api.models import AddressBookProfile, AddressBookRule, AddressBookShare
from api.response_contract import RESPONSE_MODE_JSON, RESPONSE_MODE_MARKER


class _UnrecordableMutationResponse(RuntimeError):
    """Abort the operation transaction and return a retryable response."""

    def __init__(self, response):
        super().__init__("Mutation response cannot be persisted as a receipt")
        self.response = response


def _expected_generation(request):
    value = request.META.get("HTTP_IF_MATCH", "").strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value:
        return False
    if re.fullmatch(r"[0-9]+", value) is None:
        return False
    generation = int(value)
    return generation if generation <= MAX_AUTHORIZATION_GENERATION else False


def _json_body(request):
    try:
        return json.loads(request.body)
    except (TypeError, ValueError):
        return None


def _profile_references(operation, request, route_kwargs):
    """Return explicit profile GUIDs and profile PKs referenced by a request."""

    body = _json_body(request)
    profile_guids = set()
    profile_pks = set()
    if operation.startswith(("address_book_peer_", "address_book_tag_")):
        guid = route_kwargs.get("guid")
        if guid:
            profile_guids.add(str(guid))
    elif operation == "address_book_rule_mutation" and isinstance(body, dict):
        reference = body.get("guid")
        if request.method == "POST":
            if reference:
                profile_guids.add(str(reference))
        elif reference:
            share_profile = AddressBookShare.objects.filter(guid=reference).values_list("profile_id", flat=True).first()
            rule_profile = None
            if share_profile is None:
                rule_profile = AddressBookRule.objects.filter(guid=reference).values_list("profile_id", flat=True).first()
            if share_profile is not None or rule_profile is not None:
                profile_pks.add(share_profile if share_profile is not None else rule_profile)
    elif operation == "address_book_rule_delete" and isinstance(body, list):
        references = [str(value) for value in body]
        profile_pks.update(
            AddressBookShare.objects.filter(guid__in=references).values_list("profile_id", flat=True)
        )
        profile_pks.update(
            AddressBookRule.objects.filter(guid__in=references).values_list("profile_id", flat=True)
        )
    return profile_guids, profile_pks


def _lock_profiles(profile_guids, profile_pks):
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Replayable Address Book mutation requires a transaction")
    query = AddressBookProfile.objects.select_for_update().order_by("pk")
    profiles = {profile.pk: profile for profile in query.filter(pk__in=profile_pks)}
    for profile in query.filter(guid__in=profile_guids):
        profiles[profile.pk] = profile
    return profiles


def _generation_conflict(profiles):
    generations = {str(profile.guid): profile.authorization_generation for profile in profiles.values()}
    body = {
        "error": "Resource changed",
        "code": "resource_generation_conflict",
        "current_generations": generations,
    }
    if len(generations) == 1:
        body["current_generation"] = next(iter(generations.values()))
    return ManagementMutation(
        status_code=409,
        body=body,
        applied={"mutations": 0},
        result_state={"current_generations": generations},
    )


def _parse_response(response):
    if response.status_code >= 500:
        raise _UnrecordableMutationResponse(response)
    if response.status_code == 204 and not response.content:
        return {"code": 1}
    if not 200 <= response.status_code < 500:
        raise _UnrecordableMutationResponse(
            JsonResponse(
                {
                    "error": "Mutation returned an unsupported response",
                    "code": "mutation_response_not_recordable",
                    "retryable": True,
                },
                status=502,
            )
        )
    if not str(response.get("Content-Type", "")).lower().startswith("application/json"):
        raise _UnrecordableMutationResponse(
            JsonResponse(
                {
                    "error": "Mutation response was not JSON",
                    "code": "mutation_response_not_json",
                    "retryable": True,
                },
                status=502,
            )
        )
    try:
        body = json.loads(response.content)
    except (TypeError, ValueError):
        body = None
    if not isinstance(body, dict):
        raise _UnrecordableMutationResponse(
            JsonResponse(
                {
                    "error": "Mutation response was not an object",
                    "code": "mutation_response_not_object",
                    "retryable": True,
                },
                status=502,
            )
        )
    return body


def replayable_stateless_api(view, operation, *methods):
    """Persist mutation results and serialize writes against profile generations."""

    def wrapped(request, *args, **kwargs):
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return view(request, *args, **kwargs)
        try:
            operation_id = operation_id_from_request(request)
        except InvalidIdentifier:
            return JsonResponse({"error": "Valid Idempotency-Key required"}, status=400)

        # Import lazily to avoid a urls -> wrapper -> views -> urls cycle.
        from api.views_api import _get_token_user  # noqa: PLC0415

        _token, actor = _get_token_user(request)
        if not actor:
            return view(request, *args, **kwargs)
        expected_generation = _expected_generation(request)
        if expected_generation is False:
            return JsonResponse({"error": "Invalid If-Match"}, status=400)
        profile_guids, profile_pks = _profile_references(operation, request, kwargs)
        request_document = {
            "operation": operation,
            "method": request.method,
            "path": request.path,
            "args": {key: sorted(request.GET.getlist(key)) for key in sorted(request.GET)},
            "body_sha256": hashlib.sha256(request.body).hexdigest(),
            "expected_generation": expected_generation,
        }

        def mutate():
            profiles = _lock_profiles(profile_guids, profile_pks)
            generations_before = {
                profile.pk: profile.authorization_generation for profile in profiles.values()
            }
            if expected_generation is not None and any(
                profile.authorization_generation != expected_generation for profile in profiles.values()
            ):
                return _generation_conflict(profiles)

            response = view(request, *args, **kwargs)
            body = _parse_response(response)
            if not 200 <= response.status_code < 300:
                return ManagementMutation(
                    status_code=response.status_code,
                    body=body,
                    applied={"mutations": 0},
                    result_state={"status": response.status_code, "body": body},
                )

            # A first personal-book mutation may create its profile. Re-locking
            # is harmless for existing rows and includes any new target row.
            profiles.update(_lock_profiles(profile_guids, profile_pks))
            for profile in profiles.values():
                profile.refresh_from_db(fields=("guid", "authorization_generation"))
                previous = generations_before.get(profile.pk)
                if previous is None or profile.authorization_generation == previous:
                    bump_locked_authorization_generation(profile)
                elif profile.authorization_generation < previous:
                    raise RuntimeError("Address Book generation moved backwards")
            generations = {
                str(profile.guid): profile.authorization_generation for profile in profiles.values()
            }
            if generations:
                body["mutation_generations"] = generations
            if len(generations) == 1:
                body["mutation_generation"] = next(iter(generations.values()))
            return ManagementMutation(
                status_code=200 if response.status_code == 204 else response.status_code,
                body=body,
                applied={"mutations": 1},
                result_state={
                    "status": response.status_code,
                    "body": body,
                    "mutation_generations": generations,
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
            return JsonResponse({"error": "Operation identifier conflict"}, status=409)
        except _UnrecordableMutationResponse as exc:
            return exc.response
        response = JsonResponse(result.body, status=result.status_code)
        generation = result.body.get("mutation_generation")
        if isinstance(generation, int) and generation >= 0:
            response["ETag"] = f'"{generation}"'
        return response

    wrapped = csrf_exempt(require_http_methods(methods)(wrapped))
    setattr(wrapped, RESPONSE_MODE_MARKER, RESPONSE_MODE_JSON)
    return wrapped
