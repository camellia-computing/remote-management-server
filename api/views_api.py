import base64
import binascii
import datetime
import functools
import hashlib
import ipaddress
import json
import logging
import math
import re
import secrets
import uuid
from urllib.parse import urlsplit

import requests
from authlib.integrations.requests_client import OAuth2Session
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import password_validation
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, connection, transaction
from django.db.models import Prefetch, Q, QuerySet
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.utils import timezone
from django.utils.translation import gettext as _
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from api import audit_lifecycle, ingestion_governance, recording_uploads

# from django.forms.models import model_to_dict
from api.address_book_authorization import (
    bump_locked_authorization_generation,
    lock_profile_access,
)
from api.credential_sessions import (
    CredentialGenerationExhausted,
    revoke_device_credentials,
    revoke_user_credentials,
)
from api.device_identity import (
    DeviceProofError,
    DeviceRecoveryRequired,
    consume_deployment_proof,
    consume_session_proof,
    create_recovery_approval,
    deployment_assertion,
    issue_proof_challenge,
)
from api.encrypted_fields import verify_key_canary
from api.login_admission import complete_login_success, reserve_login_attempt
from api.models import (
    AddressBookProfile,
    AddressBookRule,
    AddressBookRuleAudit,
    AddressBookShare,
    AlarmLog,
    ConnectionAuditEvent,
    ConnLog,
    DataEncryptionKeyState,
    DeviceGroup,
    DeviceProofChallenge,
    DeviceRecoveryApproval,
    FileLog,
    FileTransferAuditEvent,
    OidcIdentity,
    OidcPendingAuth,
    RemoteDevice,
    RemotePeer,
    RemoteTag,
    RemoteToken,
    StrategyProfile,
    UserProfile,
)
from api.policy_generation import (
    InvalidManagedPolicy,
    managed_policy_document,
    normalize_policy_options,
)
from api.rate_limits import enforce_authenticated_rate_limit
from api.request_utils import client_ip, load_json_body, load_json_object
from api.tag_colors import normalize_tag_color
from camellia_remote_management.access_logging import normalized_route

logger = logging.getLogger(__name__)
EFFECTIVE_SECONDS = 7200
DEVICE_LEASE_SECONDS = 60
MAX_DEPLOY_KEY_LEN = 512
OIDC_PENDING_MINUTES = settings.OIDC_PENDING_RETENTION_MINUTES
OIDC_MAX_PENDING_PER_IP = 20
OIDC_DOCUMENT_MAX_BYTES = 1024 * 1024
MAX_DEVICE_UUID_TEXT_LEN = 344
MAX_AUDIT_INFO_BYTES = 16 * 1024
MAX_AUDIT_NOTE_BYTES = 16 * 1024
MAX_AUDIT_FILES = 10
AUDIT_PROTOCOL_VERSION = 3
FILE_AUDIT_PROTOCOL_VERSION = 4
MAX_AUDIT_INTEGER = 9_223_372_036_854_775_807
MAX_AB_PEERS = 10_000
MAX_AB_TAGS = 256
MAX_AB_TAGS_PER_PEER = 32
MAX_AB_PROFILE_PASSWORD_BYTES = 240
MAX_MANAGEMENT_BATCH_ITEMS = 500
MAX_ALLOWED_INCOMINGS = 500
OIDC_SAFE_ID_TOKEN_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)


def _load_json(request):
    return load_json_body(request)


def _load_json_object(request):
    return load_json_object(request)


def _get_bearer_token(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.startswith("Bearer "):
        return auth.split("Bearer ")[-1].strip()
    return ""


def _hash_token(raw_token):
    """Tokens are stored hashed at rest; DB access must not equal session takeover."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _get_token_user(request):
    token_str = _get_bearer_token(request)
    if not token_str:
        return None, None
    token = (
        RemoteToken.objects.select_related(
            "subject_user__strategy",
            "device__owner__strategy",
            "device__device_group__strategy",
            "device__strategy",
        )
        .filter(access_token=_hash_token(token_str))
        .first()
    )
    if not token:
        return None, None
    if _token_expired(token):
        token.delete()
        return None, None
    device = token.device if token.device_id else None
    user = token.subject_user if token.subject_user_id else None
    if not device or not user:
        token.delete()
        return None, None
    if not device.is_active or device.owner_id != user.id or not user.is_active:
        token.delete()
        return None, None
    if not secrets.compare_digest(token.credential_hash, user.get_session_auth_hash()):
        token.delete()
        return None, None
    enforce_authenticated_rate_limit(request, user, device)
    return token, user


def _token_expired(token):
    return token.expires_at <= timezone.now()


def _issue_access_token(user, device):
    """Create or rotate this device's token; returns (token, raw_token).

    The raw token is returned to the client exactly once; only its hash is stored.
    """
    if not device or device.owner_id != user.id:
        raise PermissionError("Device ownership mismatch")
    expires_at = timezone.now() + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
    raw_token = secrets.token_urlsafe(32)
    with transaction.atomic():
        locked_user = UserProfile.objects.select_for_update().filter(pk=user.pk).first()
        if not locked_user or not locked_user.is_active:
            raise PermissionError("User is inactive")
        locked_device = RemoteDevice.objects.select_for_update().filter(pk=device.pk).first()
        if not locked_device or locked_device.owner_id != locked_user.id or not locked_device.is_active:
            raise PermissionError("Device ownership mismatch")
        token, _created = RemoteToken.objects.update_or_create(
            device=locked_device,
            defaults={
                "subject_user": locked_user,
                "access_token": _hash_token(raw_token),
                "credential_hash": locked_user.get_session_auth_hash(),
                "expires_at": expires_at,
            },
        )
    return token, raw_token


def _valid_device_identity(rid, device_uuid):
    if not isinstance(rid, str) or not isinstance(device_uuid, str):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,16}", rid):
        return False
    return _decode_canonical_base64(device_uuid, max_decoded_bytes=256) is not None


def _validated_login_device_info(value):
    if not isinstance(value, dict):
        return None
    result = {}
    limits = {
        "os": 100,
        "type": 32,
        "name": 100,
    }
    if set(value) - set(limits):
        return None
    for key, limit in limits.items():
        field_value = value.get(key, "")
        if (
            not isinstance(field_value, str)
            or len(field_value) > limit
            or len(field_value.encode()) > limit * 4
            or any(ord(character) < 32 for character in field_value)
        ):
            return None
        result[key] = field_value
    return result


def _decode_canonical_base64(value, *, max_decoded_bytes):
    if not isinstance(value, str) or not value or len(value) > MAX_DEVICE_UUID_TEXT_LEN:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or len(decoded) > max_decoded_bytes:
        return None
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def _deployment_identity(rid, device_uuid, public_key):
    if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{6,16}", rid):
        return None
    raw_uuid = _decode_canonical_base64(device_uuid, max_decoded_bytes=256)
    raw_public_key = _decode_canonical_base64(public_key, max_decoded_bytes=32)
    if raw_uuid is None or raw_public_key is None or len(raw_public_key) != 32:
        return None
    return rid, base64.b64encode(raw_uuid).decode("ascii"), hashlib.sha256(raw_public_key).hexdigest()


def _revoke_device_tokens(device):
    if not device:
        return 0
    DeviceProofChallenge.objects.filter(device=device).delete()
    DeviceRecoveryApproval.objects.filter(device=device, consumed_at__isnull=True).delete()
    return revoke_device_credentials((device.pk,))


def _get_device_token_user(request, rid, device_uuid):
    token, user = _get_token_user(request)
    if not token or not user:
        return token, None
    if token.device.rid != rid or token.device.uuid != device_uuid:
        return token, None
    return token, user


def _revoked_device_lease(rid, device_uuid):
    return {
        "version": 1,
        "state": "revoked",
        "id": rid,
        "uuid": device_uuid,
    }


def _get_active_token_device(token, user):
    if not token or not user:
        return None
    device = token.device
    if not _is_active_owned_device(device, user):
        return None
    return device


def _is_active_owned_device(device, user):
    return bool(
        device
        and user
        and device.is_active
        and device.public_key_hash
        and device.owner_id == user.id
        and device.owner
        and device.owner.is_active
    )


class DeviceIdentityConflict(Exception):
    pass


class DeviceCredentialFinalizationError(RuntimeError):
    pass


class _OidcPolicyRevocationRequired(Exception):
    def __init__(self, user_id):
        self.user_id = user_id
        super().__init__("OIDC policy revocation is required")


def _device_by_identity(rid, device_uuid, *, for_update=False):
    queryset = RemoteDevice.objects
    if for_update:
        # The related owner, group, and strategy rows are optional. PostgreSQL
        # rejects FOR UPDATE on the nullable side of those outer joins, and the
        # session claim only needs to serialize mutations of the device row.
        queryset = queryset.select_for_update(of=("self",))
    matches = list(
        queryset.filter(Q(rid=rid) | Q(uuid=device_uuid))
        .select_related(
            "owner__strategy",
            "device_group__strategy",
            "strategy",
        )
        .order_by("pk")
    )
    exact = next(
        (device for device in matches if device.rid == rid and device.uuid == device_uuid),
        None,
    )
    if any(device is not exact for device in matches):
        raise DeviceIdentityConflict
    return exact


def _claim_session_device(
    user,
    rid,
    device_uuid,
    ip_address="",
    device_info=None,
    device_proof=None,
    proof_purpose=None,
):
    """Return the one device row a login session is allowed to claim."""

    device_info = device_info or {}
    hostname = device_info.get("name") or "-"
    operating_system = device_info.get("os") or "-"
    for attempt in range(2):
        try:
            with transaction.atomic():
                locked_user = UserProfile.objects.select_for_update().get(pk=user.pk)
                if not locked_user.is_active:
                    raise PermissionError("User is inactive")
                device = _device_by_identity(
                    rid,
                    device_uuid,
                    for_update=True,
                )
                if device and (not device.is_active or (device.owner_id and device.owner_id != locked_user.id)):
                    raise PermissionError("Device is unavailable")
                if not device:
                    device = RemoteDevice.objects.create(
                        rid=rid,
                        cpu="-",
                        hostname=hostname,
                        memory="-",
                        os=operating_system,
                        uuid=device_uuid,
                        username="",
                        version="-",
                        ip_address=ip_address,
                        owner=locked_user,
                    )
                else:
                    update_fields = []
                    if device.owner_id is None:
                        device.owner = locked_user
                        update_fields.append("owner")
                    if ip_address and device.ip_address != ip_address:
                        device.ip_address = ip_address
                        update_fields.append("ip_address")
                    if hostname != "-" and device.hostname != hostname:
                        device.hostname = hostname
                        update_fields.append("hostname")
                    if operating_system != "-" and device.os != operating_system:
                        device.os = operating_system
                        update_fields.append("os")
                    if update_fields:
                        update_fields.append("update_time")
                        device.save(update_fields=update_fields)
                if device.public_key_hash or device_proof:
                    consume_session_proof(
                        proof=device_proof,
                        purpose=proof_purpose,
                        device=device,
                        user=locked_user,
                    )
                return device
        except IntegrityError:
            if attempt:
                raise
    raise IntegrityError("Unable to claim device")


def _auth_body(user, raw_token):
    return {
        "access_token": raw_token,
        "type": "access_token",
        "user": {
            "name": user.username,
            "display_name": user.username,
            "avatar": "",
            "status": 1 if user.is_active else 0,
            "is_admin": True if user.is_admin else False,
            "email": user.email or "",
            "note": user.note or "",
            # The desktop client's UserPayload requires `info`; without it the
            # whole body fails to deserialise and the OIDC poll silently
            # discards a successful login.
            "info": {
                "email_verification": False,
                "email_alarm_notification": False,
                "login_device_whitelist": [],
                "other": {},
            },
        },
    }


def _oidc_provider_name(op):
    name = str(op or "").strip()
    if len(name) > 4096:
        return ""
    if name.startswith("common-oidc/"):
        try:
            payload = json.loads(name[len("common-oidc/") :])
        except json.JSONDecodeError:
            name = ""
        else:
            if isinstance(payload, dict):
                name = payload.get("name") or payload.get("op") or ""
            else:
                name = ""
    if name.startswith("oidc/"):
        name = name[len("oidc/") :]
    return name if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) else ""


def _valid_https_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        _port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
    )


def _oidc_endpoint_allowed(url, allowed_hosts):
    if not _valid_https_url(url):
        return False
    try:
        hostname = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return hostname in frozenset(allowed_hosts)


def _fetch_oidc_json(url, allowed_hosts):
    if not _oidc_endpoint_allowed(url, allowed_hosts):
        raise ValueError("OIDC endpoint is outside the configured host allowlist")
    timeout = getattr(settings, "OIDC_HTTP_TIMEOUT_SECONDS", 10)
    with requests.get(
        url,
        timeout=timeout,
        allow_redirects=False,
        stream=True,
        headers={"Accept": "application/json"},
    ) as response:
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > OIDC_DOCUMENT_MAX_BYTES:
            raise ValueError("OIDC document is too large")
        body = bytearray()
        for chunk in response.iter_content(64 * 1024):
            body.extend(chunk)
            if len(body) > OIDC_DOCUMENT_MAX_BYTES:
                raise ValueError("OIDC document is too large")
    document = json.loads(body)
    if not isinstance(document, dict):
        raise ValueError("OIDC document must be a JSON object")
    return document


@functools.lru_cache(maxsize=16)
def _oidc_metadata(issuer, allowed_hosts):
    issuer = str(issuer or "").rstrip("/")
    if not _oidc_endpoint_allowed(issuer, allowed_hosts):
        raise ValueError("OIDC issuer is outside the configured host allowlist")
    metadata = _fetch_oidc_json(
        f"{issuer}/.well-known/openid-configuration",
        allowed_hosts,
    )
    metadata_issuer = str(metadata.get("issuer") or "").rstrip("/")
    if metadata_issuer != issuer:
        raise ValueError("OIDC discovery issuer mismatch")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not _oidc_endpoint_allowed(metadata.get(key), allowed_hosts):
            raise ValueError(f"OIDC discovery contains an invalid {key}")
    userinfo_endpoint = metadata.get("userinfo_endpoint")
    if userinfo_endpoint and not _oidc_endpoint_allowed(
        userinfo_endpoint,
        allowed_hosts,
    ):
        raise ValueError("OIDC discovery contains an invalid userinfo_endpoint")
    return metadata


def _oidc_client(provider, state=None):
    return OAuth2Session(
        provider["client_id"],
        provider["client_secret"],
        scope=provider.get("scope", "openid email profile"),
        redirect_uri=provider["redirect_uri"],
        state=state,
        code_challenge_method="S256",
        default_timeout=getattr(settings, "OIDC_HTTP_TIMEOUT_SECONDS", 10),
    )


def _validate_oidc_id_token(token, metadata, provider, nonce):
    encoded = token.get("id_token")
    if not isinstance(encoded, str) or not encoded or len(encoded) > 64 * 1024:
        raise ValueError("OIDC provider did not return an ID token")
    jwks = _fetch_oidc_json(
        metadata["jwks_uri"],
        provider["allowed_hosts"],
    )
    key_set = KeySet.import_key_set(jwks)
    configured_algorithms = metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
    algorithms = [value for value in configured_algorithms if value in OIDC_SAFE_ID_TOKEN_ALGORITHMS]
    if not algorithms:
        raise ValueError("OIDC provider has no supported ID token algorithm")
    decoded = jwt.decode(encoded, key_set, algorithms=algorithms)
    claims = decoded.claims
    issuer = str(metadata["issuer"]).rstrip("/")
    registry = JWTClaimsRegistry(
        leeway=60,
        iss={"essential": True, "value": issuer},
        sub={"essential": True},
        aud={"essential": True, "value": provider["client_id"]},
        exp={"essential": True},
        iat={"essential": True},
        nonce={"essential": True, "value": nonce},
    )
    registry.validate(claims)
    audience = claims.get("aud")
    azp = claims.get("azp")
    if isinstance(audience, list) and len(audience) > 1 and azp != provider["client_id"]:
        raise ValueError("OIDC ID token has an invalid authorized party")
    if azp and azp != provider["client_id"]:
        raise ValueError("OIDC ID token has an invalid authorized party")
    return claims


def _oidc_local_username(claims, issuer, subject, attempt=0):
    raw_candidates = (
        claims.get("preferred_username"),
        claims.get("name"),
        str(claims.get("email") or "").split("@", 1)[0],
        subject,
    )
    max_length = UserProfile._meta.get_field("username").max_length
    base = ""
    for value in raw_candidates:
        value = str(value or "").strip()
        value = re.sub(r"[^\w.@+-]+", "-", value, flags=re.UNICODE).strip("-")
        if value:
            base = value[:max_length]
            break
    if not base:
        base = "oidc-user"
    if attempt == 0 and not UserProfile.objects.filter(username__iexact=base).exists():
        return base
    suffix = "-" + hashlib.sha256(f"{issuer}\0{subject}\0{attempt}".encode()).hexdigest()[:10]
    return f"{base[: max_length - len(suffix)]}{suffix}"


def _validated_oidc_email(claims):
    if claims.get("email_verified") is not True:
        return ""
    email = str(claims.get("email") or "").strip()
    if not email or len(email) > 254:
        return ""
    try:
        validate_email(email)
    except ValidationError:
        return ""
    return email


def _oidc_auto_provision_allowed(provider, claims):
    if not provider.get("auto_provision", False):
        return False

    allowed_domains = provider.get("auto_provision_email_domains", ())
    required_claims = provider.get("auto_provision_required_claims", {})
    if not allowed_domains and not required_claims:
        return False
    if allowed_domains:
        email = _validated_oidc_email(claims)
        _local, separator, domain = email.rpartition("@")
        if not separator or domain.lower() not in allowed_domains:
            return False

    for claim_name, allowed_values in required_claims.items():
        claim_value = claims.get(claim_name)
        claim_values = claim_value if isinstance(claim_value, list) else [claim_value]
        if not any(isinstance(value, str) and value in allowed_values for value in claim_values):
            return False
    return True


def _resolve_oidc_user(provider_name, issuer, claims):
    provider = getattr(settings, "OIDC_PROVIDERS", {}).get(provider_name)
    if not provider or str(provider.get("issuer") or "").rstrip("/") != issuer:
        raise ValueError("OIDC provider does not match the validated issuer")
    subject = str(claims.get("sub") or "").strip()
    if not subject or len(subject) > OidcIdentity._meta.get_field("subject").max_length:
        raise ValueError("OIDC subject is invalid")
    last_username = str(claims.get("preferred_username") or claims.get("name") or "").strip()[:255]
    email = _validated_oidc_email(claims)
    auto_provision_allowed = _oidc_auto_provision_allowed(provider, claims)

    user = None
    for attempt in range(16):
        try:
            with transaction.atomic():
                identity = (
                    OidcIdentity.objects.select_for_update()
                    .select_related("user")
                    .filter(issuer=issuer, subject=subject)
                    .first()
                )
                if identity:
                    if identity.is_auto_provisioned and not auto_provision_allowed:
                        raise _OidcPolicyRevocationRequired(identity.user_id)
                    user = identity.user
                    identity.provider = provider_name
                    identity.last_username = last_username
                    identity.last_email = email
                    identity.save(
                        update_fields=[
                            "provider",
                            "last_username",
                            "last_email",
                            "updated_at",
                        ]
                    )
                else:
                    if not auto_provision_allowed:
                        raise PermissionError("OIDC identity is not pre-authorized")
                    username = _oidc_local_username(
                        claims,
                        issuer,
                        subject,
                        attempt,
                    )
                    user = UserProfile.objects.create_user(
                        username=username,
                        password=None,
                        email=email,
                        is_active=True,
                    )
                    OidcIdentity.objects.create(
                        issuer=issuer,
                        subject=subject,
                        provider=provider_name,
                        user=user,
                        is_auto_provisioned=True,
                        last_username=last_username,
                        last_email=email,
                    )
            break
        except _OidcPolicyRevocationRequired as exc:
            revoke_user_credentials((exc.user_id,))
            raise PermissionError("OIDC auto-provision policy no longer permits this identity") from None
        except (IntegrityError, ValidationError):
            identity = OidcIdentity.objects.select_related("user").filter(issuer=issuer, subject=subject).first()
            if identity:
                if identity.is_auto_provisioned and not auto_provision_allowed:
                    revoke_user_credentials((identity.user_id,))
                    raise PermissionError("OIDC auto-provision policy no longer permits this identity") from None
                user = identity.user
                break
    if user is None:
        raise RuntimeError("Unable to allocate a unique OIDC account")
    if not user.is_active:
        raise PermissionError("OIDC account is disabled")
    return user


def get_client_ip(request):
    return client_ip(request)


def _log_event(request, event, level="info", **extra):
    user = getattr(request, "user", None)
    username = (
        user.username if user and getattr(user, "is_authenticated", False) else extra.pop("username", "anonymous")
    )
    payload = {
        "event": event,
        "user": username,
        "ip": get_client_ip(request),
        "route": normalized_route(getattr(request, "resolver_match", None)),
        "method": getattr(request, "method", ""),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    details = json.dumps(payload, ensure_ascii=False, default=str)
    log_fn = getattr(logger, level, logger.info)
    log_fn("event=%s details=%s", event, details)


_record_file_lock = recording_uploads._record_file_lock


def _personal_guid(user):
    return f"personal-{user.id}"


def _personal_profile_name():
    lang = str(getattr(settings, "LANGUAGE_CODE", "")).lower()
    return "我的地址簿" if lang.startswith("zh") else "My address book"


def _is_reserved_ab_profile_name(name):
    return name in {"My address book", "我的地址簿"}


def _ensure_personal_profile(user):
    guid = _personal_guid(user)
    with transaction.atomic():
        profile, _created = AddressBookProfile.objects.get_or_create(
            guid=guid,
            defaults={
                "name": _personal_profile_name(),
                "owner": user,
                "rule": 3,
            },
        )
        if str(profile.owner_id) != str(user.id):
            raise IntegrityError("Personal address-book GUID ownership conflict")
        updates = []
        if not profile.name:
            profile.name = _personal_profile_name()
            updates.append("name")
        if profile.rule != 3:
            profile.rule = 3
            updates.append("rule")
        if updates:
            updates.append("updated_at")
            profile.save(update_fields=updates)
    return profile


def _is_personal_guid(guid):
    return str(guid).startswith("personal-")


def _get_rule_access(profile, user):
    rule = 0
    share = AddressBookShare.objects.filter(Q(profile=profile) & Q(user=user)).first()
    if share:
        rule = max(rule, share.rule)
    rules = AddressBookRule.objects.filter(Q(profile=profile))
    if rules.exists():
        rule = max(rule, rules.filter(Q(is_everyone=True)).values_list("rule", flat=True).first() or 0)
        if user.groups.exists():
            group_rules = rules.filter(Q(group__in=user.groups.all())).values_list("rule", flat=True)
            for r in group_rules:
                rule = max(rule, r)
        user_rule = rules.filter(Q(user=user)).values_list("rule", flat=True).first()
        if user_rule:
            rule = max(rule, user_rule)
    return rule


def _audit_ab_rule(profile, actor, action, target_type, target_name, rule, details=None):
    if not profile:
        return
    target_name = target_name or ""
    if len(target_name) > 150:
        raise ValueError("Address-book audit target name is too long")
    payload = _json_value(
        details if details is not None else {},
        expected_type=(dict, list),
        max_bytes=16 * 1024,
    )
    if payload is None:
        payload = {}
    if isinstance(payload, dict):
        payload.setdefault("authorization_generation", profile.authorization_generation)
    owner = getattr(profile, "owner", None)
    AddressBookRuleAudit.objects.create(
        profile=profile,
        profile_guid=str(profile.guid or ""),
        profile_name=str(profile.name or ""),
        profile_owner_name=getattr(owner, "username", "") or "",
        actor=actor if actor and getattr(actor, "id", None) else None,
        action=action,
        target_type=target_type,
        target_name=target_name,
        rule=int(rule or 1),
        details=payload,
    )


def _get_profile_access(user, guid):
    if guid == _personal_guid(user):
        profile = _ensure_personal_profile(user)
        return profile, user, 3
    profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
    if not profile:
        return None, None, 0
    if user.is_admin:
        return profile, profile.owner, 3
    if str(profile.owner_id) == str(user.id):
        return profile, profile.owner, 3
    rule = _get_rule_access(profile, user)
    if not rule:
        return profile, None, 0
    return profile, profile.owner, rule


def _can_write_rule(rule):
    return rule in (2, 3)


def _lock_profile_for_content_write(user, profile):
    current, owner, rule = lock_profile_access(user, profile.pk)
    if not current or not owner or not _can_write_rule(rule):
        return None, None, 0
    return current, owner, rule


def _lock_profile_for_management(user, profile):
    current, _owner, _rule = lock_profile_access(user, profile.pk)
    if not current or (not user.is_admin and str(current.owner_id) != str(user.pk)):
        return None
    return current


def _safe_tags(tags):
    if not isinstance(tags, list):
        return []
    output = []
    seen = set()
    for value in tags:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value or value in seen:
            continue
        output.append(value)
        seen.add(value)
    return output


def _bounded_text_value(value, max_bytes, allow_empty=True):
    if not isinstance(value, str):
        return None
    if not allow_empty and not value:
        return None
    if len(value.encode()) > max_bytes or any(ord(ch) < 32 and ch not in "\n\r\t" for ch in value):
        return None
    return value


def _model_text_value(
    value,
    model,
    field_name,
    *,
    allow_empty=True,
    strip=True,
    max_bytes=None,
):
    if not isinstance(value, str):
        return None
    value = value.strip() if strip else value
    field = model._meta.get_field(field_name)
    max_length = getattr(field, "max_length", None)
    if (not allow_empty and not value) or (max_length is not None and len(value) > max_length):
        return None
    byte_limit = max_bytes or ((max_length or 4096) * 4)
    return _bounded_text_value(value, byte_limit, allow_empty=allow_empty)


def _email_value(value, *, allow_empty=True):
    value = _model_text_value(
        value,
        UserProfile,
        "email",
        allow_empty=allow_empty,
    )
    if value is None or (allow_empty and not value):
        return value
    try:
        validate_email(value)
    except ValidationError:
        return None
    return value


def _json_value(value, *, expected_type, max_bytes):
    if not isinstance(value, expected_type):
        return None
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError):
        return None
    return value if len(encoded) <= max_bytes else None


_PROFILE_INFO_FORBIDDEN_KEYS = frozenset(
    {
        "credential",
        "credentials",
        "password",
        "rhash",
        "secret",
        "token",
    }
)


def _profile_info_contains_credential(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key.casefold() in _PROFILE_INFO_FORBIDDEN_KEYS:
                return True
            if _profile_info_contains_credential(child):
                return True
    elif isinstance(value, list):
        return any(_profile_info_contains_credential(child) for child in value)
    return False


def _profile_info_value(value):
    parsed = _json_value(value, expected_type=(dict, list), max_bytes=16 * 1024)
    if parsed is None or _profile_info_contains_credential(parsed):
        return None
    return parsed


def _public_profile_info(value):
    if isinstance(value, dict):
        return {
            key: _public_profile_info(child)
            for key, child in value.items()
            if not isinstance(key, str) or key.casefold() not in _PROFILE_INFO_FORBIDDEN_KEYS
        }
    if isinstance(value, list):
        return [_public_profile_info(child) for child in value]
    return value


def _profile_default_password(value):
    value = _bounded_text_value(value, MAX_AB_PROFILE_PASSWORD_BYTES)
    if value is None or len(value) > 60:
        return None
    return value


def _strategy_options_value(value):
    try:
        return normalize_policy_options(value)
    except InvalidManagedPolicy:
        return None


def _allowed_incomings_value(value):
    if not isinstance(value, list) or len(value) > MAX_ALLOWED_INCOMINGS:
        return None
    result = []
    seen = set()
    for item in value:
        item = _bounded_text_value(
            item.strip() if isinstance(item, str) else item,
            256,
            False,
        )
        if item is None or len(item) > 128:
            return None
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _identifier_list(value, *, numeric=False):
    if not isinstance(value, list) or len(value) > MAX_MANAGEMENT_BATCH_ITEMS:
        return None
    result = []
    seen = set()
    for item in value:
        item = str(item).strip()
        if not item or len(item) > 64 or (numeric and (not item.isascii() or not item.isdigit())):
            return None
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _strict_bool(value):
    return value if isinstance(value, bool) else None


def _user_by_identifier(value, *, active_only=False):
    value = str(value or "").strip()
    if not value or len(value) > 150:
        return None
    query = Q(username__iexact=value)
    if value.isascii() and value.isdigit():
        query |= Q(pk=int(value))
    users = UserProfile.objects.filter(query)
    if active_only:
        users = users.filter(is_active=True)
    return users.order_by("pk").first()


def _numeric_pk(value):
    value = str(value or "").strip()
    if not value or len(value) > 20 or not value.isascii() or not value.isdigit():
        return None
    return int(value)


def _validated_tags(tags):
    if not isinstance(tags, list) or len(tags) > MAX_AB_TAGS_PER_PEER:
        return None
    output = []
    seen = set()
    for value in tags:
        value = _bounded_text_value(value.strip() if isinstance(value, str) else value, 256, False)
        if value is None or value in seen:
            if value in seen:
                continue
            return None
        output.append(value)
        seen.add(value)
    return output


def _validated_peer_payload(data, is_personal, require_id=True):
    if not isinstance(data, dict):
        return None
    result = {}
    field_limits = {
        "username": (100, 400),
        "hostname": (100, 400),
        "alias": (100, 400),
        "platform": (100, 400),
        "note": (4096, 4096),
        "device_group_name": (60, 240),
        "loginName": (60, 240),
    }
    if require_id or "id" in data:
        rid = _bounded_text_value(data.get("id"), 1024, False)
        if rid is None or len(rid) > 255 or any(ch.isspace() for ch in rid):
            return None
        result["id"] = rid
    for key, (max_chars, max_bytes) in field_limits.items():
        if key in data:
            value = _bounded_text_value(data.get(key), max_bytes)
            if value is None or len(value) > max_chars:
                return None
            result[key] = value
    if "tags" in data:
        tags = _validated_tags(data.get("tags"))
        if tags is None:
            return None
        result["tags"] = tags
    secret_key = "hash" if is_personal else "password"
    if secret_key in data:
        value = _bounded_text_value(data.get(secret_key), 1024)
        if value is None or len(value) > 256:
            return None
        result[secret_key] = value
    if "same_server" in data:
        if not isinstance(data.get("same_server"), bool):
            return None
        result["same_server"] = data.get("same_server")
    return result


def _valid_ab_rule(value):
    if isinstance(value, bool):
        return None
    try:
        rule = int(value)
    except (TypeError, ValueError):
        return None
    return rule if rule in (1, 2, 3) else None


DEVICE_INVENTORY_FIELDS = frozenset(
    {
        "cpu",
        "hostname",
        "memory",
        "os",
        "username",
        "version",
    }
)
DEVICE_ADDRESS_BOOK_FIELDS = frozenset(
    {
        "address_book_name",
        "address_book_tag",
        "address_book_alias",
        "address_book_password",
        "address_book_note",
    }
)
DEVICE_SELF_SERVICE_FIELDS = DEVICE_INVENTORY_FIELDS | DEVICE_ADDRESS_BOOK_FIELDS | {"note"}
DEVICE_POLICY_INPUT_KEYS = frozenset(
    {
        "device_group_name",
        "preset-device-group-name",
        "strategy_name",
        "preset-strategy-name",
    }
)


def _device_update_fields(postdata, allowed_fields):
    mapping = {
        "cpu": "cpu",
        "hostname": "hostname",
        "memory": "memory",
        "os": "os",
        "username": "username",
        "version": "version",
        "device_name": "hostname",
        "device_username": "username",
        "note": "note",
        "preset-note": "note",
        "address_book_name": "address_book_name",
        "address_book_tag": "address_book_tag",
        "address_book_alias": "address_book_alias",
        "address_book_password": "address_book_password",
        "address_book_note": "address_book_note",
        "preset-address-book-name": "address_book_name",
        "preset-address-book-tag": "address_book_tag",
        "preset-address-book-alias": "address_book_alias",
        "preset-address-book-password": "address_book_password",
        "preset-address-book-note": "address_book_note",
    }
    updates = {}
    for key, field in mapping.items():
        if field in allowed_fields and key in postdata and postdata[key] is not None:
            updates[field] = postdata[key]
    return updates


def _validated_device_update_fields(
    postdata,
    allowed_fields=DEVICE_INVENTORY_FIELDS,
):
    updates = _device_update_fields(postdata, allowed_fields)
    limits = {
        "cpu": 100,
        "hostname": 100,
        "memory": 100,
        "os": 100,
        "username": 100,
        "version": 100,
        "note": 4096,
        "address_book_name": 60,
        "address_book_tag": 60,
        "address_book_alias": 60,
        "address_book_password": 128,
        "address_book_note": 4096,
    }
    for field, value in updates.items():
        if not isinstance(value, str) or len(value.encode()) > limits[field]:
            return None
    return updates


def _contains_device_policy_assignment(postdata):
    return any(key in postdata for key in DEVICE_POLICY_INPUT_KEYS)


def _get_or_create_profile(user, name):
    if not name:
        return None
    try:
        with transaction.atomic():
            profile, _created = AddressBookProfile.objects.get_or_create(
                owner=user,
                name=name,
                defaults={
                    "guid": uuid.uuid4().hex,
                    "rule": 3,
                },
            )
            return profile
    except IntegrityError:
        return AddressBookProfile.objects.get(owner=user, name=name)


def _upsert_ab_peer(profile, rid, data, is_personal):
    payload = dict(data)
    payload["id"] = rid
    payload = _validated_peer_payload(payload, is_personal)
    if payload is None:
        raise ValueError("Invalid address-book peer")
    rid = payload.pop("id")
    tag_names = payload.pop("tags", None)
    with transaction.atomic():
        profile = AddressBookProfile.objects.select_for_update().get(
            pk=profile.pk,
        )
        device = RemoteDevice.objects.filter(Q(rid=rid)).first()
        peer, _created = RemotePeer.objects.select_for_update().get_or_create(
            profile=profile,
            rid=rid,
            defaults={
                "username": device.username if device else "",
                "hostname": device.hostname if device else "",
                "platform": device.os if device else "",
            },
        )
        field_map = {
            "username": "username",
            "hostname": "hostname",
            "alias": "alias",
            "platform": "platform",
            "note": "note",
            "device_group_name": "device_group_name",
            "loginName": "login_name",
            "same_server": "same_server",
        }
        for source, target in field_map.items():
            if source in payload:
                setattr(peer, target, payload[source])
        if is_personal and "hash" in payload:
            peer.rhash = payload["hash"]
        if not is_personal and "password" in payload:
            peer.password = payload["password"]
        peer.save()
        if tag_names is not None:
            existing_tags = {
                tag.tag_name: tag
                for tag in RemoteTag.objects.filter(
                    profile=profile,
                    tag_name__in=tag_names,
                )
            }
            missing_names = [name for name in tag_names if name not in existing_tags]
            if RemoteTag.objects.filter(profile=profile).count() + len(missing_names) > MAX_AB_TAGS:
                raise ValueError("Address-book tag limit reached")
            RemoteTag.objects.bulk_create(
                [
                    RemoteTag(
                        profile=profile,
                        tag_name=name,
                        tag_color="",
                    )
                    for name in missing_names
                ],
                ignore_conflicts=True,
            )
            peer.tags.set(
                RemoteTag.objects.filter(
                    profile=profile,
                    tag_name__in=tag_names,
                )
            )
    return peer


def _ensure_personal_device_peer(user, device):
    if not device or not device.public_key_hash:
        return None
    profile = _ensure_personal_profile(user)
    with transaction.atomic():
        profile, owner, rule = lock_profile_access(user, profile.pk)
        if not profile or not owner or not _can_write_rule(rule) or profile.guid != _personal_guid(user):
            return None
        peer, _created = RemotePeer.objects.get_or_create(
            profile=profile,
            rid=device.rid,
            defaults={
                "username": device.username or "",
                "hostname": device.hostname or "",
                "platform": device.os or "",
            },
        )
    return peer


def _finalize_personal_device_peer(user, device):
    try:
        return _ensure_personal_device_peer(user, device)
    except IntegrityError as exc:
        raise DeviceCredentialFinalizationError("Personal device peer finalization failed") from exc


def login(request):
    result = {}
    data = _load_json_object(request)

    username_value = data.get("username", "")
    username = username_value.strip() if isinstance(username_value, str) else ""
    password = data.get("password", "")
    rid = data.get("id", "")
    uuid = data.get("uuid", "")
    device_info = _validated_login_device_info(data.get("deviceInfo", {}))
    if (
        not username
        or len(username) > UserProfile._meta.get_field("username").max_length
        or not isinstance(password, str)
        or not password
        or len(password) > settings.MAX_PASSWORD_LENGTH
        or not _valid_device_identity(rid, uuid)
        or device_info is None
    ):
        _log_event(request, "api_login_invalid_payload", level="warning", username=username)
        return JsonResponse({"error": "Invalid login payload"}, status=400)
    client_ip = get_client_ip(request)
    admission = reserve_login_attempt(client_ip, username)
    if admission is None:
        _log_event(request, "api_login_locked", level="warning", username=username)
        return JsonResponse({"error": _("尝试次数过多，请稍后再试。")}, status=429)
    user = auth.authenticate(username=username, password=password)
    if not user:
        result["error"] = _("帐号或密码错误！请重试，多次重试后将被锁定IP！")
        _log_event(request, "api_login_failed", level="warning", username=username)
        return JsonResponse(result, status=401)
    if not user.is_active:
        _log_event(request, "api_login_denied", level="warning", username=username, reason="inactive")
        return JsonResponse({"error": _("账号已被禁用")}, status=403)

    try:
        with transaction.atomic():
            device = _claim_session_device(
                user,
                rid,
                uuid,
                client_ip,
                device_info,
                data.get("device_proof"),
                DeviceProofChallenge.PURPOSE_LOGIN,
            )
            _token, raw_token = _issue_access_token(user, device)
            _finalize_personal_device_peer(user, device)
            complete_login_success(admission)
    except DeviceIdentityConflict:
        _log_event(
            request, "api_login_denied", level="warning", username=username, reason="device_identity_conflict", rid=rid
        )
        return JsonResponse({"error": "Device identity conflict"}, status=409)
    except (PermissionError, DeviceProofError):
        _log_event(
            request, "api_login_denied", level="warning", username=username, reason="device_unavailable", rid=rid
        )
        return JsonResponse({"error": "Permission denied"}, status=403)
    except IntegrityError:
        _log_event(
            request, "api_login_denied", level="warning", username=username, reason="device_identity_race", rid=rid
        )
        return JsonResponse({"error": "Device identity conflict"}, status=409)
    result.update(_auth_body(user, raw_token))
    _log_event(request, "api_login_success", username=user.username, rid=rid)
    return JsonResponse(result)


def logout(request):
    token, user = _get_token_user(request)
    if not token or not user:
        _log_event(request, "api_logout_failed", level="warning")
        return JsonResponse({"error": _("异常请求！")}, status=401)
    token.delete()

    result = {"code": 1}
    _log_event(request, "api_logout_success", username=user.username, rid=token.device.rid)
    return JsonResponse(result)


def currentUser(request):
    result = {}
    _token, user = _get_token_user(request)

    if not user:
        _log_event(request, "api_current_user_failed", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    result["type"] = "access_token"
    result["name"] = user.username
    result["status"] = 1 if user.is_active else 0
    result["is_admin"] = True if user.is_admin else False
    result["email"] = user.email or ""
    result["note"] = user.note or ""
    _log_event(request, "api_current_user_success", username=user.username)
    return JsonResponse(result)


def sysinfo(request):
    client_ip = get_client_ip(request)
    postdata = _load_json_object(request)
    rid = postdata.get("id")
    device_uuid = postdata.get("uuid")
    if not _valid_device_identity(rid, device_uuid):
        _log_event(request, "api_sysinfo_missing_id", level="warning")
        return HttpResponse("ID_NOT_FOUND", status=400)
    token, user = _get_device_token_user(request, rid, device_uuid)
    if not token or not user:
        _log_event(request, "api_sysinfo_unauthorized", level="warning", rid=rid)
        return JsonResponse({"error": "Invalid device token"}, status=401)
    if _contains_device_policy_assignment(postdata):
        _log_event(
            request,
            "api_sysinfo_policy_fields_ignored",
            level="warning",
            username=user.username,
            rid=rid,
        )
    updates = _validated_device_update_fields(postdata)
    if updates is None:
        _log_event(request, "api_sysinfo_invalid_payload", level="warning", username=user.username, rid=rid)
        return JsonResponse({"error": "Invalid device information"}, status=400)
    try:
        with transaction.atomic():
            device = _device_by_identity(rid, device_uuid, for_update=True)
            if not _is_active_owned_device(device, user):
                _log_event(request, "api_sysinfo_denied", level="warning", username=user.username, rid=rid)
                return JsonResponse({"error": "Device is not active for this account"}, status=403)
            for key, val in updates.items():
                setattr(device, key, val)
            device.ip_address = client_ip
            device.save()
    except (DeviceIdentityConflict, IntegrityError):
        _log_event(request, "api_sysinfo_conflict", level="warning", username=user.username, rid=rid)
        return JsonResponse({"error": "Device identity conflict"}, status=409)
    _log_event(request, "api_sysinfo_updated", level="debug", username=user.username, rid=rid, uuid=device_uuid)
    return HttpResponse("SYSINFO_UPDATED")


def heartbeat(request):
    postdata = _load_json_object(request)
    rid = postdata.get("id")
    device_uuid = postdata.get("uuid")
    if not _valid_device_identity(rid, device_uuid):
        _log_event(request, "api_heartbeat_missing_id", level="warning")
        return JsonResponse({"error": "ID_NOT_FOUND"}, status=400)
    token, user = _get_device_token_user(request, rid, device_uuid)
    if not token or not user:
        _log_event(request, "api_heartbeat_unauthorized", level="warning", rid=rid)
        return JsonResponse(
            {
                "error": "Invalid device token",
                "device_lease": _revoked_device_lease(rid, device_uuid),
            },
            status=401,
        )
    with transaction.atomic():
        try:
            device = _device_by_identity(rid, device_uuid, for_update=True)
        except DeviceIdentityConflict:
            return JsonResponse({"error": "Device identity conflict"}, status=409)
        if not _is_active_owned_device(device, user):
            _log_event(
                request,
                "api_heartbeat_device_denied",
                level="warning",
                username=user.username,
                rid=rid,
                uuid=device_uuid,
            )
            return JsonResponse(
                {
                    "error": "Device is not active for this account",
                    "device_lease": _revoked_device_lease(rid, device_uuid),
                },
                status=403,
            )
        device.ip_address = get_client_ip(request)
        now = timezone.now()

        # Do not save the previously loaded token instance: a concurrent
        # credential revocation may already have deleted it. A conditional
        # update cannot resurrect a deleted row and binds renewal to the
        # freshly locked device owner's current credential generation.
        renewed = RemoteToken.objects.filter(
            pk=token.pk,
            device=device,
            subject_user=device.owner,
            credential_hash=device.owner.get_session_auth_hash(),
            expires_at__gt=now,
        ).update(expires_at=now + datetime.timedelta(seconds=EFFECTIVE_SECONDS))
        if renewed != 1:
            _log_event(
                request,
                "api_heartbeat_credential_revoked",
                level="warning",
                username=user.username,
                rid=rid,
                uuid=device_uuid,
            )
            return JsonResponse(
                {
                    "error": "Invalid device token",
                    "device_lease": _revoked_device_lease(rid, device_uuid),
                },
                status=401,
            )
        device.save(update_fields=["ip_address", "update_time"])
    response = {
        "device_lease": {
            "version": 1,
            "state": "active",
            "id": device.rid,
            "uuid": device.uuid,
            "deployment_generation": device.deployment_generation,
            "valid_for_seconds": DEVICE_LEASE_SECONDS,
        }
    }
    try:
        response["managed_policy"] = managed_policy_document(device)
    except InvalidManagedPolicy:
        profile = device.effective_strategy()
        logger.error(
            "event=invalid_strategy_options strategy_id=%s",
            profile.pk if profile else None,
        )
        return JsonResponse({"error": "Invalid strategy configuration"}, status=503)
    _log_event(request, "api_heartbeat", level="debug", username=user.username, rid=rid, uuid=device_uuid)
    return JsonResponse(response)


def sysinfo_ver(request):
    _token, user = _get_token_user(request)
    if not user:
        return JsonResponse({"error": "Invalid token"}, status=401)
    _log_event(request, "api_sysinfo_ver", level="debug", username=user.username)
    return HttpResponse("1")


def health_live(request):
    return JsonResponse({"status": "live"})


def health_ready(request):
    if len(getattr(settings, "DEVICE_VERIFICATION_TOKEN", "")) < 32:
        return JsonResponse({"status": "not_ready"}, status=503)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        RemoteDevice.objects.order_by("pk").values_list("pk", flat=True).first()
        key_states = list(DataEncryptionKeyState.objects.order_by("key_id")[: settings.MAX_DATA_ENCRYPTION_KEYS + 1])
        primary_key_id = getattr(settings, "DATA_ENCRYPTION_PRIMARY_KEY_ID", "")
        if (
            not key_states
            or len(key_states) > settings.MAX_DATA_ENCRYPTION_KEYS
            or [state.key_id for state in key_states if state.is_primary] != [primary_key_id]
            or any(
                not verify_key_canary(
                    state.key_id,
                    state.key_fingerprint,
                    state.encrypted_canary,
                )
                for state in key_states
            )
        ):
            raise ValidationError("Data-encryption key inventory does not match this replica")
        ingestion_governance.check_recording_storage_capability()
    except Exception as exc:  # noqa: BLE001 - readiness normalizes backend failures
        logger.warning("readiness database check failed: %s", type(exc).__name__)
        return JsonResponse({"status": "not_ready"}, status=503)
    return JsonResponse({"status": "ready"})


def login_options(request):
    _log_event(request, "api_login_options", level="debug")
    providers = getattr(settings, "OIDC_PROVIDERS", {})
    return JsonResponse([f"oidc/{name}" for name in providers.keys()], safe=False)


def oidc_auth(request):
    data = _load_json_object(request)
    provider_name = _oidc_provider_name(data.get("op"))
    provider = getattr(settings, "OIDC_PROVIDERS", {}).get(provider_name)
    if not provider:
        _log_event(request, "api_oidc_auth_unknown_provider", level="warning", op=provider_name)
        return JsonResponse({"error": "OIDC provider is not configured"}, status=404)
    rid = data.get("id", "")
    device_uuid = data.get("uuid", "")
    if not _valid_device_identity(rid, device_uuid):
        return JsonResponse({"error": "Invalid device identity"}, status=400)
    device_info = _validated_login_device_info(data.get("deviceInfo", {}))
    device_proof = data.get("device_proof", {})
    if device_info is None or not isinstance(device_proof, dict):
        return JsonResponse({"error": "Invalid deviceInfo"}, status=400)

    now = timezone.now()
    cutoff = now - datetime.timedelta(minutes=OIDC_PENDING_MINUTES)
    client_ip = get_client_ip(request)
    if (
        OidcPendingAuth.objects.filter(
            request_ip=client_ip,
            created_at__gte=cutoff,
        ).count()
        >= OIDC_MAX_PENDING_PER_IP
    ):
        _log_event(request, "api_oidc_auth_rate_limited", level="warning", op=provider_name)
        return JsonResponse({"error": "Too many pending OIDC authorizations"}, status=429)

    state = secrets.token_urlsafe(32)
    poll_code = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    try:
        if not _valid_https_url(provider.get("redirect_uri")):
            raise ValueError("OIDC redirect URI must use HTTPS")
        metadata = _oidc_metadata(
            provider["issuer"],
            provider["allowed_hosts"],
        )
        client = _oidc_client(provider)
        auth_url = client.create_authorization_url(
            metadata["authorization_endpoint"],
            state=state,
            code_verifier=code_verifier,
            nonce=nonce,
        )[0]
        OidcPendingAuth.objects.create(
            state=state,
            poll_code_hash=_hash_token(poll_code),
            provider=provider_name,
            request_ip=client_ip,
            rid=rid,
            device_uuid=device_uuid,
            device_info=device_info,
            device_proof=device_proof,
            nonce=nonce,
            code_verifier=code_verifier,
            status=OidcPendingAuth.STATUS_PENDING,
        )
    except Exception as exc:  # noqa: BLE001 - external provider failures are normalized
        _log_event(
            request,
            "api_oidc_auth_failed",
            level="warning",
            op=provider_name,
            error_type=type(exc).__name__,
        )
        return JsonResponse({"error": "Failed to initialize OIDC authorization"}, status=502)
    _log_event(request, "api_oidc_auth_created", level="debug", op=provider_name)
    return JsonResponse({"code": poll_code, "url": auth_url})


def oidc_auth_query(request):
    data = _load_json_object(request)
    poll_code = str(data.get("code", "")).strip()
    rid = data.get("id", "")
    device_uuid = data.get("uuid", "")
    if not poll_code or len(poll_code) > 128 or not _valid_device_identity(rid, device_uuid):
        return JsonResponse({"error": "No authed oidc is found"})
    with transaction.atomic():
        session = (
            OidcPendingAuth.objects.select_for_update(of=("self",))
            .select_related("authenticated_user")
            .filter(poll_code_hash=_hash_token(poll_code))
            .first()
        )
        if not session:
            return JsonResponse({"error": "No authed oidc is found"})
        if not secrets.compare_digest(session.rid, rid) or not secrets.compare_digest(session.device_uuid, device_uuid):
            return JsonResponse({"error": "OIDC authorization failed"}, status=403)
        if timezone.now() - session.created_at > datetime.timedelta(minutes=OIDC_PENDING_MINUTES):
            session.delete()
            return JsonResponse({"error": "OIDC authorization timeout"}, status=408)
        if session.status == OidcPendingAuth.STATUS_ERROR:
            session.delete()
            return JsonResponse({"error": "OIDC authorization failed"}, status=400)
        if session.status != OidcPendingAuth.STATUS_DONE or not session.authenticated_user:
            return JsonResponse({"error": "No authed oidc is found"})
        user = session.authenticated_user
        if not user.is_active:
            session.delete()
            return JsonResponse({"error": "OIDC authorization failed"}, status=403)
        try:
            device = _claim_session_device(
                user,
                session.rid,
                session.device_uuid,
                session.request_ip,
                session.device_info,
                session.device_proof,
                DeviceProofChallenge.PURPOSE_OIDC,
            )
            _token, raw_token = _issue_access_token(user, device)
        except (DeviceIdentityConflict, IntegrityError):
            session.delete()
            return JsonResponse({"error": "OIDC authorization failed"}, status=409)
        except (PermissionError, DeviceProofError):
            session.delete()
            return JsonResponse({"error": "OIDC authorization failed"}, status=403)
        body = _auth_body(user, raw_token)
        session.delete()
    return JsonResponse(body)


def oidc_callback(request):
    state = str(request.GET.get("state", "")).strip()
    code = str(request.GET.get("code", "")).strip()
    session = OidcPendingAuth.objects.filter(Q(state=state)).first() if state else None
    provider_error = str(request.GET.get("error", "")).strip()
    if provider_error and session:
        OidcPendingAuth.objects.filter(
            state=state,
            status=OidcPendingAuth.STATUS_PENDING,
        ).update(
            status=OidcPendingAuth.STATUS_ERROR,
            error_code="provider_denied",
        )
        return HttpResponse("OIDC authorization was not completed.", status=400)
    if not state or not code or not session:
        return HttpResponse("Invalid OIDC callback", status=400)
    if timezone.now() - session.created_at > datetime.timedelta(minutes=OIDC_PENDING_MINUTES):
        session.delete()
        return HttpResponse("OIDC authorization expired", status=408)
    if session.status == OidcPendingAuth.STATUS_DONE:
        return HttpResponse("OIDC authorization completed. You can close this window.")
    if session.status != OidcPendingAuth.STATUS_PENDING:
        return HttpResponse("OIDC authorization was not completed.", status=400)
    provider = getattr(settings, "OIDC_PROVIDERS", {}).get(session.provider)
    if not provider:
        session.status = OidcPendingAuth.STATUS_ERROR
        session.error_code = "provider_not_configured"
        session.save(update_fields=["status", "error_code"])
        return HttpResponse("OIDC provider is not configured", status=400)
    try:
        metadata = _oidc_metadata(
            provider["issuer"],
            provider["allowed_hosts"],
        )
        client = _oidc_client(provider, state=state)
        token = client.fetch_token(
            metadata["token_endpoint"],
            code=code,
            code_verifier=session.code_verifier,
            allow_redirects=False,
        )
        claims = _validate_oidc_id_token(token, metadata, provider, session.nonce)
        issuer = str(claims["iss"]).rstrip("/")
        user = _resolve_oidc_user(session.provider, issuer, claims)
        with transaction.atomic():
            pending = OidcPendingAuth.objects.select_for_update().filter(state=state).first()
            if not pending or pending.status != OidcPendingAuth.STATUS_PENDING:
                return HttpResponse("OIDC authorization was already consumed.", status=409)
            pending.authenticated_user = user
            pending.status = OidcPendingAuth.STATUS_DONE
            pending.error_code = ""
            pending.save(update_fields=["authenticated_user", "status", "error_code"])
        _log_event(request, "api_oidc_callback_success", username=user.username)
    except Exception as exc:  # noqa: BLE001 - external provider failures are normalized
        OidcPendingAuth.objects.filter(
            state=state,
            status=OidcPendingAuth.STATUS_PENDING,
        ).update(
            status=OidcPendingAuth.STATUS_ERROR,
            error_code="verification_failed",
        )
        _log_event(
            request,
            "api_oidc_callback_failed",
            level="warning",
            error_type=type(exc).__name__,
        )
        return HttpResponse("OIDC authorization failed", status=400)
    return HttpResponse("OIDC authorization completed. You can close this window.")


def devices_cli(request):
    postdata = _load_json_object(request)
    rid = postdata.get("id", "")
    device_uuid = postdata.get("uuid", "")
    if not _valid_device_identity(rid, device_uuid):
        _log_event(request, "api_devices_cli_missing_id", level="warning")
        return JsonResponse({"error": "ID_NOT_FOUND"}, status=400)
    token, user = _get_device_token_user(request, rid, device_uuid)
    if not token or not user:
        _log_event(request, "api_devices_cli_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid device token"}, status=401)
    owner_name = postdata.get("user_name", "")
    if not isinstance(owner_name, str) or len(owner_name) > 150:
        return JsonResponse({"error": "Invalid user_name"}, status=400)
    if owner_name and owner_name != user.username:
        _log_event(
            request, "api_devices_cli_denied", level="warning", username=user.username, rid=rid, reason="owner_mismatch"
        )
        return JsonResponse({"error": "Device ownership cannot be changed here"}, status=403)
    if _contains_device_policy_assignment(postdata):
        _log_event(
            request,
            "api_devices_cli_policy_fields_ignored",
            level="warning",
            username=user.username,
            rid=rid,
        )
    updates = _validated_device_update_fields(
        postdata,
        DEVICE_SELF_SERVICE_FIELDS,
    )
    if updates is None:
        return JsonResponse({"error": "Invalid device information"}, status=400)
    ab_name = postdata.get("address_book_name", "")
    ab_tag = postdata.get("address_book_tag", "")
    ab_alias = postdata.get("address_book_alias", "")
    ab_password = postdata.get("address_book_password", "")
    ab_note = postdata.get("address_book_note", "")
    requires_ab = any([ab_name, ab_tag, ab_alias, ab_password, ab_note])

    try:
        with transaction.atomic():
            device = _device_by_identity(rid, device_uuid, for_update=True)
            if not _is_active_owned_device(device, user):
                _log_event(
                    request,
                    "api_devices_cli_denied",
                    level="warning",
                    username=user.username,
                    rid=rid,
                    reason="device_owner_mismatch",
                )
                return JsonResponse({"error": "Device is not active for this account"}, status=403)
            for key, val in updates.items():
                setattr(device, key, val)
            device.save()

            if requires_ab:
                if not device.owner:
                    raise ValueError("Invalid user_name")
                profile = _get_or_create_profile(device.owner, ab_name) if ab_name else None
                profile = profile or _ensure_personal_profile(device.owner)
                profile, current_owner, current_rule = lock_profile_access(device.owner, profile.pk)
                if not profile or not current_owner or not _can_write_rule(current_rule):
                    raise PermissionError("Address-book authorization changed")
                guid = profile.guid
                is_personal = guid == _personal_guid(device.owner)
                tags = [ab_tag] if ab_tag else []
                peer_data = {
                    "alias": ab_alias,
                    "tags": tags,
                    "note": ab_note,
                }
                if ab_password:
                    if is_personal:
                        peer_data["hash"] = ab_password
                    else:
                        peer_data["password"] = ab_password
                _upsert_ab_peer(profile, rid, peer_data, is_personal)
                if ab_tag:
                    RemoteTag.objects.get_or_create(
                        profile=profile,
                        tag_name=ab_tag,
                        defaults={"tag_color": ""},
                    )
    except PermissionError:
        _log_event(
            request,
            "api_devices_cli_denied",
            level="warning",
            username=user.username,
            rid=rid,
            reason="address_book_authorization_changed",
        )
        return JsonResponse({"error": "Address-book authorization changed"}, status=403)
    except ValueError:
        _log_event(
            request,
            "api_devices_cli_failed",
            level="warning",
            username=user.username,
            rid=rid,
            reason="invalid_user_name",
        )
        return JsonResponse({"error": "Invalid user_name"}, status=400)
    except (DeviceIdentityConflict, IntegrityError):
        _log_event(request, "api_devices_cli_conflict", level="warning", username=user.username, rid=rid)
        return JsonResponse({"error": "Device identity conflict"}, status=409)
    _log_event(request, "api_devices_cli_updated", username=user.username, rid=rid)
    return HttpResponse("")


def devices_proof_challenge(request):
    postdata = _load_json_object(request)
    purpose = str(postdata.get("purpose", "")).strip()
    rid = str(postdata.get("id", "")).strip()
    uuid_value = str(postdata.get("uuid", "")).strip()
    public_key = str(postdata.get("pk", "")).strip()
    if not _valid_device_identity(rid, uuid_value):
        return JsonResponse({"error": "Invalid device identity"}, status=400)

    token = user = None
    if purpose == DeviceProofChallenge.PURPOSE_DEPLOY:
        token, user = _get_token_user(request)
        device = token.device if token and user else None
        if not device or device.uuid != uuid_value:
            return JsonResponse({"error": "Invalid device token"}, status=401)
    elif purpose not in (
        DeviceProofChallenge.PURPOSE_LOGIN,
        DeviceProofChallenge.PURPOSE_OIDC,
    ):
        return JsonResponse({"error": "Invalid proof purpose"}, status=400)
    else:
        try:
            device = _device_by_identity(rid, uuid_value)
        except DeviceIdentityConflict:
            return JsonResponse({"error": "Device identity conflict"}, status=409)
    try:
        body = issue_proof_challenge(
            purpose=purpose,
            rid=rid,
            device_uuid=uuid_value,
            public_key_text=public_key,
            request_ip=get_client_ip(request),
            device=device,
            user=user,
        )
    except DeviceProofError as exc:
        status = 429 if "Too many" in str(exc) else 400
        return JsonResponse({"error": str(exc)}, status=status)
    return JsonResponse(body)


def devices_deploy(request):
    token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_devices_deploy_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    if len(settings.DEVICE_VERIFICATION_TOKEN) < 32:
        _log_event(request, "api_devices_deploy_not_enabled", level="error", username=user.username)
        return JsonResponse({"result": "NOT_ENABLED"}, status=503)
    postdata = _load_json_object(request)
    rid = str(postdata.get("id", "")).strip()
    uuid_value = str(postdata.get("uuid", "")).strip()
    pk = str(postdata.get("pk", "")).strip()
    device_proof = postdata.get("device_proof")
    identity = _deployment_identity(rid, uuid_value, pk)
    if identity is None or len(pk) > MAX_DEPLOY_KEY_LEN:
        _log_event(request, "api_devices_deploy_invalid_input", level="warning", username=user.username, rid=rid)
        return JsonResponse({"result": "INVALID_INPUT"}, status=400)
    rid, uuid_value, public_key_hash = identity
    if token.device.uuid != uuid_value:
        _log_event(
            request,
            "api_devices_deploy_denied",
            level="warning",
            username=user.username,
            rid=rid,
            reason="token_device_mismatch",
        )
        return JsonResponse({"error": "Device token mismatch"}, status=403)

    try:
        with transaction.atomic():
            # Identity mutations use one lock order: user authority first,
            # then devices by primary key, followed by proofs and tokens.
            # In particular, a full device save and personal-profile
            # finalization can both require PostgreSQL to validate an owner
            # FK. Locking a device first would therefore deadlock with account
            # deletion, which holds the user row before locking its devices.
            locked_user = UserProfile.objects.select_for_update().filter(pk=user.pk, is_active=True).first()
            if not locked_user:
                _log_event(
                    request,
                    "api_devices_deploy_denied",
                    level="warning",
                    username=user.username,
                    rid=rid,
                    reason="inactive_user",
                )
                return JsonResponse({"error": "Invalid token"}, status=401)
            token_is_current = RemoteToken.objects.filter(
                pk=token.pk,
                device_id=token.device_id,
                subject_user=locked_user,
                credential_hash=locked_user.get_session_auth_hash(),
                expires_at__gt=timezone.now(),
            ).exists()
            if not token_is_current:
                _log_event(
                    request,
                    "api_devices_deploy_denied",
                    level="warning",
                    username=locked_user.username,
                    rid=rid,
                    reason="stale_token",
                )
                return JsonResponse({"error": "Invalid token"}, status=401)
            user = locked_user
            matches = list(
                RemoteDevice.objects.select_for_update().filter(Q(rid=rid) | Q(uuid=uuid_value)).order_by("pk")
            )
            id_match = next((item for item in matches if item.rid == rid), None)
            uuid_match = next((item for item in matches if item.uuid == uuid_value), None)
            if id_match and id_match.uuid != uuid_value:
                _log_event(request, "api_devices_deploy_id_taken", level="warning", username=user.username, rid=rid)
                return JsonResponse({"result": "ID_TAKEN"}, status=409)
            if id_match and uuid_match and id_match.pk != uuid_match.pk:
                _log_event(request, "api_devices_deploy_conflict", level="error", username=user.username, rid=rid)
                return JsonResponse({"result": "ID_TAKEN"}, status=409)
            device = uuid_match or id_match
            if device and device.owner_id and device.owner_id != user.id:
                _log_event(request, "api_devices_deploy_denied", level="warning", username=user.username, rid=rid)
                return JsonResponse({"error": "Permission denied"}, status=403)
            if device and not device.is_active:
                _log_event(
                    request,
                    "api_devices_deploy_denied",
                    level="warning",
                    username=user.username,
                    rid=rid,
                    reason="inactive",
                )
                return JsonResponse({"error": "Device disabled"}, status=403)
            if not device:
                device = RemoteDevice(
                    rid=rid,
                    cpu="-",
                    hostname="-",
                    memory="-",
                    os="-",
                    uuid=uuid_value,
                    username="",
                    version="-",
                    ip_address=get_client_ip(request),
                )
            old_rid = device.rid
            old_uuid = device.uuid
            old_key_hash = device.public_key_hash
            proof_result = consume_deployment_proof(
                proof=device_proof,
                device=device,
                user=user,
                new_rid=rid,
                new_uuid=uuid_value,
            )
            device.rid = rid
            device.uuid = uuid_value
            device.public_key_hash = proof_result.public_key_hash
            device.owner = user
            device.ip_address = get_client_ip(request)
            device.save()
            if old_rid != rid or old_uuid != uuid_value or (old_key_hash and old_key_hash != public_key_hash):
                _revoke_device_tokens(device)
            _finalize_personal_device_peer(user, device)
    except DeviceRecoveryRequired:
        return JsonResponse({"result": "RECOVERY_REQUIRED"}, status=409)
    except DeviceProofError:
        return JsonResponse({"error": "Invalid device proof"}, status=403)
    except IntegrityError:
        _log_event(request, "api_devices_deploy_conflict", level="warning", username=user.username, rid=rid)
        return JsonResponse({"result": "ID_TAKEN"}, status=409)

    _log_event(request, "api_devices_deploy_ok", username=user.username, rid=rid)
    return JsonResponse({"result": "OK"})


def devices_verify_deployment(request):
    expected_token = settings.DEVICE_VERIFICATION_TOKEN
    supplied_token = _get_bearer_token(request)
    if (
        not expected_token
        or len(expected_token) < 32
        or not supplied_token
        or not secrets.compare_digest(supplied_token, expected_token)
    ):
        _log_event(request, "api_devices_verify_unauthorized", level="warning")
        return HttpResponse(status=401)
    if len(request.body) > 4096:
        return HttpResponse(status=413)
    postdata = _load_json_object(request)
    rid = str(postdata.get("id", "")).strip()
    uuid_value = str(postdata.get("uuid", "")).strip()
    public_key_hash = str(postdata.get("public_key_hash", "")).strip().lower()
    request_nonce = str(postdata.get("request_nonce", "")).strip()
    if (
        not re.fullmatch(r"[A-Za-z0-9_-]{6,16}", rid)
        or _decode_canonical_base64(uuid_value, max_decoded_bytes=256) is None
        or not re.fullmatch(r"[0-9a-f]{64}", public_key_hash)
        or len(request_nonce) > 128
    ):
        return HttpResponse(status=400)
    device = RemoteDevice.objects.filter(
        rid=rid,
        uuid=uuid_value,
        public_key_hash=public_key_hash,
        is_active=True,
        owner__is_active=True,
    ).first()
    if not device:
        return HttpResponse(status=404)
    try:
        body = deployment_assertion(
            secret=expected_token,
            rid=rid,
            device_uuid=uuid_value,
            key_hash=public_key_hash,
            generation=device.deployment_generation,
            request_nonce=request_nonce,
        )
    except DeviceProofError:
        return HttpResponse(status=400)
    return JsonResponse(body)


def record(request):
    token, user = _get_token_user(request)
    if not token or not user or not _get_active_token_device(token, user):
        _log_event(request, "api_record_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid device token"}, status=401)
    try:
        try:
            required_bytes = int(request.META.get("CONTENT_LENGTH", "0") or 0)
        except (TypeError, ValueError):
            required_bytes = 0
        ingestion_governance.check_recording_storage_capability(max(0, required_bytes))
    except ingestion_governance.RecordingStorageUnavailable as error:
        return ingestion_governance.storage_error_response(error)
    return recording_uploads.handle_record_upload(request, token)


def audit_with_type(request, typ):
    _log_event(request, "api_audit_dispatch", level="debug", typ=typ)
    try:
        if request.method == "GET":
            if typ == "conn/active":
                return _audit_conn_active(request)
            return JsonResponse({"error": "Not found"}, status=404)
        if typ == "conn":
            return _audit_conn(request)
        if typ == "file":
            return _audit_file(request)
        if typ == "alarm":
            return _audit_alarm(request)
        _log_event(request, "api_audit_unknown", level="warning", typ=typ)
        return JsonResponse({"error": "Not found"}, status=404)
    except ingestion_governance.IngestionQuotaExceeded as error:
        return ingestion_governance.quota_response(error)


def audit_note(request):
    postdata = _load_json_object(request)
    try:
        return _audit_controller_note_by_capability(request, postdata)
    except ingestion_governance.IngestionQuotaExceeded as error:
        return ingestion_governance.quota_response(error)


def audit_root(request):
    return audit_note(request)


def ab_settings(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_settings_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    _log_event(request, "api_ab_settings", level="debug", username=user.username)
    return JsonResponse(
        {
            "max_peer_one_ab": MAX_AB_PEERS,
            "max_tag_one_ab": MAX_AB_TAGS,
            "max_tag_one_peer": MAX_AB_TAGS_PER_PEER,
        }
    )


def ab_personal(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_personal_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile = _ensure_personal_profile(user)
    _log_event(request, "api_ab_personal", level="debug", username=user.username)
    return JsonResponse({"guid": _personal_guid(user), "name": profile.name})


def ab_shared_profiles(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_shared_profiles_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    current, page_size, _start, _end = _pagination(request)
    items = {}

    def add_profile(p, rule_value):
        if not p or _is_personal_guid(p.guid):
            return
        info = _public_profile_info(p.info)
        owner_name = p.owner.username if p.owner else ""
        existing = items.get(p.guid)
        rule_value = int(rule_value or 0)
        if existing:
            if rule_value > existing.get("rule", 0):
                existing["rule"] = rule_value
            return
        items[p.guid] = {
            "guid": p.guid,
            "name": p.name,
            "owner": owner_name,
            "note": p.note,
            "info": info,
            "rule": rule_value,
        }

    if user.is_admin:
        for p in AddressBookProfile.objects.defer("default_password").all():
            add_profile(p, 3)
    else:
        for p in AddressBookProfile.objects.defer("default_password").filter(Q(owner=user)):
            add_profile(p, 3)
        for share in (
            AddressBookShare.objects.filter(Q(user=user))
            .select_related("profile", "profile__owner")
            .defer("profile__default_password")
        ):
            add_profile(share.profile, share.rule)
        group_ids = list(user.groups.values_list("id", flat=True))
        rules_qs = AddressBookRule.objects.filter(Q(is_everyone=True))
        if group_ids:
            rules_qs = rules_qs | AddressBookRule.objects.filter(Q(group_id__in=group_ids))
        rules_qs = rules_qs | AddressBookRule.objects.filter(Q(user=user))
        for r in rules_qs.select_related("profile", "profile__owner").defer("profile__default_password"):
            add_profile(r.profile, r.rule)
    data = list(items.values())
    data.sort(key=lambda x: x.get("name", ""))
    total = len(data)
    start = (current - 1) * page_size
    end = start + page_size
    _log_event(
        request,
        "api_ab_shared_profiles",
        level="debug",
        username=user.username,
        total=total,
        page=current,
        page_size=page_size,
    )
    return JsonResponse({"total": total, "data": data[start:end]})


def ab_shared_credential(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_shared_credential_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json_object(request)
    guid = _bounded_text_value(postdata.get("guid"), 60, allow_empty=False)
    rid = _bounded_text_value(postdata.get("id"), 16, allow_empty=False)
    if guid is None or rid is None or any(ch.isspace() for ch in rid):
        return JsonResponse({"error": "Invalid target"}, status=400)

    with transaction.atomic():
        profile_id = AddressBookProfile.objects.filter(guid=guid).values_list("pk", flat=True).first()
        if profile_id is None or _is_personal_guid(guid):
            return JsonResponse({"error": "Not found"}, status=404)
        profile, owner, rule = lock_profile_access(user, profile_id)
        if not profile or not owner or not rule:
            _log_event(
                request,
                "api_ab_shared_credential_denied",
                level="warning",
                username=user.username,
                guid=guid,
                rid=rid,
            )
            return JsonResponse({"error": "No access"}, status=403)
        if not RemotePeer.objects.filter(profile_id=profile.pk, rid=rid).exists():
            return JsonResponse({"error": "Target not found"}, status=404)
        password = profile.default_password
        if not password:
            return JsonResponse({"error": "Default credential not configured"}, status=404)

    _log_event(
        request,
        "api_ab_shared_credential_issued",
        level="info",
        username=user.username,
        guid=guid,
        rid=rid,
    )
    return JsonResponse({"password": password})


def ab_shared_add(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_shared_add_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json_object(request)
    name = str(postdata.get("name", "")).strip()
    note = postdata.get("note", "")
    info = postdata.get("info", None)
    default_password = (
        _profile_default_password(postdata["default_password"]) if "default_password" in postdata else None
    )
    if not name or len(name) > 60 or _bounded_text_value(note, 4096) is None:
        _log_event(request, "api_ab_shared_add_failed", level="warning", username=user.username, reason="missing_name")
        return JsonResponse({"error": "Invalid name"}, status=400)
    if _is_reserved_ab_profile_name(name):
        return JsonResponse({"error": "Reserved name"}, status=400)
    if "default_password" in postdata and default_password is None:
        return JsonResponse({"error": "Invalid default password"}, status=400)
    parsed_info = None
    if info is not None:
        parsed_info = _profile_info_value(info)
        if parsed_info is None:
            return JsonResponse({"error": "Invalid info"}, status=400)
    profile = _get_or_create_profile(user, name)
    with transaction.atomic():
        profile = _lock_profile_for_management(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        profile.note = note
        update_fields = ["note", "updated_at"]
        if parsed_info is not None:
            profile.info = parsed_info
            update_fields.append("info")
        if "default_password" in postdata:
            profile.default_password = default_password
            update_fields.append("default_password")
        profile.save(update_fields=update_fields)
    _log_event(request, "api_ab_shared_add", username=user.username, guid=profile.guid, name=name)
    return JsonResponse({"code": 1, "guid": profile.guid})


def ab_shared_update_profile(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_shared_update_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json_object(request)
    guid = postdata.get("guid", "")
    if not guid:
        return JsonResponse({"error": "Invalid guid"}, status=400)
    profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
    if not profile:
        return JsonResponse({"error": "Not found"}, status=404)
    if _is_personal_guid(profile.guid):
        return JsonResponse({"error": "Personal address book cannot be modified"}, status=403)
    if not user.is_admin and str(profile.owner_id) != str(user.id):
        return JsonResponse({"error": "No access"}, status=403)
    if "name" in postdata:
        name = str(postdata.get("name") or "").strip()
        if (
            not name
            or len(name) > 60
            or _is_reserved_ab_profile_name(name)
            or AddressBookProfile.objects.filter(owner=profile.owner, name=name).exclude(pk=profile.pk).exists()
        ):
            return JsonResponse({"error": "Invalid or duplicate name"}, status=400)
        profile.name = name
    if "note" in postdata and postdata.get("note") is not None:
        note = _bounded_text_value(postdata.get("note"), 4096)
        if note is None:
            return JsonResponse({"error": "Invalid note"}, status=400)
        profile.note = note
    default_password = None
    if "default_password" in postdata:
        default_password = _profile_default_password(postdata["default_password"])
        if default_password is None:
            return JsonResponse({"error": "Invalid default password"}, status=400)
    if "info" in postdata and postdata.get("info") is not None:
        info = _profile_info_value(postdata.get("info"))
        if info is None:
            return JsonResponse({"error": "Invalid info"}, status=400)
        profile.info = info
    new_owner = None
    if "owner" in postdata and postdata.get("owner"):
        if not user.is_admin:
            return JsonResponse({"error": "Only admin can transfer owner"}, status=403)
        new_owner = _user_by_identifier(
            postdata.get("owner"),
            active_only=True,
        )
        if not new_owner:
            return JsonResponse({"error": "Owner not found"}, status=404)
        if AddressBookProfile.objects.filter(owner=new_owner, name=profile.name).exclude(pk=profile.pk).exists():
            return JsonResponse({"error": "Owner already has an address book with this name"}, status=409)
    profile_values = {
        "name": profile.name,
        "note": profile.note,
        "info": profile.info,
    }
    with transaction.atomic():
        profile = _lock_profile_for_management(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        target_owner = new_owner or profile.owner
        if (
            AddressBookProfile.objects.filter(owner=target_owner, name=profile_values["name"])
            .exclude(pk=profile.pk)
            .exists()
        ):
            return JsonResponse({"error": "Owner already has an address book with this name"}, status=409)
        profile.name = profile_values["name"]
        profile.note = profile_values["note"]
        profile.info = profile_values["info"]
        if "default_password" in postdata:
            profile.default_password = default_password
        old_owner_id = profile.owner_id
        if new_owner and new_owner.id != old_owner_id:
            profile.owner = new_owner
            AddressBookShare.objects.filter(profile=profile, user=new_owner).delete()
        profile.save()
    _log_event(request, "api_ab_shared_update", username=user.username, guid=guid)
    return JsonResponse({"code": 1, "data": "ok"})


def ab_shared_delete(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_shared_delete_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json(request)
    if not isinstance(postdata, list):
        return JsonResponse({"error": "Invalid data"}, status=400)
    if len(postdata) > 100:
        return JsonResponse({"error": "Too many address books"}, status=400)
    requested_guids = [str(value) for value in postdata]
    with transaction.atomic():
        candidates = AddressBookProfile.objects.select_for_update().filter(guid__in=requested_guids)
        if not user.is_admin:
            candidates = candidates.filter(owner=user)
        candidates = candidates.exclude(guid__startswith="personal-").order_by("pk")
        locked_profiles = list(candidates.select_related("owner"))
        for profile in locked_profiles:
            profile._audit_actor = user
            profile.delete()
        deleted = len(locked_profiles)
    _log_event(request, "api_ab_shared_delete", username=user.username, count=deleted)
    return JsonResponse({"code": 1, "deleted": deleted})


def ab_rules(request):
    if request.method == "DELETE":
        return ab_rules_delete(request)
    _token, user = _get_token_user(request)
    if not user:
        session_user = getattr(request, "user", None)
        if session_user and getattr(session_user, "is_authenticated", False):
            return HttpResponseRedirect("/api/ab_rules")
        _log_event(request, "api_ab_rules_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    guid = request.GET.get("ab", "") or request.GET.get("guid", "")
    if not guid:
        return JsonResponse({"error": "Invalid guid"}, status=400)
    if _is_personal_guid(guid):
        return JsonResponse({"error": "Personal address book cannot be shared"}, status=403)
    profile, _owner, _rule = _get_profile_access(user, guid)
    if not profile:
        return JsonResponse({"error": "Not found"}, status=404)
    if not user.is_admin and str(profile.owner_id) != str(user.id):
        _log_event(request, "api_ab_rules_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    current, page_size, _start, _end = _pagination(request)
    data = []
    shares = AddressBookShare.objects.filter(Q(profile=profile)).select_related("user")
    for share in shares:
        data.append(
            {
                "guid": share.guid,
                "rule": share.rule,
                "user": share.user.username if share.user else "",
            }
        )
    rules = AddressBookRule.objects.filter(Q(profile=profile)).select_related("user", "group")
    for one in rules:
        data.append(
            {
                "guid": one.guid,
                "rule": one.rule,
                "user": one.user.username if one.user_id else "",
                "group": one.group.name if one.group_id else "",
            }
        )
    total = len(data)
    start = (current - 1) * page_size
    end = start + page_size
    _log_event(request, "api_ab_rules", level="debug", username=user.username, guid=guid, total=total)
    return JsonResponse({"total": total, "data": data[start:end]})


def ab_rule(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_rule_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json_object(request)
    if request.method == "POST":
        guid = postdata.get("guid", "")
        rule_value = _valid_ab_rule(postdata.get("rule", 1))
        if rule_value is None:
            return JsonResponse({"error": "Invalid rule"}, status=400)
        if not guid:
            return JsonResponse({"error": "Invalid guid"}, status=400)
        profile = AddressBookProfile.objects.filter(Q(guid=guid)).first()
        if not profile:
            return JsonResponse({"error": "Not found"}, status=404)
        if _is_personal_guid(profile.guid):
            return JsonResponse({"error": "Personal address book cannot be shared"}, status=403)
        if not user.is_admin and str(profile.owner_id) != str(user.id):
            return JsonResponse({"error": "No access"}, status=403)
        user_name = postdata.get("user", "")
        group_name = postdata.get("group", "")
        if user_name and group_name:
            return JsonResponse(
                {"error": "Specify exactly one rule target"},
                status=400,
            )
        target_user = None
        target_group = None
        if user_name:
            target_user = _user_by_identifier(user_name, active_only=True)
            if not target_user:
                return JsonResponse({"error": "User not found"}, status=404)
        elif group_name:
            target_group = Group.objects.filter(Q(name=group_name)).first()
            if not target_group:
                return JsonResponse({"error": "Group not found"}, status=404)
        with transaction.atomic():
            profile = _lock_profile_for_management(user, profile)
            if not profile:
                return JsonResponse({"error": "Authorization changed"}, status=403)
            if target_user:
                if target_user.id == profile.owner_id:
                    return JsonResponse({"error": "Owner already has full access"}, status=400)
                changed, created = AddressBookShare.objects.update_or_create(
                    profile=profile,
                    user=target_user,
                    defaults={"rule": rule_value},
                )
                target_type = "user"
                target_name = target_user.username
            else:
                target_key = f"group:{target_group.id}" if target_group else "everyone"
                changed, created = AddressBookRule.objects.update_or_create(
                    profile=profile,
                    target_key=target_key,
                    defaults={
                        "group": target_group,
                        "user": None,
                        "rule": rule_value,
                        "is_everyone": target_group is None,
                    },
                )
                target_type = "group" if target_group else "everyone"
                target_name = target_group.name if target_group else "Everyone"
            bump_locked_authorization_generation(profile)
            _audit_ab_rule(
                profile,
                user,
                ("share_add" if created else "share_update")
                if target_user
                else ("rule_add" if created else "rule_update"),
                target_type,
                target_name,
                rule_value,
                {"guid": str(changed.guid)},
            )
        _log_event(
            request,
            "api_ab_rule_add",
            username=user.username,
            guid=guid,
            rule=rule_value,
            target=target_name,
        )
        return JsonResponse({"guid": changed.guid, "rule": changed.rule})

    rule_guid = postdata.get("guid", "")
    rule_value = _valid_ab_rule(postdata.get("rule", 1))
    if rule_value is None:
        return JsonResponse({"error": "Invalid rule"}, status=400)
    if not rule_guid:
        return JsonResponse({"error": "Invalid guid"}, status=400)
    share = AddressBookShare.objects.filter(Q(guid=rule_guid)).select_related("profile").first()
    rule_obj = None
    if share:
        profile = share.profile
    else:
        rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related("profile").first()
        if not rule_obj:
            return JsonResponse({"error": "Not found"}, status=404)
        profile = rule_obj.profile
    with transaction.atomic():
        profile = _lock_profile_for_management(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        if share:
            share = (
                AddressBookShare.objects.select_for_update()
                .select_related("user")
                .filter(pk=share.pk, profile=profile)
                .first()
            )
            if not share:
                return JsonResponse({"error": "Not found"}, status=404)
            share.rule = rule_value
            share.save(update_fields=("rule",))
            target_type = "user"
            target_name = share.user.username if share.user else ""
            changed = share
        else:
            rule_obj = (
                AddressBookRule.objects.select_for_update()
                .select_related("user", "group")
                .filter(pk=rule_obj.pk, profile=profile)
                .first()
            )
            if not rule_obj:
                return JsonResponse({"error": "Not found"}, status=404)
            rule_obj.rule = rule_value
            rule_obj.save(update_fields=("rule", "target_key", "updated_at"))
            if rule_obj.is_everyone:
                target_type, target_name = "everyone", "Everyone"
            elif rule_obj.group_id:
                target_type = "group"
                target_name = rule_obj.group.name if rule_obj.group else ""
            else:
                target_type = "user"
                target_name = rule_obj.user.username if rule_obj.user else ""
            changed = rule_obj
        bump_locked_authorization_generation(profile)
        _audit_ab_rule(
            profile,
            user,
            "share_update" if share else "rule_update",
            target_type,
            target_name,
            rule_value,
            {"guid": str(changed.guid)},
        )
    _log_event(request, "api_ab_rule_update", username=user.username, guid=rule_guid, rule=rule_value)
    return JsonResponse({"code": 1})


def ab_rules_delete(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_rules_delete_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json(request)
    if not isinstance(postdata, list):
        return JsonResponse({"error": "Invalid data"}, status=400)
    if len(postdata) > 100:
        return JsonResponse({"error": "Too many rules"}, status=400)
    deleted = 0
    for rule_guid in postdata:
        share = AddressBookShare.objects.filter(Q(guid=rule_guid)).select_related("profile").first()
        if share:
            profile = share.profile
            with transaction.atomic():
                profile = _lock_profile_for_management(user, profile)
                if not profile:
                    continue
                share = (
                    AddressBookShare.objects.select_for_update()
                    .select_related("user")
                    .filter(pk=share.pk, profile=profile)
                    .first()
                )
                if not share:
                    continue
                target_name = share.user.username if share.user else ""
                bump_locked_authorization_generation(profile)
                _audit_ab_rule(
                    profile, user, "share_delete", "user", target_name, share.rule, {"guid": str(share.guid)}
                )
                share.delete()
                deleted += 1
            continue
        rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related("profile").first()
        if rule_obj:
            profile = rule_obj.profile
            with transaction.atomic():
                profile = _lock_profile_for_management(user, profile)
                if not profile:
                    continue
                rule_obj = (
                    AddressBookRule.objects.select_for_update()
                    .select_related("user", "group")
                    .filter(pk=rule_obj.pk, profile=profile)
                    .first()
                )
                if not rule_obj:
                    continue
                if rule_obj.is_everyone:
                    target_type = "everyone"
                    target_name = "Everyone"
                elif rule_obj.group_id:
                    target_type = "group"
                    target_name = rule_obj.group.name if rule_obj.group else ""
                else:
                    target_type = "user"
                    target_name = rule_obj.user.username if rule_obj.user else ""
                bump_locked_authorization_generation(profile)
                _audit_ab_rule(
                    profile, user, "rule_delete", target_type, target_name, rule_obj.rule, {"guid": str(rule_obj.guid)}
                )
                rule_obj.delete()
                deleted += 1
    _log_event(request, "api_ab_rules_delete", username=user.username, count=deleted)
    return JsonResponse({"code": 1, "deleted": deleted})


def ab_peers(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_peers_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    guid = request.GET.get("ab", "") or _personal_guid(user)
    profile, owner, _rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
    if not owner:
        _log_event(request, "api_ab_peers_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    current, page_size, _start, _end = _pagination(request)
    qs = (
        RemotePeer.objects.filter(profile=profile)
        .prefetch_related(
            Prefetch(
                "tags",
                queryset=RemoteTag.objects.order_by("tag_name"),
                to_attr="ordered_tags",
            )
        )
        .order_by("rid")
    )
    total = qs.count()
    start = (current - 1) * page_size
    end = start + page_size
    data = []
    is_personal = guid == _personal_guid(owner)
    for p in qs[start:end]:
        tags = [tag.tag_name for tag in p.ordered_tags]
        item = {
            "id": p.rid,
            "username": p.username,
            "hostname": p.hostname,
            "platform": p.platform,
            "alias": p.alias,
            "tags": tags,
            "note": p.note,
            "device_group_name": p.device_group_name,
            "loginName": p.login_name,
            "same_server": p.same_server,
        }
        if is_personal:
            item["hash"] = p.rhash
            item["password"] = ""
        else:
            item["hash"] = ""
            item["password"] = p.password
        data.append(item)
    _log_event(
        request,
        "api_ab_peers",
        level="debug",
        username=user.username,
        guid=guid,
        total=total,
        page=current,
        page_size=page_size,
    )
    return JsonResponse({"total": total, "data": data})


def ab_tags(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_tags_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, _rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
    if not owner:
        _log_event(request, "api_ab_tags_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    tags = RemoteTag.objects.filter(profile=profile)
    data = []
    for t in tags:
        try:
            color = int(t.tag_color)
        except (TypeError, ValueError):
            color = 0
        data.append({"name": t.tag_name, "color": color})
    _log_event(request, "api_ab_tags", level="debug", username=user.username, guid=guid, total=len(data))
    return JsonResponse(data, safe=False)


def ab_peer_add(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_peer_add_unauthorized", level="warning", guid=guid)
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        profile = _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, "api_ab_peer_add_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    if not _can_write_rule(rule):
        _log_event(
            request, "api_ab_peer_add_denied", level="warning", username=user.username, guid=guid, reason="read_only"
        )
        return JsonResponse({"error": "Read-only"}, status=403)
    postdata = _load_json_object(request)
    payload = _validated_peer_payload(
        postdata,
        guid == _personal_guid(owner),
    )
    if payload is None:
        _log_event(
            request, "api_ab_peer_add_failed", level="warning", username=user.username, guid=guid, reason="missing_id"
        )
        return JsonResponse({"error": "Invalid peer"}, status=400)
    rid = payload["id"]
    is_personal = guid == _personal_guid(owner)
    peer_data = payload
    if is_personal:
        peer_data.pop("password", None)
    else:
        peer_data.pop("hash", None)
    try:
        with transaction.atomic():
            profile, owner, _rule = _lock_profile_for_content_write(user, profile)
            if not profile:
                return JsonResponse({"error": "Authorization changed"}, status=403)
            is_personal = profile.guid == _personal_guid(owner)
            existing = RemotePeer.objects.filter(
                profile=profile,
                rid=rid,
            ).exists()
            if (
                not existing
                and RemotePeer.objects.filter(
                    profile=profile,
                ).count()
                >= MAX_AB_PEERS
            ):
                return JsonResponse(
                    {"error": "Address book peer limit reached"},
                    status=409,
                )
            _upsert_ab_peer(profile, rid, peer_data, is_personal)
    except ValueError:
        return JsonResponse({"error": "Invalid peer"}, status=400)
    _log_event(request, "api_ab_peer_add", username=user.username, guid=guid, rid=rid)
    return HttpResponse("")


def ab_peer_update(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_peer_update_unauthorized", level="warning", guid=guid)
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, "api_ab_peer_update_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    if not _can_write_rule(rule):
        _log_event(
            request, "api_ab_peer_update_denied", level="warning", username=user.username, guid=guid, reason="read_only"
        )
        return JsonResponse({"error": "Read-only"}, status=403)
    postdata = _load_json_object(request)
    is_personal = guid == _personal_guid(owner)
    payload = _validated_peer_payload(postdata, is_personal)
    if payload is None:
        _log_event(
            request,
            "api_ab_peer_update_failed",
            level="warning",
            username=user.username,
            guid=guid,
            reason="missing_id",
        )
        return JsonResponse({"error": "Invalid peer"}, status=400)
    rid = payload["id"]
    peer_data = payload
    if is_personal:
        peer_data.pop("password", None)
    else:
        peer_data.pop("hash", None)
    try:
        with transaction.atomic():
            profile, owner, _rule = _lock_profile_for_content_write(user, profile)
            if not profile:
                return JsonResponse({"error": "Authorization changed"}, status=403)
            is_personal = profile.guid == _personal_guid(owner)
            if not RemotePeer.objects.filter(profile=profile, rid=rid).exists():
                _log_event(
                    request,
                    "api_ab_peer_update_failed",
                    level="warning",
                    username=user.username,
                    guid=guid,
                    rid=rid,
                    reason="not_found",
                )
                return JsonResponse({"error": "ID_NOT_FOUND"}, status=404)
            _upsert_ab_peer(profile, rid, peer_data, is_personal)
    except ValueError:
        return JsonResponse({"error": "Invalid peer"}, status=400)
    _log_event(request, "api_ab_peer_update", username=user.username, guid=guid, rid=rid)
    return HttpResponse("")


def ab_peer_delete(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_peer_delete_unauthorized", level="warning", guid=guid)
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, "api_ab_peer_delete_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    if not _can_write_rule(rule):
        _log_event(
            request, "api_ab_peer_delete_denied", level="warning", username=user.username, guid=guid, reason="read_only"
        )
        return JsonResponse({"error": "Read-only"}, status=403)
    postdata = _load_json(request)
    if (
        not isinstance(postdata, list)
        or len(postdata) > 1000
        or any(_bounded_text_value(value, 1024, False) is None for value in postdata)
    ):
        _log_event(
            request,
            "api_ab_peer_delete_failed",
            level="warning",
            username=user.username,
            guid=guid,
            reason="invalid_ids",
        )
        return JsonResponse({"error": "Invalid ids"}, status=400)
    with transaction.atomic():
        profile, _owner, _rule = _lock_profile_for_content_write(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        RemotePeer.objects.filter(profile=profile, rid__in=postdata).delete()
    _log_event(request, "api_ab_peer_delete", username=user.username, guid=guid, count=len(postdata))
    return HttpResponse("")


def ab_tag_add(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_tag_add_unauthorized", level="warning", guid=guid)
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        profile = _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, "api_ab_tag_add_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    if not _can_write_rule(rule):
        _log_event(
            request, "api_ab_tag_add_denied", level="warning", username=user.username, guid=guid, reason="read_only"
        )
        return JsonResponse({"error": "Read-only"}, status=403)
    postdata = _load_json_object(request)
    name = str(postdata.get("name", "")).strip()
    color = normalize_tag_color(postdata.get("color", ""))
    if _bounded_text_value(name, 256, False) is None or len(name) > 64 or color is None:
        _log_event(
            request, "api_ab_tag_add_failed", level="warning", username=user.username, guid=guid, reason="missing_name"
        )
        return JsonResponse({"error": "Invalid tag"}, status=400)
    with transaction.atomic():
        profile, _owner, _rule = _lock_profile_for_content_write(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        if (
            not RemoteTag.objects.filter(
                profile=profile,
                tag_name=name,
            ).exists()
            and RemoteTag.objects.filter(
                profile=profile,
            ).count()
            >= MAX_AB_TAGS
        ):
            return JsonResponse(
                {"error": "Address book tag limit reached"},
                status=409,
            )
        RemoteTag.objects.get_or_create(
            profile=profile,
            tag_name=name,
            defaults={"tag_color": color},
        )
    _log_event(request, "api_ab_tag_add", username=user.username, guid=guid, tag=name)
    return HttpResponse("")


def ab_tag_rename(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_tag_rename_unauthorized", level="warning", guid=guid)
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, "api_ab_tag_rename_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    if not _can_write_rule(rule):
        _log_event(
            request, "api_ab_tag_rename_denied", level="warning", username=user.username, guid=guid, reason="read_only"
        )
        return JsonResponse({"error": "Read-only"}, status=403)
    postdata = _load_json_object(request)
    old = str(postdata.get("old", "")).strip()
    new = str(postdata.get("new", "")).strip()
    if (
        _bounded_text_value(old, 256, False) is None
        or _bounded_text_value(new, 256, False) is None
        or len(old) > 64
        or len(new) > 64
    ):
        _log_event(
            request,
            "api_ab_tag_rename_failed",
            level="warning",
            username=user.username,
            guid=guid,
            reason="invalid_tag",
        )
        return JsonResponse({"error": "Invalid tag"}, status=400)
    with transaction.atomic():
        profile, _owner, _rule = _lock_profile_for_content_write(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        old_tag = (
            RemoteTag.objects.select_for_update()
            .filter(
                profile=profile,
                tag_name=old,
            )
            .first()
        )
        if not old_tag:
            return JsonResponse({"error": "Tag not found"}, status=404)
        target = RemoteTag.objects.filter(
            profile=profile,
            tag_name=new,
        ).first()
        if target and target.pk != old_tag.pk:
            target.peers.add(*old_tag.peers.all())
            old_tag.delete()
        else:
            old_tag.tag_name = new
            old_tag.save(update_fields=["tag_name"])
    _log_event(request, "api_ab_tag_rename", username=user.username, guid=guid, old=old, new=new)
    return HttpResponse("")


def ab_tag_update(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_tag_update_unauthorized", level="warning", guid=guid)
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, "api_ab_tag_update_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    if not _can_write_rule(rule):
        _log_event(
            request, "api_ab_tag_update_denied", level="warning", username=user.username, guid=guid, reason="read_only"
        )
        return JsonResponse({"error": "Read-only"}, status=403)
    postdata = _load_json_object(request)
    name = str(postdata.get("name", "")).strip()
    color = normalize_tag_color(postdata.get("color", ""))
    if _bounded_text_value(name, 256, False) is None or len(name) > 64 or color is None:
        _log_event(
            request,
            "api_ab_tag_update_failed",
            level="warning",
            username=user.username,
            guid=guid,
            reason="missing_name",
        )
        return JsonResponse({"error": "Invalid tag"}, status=400)
    with transaction.atomic():
        profile, _owner, _rule = _lock_profile_for_content_write(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        RemoteTag.objects.filter(profile=profile, tag_name=name).update(
            tag_color=str(color),
        )
    _log_event(request, "api_ab_tag_update", username=user.username, guid=guid, tag=name)
    return HttpResponse("")


def ab_tag_delete(request, guid):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_tag_delete_unauthorized", level="warning", guid=guid)
        return JsonResponse({"error": "Invalid token"}, status=401)
    profile, owner, rule = _get_profile_access(user, guid)
    if guid == _personal_guid(user):
        _ensure_personal_profile(user)
        owner = user
        rule = 3
    if not owner:
        _log_event(request, "api_ab_tag_delete_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "No access"}, status=403)
    if not _can_write_rule(rule):
        _log_event(
            request, "api_ab_tag_delete_denied", level="warning", username=user.username, guid=guid, reason="read_only"
        )
        return JsonResponse({"error": "Read-only"}, status=403)
    postdata = _load_json(request)
    if (
        not isinstance(postdata, list)
        or len(postdata) > MAX_AB_TAGS
        or any(_bounded_text_value(value, 256, False) is None for value in postdata)
    ):
        _log_event(
            request,
            "api_ab_tag_delete_failed",
            level="warning",
            username=user.username,
            guid=guid,
            reason="invalid_tags",
        )
        return JsonResponse({"error": "Invalid tags"}, status=400)
    with transaction.atomic():
        profile, _owner, _rule = _lock_profile_for_content_write(user, profile)
        if not profile:
            return JsonResponse({"error": "Authorization changed"}, status=403)
        RemoteTag.objects.filter(
            profile=profile,
            tag_name__in=postdata,
        ).delete()
    _log_event(request, "api_ab_tag_delete", username=user.username, guid=guid, count=len(postdata))
    return HttpResponse("")


def _audit_device_context(request, postdata):
    rid = postdata.get("id")
    device_uuid = postdata.get("uuid")
    if not _valid_device_identity(rid, device_uuid):
        return None, None, JsonResponse({"error": "Invalid device identity"}, status=400)
    token, user = _get_device_token_user(request, rid, device_uuid)
    if not token or not user:
        return None, None, JsonResponse({"error": "Invalid device token"}, status=401)
    device = _get_active_token_device(token, user)
    if not device:
        return None, None, JsonResponse({"error": "Device is not active"}, status=403)
    return token, user, None


def _bounded_audit_text(value, max_bytes):
    if not isinstance(value, str) or len(value.encode()) > max_bytes:
        return None
    return value


def _audit_rid(value):
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{6,16}", value):
        return value
    return None


def _audit_connection_id(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 2_147_483_647 else None


def _audit_revision(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1 <= value <= 9_223_372_036_854_775_807 else None


def _audit_session_id(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value)
    if not re.fullmatch(r"[1-9][0-9]{0,19}", text):
        return None
    try:
        numeric = int(text)
    except ValueError:
        return None
    return text if numeric <= 18_446_744_073_709_551_615 else None


def _audit_ip(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _audit_enum(value, allowed):
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed in allowed else None


def _audit_uuid4(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return parsed if parsed.version == 4 and str(parsed) == value.lower() else None


def _audit_version_is_current(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == AUDIT_PROTOCOL_VERSION
    return isinstance(value, str) and value == str(AUDIT_PROTOCOL_VERSION)


def _audit_upgrade_required(required_version=AUDIT_PROTOCOL_VERSION):
    return JsonResponse(
        {
            "error": "Unsupported audit protocol version",
            "required_version": required_version,
        },
        status=426,
    )


def _file_audit_version_is_current(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == FILE_AUDIT_PROTOCOL_VERSION
    return isinstance(value, str) and value == str(FILE_AUDIT_PROTOCOL_VERSION)


def _audit_nonnegative_integer(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= MAX_AUDIT_INTEGER else None


def _audit_success(connection_log, event_id, *, status=200):
    now = audit_lifecycle.database_now()
    lease_remaining = 0
    if connection_log.state in ConnLog.OPEN_STATES and connection_log.lease_expires_at is not None:
        lease_remaining = max(0, math.ceil((connection_log.lease_expires_at - now).total_seconds()))
    return JsonResponse(
        {
            "version": AUDIT_PROTOCOL_VERSION,
            "audit_session_id": str(connection_log.guid),
            "acknowledged_event_id": str(event_id),
            "event_revision": connection_log.event_revision,
            "state": connection_log.state,
            "state_revision": connection_log.state_revision,
            "heartbeat_revision": connection_log.heartbeat_revision,
            "lease_remaining_seconds": lease_remaining,
            "terminal_reason": connection_log.terminal_reason,
            "terminal_source": connection_log.terminal_source,
        },
        status=status,
    )


def _file_audit_success(connection_log, transfer_event):
    return JsonResponse(
        {
            "version": FILE_AUDIT_PROTOCOL_VERSION,
            "audit_session_id": str(connection_log.guid),
            "acknowledged_event_id": str(transfer_event.connection_event.event_id),
            "transfer_id": str(transfer_event.transfer.transfer_id),
            "transfer_revision": transfer_event.revision,
            "transfer_state": transfer_event.state,
            "transferred_bytes": transfer_event.transferred_bytes,
        }
    )


def _audit_terminal_conflict(connection_log):
    return JsonResponse(
        {
            "error": "Connection is not active",
            "version": AUDIT_PROTOCOL_VERSION,
            "state": connection_log.state,
            "state_revision": connection_log.state_revision,
            "terminal_reason": connection_log.terminal_reason,
            "terminal_source": connection_log.terminal_source,
        },
        status=409,
    )


def _locked_audit_device(token, user):
    return (
        RemoteDevice.objects.select_for_update()
        .filter(
            pk=token.device_id,
            owner=user,
            is_active=True,
        )
        .first()
    )


def _audit_host_authority_is_current(connection_log, host_device):
    return (
        connection_log.audit_version == AUDIT_PROTOCOL_VERSION
        and connection_log.host_device_id == host_device.id
        and connection_log.host_device_id_at_create == host_device.id
        and connection_log.host_device_generation == host_device.deployment_generation
        and connection_log.owner_id_at_create == host_device.owner_id
        and host_device.is_active
    )


def _audit_controller_authority_is_current(connection_log, controller_device):
    return (
        controller_device is not None
        and controller_device.owner_id is not None
        and connection_log.actor_id is not None
        and connection_log.controller_device_id == controller_device.id
        and connection_log.controller_device_id_at_bind == controller_device.id
        and connection_log.controller_device_generation == controller_device.deployment_generation
        and connection_log.controller_owner_id_at_bind == controller_device.owner_id
        and connection_log.actor_id == controller_device.owner_id
        and connection_log.from_id == controller_device.rid
        and controller_device.is_active
    )


def _locked_host_audit_session(token, user, audit_session_id, *, active=True, require_controller=False):
    authority = (
        ConnLog.objects.filter(
            guid=audit_session_id,
            audit_version=AUDIT_PROTOCOL_VERSION,
            host_device_id=token.device_id,
        )
        .values("host_device_id", "controller_device_id")
        .first()
    )
    if not authority:
        return None, None, JsonResponse({"error": "Connection not found"}, status=404)
    device_ids = {authority["host_device_id"]}
    if require_controller and authority["controller_device_id"] is not None:
        device_ids.add(authority["controller_device_id"])
    locked_devices = {
        device.id: device
        for device in RemoteDevice.objects.select_for_update().filter(pk__in=device_ids).order_by("pk")
    }
    device = locked_devices.get(authority["host_device_id"])
    if not device or device.owner_id != user.id or not device.is_active:
        return None, None, JsonResponse({"error": "Device is not active"}, status=403)
    connection_log = (
        ConnLog.objects.select_for_update()
        .filter(
            guid=audit_session_id,
            audit_version=AUDIT_PROTOCOL_VERSION,
            host_device=device,
        )
        .first()
    )
    if not connection_log:
        return device, None, JsonResponse({"error": "Connection not found"}, status=404)
    if not _audit_host_authority_is_current(connection_log, device):
        return device, None, JsonResponse({"error": "Connection authority changed"}, status=403)
    if require_controller:
        controller_device = locked_devices.get(connection_log.controller_device_id)
        if not _audit_controller_authority_is_current(connection_log, controller_device):
            return device, None, JsonResponse({"error": "Controller is not bound"}, status=403)
    if active:
        now = audit_lifecycle.database_now()
        audit_lifecycle.expire_locked_connection(connection_log, now, source="request_reconciler")
        if connection_log.state not in ConnLog.OPEN_STATES:
            return device, None, _audit_terminal_conflict(connection_log)
    return device, connection_log, None


def _existing_audit_event(event_id):
    return ConnectionAuditEvent.objects.filter(event_id=event_id).first()


def _matching_audit_event(existing, connection_log, kind, actor, reporter_device_uuid, details):
    return (
        existing.connection_id == connection_log.id
        and existing.kind == kind
        and existing.actor_id == (actor.id if actor else None)
        and existing.reporter_device_uuid == reporter_device_uuid
        and existing.details == details
    )


def _append_audit_event(connection_log, event_id, kind, actor, reporter_device_uuid, details):
    existing = _existing_audit_event(event_id)
    if existing:
        if not _matching_audit_event(existing, connection_log, kind, actor, reporter_device_uuid, details):
            raise IntegrityError("Audit event identity conflict")
        return existing, False
    if connection_log.event_revision >= 9_223_372_036_854_775_807:
        raise IntegrityError("Audit event revision exhausted")
    ingestion_governance.reserve_audit_event(
        connection_log.owner_id_at_create,
        connection_log.host_device_id_at_create,
        connection_log.event_revision,
        closes_connection=kind
        in (
            ConnectionAuditEvent.KIND_CLOSED,
            ConnectionAuditEvent.KIND_ABORTED,
            ConnectionAuditEvent.KIND_EXPIRED,
        ),
    )
    sequence = connection_log.event_revision + 1
    event = ConnectionAuditEvent.objects.create(
        event_id=event_id,
        connection=connection_log,
        sequence=sequence,
        kind=kind,
        actor=actor,
        actor_id_at_event=actor.id if actor else connection_log.owner_id_at_create,
        reporter_device_uuid=reporter_device_uuid,
        details=details,
    )
    connection_log.event_revision = sequence
    connection_log.save(update_fields=["event_revision"])
    return event, True


def _audit_event_conflict():
    return JsonResponse({"error": "Audit event identity conflict"}, status=409)


def _audit_conn_active(request):
    token, user = _get_token_user(request)
    if not token or not user or not _get_active_token_device(token, user):
        _log_event(request, "api_audit_conn_active_unauthorized", level="warning")
        return JsonResponse("", safe=False, status=401)
    if not _audit_version_is_current(request.GET.get("version")):
        return _audit_upgrade_required()
    peer_id = _audit_rid(request.GET.get("id", ""))
    session_id = _audit_session_id(request.GET.get("session_id", ""))
    conn_type = _audit_enum(request.GET.get("conn_type", 0), range(5))
    event_id = _audit_uuid4(request.GET.get("event_id"))
    if peer_id is None or session_id is None or conn_type is None or event_id is None:
        _log_event(request, "api_audit_conn_active_failed", level="warning", reason="missing_id")
        return JsonResponse("", safe=False, status=400)
    try:
        with transaction.atomic():
            controller_rid = RemoteDevice.objects.filter(pk=token.device_id).values_list("rid", flat=True).first()
            if controller_rid is None:
                return JsonResponse("", safe=False, status=403)
            candidate = (
                ConnLog.objects.filter(
                    audit_version=AUDIT_PROTOCOL_VERSION,
                    rid=peer_id,
                    session_id=session_id,
                    from_id=controller_rid,
                )
                .order_by("-conn_start", "-pk")
                .values_list("host_device_id", flat=True)
                .first()
            )
            if candidate is None:
                # The host publishes the authenticated controller identity after
                # opening the audit session. Empty 200 keeps the bounded client
                # retry alive without exposing another session capability.
                return JsonResponse("", safe=False)
            locked_devices = {
                device.id: device
                for device in RemoteDevice.objects.select_for_update()
                .filter(pk__in={candidate, token.device_id})
                .order_by("pk")
            }
            host_device = locked_devices.get(candidate)
            controller_device = locked_devices.get(token.device_id)
            connection_log = (
                ConnLog.objects.select_for_update()
                .filter(
                    audit_version=AUDIT_PROTOCOL_VERSION,
                    rid=peer_id,
                    session_id=session_id,
                    from_id=controller_device.rid if controller_device else "",
                )
                .order_by("-conn_start", "-pk")
                .first()
            )
            if not connection_log or not host_device or not controller_device:
                return JsonResponse("", safe=False, status=403)
            if not _audit_host_authority_is_current(connection_log, host_device):
                return JsonResponse("", safe=False, status=403)
            if controller_device.owner_id != user.id or not controller_device.is_active:
                return JsonResponse("", safe=False, status=403)
            if connection_log.conn_type is None:
                return JsonResponse("", safe=False)
            if connection_log.conn_type != conn_type:
                return JsonResponse("", safe=False, status=409)
            if connection_log.actor_id and connection_log.actor_id != user.id:
                return JsonResponse("", safe=False, status=403)
            now = audit_lifecycle.database_now()
            audit_lifecycle.expire_locked_connection(connection_log, now, source="controller_query")
            if connection_log.state != ConnLog.STATE_ACTIVE:
                if connection_log.state == ConnLog.STATE_STARTING:
                    return JsonResponse("", safe=False)
                return _audit_terminal_conflict(connection_log)
            details = {
                "controller_device_id": controller_device.rid,
                "controller_device_pk": controller_device.id,
                "controller_device_uuid": controller_device.uuid,
                "controller_device_generation": controller_device.deployment_generation,
                "controller_owner_id": user.id,
                "conn_type": conn_type,
            }
            existing = _existing_audit_event(event_id)
            if existing:
                if not _matching_audit_event(
                    existing,
                    connection_log,
                    ConnectionAuditEvent.KIND_CONTROLLER_BOUND,
                    user,
                    controller_device.uuid,
                    details,
                ):
                    return _audit_event_conflict()
                return _audit_success(connection_log, event_id)
            if connection_log.actor_id is None:
                if connection_log.controller_device_id is not None:
                    return JsonResponse("", safe=False, status=409)
                _append_audit_event(
                    connection_log,
                    event_id,
                    ConnectionAuditEvent.KIND_CONTROLLER_BOUND,
                    user,
                    controller_device.uuid,
                    details,
                )
                connection_log.actor = user
                connection_log.controller_device = controller_device
                connection_log.controller_device_id_at_bind = controller_device.id
                connection_log.controller_device_generation = controller_device.deployment_generation
                connection_log.controller_owner_id_at_bind = user.id
                connection_log.save(
                    update_fields=[
                        "actor",
                        "controller_device",
                        "controller_device_id_at_bind",
                        "controller_device_generation",
                        "controller_owner_id_at_bind",
                    ]
                )
            else:
                if not _audit_controller_authority_is_current(connection_log, controller_device):
                    return JsonResponse("", safe=False, status=403)
    except IntegrityError:
        return _audit_event_conflict()
    _log_event(
        request,
        "api_audit_conn_active",
        level="debug",
        username=user.username,
        peer_id=peer_id,
        session_id=session_id,
        conn_type=conn_type,
    )
    return _audit_success(connection_log, event_id)


def _audit_controller_note(request, postdata):
    return _audit_controller_note_by_capability(request, postdata)


def _audit_controller_note_by_capability(request, postdata):
    token, user = _get_token_user(request)
    if not token or not user or not _get_active_token_device(token, user):
        return JsonResponse({"error": "Invalid token"}, status=401)
    if not _audit_version_is_current(postdata.get("version")):
        return _audit_upgrade_required()
    audit_session_id = _audit_uuid4(postdata.get("audit_session_id") or postdata.get("guid"))
    event_id = _audit_uuid4(postdata.get("event_id"))
    note = postdata.get("note")
    if (
        audit_session_id is None
        or event_id is None
        or not isinstance(note, str)
        or len(note.encode()) > MAX_AUDIT_NOTE_BYTES
    ):
        return JsonResponse({"error": "Invalid audit note"}, status=400)
    try:
        with transaction.atomic():
            authority = (
                ConnLog.objects.filter(
                    guid=audit_session_id,
                    audit_version=AUDIT_PROTOCOL_VERSION,
                )
                .values("host_device_id", "controller_device_id")
                .first()
            )
            if not authority or authority["controller_device_id"] != token.device_id:
                return JsonResponse({"error": "Connection audit not found"}, status=404)
            locked_devices = {
                device.id: device
                for device in RemoteDevice.objects.select_for_update()
                .filter(pk__in={authority["host_device_id"], token.device_id})
                .order_by("pk")
            }
            host_device = locked_devices.get(authority["host_device_id"])
            controller_device = locked_devices.get(token.device_id)
            connection_log = (
                ConnLog.objects.select_for_update()
                .filter(
                    guid=audit_session_id,
                    audit_version=AUDIT_PROTOCOL_VERSION,
                    controller_device=controller_device,
                    actor=user,
                )
                .first()
            )
            if not connection_log:
                return JsonResponse({"error": "Connection audit not found"}, status=404)
            if not host_device or not controller_device:
                return JsonResponse({"error": "Connection authority changed"}, status=403)
            if not _audit_host_authority_is_current(connection_log, host_device):
                return JsonResponse({"error": "Connection authority changed"}, status=403)
            if not _audit_controller_authority_is_current(connection_log, controller_device):
                return JsonResponse({"error": "Controller authority changed"}, status=403)
            existing = _existing_audit_event(event_id)
            if existing:
                if (
                    existing.connection_id != connection_log.id
                    or existing.kind != ConnectionAuditEvent.KIND_NOTE
                    or existing.actor_id != user.id
                    or existing.reporter_device_uuid != controller_device.uuid
                    or existing.details.get("note") != note
                ):
                    return _audit_event_conflict()
                return _audit_success(connection_log, event_id)
            observed_at = audit_lifecycle.database_now()
            audit_lifecycle.expire_locked_connection(connection_log, observed_at, source="controller_note")
            if connection_log.state != ConnLog.STATE_ACTIVE:
                return _audit_terminal_conflict(connection_log)
            details = {"previous_note": connection_log.note, "note": note}
            _append_audit_event(
                connection_log,
                event_id,
                ConnectionAuditEvent.KIND_NOTE,
                user,
                controller_device.uuid,
                details,
            )
            connection_log.note = note
            connection_log.save(update_fields=["note"])
    except IntegrityError:
        return _audit_event_conflict()
    _log_event(request, "api_audit_note_update", username=user.username, guid=connection_log.guid)
    return _audit_success(connection_log, event_id)


def _audit_conn(request):
    postdata = _load_json_object(request)
    if "note" in postdata and "uuid" not in postdata:
        return _audit_controller_note(request, postdata)
    token, user, error = _audit_device_context(request, postdata)
    if error:
        return error
    if not _audit_version_is_current(postdata.get("version")):
        return _audit_upgrade_required()
    action = postdata.get("action", "")
    conn_id = _audit_connection_id(postdata.get("conn_id"))
    session_id = _audit_session_id(postdata.get("session_id"))
    event_id = _audit_uuid4(postdata.get("event_id"))
    if conn_id is None or session_id is None or event_id is None:
        return JsonResponse({"error": "Invalid connection identity"}, status=400)
    if action == "new":
        raw_conn_type = postdata.get("type")
        conn_type = None if raw_conn_type is None else _audit_enum(raw_conn_type, range(5))
        if raw_conn_type is not None and conn_type is None:
            return JsonResponse({"error": "Invalid connection type"}, status=400)
        source_ip = _audit_ip(postdata.get("ip"))
        if source_ip is None:
            return JsonResponse({"error": "Invalid source IP"}, status=400)
        audit_ref = _bounded_audit_text(postdata.get("conn_audit_ref", ""), 256)
        if audit_ref is None:
            return JsonResponse({"error": "Invalid audit reference"}, status=400)
        created = False
        try:
            with transaction.atomic():
                device = _locked_audit_device(token, user)
                if not device:
                    return JsonResponse({"error": "Device is not active"}, status=403)
                observed_at = audit_lifecycle.database_now()
                connection_log = (
                    ConnLog.objects.select_for_update()
                    .filter(
                        audit_version=AUDIT_PROTOCOL_VERSION,
                        host_device=device,
                        create_id=event_id,
                    )
                    .first()
                )
                if connection_log:
                    if (
                        connection_log.conn_id != conn_id
                        or connection_log.rid != device.rid
                        or connection_log.uuid != device.uuid
                        or connection_log.session_id != session_id
                        or connection_log.from_ip != source_ip
                        or connection_log.conn_type != conn_type
                        or connection_log.audit_ref != audit_ref
                        or connection_log.reporter_id != user.id
                        or not _audit_host_authority_is_current(connection_log, device)
                    ):
                        return JsonResponse({"error": "Connection session conflict"}, status=409)
                else:
                    ingestion_governance.reserve_audit_connection(user.id, device.id)
                    connection_log = ConnLog.objects.create(
                        audit_version=AUDIT_PROTOCOL_VERSION,
                        create_id=event_id,
                        host_device=device,
                        host_device_id_at_create=device.id,
                        host_device_generation=device.deployment_generation,
                        owner_id_at_create=user.id,
                        event_revision=1,
                        state=ConnLog.STATE_STARTING,
                        state_revision=1,
                        last_seen_at=observed_at,
                        lease_expires_at=audit_lifecycle.lease_deadline(observed_at),
                        conn_id=conn_id,
                        from_ip=source_ip,
                        from_id="",
                        rid=device.rid,
                        conn_start=observed_at,
                        session_id=session_id,
                        uuid=device.uuid,
                        conn_type=conn_type,
                        audit_ref=audit_ref,
                        reporter=user,
                    )
                    ConnectionAuditEvent.objects.create(
                        event_id=event_id,
                        connection=connection_log,
                        sequence=1,
                        kind=ConnectionAuditEvent.KIND_OPENED,
                        actor=user,
                        actor_id_at_event=user.id,
                        reporter_device_uuid=device.uuid,
                        details={
                            "conn_id": conn_id,
                            "from_ip": source_ip,
                            "host_id": device.rid,
                            "host_device_pk": device.id,
                            "host_device_uuid": device.uuid,
                            "host_device_generation": device.deployment_generation,
                            "owner_id_at_create": user.id,
                            "session_id": session_id,
                            "conn_type": conn_type,
                            "audit_ref": audit_ref,
                            "state": ConnLog.STATE_STARTING,
                            "state_revision": 1,
                            "lease_seconds": settings.AUDIT_CONNECTION_LEASE_SECONDS,
                        },
                    )
                    created = True
        except IntegrityError:
            return JsonResponse({"error": "Connection session conflict"}, status=409)
        _log_event(
            request,
            "api_audit_conn_new",
            level="info",
            username=user.username,
            conn_id=conn_id,
            peer_id=connection_log.rid,
            session_id=session_id,
            conn_type=conn_type,
        )
        return _audit_success(connection_log, event_id, status=201 if created else 200)
    elif action == "heartbeat":
        audit_session_id = _audit_uuid4(postdata.get("audit_session_id"))
        heartbeat_revision = _audit_revision(postdata.get("heartbeat_revision"))
        if audit_session_id is None or heartbeat_revision is None:
            return JsonResponse({"error": "Invalid audit heartbeat"}, status=400)
        with transaction.atomic():
            device, connection_log, authority_error = _locked_host_audit_session(
                token,
                user,
                audit_session_id,
            )
            if authority_error:
                return authority_error
            if connection_log.conn_id != conn_id or connection_log.session_id != session_id:
                return JsonResponse({"error": "Connection not found"}, status=404)
            if heartbeat_revision < connection_log.heartbeat_revision:
                return JsonResponse({"error": "Stale audit heartbeat"}, status=409)
            if heartbeat_revision == connection_log.heartbeat_revision:
                if connection_log.last_heartbeat_id != event_id:
                    return JsonResponse({"error": "Audit heartbeat identity conflict"}, status=409)
                return _audit_success(connection_log, event_id)
            observed_at = audit_lifecycle.database_now()
            connection_log.heartbeat_revision = heartbeat_revision
            connection_log.last_heartbeat_id = event_id
            audit_lifecycle.refresh_host_lease(connection_log, observed_at)
            connection_log.save(
                update_fields=(
                    "heartbeat_revision",
                    "last_heartbeat_id",
                    "last_seen_at",
                    "lease_expires_at",
                )
            )
        _log_event(
            request,
            "api_audit_conn_heartbeat",
            level="debug",
            username=user.username,
            conn_id=conn_id,
            session_id=session_id,
            heartbeat_revision=heartbeat_revision,
        )
        return _audit_success(connection_log, event_id)
    elif action == "close":
        audit_session_id = _audit_uuid4(postdata.get("audit_session_id"))
        if audit_session_id is None:
            return JsonResponse({"error": "Invalid audit session capability"}, status=400)
        try:
            with transaction.atomic():
                device, connection_log, authority_error = _locked_host_audit_session(
                    token,
                    user,
                    audit_session_id,
                    active=False,
                )
                if authority_error:
                    return authority_error
                if connection_log.conn_id != conn_id or connection_log.session_id != session_id:
                    return JsonResponse({"error": "Connection not found"}, status=404)
                existing = _existing_audit_event(event_id)
                if existing:
                    if (
                        existing.connection_id != connection_log.id
                        or existing.kind not in (ConnectionAuditEvent.KIND_CLOSED, ConnectionAuditEvent.KIND_ABORTED)
                        or existing.actor_id != user.id
                        or existing.reporter_device_uuid != device.uuid
                    ):
                        return _audit_event_conflict()
                    return _audit_success(connection_log, event_id)
                terminal_at = audit_lifecycle.database_now()
                audit_lifecycle.expire_locked_connection(connection_log, terminal_at, source="close_reconciler")
                if connection_log.state not in ConnLog.OPEN_STATES:
                    return _audit_terminal_conflict(connection_log)
                event_kind = (
                    ConnectionAuditEvent.KIND_CLOSED
                    if connection_log.state == ConnLog.STATE_ACTIVE
                    else ConnectionAuditEvent.KIND_ABORTED
                )
                terminal_state = (
                    ConnLog.STATE_CLOSED if connection_log.state == ConnLog.STATE_ACTIVE else ConnLog.STATE_ABORTED
                )
                terminal_reason = "host_close" if terminal_state == ConnLog.STATE_CLOSED else "ended_before_active"
                terminal_event, _created = _append_audit_event(
                    connection_log,
                    event_id,
                    event_kind,
                    user,
                    device.uuid,
                    {
                        "terminal_at": terminal_at.isoformat(),
                        "terminal_state": terminal_state,
                        "reason": terminal_reason,
                        "source": "host",
                    },
                )
                if connection_log.state_revision >= 9_223_372_036_854_775_807:
                    raise IntegrityError("Audit state revision exhausted")
                connection_log.state = terminal_state
                connection_log.state_revision += 1
                connection_log.last_seen_at = terminal_at
                connection_log.lease_expires_at = terminal_at
                connection_log.terminal_at = terminal_at
                connection_log.terminal_reason = terminal_reason
                connection_log.terminal_source = "host"
                connection_log.conn_end = terminal_at
                connection_log.save(
                    update_fields=(
                        "state",
                        "state_revision",
                        "last_seen_at",
                        "lease_expires_at",
                        "terminal_at",
                        "terminal_reason",
                        "terminal_source",
                        "conn_end",
                    )
                )
                audit_lifecycle.reconcile_open_file_transfers(
                    connection_log,
                    terminal_event,
                    terminal_at,
                    reason=terminal_reason,
                )
        except IntegrityError:
            return _audit_event_conflict()
        _log_event(
            request,
            "api_audit_conn_close",
            level="info",
            username=user.username,
            conn_id=conn_id,
            peer_id=connection_log.rid,
            session_id=session_id,
        )
        return _audit_success(connection_log, event_id)
    else:
        if action not in ("", "update"):
            return JsonResponse({"error": "Invalid action"}, status=400)
        audit_session_id = _audit_uuid4(postdata.get("audit_session_id"))
        if audit_session_id is None:
            return JsonResponse({"error": "Invalid audit session capability"}, status=400)
        submitted = {}
        if "peer" in postdata:
            peer = postdata.get("peer", [])
            if not isinstance(peer, (list, tuple)) or len(peer) != 2:
                return JsonResponse({"error": "Invalid peer identity"}, status=400)
            from_id = _audit_rid(peer[0])
            if from_id is None:
                return JsonResponse({"error": "Invalid peer identity"}, status=400)
            submitted["from_id"] = from_id
        if "type" in postdata:
            update_type = _audit_enum(postdata.get("type"), range(5))
            if update_type is None:
                return JsonResponse({"error": "Invalid connection type"}, status=400)
            submitted["conn_type"] = update_type
        if "primary_auth" in postdata:
            primary_auth = _audit_enum(postdata.get("primary_auth"), range(1, 5))
            if primary_auth is None:
                return JsonResponse({"error": "Invalid primary authentication"}, status=400)
            submitted["primary_auth"] = primary_auth
        if "two_factor" in postdata:
            two_factor = _audit_enum(postdata.get("two_factor"), range(1, 3))
            if two_factor is None:
                return JsonResponse({"error": "Invalid second factor"}, status=400)
            submitted["two_factor"] = two_factor
        if "conn_audit_ref" in postdata:
            audit_ref = _bounded_audit_text(postdata.get("conn_audit_ref"), 256)
            if audit_ref is None:
                return JsonResponse({"error": "Invalid audit reference"}, status=400)
            submitted["audit_ref"] = audit_ref
        if "note" in postdata:
            return JsonResponse({"error": "Host cannot write controller notes"}, status=403)
        try:
            with transaction.atomic():
                device, connection_log, authority_error = _locked_host_audit_session(
                    token,
                    user,
                    audit_session_id,
                )
                if authority_error:
                    return authority_error
                if connection_log.conn_id != conn_id or connection_log.session_id != session_id:
                    return JsonResponse({"error": "Connection not found"}, status=404)
                existing = _existing_audit_event(event_id)
                if existing:
                    if not _matching_audit_event(
                        existing,
                        connection_log,
                        ConnectionAuditEvent.KIND_AUTHORIZED,
                        user,
                        device.uuid,
                        submitted,
                    ):
                        return _audit_event_conflict()
                    return _audit_success(connection_log, event_id)
                update_fields = []
                for field, value in submitted.items():
                    previous = getattr(connection_log, field)
                    unset = previous is None or (field in ("from_id", "audit_ref") and previous == "")
                    if unset:
                        setattr(connection_log, field, value)
                        update_fields.append(field)
                    elif previous != value:
                        return JsonResponse({"error": "Connection fact is immutable"}, status=409)
                if (
                    connection_log.state == ConnLog.STATE_STARTING
                    and connection_log.from_id
                    and connection_log.conn_type is not None
                ):
                    if connection_log.state_revision >= 9_223_372_036_854_775_807:
                        raise IntegrityError("Audit state revision exhausted")
                    connection_log.state = ConnLog.STATE_ACTIVE
                    connection_log.state_revision += 1
                    update_fields.extend(("state", "state_revision"))
                observed_at = audit_lifecycle.database_now()
                audit_lifecycle.refresh_host_lease(connection_log, observed_at)
                update_fields.extend(("last_seen_at", "lease_expires_at"))
                connection_log.save(update_fields=tuple(dict.fromkeys(update_fields)))
                _append_audit_event(
                    connection_log,
                    event_id,
                    ConnectionAuditEvent.KIND_AUTHORIZED,
                    user,
                    device.uuid,
                    submitted,
                )
        except IntegrityError:
            return _audit_event_conflict()
        _log_event(
            request,
            "api_audit_conn_update",
            level="debug",
            username=user.username,
            conn_id=conn_id,
            peer_id=connection_log.rid,
            session_id=session_id,
        )
        return _audit_success(connection_log, event_id)


def _audit_file(request):
    postdata = _load_json_object(request)
    token, user, error = _audit_device_context(request, postdata)
    if error:
        return error
    if not _file_audit_version_is_current(postdata.get("version")):
        return _audit_upgrade_required(FILE_AUDIT_PROTOCOL_VERSION)
    audit_session_id = _audit_uuid4(postdata.get("audit_session_id"))
    event_id = _audit_uuid4(postdata.get("event_id"))
    transfer_id = _audit_uuid4(postdata.get("transfer_id"))
    transfer_revision = _audit_revision(postdata.get("transfer_revision"))
    conn_id = _audit_connection_id(postdata.get("conn_id"))
    if (
        audit_session_id is None
        or event_id is None
        or transfer_id is None
        or transfer_revision is None
        or conn_id is None
    ):
        return JsonResponse({"error": "Invalid connection identity"}, status=400)
    if not isinstance(postdata.get("is_file"), bool):
        return JsonResponse({"error": "Invalid file audit"}, status=400)

    state = postdata.get("state")
    if state not in dict(FileLog.STATES):
        return JsonResponse({"error": "Invalid file transfer state"}, status=400)
    path = _bounded_audit_text(postdata.get("path", ""), 500)
    remote_id = _audit_rid(postdata.get("peer_id", ""))
    direction = _audit_enum(postdata.get("direction"), (0, 1))
    planned_file_count = _audit_nonnegative_integer(postdata.get("planned_file_count"))
    planned_bytes = _audit_nonnegative_integer(postdata.get("planned_bytes"))
    transferred_bytes = _audit_nonnegative_integer(postdata.get("transferred_bytes"))
    source_kind = postdata.get("source_kind")
    terminal_reason = _bounded_audit_text(postdata.get("terminal_reason", ""), 256)
    if (
        path is None
        or remote_id is None
        or direction is None
        or planned_file_count is None
        or planned_bytes is None
        or transferred_bytes is None
        or source_kind not in dict(FileLog.SOURCE_KINDS)
        or terminal_reason is None
    ):
        return JsonResponse({"error": "Invalid file audit"}, status=400)
    if transferred_bytes > planned_bytes:
        return JsonResponse({"error": "Invalid transferred bytes"}, status=400)
    if state in (FileLog.STATE_STARTED, FileLog.STATE_PROGRESS, FileLog.STATE_COMPLETED):
        if terminal_reason:
            return JsonResponse({"error": "Invalid terminal reason"}, status=400)
    elif not terminal_reason:
        return JsonResponse({"error": "Terminal reason is required"}, status=400)

    sample_files = postdata.get("sample_files")
    if not isinstance(sample_files, list) or len(sample_files) > MAX_AUDIT_FILES:
        return JsonResponse({"error": "Invalid audit files"}, status=400)
    normalized_samples = []
    sample_bytes = 0
    for item in sample_files:
        if not isinstance(item, dict) or set(item) != {"path", "size"}:
            return JsonResponse({"error": "Invalid audit files"}, status=400)
        sample_path = _bounded_audit_text(item.get("path"), 500)
        sample_size = _audit_nonnegative_integer(item.get("size"))
        if sample_path is None or sample_size is None:
            return JsonResponse({"error": "Invalid audit files"}, status=400)
        if sample_bytes > MAX_AUDIT_INTEGER - sample_size:
            return JsonResponse({"error": "Invalid audit files"}, status=400)
        sample_bytes += sample_size
        normalized_samples.append({"path": sample_path, "size": sample_size})
    if len(normalized_samples) > planned_file_count or sample_bytes > planned_bytes:
        return JsonResponse({"error": "Invalid file plan"}, status=400)

    details = {
        "transfer_id": str(transfer_id),
        "transfer_revision": transfer_revision,
        "state": state,
        "conn_id": conn_id,
        "path": path,
        "peer_id": remote_id,
        "direction": direction,
        "is_file": postdata["is_file"],
        "planned_file_count": planned_file_count,
        "planned_bytes": planned_bytes,
        "transferred_bytes": transferred_bytes,
        "sample_files": normalized_samples,
        "source_kind": source_kind,
        "terminal_reason": terminal_reason,
    }
    try:
        with transaction.atomic():
            device, connection_log, authority_error = _locked_host_audit_session(
                token,
                user,
                audit_session_id,
                active=False,
                require_controller=True,
            )
            if authority_error:
                return authority_error
            if connection_log.conn_id != conn_id:
                return JsonResponse({"error": "Connection not found"}, status=404)
            if not connection_log.from_id or connection_log.from_id != remote_id:
                return JsonResponse({"error": "Invalid file audit participant"}, status=403)
            existing = _existing_audit_event(event_id)
            if existing:
                if not _matching_audit_event(
                    existing,
                    connection_log,
                    ConnectionAuditEvent.KIND_FILE,
                    user,
                    device.uuid,
                    details,
                ):
                    return _audit_event_conflict()
                transfer_event = (
                    FileTransferAuditEvent.objects.select_related("transfer", "connection_event")
                    .filter(
                        connection_event=existing,
                        transfer__connection=connection_log,
                        transfer__transfer_id=transfer_id,
                        revision=transfer_revision,
                    )
                    .first()
                )
                if transfer_event is None:
                    raise IntegrityError("File transfer audit receipt is missing")
                return _file_audit_success(connection_log, transfer_event)

            observed_at = audit_lifecycle.database_now()
            audit_lifecycle.expire_locked_connection(connection_log, observed_at, source="file_event")
            if connection_log.state != ConnLog.STATE_ACTIVE:
                return _audit_terminal_conflict(connection_log)

            transfer = FileLog.objects.select_for_update().filter(transfer_id=transfer_id).first()
            if transfer is None:
                if transfer_revision != 1 or state != FileLog.STATE_STARTED or transferred_bytes != 0:
                    return JsonResponse({"error": "File transfer must start at revision one"}, status=409)
            else:
                immutable_plan = (
                    transfer.audit_version == FILE_AUDIT_PROTOCOL_VERSION
                    and transfer.connection_id == connection_log.id
                    and transfer.file == path
                    and transfer.remote_id == device.rid
                    and transfer.user_id == remote_id
                    and str(transfer.user_ip) == connection_log.from_ip
                    and transfer.direction == direction
                    and transfer.is_file == postdata["is_file"]
                    and transfer.planned_file_count == planned_file_count
                    and transfer.planned_bytes == planned_bytes
                    and transfer.sample_files == normalized_samples
                    and transfer.source_kind == source_kind
                    and transfer.reporter_id == user.id
                    and transfer.reporter_device_uuid == device.uuid
                )
                if not immutable_plan:
                    return JsonResponse({"error": "File transfer plan is immutable"}, status=409)
                if transfer.state in FileLog.TERMINAL_STATES:
                    return JsonResponse({"error": "File transfer is terminal"}, status=409)
                if transfer_revision != transfer.transfer_revision + 1:
                    return JsonResponse({"error": "File transfer revision is out of order"}, status=409)
                if state not in (
                    FileLog.STATE_PROGRESS,
                    FileLog.STATE_COMPLETED,
                    FileLog.STATE_FAILED,
                    FileLog.STATE_CANCELLED,
                    FileLog.STATE_UNKNOWN,
                ):
                    return JsonResponse({"error": "Invalid file transfer transition"}, status=409)
                if transferred_bytes < transfer.transferred_bytes:
                    return JsonResponse({"error": "Transferred bytes cannot decrease"}, status=409)

            audit_lifecycle.refresh_host_lease(connection_log, observed_at)
            connection_log.save(update_fields=("last_seen_at", "lease_expires_at"))
            event, _created = _append_audit_event(
                connection_log,
                event_id,
                ConnectionAuditEvent.KIND_FILE,
                user,
                device.uuid,
                details,
            )
            terminal_at = observed_at if state in FileLog.TERMINAL_STATES else None
            if transfer is None:
                transfer = FileLog.objects.create(
                    audit_version=FILE_AUDIT_PROTOCOL_VERSION,
                    connection=connection_log,
                    event=event,
                    transfer_id=transfer_id,
                    transfer_revision=transfer_revision,
                    state=state,
                    file=path,
                    user_id=remote_id,
                    user_ip=connection_log.from_ip,
                    remote_id=device.rid,
                    filesize=planned_bytes,
                    direction=direction,
                    is_file=postdata["is_file"],
                    planned_file_count=planned_file_count,
                    planned_bytes=planned_bytes,
                    transferred_bytes=transferred_bytes,
                    sample_files=normalized_samples,
                    source_kind=source_kind,
                    started_at=observed_at,
                    terminal_at=terminal_at,
                    terminal_reason=terminal_reason,
                    logged_at=observed_at,
                    details={"sample_files": normalized_samples},
                    reporter=user,
                    reporter_device_uuid=device.uuid,
                )
            else:
                transfer.transfer_revision = transfer_revision
                transfer.state = state
                transfer.transferred_bytes = transferred_bytes
                transfer.terminal_at = terminal_at
                transfer.terminal_reason = terminal_reason
                transfer.save(
                    update_fields=(
                        "transfer_revision",
                        "state",
                        "transferred_bytes",
                        "terminal_at",
                        "terminal_reason",
                    )
                )
            transfer_event = FileTransferAuditEvent.objects.create(
                transfer=transfer,
                connection_event=event,
                revision=transfer_revision,
                state=state,
                transferred_bytes=transferred_bytes,
                terminal_reason=terminal_reason,
                source_kind=source_kind,
                created_at=observed_at,
            )
    except IntegrityError:
        return _audit_event_conflict()
    _log_event(
        request,
        "api_audit_file",
        level="info",
        username=user.username,
        peer_id=remote_id,
        remote_id=connection_log.rid,
        direction=direction,
        transfer_id=transfer_id,
        transfer_revision=transfer_revision,
        state=state,
        planned_bytes=planned_bytes,
        transferred_bytes=transferred_bytes,
    )
    return _file_audit_success(connection_log, transfer_event)


def _audit_alarm(request):
    postdata = _load_json_object(request)
    token, user, error = _audit_device_context(request, postdata)
    if error:
        return error
    if not _audit_version_is_current(postdata.get("version")):
        return _audit_upgrade_required()
    audit_session_id = _audit_uuid4(postdata.get("audit_session_id"))
    event_id = _audit_uuid4(postdata.get("event_id"))
    conn_id = _audit_connection_id(postdata.get("conn_id"))
    if audit_session_id is None or event_id is None or conn_id is None:
        return JsonResponse({"error": "Invalid connection identity"}, status=400)
    typ = _audit_enum(postdata.get("typ", 0), AlarmLog.TYPES)
    if typ is None:
        return JsonResponse({"error": "Invalid alarm type"}, status=400)
    raw_info = postdata.get("info", "{}")
    if not isinstance(raw_info, (str, dict)):
        return JsonResponse({"error": "Invalid alarm information"}, status=400)
    if isinstance(raw_info, str) and len(raw_info.encode()) > MAX_AUDIT_INFO_BYTES:
        return JsonResponse({"error": "Alarm information is too large"}, status=413)
    try:
        info = json.loads(raw_info) if isinstance(raw_info, str) else raw_info
    except (TypeError, ValueError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid alarm information"}, status=400)
    if not isinstance(info, dict):
        return JsonResponse({"error": "Invalid alarm information"}, status=400)
    audit_ref = _bounded_audit_text(postdata.get("conn_audit_ref", ""), 256)
    if audit_ref is None:
        return JsonResponse({"error": "Invalid audit reference"}, status=400)
    details = {
        "conn_id": conn_id,
        "typ": typ,
        "info": info,
        "audit_ref": audit_ref,
    }
    try:
        with transaction.atomic():
            device, connection_log, authority_error = _locked_host_audit_session(
                token,
                user,
                audit_session_id,
                active=False,
                require_controller=True,
            )
            if authority_error:
                return authority_error
            if connection_log.conn_id != conn_id:
                return JsonResponse({"error": "Connection not found"}, status=404)
            if audit_ref and audit_ref != connection_log.audit_ref:
                return JsonResponse({"error": "Invalid audit reference"}, status=409)
            existing = _existing_audit_event(event_id)
            if existing:
                if not _matching_audit_event(
                    existing,
                    connection_log,
                    ConnectionAuditEvent.KIND_ALARM,
                    user,
                    device.uuid,
                    details,
                ):
                    return _audit_event_conflict()
                if not AlarmLog.objects.filter(event=existing, connection=connection_log).exists():
                    raise IntegrityError("Alarm audit receipt is missing")
                return _audit_success(connection_log, event_id)
            observed_at = audit_lifecycle.database_now()
            audit_lifecycle.expire_locked_connection(connection_log, observed_at, source="alarm_event")
            if connection_log.state != ConnLog.STATE_ACTIVE:
                return _audit_terminal_conflict(connection_log)
            audit_lifecycle.refresh_host_lease(connection_log, observed_at)
            connection_log.save(update_fields=("last_seen_at", "lease_expires_at"))
            event, created = _append_audit_event(
                connection_log,
                event_id,
                ConnectionAuditEvent.KIND_ALARM,
                user,
                device.uuid,
                details,
            )
            if created:
                AlarmLog.objects.create(
                    audit_version=AUDIT_PROTOCOL_VERSION,
                    connection=connection_log,
                    event=event,
                    typ=typ,
                    info=info,
                    reporter=user,
                    reporter_device_id=device.rid,
                    reporter_device_uuid=device.uuid,
                    conn_id=conn_id,
                    audit_ref=connection_log.audit_ref,
                )
            elif not AlarmLog.objects.filter(event=event, connection=connection_log).exists():
                raise IntegrityError("Alarm audit receipt is missing")
    except IntegrityError:
        return _audit_event_conflict()
    _log_event(request, "api_audit_alarm", level="warning", username=user.username, typ=typ)
    return _audit_success(connection_log, event_id)


def audit(request):
    return _audit_conn(request)


def _pagination(request, default=100):
    try:
        current = max(1, int(request.GET.get("current", 1)))
        page_size = max(1, min(500, int(request.GET.get("pageSize", default))))
    except (TypeError, ValueError):
        current = 1
        page_size = default
    start = (current - 1) * page_size
    return current, page_size, start, start + page_size


def _paged_response(request, qs, serializer, default_page_size=100):
    current, page_size, start, end = _pagination(request, default_page_size)
    total = qs.count() if isinstance(qs, QuerySet) else len(qs)
    rows = qs[start:end]
    return JsonResponse(
        {
            "total": total,
            "current": current,
            "pageSize": page_size,
            "data": [serializer(item) for item in rows],
        }
    )


def _filter_text(qs, field, value):
    value = str(value or "").strip()
    if not value:
        return qs
    if "%" in value:
        return qs.filter(**{f"{field}__icontains": value.replace("%", "")})
    return qs.filter(**{field: value})


def _require_admin(request, event):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, f"{event}_unauthorized", level="warning")
        return None, JsonResponse({"error": "Invalid token"}, status=401)
    if not user.is_admin:
        _log_event(request, f"{event}_denied", level="warning", username=user.username)
        return user, JsonResponse({"error": "Admin required"}, status=403)
    return user, None


def _device_guid(device):
    return str(device.pk)


def _user_guid(user):
    return str(user.pk)


def _user_group_names(user):
    cached_groups = getattr(
        user,
        "_prefetched_objects_cache",
        {},
    ).get("groups")
    if cached_groups is None:
        return list(user.groups.order_by("name").values_list("name", flat=True))
    return sorted(group.name for group in cached_groups)


def _serialize_user(u):
    group_names = _user_group_names(u)
    return {
        "guid": _user_guid(u),
        "name": u.username,
        "username": u.username,
        "status": 1 if u.is_active else 0,
        "is_admin": True if u.is_admin else False,
        "email": u.email or "",
        "note": u.note or "",
        "group_name": group_names[0] if group_names else "",
        "group_names": group_names,
        "strategy_name": u.strategy.name if u.strategy_id else "",
    }


def _serialize_device(device):
    owner_name = device.owner.username if device.owner else ""
    owner_group_names = _user_group_names(device.owner) if device.owner else []
    effective_strategy = device.effective_strategy()
    deployed = bool(device.public_key_hash and device.owner and device.owner.is_active and device.is_active)
    return {
        "guid": _device_guid(device),
        "id": device.rid,
        "name": device.hostname,
        "device_name": device.hostname,
        "device_username": device.username,
        "user_name": owner_name or "",
        "group_name": owner_group_names[0] if owner_group_names else "",
        "group_names": owner_group_names,
        "device_group_name": (device.device_group.name if device.device_group_id else ""),
        "strategy_name": (effective_strategy.name if effective_strategy else ""),
        "status": 1 if device.is_active else 0,
        "online": _is_online(device.update_time),
        "last_online": device.update_time.isoformat() if device.update_time else "",
        "platform": device.os,
        "version": device.version,
        "ip_address": device.ip_address or "",
        "note": device.note or "",
        "is_deployed": deployed,
        "deployment_status": ("disabled" if not device.is_active else ("verified" if deployed else "pending")),
    }


def _serialize_device_group(group):
    return {
        "guid": str(group.guid),
        "name": group.name,
        "note": group.note or "",
        "allowed_incomings": (group.allowed_incomings if isinstance(group.allowed_incomings, list) else []),
        "strategy_name": group.strategy.name if group.strategy_id else "",
    }


def _serialize_strategy(strategy):
    options = _strategy_options_value(strategy.config_options)
    return {
        "guid": str(strategy.guid),
        "name": strategy.name,
        "enabled": bool(strategy.enabled),
        "status": 1 if strategy.enabled else 0,
        "config_options": options if options is not None else {},
        "updated_at": strategy.updated_at.isoformat() if strategy.updated_at else "",
    }


def _is_online(updated_at):
    return (timezone.now() - updated_at).total_seconds() <= 120 if updated_at else False


def users(request):
    if request.method == "POST":
        admin_user, error = _require_admin(request, "api_users_create")
        if error:
            return error
        data = _load_json_object(request)
        username = _model_text_value(
            data.get("name") or data.get("username"),
            UserProfile,
            "username",
            allow_empty=False,
        )
        password = data.get("password")
        email = _email_value(data.get("email", ""))
        note = _model_text_value(
            data.get("note", ""),
            UserProfile,
            "note",
            max_bytes=4096,
            strip=False,
        )
        group_name = _model_text_value(
            data.get("group_name", ""),
            Group,
            "name",
        )
        if (
            username is None
            or len(username) < 3
            or not isinstance(password, str)
            or not password
            or len(password) > settings.MAX_PASSWORD_LENGTH
            or email is None
            or note is None
            or group_name is None
        ):
            return JsonResponse({"error": "Invalid user payload"}, status=400)
        if UserProfile.objects.filter(username__iexact=username).exists():
            return JsonResponse({"error": "User already exists"}, status=409)
        candidate = UserProfile(
            username=username,
            email=email,
            note=note,
        )
        try:
            candidate.set_password(password)
            candidate.full_clean()
            password_validation.validate_password(password, user=candidate)
        except ValidationError:
            return JsonResponse({"error": "Password does not meet security requirements"}, status=400)
        try:
            with transaction.atomic():
                user = UserProfile.objects.create_user(
                    username=username,
                    password=password,
                    email=email,
                    note=note,
                )
                if group_name:
                    group = Group.objects.filter(
                        name__iexact=group_name,
                    ).first()
                    if not group:
                        group = Group.objects.create(name=group_name)
                    user.groups.add(group)
        except IntegrityError:
            return JsonResponse({"error": "User already exists"}, status=409)
        _log_event(request, "api_users_created", username=admin_user.username, target=username)
        return JsonResponse(_serialize_user(user))
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_users_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    qs = UserProfile.objects.select_related("strategy").prefetch_related("groups").order_by("id")
    if not user.is_admin:
        qs = qs.filter(Q(id=user.id))
    qs = _filter_text(qs, "username", request.GET.get("name"))
    qs = _filter_text(qs, "groups__name", request.GET.get("group_name"))
    status = request.GET.get("status", "")
    if status == "1":
        qs = qs.filter(Q(is_active=True))
    elif status == "0":
        qs = qs.filter(Q(is_active=False))
    _log_event(request, "api_users", level="debug", username=user.username, total=qs.count())
    return _paged_response(request, qs.distinct(), _serialize_user)


def _user_by_guid(guid):
    pk = _numeric_pk(guid)
    return UserProfile.objects.filter(pk=pk).first() if pk is not None else None


def user_status(request, guid, action):
    admin_user, error = _require_admin(request, f"api_user_{action}")
    if error:
        return error
    try:
        with transaction.atomic():
            target_pk = _numeric_pk(guid)
            target = (
                UserProfile.objects.select_for_update().filter(pk=target_pk).first() if target_pk is not None else None
            )
            if not target:
                return JsonResponse({"error": "User not found"}, status=404)
            if target.id == admin_user.id and action == "disable":
                return JsonResponse({"error": "Cannot disable current user"}, status=400)
            target.is_active = action == "enable"
            target.save(update_fields=["is_active"])
            if not target.is_active:
                revoke_user_credentials((target.pk,))
    except CredentialGenerationExhausted:
        _log_event(
            request,
            f"api_user_{action}_failed",
            level="error",
            username=admin_user.username,
            target=guid,
        )
        return JsonResponse({"error": "Credential revocation failed"}, status=409)
    _log_event(request, f"api_user_{action}", username=admin_user.username, target=target.username)
    return JsonResponse(_serialize_user(target))


def user_delete(request, guid):
    admin_user, error = _require_admin(request, "api_user_delete")
    if error:
        return error
    with transaction.atomic():
        target_pk = _numeric_pk(guid)
        target = UserProfile.objects.select_for_update().filter(pk=target_pk).first() if target_pk is not None else None
        if not target:
            return JsonResponse({"error": "User not found"}, status=404)
        if target.id == admin_user.id:
            return JsonResponse({"error": "Cannot delete current user"}, status=400)
        username = target.username
        # Keep the user -> device -> credential lock order used by session
        # issuance. Heartbeat locks the device before conditionally renewing
        # its credential, so deleting credentials before locking devices could
        # deadlock with a concurrent heartbeat.
        device_ids = list(
            RemoteDevice.objects.select_for_update().filter(owner=target).order_by("pk").values_list("pk", flat=True)
        )
        DeviceProofChallenge.objects.filter(device_id__in=device_ids).delete()
        DeviceRecoveryApproval.objects.filter(device_id__in=device_ids).delete()
        RemoteToken.objects.filter(device__owner=target).delete()
        RemoteDevice.objects.filter(pk__in=device_ids).update(
            owner=None,
            public_key_hash=None,
            is_active=False,
            update_time=timezone.now(),
        )
        target.delete()
    _log_event(request, "api_user_deleted", username=admin_user.username, target=username)
    return JsonResponse({"result": "OK"})


def users_force_logout(request):
    admin_user, error = _require_admin(request, "api_users_force_logout")
    if error:
        return error
    data = _load_json_object(request)
    guids = _identifier_list(data.get("user_guids"), numeric=True)
    if guids is None:
        return JsonResponse({"error": "Invalid user list"}, status=400)
    try:
        revocation = revoke_user_credentials(guids)
    except CredentialGenerationExhausted:
        _log_event(request, "api_users_force_logout_failed", level="error", username=admin_user.username)
        return JsonResponse({"error": "Credential revocation failed"}, status=409)
    _log_event(
        request,
        "api_users_force_logout",
        username=admin_user.username,
        deleted=revocation.deleted_tokens,
        revoked_users=revocation.revoked_users,
    )
    return JsonResponse(
        {
            "result": "OK",
            "deleted": revocation.deleted_tokens,
            "revoked_users": revocation.revoked_users,
        }
    )


def devices(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_devices_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    qs = (
        RemoteDevice.objects.select_related(
            "owner__strategy",
            "device_group__strategy",
            "strategy",
        )
        .prefetch_related("owner__groups")
        .order_by("rid")
    )
    if not user.is_admin:
        qs = qs.filter(Q(owner=user))
    qs = _filter_text(qs, "rid", request.GET.get("id"))
    qs = _filter_text(qs, "hostname", request.GET.get("device_name"))
    qs = _filter_text(qs, "username", request.GET.get("device_username"))
    qs = _filter_text(
        qs,
        "device_group__name",
        request.GET.get("device_group_name"),
    )
    user_name = request.GET.get("user_name")
    if user_name:
        qs = _filter_text(qs, "owner__username", user_name)
    group_name = request.GET.get("group_name")
    if group_name:
        lookup = "owner__groups__name__icontains" if "%" in group_name else "owner__groups__name"
        qs = qs.filter(**{lookup: group_name.replace("%", "")}).distinct()
    return _paged_response(request, qs, _serialize_device)


def _device_by_guid(guid):
    pk = _numeric_pk(guid)
    return (
        RemoteDevice.objects.select_related(
            "owner__strategy",
            "device_group__strategy",
            "strategy",
        )
        .filter(pk=pk)
        .first()
        if pk is not None
        else None
    )


def device_status(request, guid, action):
    admin_user, error = _require_admin(request, f"api_device_{action}")
    if error:
        return error
    device_pk = _numeric_pk(guid)
    with transaction.atomic():
        device = (
            RemoteDevice.objects.select_for_update().filter(pk=device_pk).first() if device_pk is not None else None
        )
        if not device:
            return JsonResponse({"error": "Device not found"}, status=404)
        device.is_active = action == "enable"
        device.save(update_fields=["is_active", "update_time"])
        if not device.is_active:
            _revoke_device_tokens(device)
    _log_event(request, f"api_device_{action}", username=admin_user.username, rid=device.rid)
    return JsonResponse(_serialize_device(device))


def device_approve_recovery(request, guid):
    admin_user, error = _require_admin(request, "api_device_approve_recovery")
    if error:
        return error
    device_pk = _numeric_pk(guid)
    public_key = str(_load_json_object(request).get("pk", "")).strip()
    with transaction.atomic():
        device = (
            RemoteDevice.objects.select_for_update().filter(pk=device_pk).first() if device_pk is not None else None
        )
        if not device:
            return JsonResponse({"error": "Device not found"}, status=404)
        if not device.is_active or not device.owner_id or not device.public_key_hash:
            return JsonResponse({"error": "Device is not eligible for recovery"}, status=409)
        try:
            approval = create_recovery_approval(
                device=device,
                public_key_text=public_key,
                admin_user=admin_user,
            )
        except DeviceProofError:
            return JsonResponse({"error": "Invalid public key"}, status=400)
    _log_event(
        request,
        "api_device_recovery_approved",
        username=admin_user.username,
        rid=device.rid,
    )
    return JsonResponse(
        {
            "result": "OK",
            "expires_at": int(approval.expires_at.timestamp()),
        }
    )


def device_delete(request, guid):
    admin_user, error = _require_admin(request, "api_device_delete")
    if error:
        return error
    device_pk = _numeric_pk(guid)
    with transaction.atomic():
        device = (
            RemoteDevice.objects.select_for_update().filter(pk=device_pk).first() if device_pk is not None else None
        )
        if not device:
            return JsonResponse({"error": "Device not found"}, status=404)
        rid = device.rid
        _revoke_device_tokens(device)
        device.delete()
    _log_event(request, "api_device_deleted", username=admin_user.username, rid=rid)
    return JsonResponse({"result": "OK"})


def device_assign(request, guid):
    admin_user, error = _require_admin(request, "api_device_assign")
    if error:
        return error
    data = _load_json_object(request)
    typ = str(data.get("type") or "")
    value = data.get("value")
    owner_changed = False
    device_pk = _numeric_pk(guid)
    owner = _user_by_identifier(value, active_only=True) if typ == "user_name" else None
    if typ == "user_name" and not owner:
        return JsonResponse({"error": "Active user not found"}, status=404)
    with transaction.atomic():
        if owner:
            owner = UserProfile.objects.select_for_update().filter(pk=owner.pk, is_active=True).first()
            if not owner:
                return JsonResponse({"error": "Active user not found"}, status=404)
        device = (
            RemoteDevice.objects.select_for_update(of=("self",)).select_related("owner").filter(pk=device_pk).first()
            if device_pk is not None
            else None
        )
        if not device:
            return JsonResponse({"error": "Device not found"}, status=404)
        if typ == "user_name":
            owner_changed = device.owner_id != owner.id
            device.owner = owner
        elif typ == "device_group_name":
            group_name = _bounded_text_value(value, 480)
            if group_name is not None:
                group_name = group_name.strip()
            if group_name is None:
                return JsonResponse({"error": "Invalid device group"}, status=400)
            group = DeviceGroup.objects.filter(name=group_name).first() if group_name else None
            if group_name and not group:
                return JsonResponse({"error": "Device group not found"}, status=404)
            device.device_group = group
        elif typ == "strategy_name":
            strategy_name = _bounded_text_value(value, 240)
            if strategy_name is not None:
                strategy_name = strategy_name.strip()
            if strategy_name is None:
                return JsonResponse({"error": "Invalid strategy"}, status=400)
            strategy = StrategyProfile.objects.filter(name=strategy_name).first() if strategy_name else None
            if strategy_name and not strategy:
                return JsonResponse({"error": "Strategy not found"}, status=404)
            device.strategy = strategy
        elif typ in ("note", "device_username", "device_name"):
            field_name = {
                "note": "note",
                "device_username": "username",
                "device_name": "hostname",
            }[typ]
            text_value = _model_text_value(
                value,
                RemoteDevice,
                field_name,
                strip=False,
                max_bytes=4096 if field_name == "note" else None,
            )
            if text_value is None:
                return JsonResponse({"error": "Invalid assignment value"}, status=400)
            setattr(device, field_name, text_value)
        elif typ == "ab":
            if not isinstance(value, dict):
                return JsonResponse(
                    {"error": "Address-book assignment must be an object"},
                    status=400,
                )
            ab_updates = _validated_device_update_fields(
                value,
                DEVICE_ADDRESS_BOOK_FIELDS,
            )
            allowed_fields = {
                "address_book_name",
                "address_book_tag",
                "address_book_alias",
                "address_book_password",
                "address_book_note",
            }
            if ab_updates is None or not ab_updates or any(field not in allowed_fields for field in ab_updates):
                return JsonResponse(
                    {"error": "Invalid address-book assignment"},
                    status=400,
                )
            for field, field_value in ab_updates.items():
                setattr(device, field, field_value)
        else:
            return JsonResponse({"error": "Invalid assign type"}, status=400)
        device.save()
        if owner_changed:
            _revoke_device_tokens(device)
    _log_event(request, "api_device_assigned", username=admin_user.username, rid=device.rid, typ=typ)
    return JsonResponse(_serialize_device(device))


def peers(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_peers_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    current, page_size, _start, _end = _pagination(request)
    if user.is_admin:
        device_qs = RemoteDevice.objects.select_related(
            "owner__strategy",
            "device_group__strategy",
            "strategy",
        ).order_by("rid")
        peer_qs = RemotePeer.objects.filter(
            profile__guid__startswith="personal-",
        ).select_related("profile__owner")
    else:
        peer_qs = RemotePeer.objects.filter(
            profile__owner=user,
            profile__guid=_personal_guid(user),
        ).select_related("profile__owner")
        device_qs = RemoteDevice.objects.filter(
            owner=user,
        ).select_related(
            "owner__strategy",
            "device_group__strategy",
            "strategy",
        )
        device_qs = device_qs.order_by("rid")
    devices = {x.rid: x for x in device_qs}
    if user.is_admin:
        peers_by_owner_and_rid = {(peer.profile.owner_id, peer.rid): peer for peer in peer_qs}
        peers_by_rid = {rid: peers_by_owner_and_rid.get((device.owner_id, rid)) for rid, device in devices.items()}
        device_ids = sorted(devices)
    else:
        peers_by_rid = {peer.rid: peer for peer in peer_qs}
        device_ids = sorted(set(devices) | set(peers_by_rid))
    status_filter = request.GET.get("status", "")
    if status_filter in ("0", "1"):
        target = 1 if status_filter == "1" else 0
        device_ids = [
            rid for rid in device_ids if (devices[rid].is_active if rid in devices else True) == (target == 1)
        ]
    total = len(device_ids)
    start = (current - 1) * page_size
    end = start + page_size
    data = []
    for rid in device_ids[start:end]:
        device = devices.get(rid)
        peer = peers_by_rid.get(rid)
        username = device.username if device and device.username else (peer.username if peer else "")
        owner = ""
        if device and device.owner:
            owner = device.owner.username
        elif peer:
            owner = peer.profile.owner.username
        status = 1 if not device or device.is_active else 0
        data.append(
            {
                "id": rid,
                "info": {
                    "username": username,
                    "os": (device.os if device else (peer.platform if peer else "")),
                    "device_name": (device.hostname if device else (peer.hostname if peer else "")),
                },
                "status": status,
                "user": owner,
                "user_name": owner,
                "device_group_name": (
                    device.device_group.name
                    if device and device.device_group_id
                    else (peer.device_group_name if peer else "")
                ),
                "note": device.note if device else (peer.note if peer else ""),
            }
        )
    _log_event(
        request, "api_peers", level="debug", username=user.username, total=total, page=current, page_size=page_size
    )
    return JsonResponse({"total": total, "data": data})


def device_group_accessible(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_device_group_accessible_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    if user.is_admin:
        groups = list(DeviceGroup.objects.select_related("strategy").order_by("name"))
    else:
        groups = list(
            DeviceGroup.objects.filter(
                devices__in=RemoteDevice.objects.filter(
                    owner=user,
                )
            )
            .select_related("strategy")
            .distinct()
            .order_by("name")
        )
    data = [_serialize_device_group(group) for group in groups]
    _log_event(request, "api_device_group_accessible", level="debug", username=user.username, total=len(data))
    return JsonResponse({"total": len(data), "data": data})


def device_groups(request):
    if request.method == "POST":
        admin_user, error = _require_admin(request, "api_device_groups_create")
        if error:
            return error
        data = _load_json_object(request)
        name = _model_text_value(
            data.get("name"),
            DeviceGroup,
            "name",
            allow_empty=False,
        )
        note = _model_text_value(
            data.get("note", ""),
            DeviceGroup,
            "note",
            strip=False,
            max_bytes=4096,
        )
        allowed_incomings = _allowed_incomings_value(data.get("allowed_incomings", []))
        strategy_name = _bounded_text_value(
            data.get("strategy_name", ""),
            240,
        )
        if strategy_name is not None:
            strategy_name = strategy_name.strip()
        if name is None or note is None or allowed_incomings is None or strategy_name is None:
            return JsonResponse({"error": "Invalid device group"}, status=400)
        strategy = StrategyProfile.objects.filter(name=strategy_name).first() if strategy_name else None
        if strategy_name and not strategy:
            return JsonResponse({"error": "Strategy not found"}, status=404)
        try:
            group = DeviceGroup.objects.create(
                name=name,
                note=note,
                allowed_incomings=allowed_incomings,
                strategy=strategy,
            )
        except IntegrityError:
            return JsonResponse(
                {"error": "Device group already exists"},
                status=409,
            )
        _log_event(request, "api_device_groups_created", username=admin_user.username, target=name)
        return JsonResponse(_serialize_device_group(group))
    admin_user, error = _require_admin(request, "api_device_groups")
    if error:
        return error
    qs = DeviceGroup.objects.select_related("strategy").order_by("name")
    qs = _filter_text(qs, "name", request.GET.get("name"))
    return _paged_response(request, qs, _serialize_device_group)


def _device_group_by_guid(guid):
    return DeviceGroup.objects.filter(guid=guid).first()


def device_group_detail(request, guid):
    admin_user, error = _require_admin(request, "api_device_group_detail")
    if error:
        return error
    if request.method == "PATCH":
        data = _load_json_object(request)
        if not data:
            return JsonResponse({"error": "Invalid device group"}, status=400)
        with transaction.atomic():
            group = DeviceGroup.objects.select_for_update().filter(guid=guid).first()
            if not group:
                return JsonResponse({"error": "Device group not found"}, status=404)
            if "name" in data:
                new_name = _model_text_value(
                    data.get("name"),
                    DeviceGroup,
                    "name",
                    allow_empty=False,
                )
                if new_name is None:
                    return JsonResponse({"error": "Invalid name"}, status=400)
                group.name = new_name
            if "note" in data:
                note = _model_text_value(
                    data.get("note"),
                    DeviceGroup,
                    "note",
                    strip=False,
                    max_bytes=4096,
                )
                if note is None:
                    return JsonResponse({"error": "Invalid note"}, status=400)
                group.note = note
            if "allowed_incomings" in data:
                allowed_incomings = _allowed_incomings_value(data.get("allowed_incomings"))
                if allowed_incomings is None:
                    return JsonResponse(
                        {"error": "Invalid allowed_incomings"},
                        status=400,
                    )
                group.allowed_incomings = allowed_incomings
            if "strategy_name" in data:
                strategy_name = _bounded_text_value(
                    data.get("strategy_name"),
                    240,
                )
                if strategy_name is not None:
                    strategy_name = strategy_name.strip()
                if strategy_name is None:
                    return JsonResponse({"error": "Invalid strategy"}, status=400)
                strategy = StrategyProfile.objects.filter(name=strategy_name).first() if strategy_name else None
                if strategy_name and not strategy:
                    return JsonResponse({"error": "Strategy not found"}, status=404)
                group.strategy = strategy
            try:
                group.save()
            except IntegrityError:
                return JsonResponse({"error": "Device group already exists"}, status=409)
        return JsonResponse(_serialize_device_group(group))
    elif request.method == "POST":
        ids = _load_json(request)
        ids = _identifier_list(ids)
        if ids is None or any(not re.fullmatch(r"[A-Za-z0-9_-]{6,16}", item) for item in ids):
            return JsonResponse({"error": "Device id list required"}, status=400)
        group = _device_group_by_guid(guid)
        if not group:
            return JsonResponse({"error": "Device group not found"}, status=404)
        updated = RemoteDevice.objects.filter(rid__in=[str(x) for x in ids]).update(device_group=group)
        _log_event(
            request, "api_device_group_add_devices", username=admin_user.username, target=group.name, updated=updated
        )
        return JsonResponse({"result": "OK", "updated": updated})
    else:
        with transaction.atomic():
            group = DeviceGroup.objects.select_for_update().filter(guid=guid).first()
            if not group:
                return JsonResponse({"error": "Device group not found"}, status=404)
            name = group.name
            group.delete()
        _log_event(request, "api_device_group_deleted", username=admin_user.username, target=name)
        return JsonResponse({"result": "OK"})


def device_group_remove_devices(request, guid):
    admin_user, error = _require_admin(request, "api_device_group_remove_devices")
    if error:
        return error
    group = _device_group_by_guid(guid)
    if not group:
        return JsonResponse({"error": "Device group not found"}, status=404)
    ids = _load_json(request)
    ids = _identifier_list(ids)
    if ids is None or any(not re.fullmatch(r"[A-Za-z0-9_-]{6,16}", item) for item in ids):
        return JsonResponse({"error": "Device id list required"}, status=400)
    updated = RemoteDevice.objects.filter(
        rid__in=[str(x) for x in ids],
        device_group=group,
    ).update(device_group=None)
    _log_event(
        request, "api_device_group_remove_devices", username=admin_user.username, target=group.name, updated=updated
    )
    return JsonResponse({"result": "OK", "updated": updated})


def strategies(request):
    admin_user, error = _require_admin(request, "api_strategies")
    if error:
        return error
    if request.method == "POST":
        data = _load_json_object(request)
        name = _model_text_value(
            data.get("name"),
            StrategyProfile,
            "name",
            allow_empty=False,
        )
        options = _strategy_options_value(
            data.get("config_options", {}),
        )
        enabled = _strict_bool(data.get("enabled", True))
        if name is None or options is None or enabled is None:
            return JsonResponse({"error": "Invalid strategy"}, status=400)
        try:
            strategy = StrategyProfile.objects.create(
                name=name,
                config_options=options,
                enabled=enabled,
            )
        except IntegrityError:
            return JsonResponse({"error": "Strategy already exists"}, status=409)
        _log_event(
            request,
            "api_strategy_created",
            username=admin_user.username,
            target=name,
        )
        return JsonResponse(_serialize_strategy(strategy))
    qs = StrategyProfile.objects.all().order_by("name")
    return JsonResponse([_serialize_strategy(strategy) for strategy in qs], safe=False)


def strategy_detail(request, guid):
    admin_user, error = _require_admin(request, "api_strategy_detail")
    if error:
        return error
    if request.method == "GET":
        strategy = StrategyProfile.objects.filter(guid=guid).first()
        if not strategy:
            return JsonResponse({"error": "Strategy not found"}, status=404)
        return JsonResponse(_serialize_strategy(strategy))
    elif request.method == "PATCH":
        data = _load_json_object(request)
        if not data:
            return JsonResponse({"error": "Invalid strategy"}, status=400)
        with transaction.atomic():
            strategy = StrategyProfile.objects.select_for_update().filter(guid=guid).first()
            if not strategy:
                return JsonResponse({"error": "Strategy not found"}, status=404)
            if "name" in data:
                name = _model_text_value(
                    data.get("name"),
                    StrategyProfile,
                    "name",
                    allow_empty=False,
                )
                if name is None:
                    return JsonResponse({"error": "Invalid strategy name"}, status=400)
                strategy.name = name
            if "config_options" in data:
                options = _strategy_options_value(
                    data.get("config_options"),
                )
                if options is None:
                    return JsonResponse(
                        {"error": "Invalid strategy options"},
                        status=400,
                    )
                strategy.config_options = options
            if "enabled" in data:
                enabled = _strict_bool(data.get("enabled"))
                if enabled is None:
                    return JsonResponse(
                        {"error": "Invalid enabled value"},
                        status=400,
                    )
                strategy.enabled = enabled
            try:
                strategy.save()
            except IntegrityError:
                return JsonResponse({"error": "Strategy already exists"}, status=409)
        _log_event(
            request,
            "api_strategy_updated",
            username=admin_user.username,
            target=strategy.name,
        )
        return JsonResponse(_serialize_strategy(strategy))
    else:
        with transaction.atomic():
            strategy = StrategyProfile.objects.select_for_update().filter(guid=guid).first()
            if not strategy:
                return JsonResponse({"error": "Strategy not found"}, status=404)
            name = strategy.name
            strategy.delete()
        _log_event(
            request,
            "api_strategy_deleted",
            username=admin_user.username,
            target=name,
        )
        return JsonResponse({"result": "OK"})


def strategy_status(request, guid):
    admin_user, error = _require_admin(request, "api_strategy_status")
    if error:
        return error
    strategy = StrategyProfile.objects.filter(guid=guid).first()
    if not strategy:
        return JsonResponse({"error": "Strategy not found"}, status=404)
    data = _load_json(request)
    enabled = _strict_bool(data if isinstance(data, bool) else data.get("enabled") if isinstance(data, dict) else None)
    if enabled is None:
        return JsonResponse({"error": "Boolean enabled value required"}, status=400)
    strategy.enabled = enabled
    strategy.save(update_fields=["enabled", "updated_at"])
    _log_event(
        request, "api_strategy_status", username=admin_user.username, target=strategy.name, enabled=strategy.enabled
    )
    return JsonResponse(_serialize_strategy(strategy))


def strategy_assign(request):
    admin_user, error = _require_admin(request, "api_strategy_assign")
    if error:
        return error
    data = _load_json_object(request)
    strategy = None
    strategy_guid = data.get("strategy")
    if strategy_guid:
        if not isinstance(strategy_guid, str) or len(strategy_guid) > 64:
            return JsonResponse({"error": "Invalid strategy"}, status=400)
        strategy = StrategyProfile.objects.filter(guid=strategy_guid).first()
        if not strategy:
            return JsonResponse({"error": "Strategy not found"}, status=404)
    peer_guids = _identifier_list(data.get("peers", []), numeric=True)
    user_guids = _identifier_list(data.get("users", []), numeric=True)
    group_guids = _identifier_list(data.get("groups", []))
    if peer_guids is None or user_guids is None or group_guids is None:
        return JsonResponse({"error": "Invalid assignment targets"}, status=400)
    if not peer_guids and not user_guids and not group_guids:
        return JsonResponse({"error": "No assignment targets"}, status=400)
    with transaction.atomic():
        devices_updated = RemoteDevice.objects.filter(pk__in=peer_guids).update(strategy=strategy)
        users_updated = UserProfile.objects.filter(pk__in=user_guids).update(strategy=strategy)
        groups = DeviceGroup.objects.filter(guid__in=group_guids)
        groups_updated = groups.update(strategy=strategy)
    _log_event(
        request,
        "api_strategy_assign",
        username=admin_user.username,
        strategy=strategy.name if strategy else "",
        devices=devices_updated,
        users=users_updated,
        groups=groups_updated,
    )
    return JsonResponse({"result": "OK", "devices": devices_updated, "users": users_updated, "groups": groups_updated})
