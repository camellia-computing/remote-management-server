import base64
import binascii
import contextlib
import datetime
import functools
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import stat
import time
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

# from django.forms.models import model_to_dict
from api.encrypted_fields import verify_key_canary
from api.models import (
    AddressBookProfile,
    AddressBookRule,
    AddressBookRuleAudit,
    AddressBookShare,
    AlarmLog,
    ConnLog,
    DataEncryptionKeyState,
    DeviceGroup,
    FileLog,
    LoginAttempt,
    OidcIdentity,
    OidcPendingAuth,
    RemoteDevice,
    RemotePeer,
    RemoteTag,
    RemoteToken,
    StrategyProfile,
    UserProfile,
)
from api.request_utils import client_ip, load_json_body, load_json_object
from api.tag_colors import normalize_tag_color

logger = logging.getLogger(__name__)
EFFECTIVE_SECONDS = 7200
MAX_DEPLOY_KEY_LEN = 512
OIDC_PENDING_MINUTES = settings.OIDC_PENDING_RETENTION_MINUTES
OIDC_MAX_PENDING_PER_IP = 20
OIDC_DOCUMENT_MAX_BYTES = 1024 * 1024
LOGIN_LOCK_MAX_FAILURES = 10
LOGIN_LOCK_MAX_IP_FAILURES = 100
LOGIN_LOCK_WINDOW_MINUTES = settings.LOGIN_ATTEMPT_RETENTION_MINUTES
MAX_DEVICE_UUID_TEXT_LEN = 344
MAX_AUDIT_INFO_BYTES = 16 * 1024
MAX_AUDIT_NOTE_BYTES = 16 * 1024
MAX_AUDIT_FILES = 10
MAX_AB_PEERS = 10_000
MAX_AB_TAGS = 256
MAX_AB_TAGS_PER_PEER = 32
MAX_MANAGEMENT_BATCH_ITEMS = 500
MAX_STRATEGY_OPTIONS_BYTES = 64 * 1024
MAX_ALLOWED_INCOMINGS = 500
RECORD_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")
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
    user = token.device.owner if token.device_id else None
    if not user:
        token.delete()
        return None, None
    if user and not user.is_active:
        token.delete()
        return None, None
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
        locked_device = RemoteDevice.objects.select_for_update().get(
            pk=device.pk,
        )
        if locked_device.owner_id != user.id or not locked_device.is_active:
            raise PermissionError("Device ownership mismatch")
        token, _created = RemoteToken.objects.update_or_create(
            device=locked_device,
            defaults={
                "access_token": _hash_token(raw_token),
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
    return RemoteToken.objects.filter(device=device).delete()[0]


def _get_device_token_user(request, rid, device_uuid):
    token, user = _get_token_user(request)
    if not token or not user:
        return token, None
    if token.device.rid != rid or token.device.uuid != device_uuid:
        return token, None
    return token, user


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
):
    """Return the one device row a login session is allowed to claim."""

    device_info = device_info or {}
    hostname = device_info.get("name") or "-"
    operating_system = device_info.get("os") or "-"
    for attempt in range(2):
        try:
            with transaction.atomic():
                device = _device_by_identity(
                    rid,
                    device_uuid,
                    for_update=True,
                )
                if device and (not device.is_active or (device.owner_id and device.owner_id != user.id)):
                    raise PermissionError("Device is unavailable")
                if not device:
                    return RemoteDevice.objects.create(
                        rid=rid,
                        cpu="-",
                        hostname=hostname,
                        memory="-",
                        os=operating_system,
                        uuid=device_uuid,
                        username="",
                        version="-",
                        ip_address=ip_address,
                        owner=user,
                    )
                update_fields = []
                if device.owner_id is None:
                    device.owner = user
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


def _resolve_oidc_user(provider_name, issuer, claims):
    subject = str(claims.get("sub") or "").strip()
    if not subject or len(subject) > OidcIdentity._meta.get_field("subject").max_length:
        raise ValueError("OIDC subject is invalid")
    last_username = str(claims.get("preferred_username") or claims.get("name") or "").strip()[:255]
    email = str(claims.get("email") or "").strip()
    if claims.get("email_verified") is not True:
        email = ""
    email = email[:254]
    if email:
        try:
            validate_email(email)
        except ValidationError:
            email = ""

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
                        last_username=last_username,
                        last_email=email,
                    )
            break
        except IntegrityError:
            identity = OidcIdentity.objects.select_related("user").filter(issuer=issuer, subject=subject).first()
            if identity:
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
        "path": getattr(request, "path", ""),
        "method": getattr(request, "method", ""),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    details = json.dumps(payload, ensure_ascii=False, default=str)
    log_fn = getattr(logger, level, logger.info)
    log_fn("event=%s details=%s", event, details)


def _record_dir():
    return os.fspath(settings.RECORD_UPLOAD_ROOT)


def _safe_record_name(name):
    if not isinstance(name, str) or name != os.path.basename(name):
        return ""
    return name if RECORD_NAME_RE.fullmatch(name) else ""


def _record_device_dir(token):
    namespace = hashlib.sha256(
        (f"{token.device.owner_id}\0{token.device.rid}\0{token.device.uuid}").encode()
    ).hexdigest()
    return os.path.join(_record_dir(), namespace)


def _secure_directory(path):
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    directory_stat = os.lstat(path)
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
        raise OSError("Recording directory is not a real directory")
    if directory_stat.st_mode & 0o077:
        os.chmod(path, 0o700)


def _ensure_record_device_dir(token):
    root = _record_dir()
    _secure_directory(root)
    device_dir = _record_device_dir(token)
    _secure_directory(device_dir)
    return device_dir


def _fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path, flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextlib.contextmanager
def _record_file_lock(base_dir, filename):
    lock_dir = os.path.join(base_dir, ".locks")
    _secure_directory(lock_dir)
    lock_name = hashlib.sha256(filename.encode()).hexdigest() + ".lock"
    lock_path = os.path.join(lock_dir, lock_name)
    lock_fd = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    for _attempt in range(2):
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
            break
        except FileExistsError:
            try:
                lock_stat = os.lstat(lock_path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(lock_stat.st_mode) or time.time() - lock_stat.st_mtime <= 300:
                raise BlockingIOError("Recording is busy") from None
            try:
                os.unlink(lock_path)
            except FileNotFoundError:
                continue
    if lock_fd is None:
        raise BlockingIOError("Recording is busy")
    try:
        os.write(lock_fd, f"{os.getpid()} {time.time_ns()}\n".encode())
        os.fsync(lock_fd)
        yield
    finally:
        os.close(lock_fd)
        try:
            os.unlink(lock_path)
        except FileNotFoundError:
            pass


def _open_record_file(filepath, flags):
    fd = os.open(
        filepath,
        flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    file_stat = os.fstat(fd)
    if not stat.S_ISREG(file_stat.st_mode):
        os.close(fd)
        raise OSError("Recording path is not a regular file")
    return fd


def _write_all(fd, data):
    written = 0
    while written < len(data):
        count = os.write(fd, data[written:])
        if count <= 0:
            raise OSError("Recording write did not make progress")
        written += count


def _request_content_length(request):
    try:
        return int(request.META.get("CONTENT_LENGTH", "0") or 0)
    except (TypeError, ValueError):
        return -1


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
    payload = _json_value(
        details if details is not None else {},
        expected_type=(dict, list),
        max_bytes=16 * 1024,
    )
    if payload is None:
        payload = {}
    AddressBookRuleAudit.objects.create(
        profile=profile,
        actor=actor if actor and getattr(actor, "id", None) else None,
        action=action,
        target_type=target_type,
        target_name=target_name or "",
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


def _strategy_options_value(value):
    value = _json_value(
        value,
        expected_type=dict,
        max_bytes=MAX_STRATEGY_OPTIONS_BYTES,
    )
    if value is None or len(value) > 512:
        return None
    output = {}
    for key, option_value in value.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 128
            or len(key.encode()) > 512
            or any(ord(character) < 32 for character in key)
            or not isinstance(option_value, str)
            or len(option_value) > 4096
            or len(option_value.encode()) > 16 * 1024
        ):
            return None
        output[key] = option_value
    return output


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


def _login_locked(ip, username):
    window_start = timezone.now() - datetime.timedelta(minutes=LOGIN_LOCK_WINDOW_MINUTES)
    attempts = LoginAttempt.objects.filter(Q(ip=ip) & Q(created_at__gte=window_start))
    if attempts.count() >= LOGIN_LOCK_MAX_IP_FAILURES:
        return True
    return attempts.filter(Q(username=username.casefold())).count() >= LOGIN_LOCK_MAX_FAILURES


def _record_login_failure(ip, username):
    LoginAttempt.objects.create(
        ip=ip or "0.0.0.0",  # noqa: S104 - non-routable audit sentinel, not a bind address
        username=username.casefold()[:150],
    )


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
    if _login_locked(client_ip, username):
        _log_event(request, "api_login_locked", level="warning", username=username)
        return JsonResponse({"error": _("尝试次数过多，请稍后再试。")}, status=429)
    user = auth.authenticate(username=username, password=password)
    if not user:
        _record_login_failure(client_ip, username)
        result["error"] = _("帐号或密码错误！请重试，多次重试后将被锁定IP！")
        _log_event(request, "api_login_failed", level="warning", username=username)
        return JsonResponse(result, status=401)
    if not user.is_active:
        _log_event(request, "api_login_denied", level="warning", username=username, reason="inactive")
        return JsonResponse({"error": _("账号已被禁用")}, status=403)

    try:
        device = _claim_session_device(
            user,
            rid,
            uuid,
            client_ip,
            device_info,
        )
        _token, raw_token = _issue_access_token(user, device)
    except DeviceIdentityConflict:
        _log_event(
            request, "api_login_denied", level="warning", username=username, reason="device_identity_conflict", rid=rid
        )
        return JsonResponse({"error": "Device identity conflict"}, status=409)
    except PermissionError:
        _log_event(
            request, "api_login_denied", level="warning", username=username, reason="device_unavailable", rid=rid
        )
        return JsonResponse({"error": "Permission denied"}, status=403)
    except IntegrityError:
        _log_event(
            request, "api_login_denied", level="warning", username=username, reason="device_identity_race", rid=rid
        )
        return JsonResponse({"error": "Device identity conflict"}, status=409)
    LoginAttempt.objects.filter(Q(ip=client_ip) & Q(username=username.casefold())).delete()

    _ensure_personal_device_peer(user, device)

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
    token, user = _get_token_user(request)

    if not user:
        _log_event(request, "api_current_user_failed", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    if token:
        # Tokens are stored hashed; echo back the raw token the client presented.
        result["access_token"] = _get_bearer_token(request)
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
        return JsonResponse({"error": "Invalid device token"}, status=401)
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
                {"error": "Device is not active for this account"},
                status=403,
            )
        device.ip_address = get_client_ip(request)
        device.save(update_fields=["ip_address", "update_time"])

        # Sliding expiry is extended only after the device authorization is
        # revalidated while holding the same transaction lock.
        token.expires_at = timezone.now() + datetime.timedelta(seconds=EFFECTIVE_SECONDS)
        token.save(update_fields=["expires_at"])
    response = {}
    try:
        client_modified = int(postdata.get("modified_at", 0))
    except (TypeError, ValueError):
        client_modified = 0
    if device:
        profile = device.effective_strategy()
        if profile and profile.enabled:
            server_modified = int(profile.updated_at.timestamp())
            if server_modified != client_modified:
                response["modified_at"] = server_modified
                options = _strategy_options_value(profile.config_options)
                if options is None:
                    logger.error(
                        "event=invalid_strategy_options strategy_id=%s",
                        profile.pk,
                    )
                    return JsonResponse({"error": "Invalid strategy configuration"}, status=503)
                response["strategy"] = {"config_options": options, "extra": {}}
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
        key_states = list(
            DataEncryptionKeyState.objects.order_by("key_id")[: settings.MAX_DATA_ENCRYPTION_KEYS + 1]
        )
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
    if device_info is None:
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
    poll_code = str(request.GET.get("code", "")).strip()
    if not poll_code or len(poll_code) > 128:
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
            )
            _token, raw_token = _issue_access_token(user, device)
        except (DeviceIdentityConflict, IntegrityError):
            session.delete()
            return JsonResponse({"error": "OIDC authorization failed"}, status=409)
        except PermissionError:
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
            device.rid = rid
            device.uuid = uuid_value
            device.public_key_hash = public_key_hash
            device.owner = user
            device.ip_address = get_client_ip(request)
            device.save()
            if old_rid != rid or old_uuid != uuid_value or (old_key_hash and old_key_hash != public_key_hash):
                _revoke_device_tokens(device)
    except IntegrityError:
        _log_event(request, "api_devices_deploy_conflict", level="warning", username=user.username, rid=rid)
        return JsonResponse({"result": "ID_TAKEN"}, status=409)

    _ensure_personal_device_peer(user, device)
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
    if (
        not re.fullmatch(r"[A-Za-z0-9_-]{6,16}", rid)
        or _decode_canonical_base64(uuid_value, max_decoded_bytes=256) is None
        or not re.fullmatch(r"[0-9a-f]{64}", public_key_hash)
    ):
        return HttpResponse(status=400)
    authorized = RemoteDevice.objects.filter(
        rid=rid,
        uuid=uuid_value,
        public_key_hash=public_key_hash,
        is_active=True,
        owner__is_active=True,
    ).exists()
    return HttpResponse(status=204 if authorized else 404)


def record(request):
    token, user = _get_token_user(request)
    if not token or not user or not _get_active_token_device(token, user):
        _log_event(request, "api_record_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid device token"}, status=401)
    record_type = request.GET.get("type", "")
    filename = _safe_record_name(request.GET.get("file", ""))
    if not filename:
        _log_event(request, "api_record_invalid_file", level="warning")
        return JsonResponse({"error": "Invalid file"}, status=400)
    content_length = _request_content_length(request)
    max_chunk = settings.RECORD_UPLOAD_MAX_CHUNK_BYTES
    if content_length < 0 or content_length > max_chunk:
        return JsonResponse({"error": "Upload chunk is too large"}, status=413)
    try:
        base_dir = _ensure_record_device_dir(token)
    except OSError:
        _log_event(
            request,
            "api_record_storage_error",
            level="error",
            username=user.username,
            rid=token.device.rid,
        )
        return JsonResponse({"error": "Recording storage failed"}, status=500)
    filepath = os.path.join(base_dir, filename)
    if record_type == "new":
        if content_length != 0:
            return JsonResponse({"error": "New recording body must be empty"}, status=400)
        try:
            with _record_file_lock(base_dir, filename):
                fd = _open_record_file(filepath, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                _fsync_directory(base_dir)
        except BlockingIOError:
            return JsonResponse({"error": "Recording is busy"}, status=423)
        except FileExistsError:
            return JsonResponse({"error": "Recording already exists"}, status=409)
        except OSError:
            _log_event(request, "api_record_storage_error", level="error", username=user.username, rid=token.device.rid)
            return JsonResponse({"error": "Recording storage failed"}, status=500)
        _log_event(request, "api_record_new", level="info", username=user.username, rid=token.device.rid, file=filename)
        return HttpResponse("")
    if record_type in ("part", "tail"):
        try:
            offset = int(request.GET.get("offset", "0"))
            declared_length = int(request.GET.get("length", "-1"))
        except (TypeError, ValueError):
            return JsonResponse({"error": "Invalid upload range"}, status=400)
        if offset < 0 or declared_length != content_length:
            return JsonResponse({"error": "Invalid upload range"}, status=400)
        data = request.body or b""
        if len(data) != content_length:
            return JsonResponse({"error": "Incomplete upload body"}, status=400)
        if record_type == "tail" and offset != 0:
            return JsonResponse({"error": "Invalid tail offset"}, status=400)
        try:
            with _record_file_lock(base_dir, filename):
                fd = _open_record_file(filepath, os.O_RDWR)
                try:
                    current_size = os.fstat(fd).st_size
                    if record_type == "part":
                        if offset != current_size:
                            return JsonResponse({"error": "Upload offset conflict"}, status=409)
                        if current_size + len(data) > settings.RECORD_UPLOAD_MAX_FILE_BYTES:
                            return JsonResponse({"error": "Recording is too large"}, status=413)
                    os.lseek(fd, offset, os.SEEK_SET)
                    _write_all(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except BlockingIOError:
            return JsonResponse({"error": "Recording is busy"}, status=423)
        except FileNotFoundError:
            return JsonResponse({"error": "Recording does not exist"}, status=404)
        except OSError:
            _log_event(request, "api_record_storage_error", level="error", username=user.username, rid=token.device.rid)
            return JsonResponse({"error": "Recording storage failed"}, status=500)
        _log_event(
            request,
            "api_record_write",
            level="debug",
            username=user.username,
            rid=token.device.rid,
            file=filename,
            offset=offset,
            size=len(data),
        )
        return HttpResponse("")
    if record_type == "remove":
        if content_length != 0:
            return JsonResponse({"error": "Remove recording body must be empty"}, status=400)
        try:
            with _record_file_lock(base_dir, filename):
                file_stat = os.lstat(filepath)
                if not stat.S_ISREG(file_stat.st_mode):
                    return JsonResponse({"error": "Invalid recording path"}, status=400)
                os.unlink(filepath)
                _fsync_directory(base_dir)
        except BlockingIOError:
            return JsonResponse({"error": "Recording is busy"}, status=423)
        except FileNotFoundError:
            pass
        except OSError:
            _log_event(request, "api_record_storage_error", level="error", username=user.username, rid=token.device.rid)
            return JsonResponse({"error": "Recording storage failed"}, status=500)
        _log_event(
            request, "api_record_remove", level="info", username=user.username, rid=token.device.rid, file=filename
        )
        return HttpResponse("")
    return JsonResponse({"error": "Invalid type"}, status=400)


def audit_with_type(request, typ):
    _log_event(request, "api_audit_dispatch", level="debug", typ=typ)
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


def audit_note(request):
    token, user = _get_token_user(request)
    if not token or not user or not _get_active_token_device(token, user):
        _log_event(request, "api_audit_note_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json_object(request)
    guid = postdata.get("guid", "")
    note = postdata.get("note", "")
    if not isinstance(guid, str) or not isinstance(note, str):
        _log_event(request, "api_audit_note_invalid_guid", level="warning")
        return JsonResponse({"error": "Invalid audit note"}, status=400)
    try:
        parsed_guid = uuid.UUID(guid)
    except (ValueError, AttributeError):
        return JsonResponse({"error": "Invalid audit note"}, status=400)
    if len(note.encode()) > MAX_AUDIT_NOTE_BYTES:
        return JsonResponse({"error": "Audit note is too large"}, status=413)
    updated = ConnLog.objects.filter(
        guid=parsed_guid,
        actor=user,
        from_id=token.device.rid,
    ).update(note=note)
    if updated != 1:
        _log_event(request, "api_audit_note_denied", level="warning", username=user.username, guid=guid)
        return JsonResponse({"error": "Connection audit not found"}, status=404)
    _log_event(request, "api_audit_note_update", username=user.username, guid=guid)
    return JsonResponse({"code": 1, "data": "ok"})


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
        info = p.info
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
        for p in AddressBookProfile.objects.all():
            add_profile(p, 3)
    else:
        for p in AddressBookProfile.objects.filter(Q(owner=user)):
            add_profile(p, 3)
        for share in AddressBookShare.objects.filter(Q(user=user)).select_related("profile", "profile__owner"):
            add_profile(share.profile, share.rule)
        group_ids = list(user.groups.values_list("id", flat=True))
        rules_qs = AddressBookRule.objects.filter(Q(is_everyone=True))
        if group_ids:
            rules_qs = rules_qs | AddressBookRule.objects.filter(Q(group_id__in=group_ids))
        rules_qs = rules_qs | AddressBookRule.objects.filter(Q(user=user))
        for r in rules_qs.select_related("profile", "profile__owner"):
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


def ab_shared_add(request):
    _token, user = _get_token_user(request)
    if not user:
        _log_event(request, "api_ab_shared_add_unauthorized", level="warning")
        return JsonResponse({"error": "Invalid token"}, status=401)
    postdata = _load_json_object(request)
    name = str(postdata.get("name", "")).strip()
    note = postdata.get("note", "")
    info = postdata.get("info", None)
    if not name or len(name) > 60 or _bounded_text_value(note, 4096) is None:
        _log_event(request, "api_ab_shared_add_failed", level="warning", username=user.username, reason="missing_name")
        return JsonResponse({"error": "Invalid name"}, status=400)
    if _is_reserved_ab_profile_name(name):
        return JsonResponse({"error": "Reserved name"}, status=400)
    profile = _get_or_create_profile(user, name)
    profile.note = note
    if info is not None:
        info = _json_value(
            info,
            expected_type=(dict, list),
            max_bytes=16 * 1024,
        )
        if info is None:
            return JsonResponse({"error": "Invalid info"}, status=400)
        profile.info = info
    profile.save()
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
    if "info" in postdata and postdata.get("info") is not None:
        info = _json_value(
            postdata.get("info"),
            expected_type=(dict, list),
            max_bytes=16 * 1024,
        )
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
        profile = AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
        profile.name = profile_values["name"]
        profile.note = profile_values["note"]
        profile.info = profile_values["info"]
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
    candidates = AddressBookProfile.objects.filter(guid__in=[str(x) for x in postdata])
    if not user.is_admin:
        candidates = candidates.filter(owner=user)
    candidates = candidates.exclude(guid__startswith="personal-")
    guids = list(candidates.values_list("guid", flat=True))
    with transaction.atomic():
        candidates.delete()
        deleted = len(guids)
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
        if user_name:
            target_user = _user_by_identifier(user_name, active_only=True)
            if not target_user:
                return JsonResponse({"error": "User not found"}, status=404)
            if target_user.id == profile.owner_id:
                return JsonResponse({"error": "Owner already has full access"}, status=400)
            share, created = AddressBookShare.objects.update_or_create(
                profile=profile,
                user=target_user,
                defaults={"rule": rule_value},
            )
            _audit_ab_rule(
                profile,
                user,
                "share_add" if created else "share_update",
                "user",
                target_user.username,
                rule_value,
                {"guid": str(share.guid)},
            )
            _log_event(
                request,
                "api_ab_rule_add",
                username=user.username,
                guid=guid,
                rule=rule_value,
                user=target_user.username,
            )
            return JsonResponse({"guid": share.guid, "rule": share.rule})
        if group_name:
            group = Group.objects.filter(Q(name=group_name)).first()
            if not group:
                return JsonResponse({"error": "Group not found"}, status=404)
            rule_obj, created = AddressBookRule.objects.update_or_create(
                profile=profile,
                target_key=f"group:{group.id}",
                defaults={
                    "group": group,
                    "user": None,
                    "rule": rule_value,
                    "is_everyone": False,
                },
            )
            _audit_ab_rule(
                profile,
                user,
                "rule_add" if created else "rule_update",
                "group",
                group.name,
                rule_value,
                {"guid": str(rule_obj.guid)},
            )
            _log_event(request, "api_ab_rule_add", username=user.username, guid=guid, rule=rule_value, group=group.name)
            return JsonResponse({"guid": rule_obj.guid, "rule": rule_obj.rule})
        rule_obj, created = AddressBookRule.objects.update_or_create(
            profile=profile,
            target_key="everyone",
            defaults={
                "group": None,
                "user": None,
                "rule": rule_value,
                "is_everyone": True,
            },
        )
        _audit_ab_rule(
            profile,
            user,
            "rule_add" if created else "rule_update",
            "everyone",
            "Everyone",
            rule_value,
            {"guid": str(rule_obj.guid)},
        )
        _log_event(request, "api_ab_rule_add", username=user.username, guid=guid, rule=rule_value, target="everyone")
        return JsonResponse({"guid": rule_obj.guid, "rule": rule_obj.rule})
    else:
        rule_guid = postdata.get("guid", "")
        rule_value = _valid_ab_rule(postdata.get("rule", 1))
        if rule_value is None:
            return JsonResponse({"error": "Invalid rule"}, status=400)
        if not rule_guid:
            return JsonResponse({"error": "Invalid guid"}, status=400)
        share = AddressBookShare.objects.filter(Q(guid=rule_guid)).select_related("profile").first()
        if share:
            profile = share.profile
            if not user.is_admin and str(profile.owner_id) != str(user.id):
                return JsonResponse({"error": "No access"}, status=403)
            share.rule = rule_value
            share.save()
            target_name = share.user.username if share.user else ""
            _audit_ab_rule(profile, user, "share_update", "user", target_name, rule_value, {"guid": str(share.guid)})
            _log_event(request, "api_ab_rule_update", username=user.username, guid=rule_guid, rule=rule_value)
            return JsonResponse({"code": 1})
        rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related("profile").first()
        if not rule_obj:
            return JsonResponse({"error": "Not found"}, status=404)
        profile = rule_obj.profile
        if not user.is_admin and str(profile.owner_id) != str(user.id):
            return JsonResponse({"error": "No access"}, status=403)
        rule_obj.rule = rule_value
        rule_obj.save()
        if rule_obj.is_everyone:
            target_type = "everyone"
            target_name = "Everyone"
        elif rule_obj.group_id:
            target_type = "group"
            target_name = rule_obj.group.name if rule_obj.group else ""
        else:
            target_type = "user"
            target_name = rule_obj.user.username if rule_obj.user else ""
        _audit_ab_rule(profile, user, "rule_update", target_type, target_name, rule_value, {"guid": str(rule_obj.guid)})
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
            if user.is_admin or str(profile.owner_id) == str(user.id):
                target_name = share.user.username if share.user else ""
                _audit_ab_rule(
                    profile, user, "share_delete", "user", target_name, share.rule, {"guid": str(share.guid)}
                )
                share.delete()
                deleted += 1
            continue
        rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related("profile").first()
        if rule_obj:
            profile = rule_obj.profile
            if user.is_admin or str(profile.owner_id) == str(user.id):
                if rule_obj.is_everyone:
                    target_type = "everyone"
                    target_name = "Everyone"
                elif rule_obj.group_id:
                    target_type = "group"
                    target_name = rule_obj.group.name if rule_obj.group else ""
                else:
                    target_type = "user"
                    target_name = rule_obj.user.username if rule_obj.user else ""
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
            AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
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
    peer = RemotePeer.objects.filter(profile=profile, rid=rid).first()
    if not peer:
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
    try:
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
        AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
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


def _audit_conn_active(request):
    token, user = _get_token_user(request)
    if not token or not user or not _get_active_token_device(token, user):
        _log_event(request, "api_audit_conn_active_unauthorized", level="warning")
        return JsonResponse("", safe=False, status=401)
    peer_id = _audit_rid(request.GET.get("id", ""))
    session_id = _audit_session_id(request.GET.get("session_id", ""))
    conn_type = _audit_enum(request.GET.get("conn_type", 0), range(5))
    if peer_id is None or session_id is None or conn_type is None:
        _log_event(request, "api_audit_conn_active_failed", level="warning", reason="missing_id")
        return JsonResponse("", safe=False, status=400)
    with transaction.atomic():
        connection_log = (
            ConnLog.objects.select_for_update()
            .filter(
                rid=peer_id,
                session_id=session_id,
                from_id=token.device.rid,
            )
            .first()
        )
        if not connection_log:
            # The host posts the controller identity after the initial
            # connection record. An empty 200 keeps the client's bounded retry
            # loop alive without exposing another user's audit GUID.
            return JsonResponse("", safe=False)
        if connection_log.actor_id and connection_log.actor_id != user.id:
            return JsonResponse("", safe=False, status=403)
        update_fields = []
        if connection_log.actor_id is None:
            connection_log.actor = user
            update_fields.append("actor")
        if connection_log.conn_type is None:
            connection_log.conn_type = conn_type
            update_fields.append("conn_type")
        elif connection_log.conn_type != conn_type:
            return JsonResponse("", safe=False, status=409)
        if update_fields:
            connection_log.save(update_fields=update_fields)
    _log_event(
        request,
        "api_audit_conn_active",
        level="debug",
        username=user.username,
        peer_id=peer_id,
        session_id=session_id,
        conn_type=conn_type,
    )
    return JsonResponse(str(connection_log.guid), safe=False)


def _audit_controller_note(request, postdata):
    token, user = _get_token_user(request)
    if not token or not user or not _get_active_token_device(token, user):
        return JsonResponse({"error": "Invalid token"}, status=401)
    peer_id = _audit_rid(postdata.get("id"))
    session_id = _audit_session_id(postdata.get("session_id"))
    note = postdata.get("note")
    if peer_id is None or session_id is None or not isinstance(note, str) or len(note.encode()) > MAX_AUDIT_NOTE_BYTES:
        return JsonResponse({"error": "Invalid audit note"}, status=400)
    with transaction.atomic():
        connection_log = (
            ConnLog.objects.select_for_update()
            .filter(
                rid=peer_id,
                session_id=session_id,
                from_id=token.device.rid,
            )
            .first()
        )
        if not connection_log:
            return JsonResponse({"error": "Connection audit not found"}, status=404)
        if connection_log.actor_id and connection_log.actor_id != user.id:
            return JsonResponse({"error": "Connection audit not found"}, status=404)
        connection_log.actor = connection_log.actor or user
        connection_log.note = note
        connection_log.save(update_fields=["actor", "note"])
    _log_event(request, "api_audit_note_update", username=user.username, guid=connection_log.guid)
    return JsonResponse({"code": 1, "data": "ok"})


def _audit_conn(request):
    postdata = _load_json_object(request)
    if "note" in postdata and "uuid" not in postdata:
        return _audit_controller_note(request, postdata)
    token, user, error = _audit_device_context(request, postdata)
    if error:
        return error
    action = postdata.get("action", "")
    conn_id = _audit_connection_id(postdata.get("conn_id"))
    peer_id = token.device.rid
    session_id = _audit_session_id(postdata.get("session_id"))
    if conn_id is None or session_id is None:
        return JsonResponse({"error": "Invalid connection identity"}, status=400)
    scoped_logs = ConnLog.objects.filter(
        conn_id=conn_id,
        rid=token.device.rid,
        uuid=token.device.uuid,
        session_id=session_id,
    )
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
        try:
            with transaction.atomic():
                connection_log, created = ConnLog.objects.get_or_create(
                    rid=peer_id,
                    session_id=session_id,
                    uuid=token.device.uuid,
                    defaults={
                        "conn_id": conn_id,
                        "from_ip": source_ip,
                        "from_id": "",
                        "conn_type": conn_type,
                        "audit_ref": audit_ref,
                        "reporter": user,
                    },
                )
                if not created and (
                    connection_log.conn_id != conn_id
                    or connection_log.from_ip != source_ip
                    or connection_log.reporter_id != user.id
                ):
                    return JsonResponse(
                        {"error": "Connection session conflict"},
                        status=409,
                    )
        except IntegrityError:
            return JsonResponse({"error": "Connection session conflict"}, status=409)
        _log_event(
            request,
            "api_audit_conn_new",
            level="info",
            username=user.username,
            conn_id=conn_id,
            peer_id=peer_id,
            session_id=session_id,
            conn_type=conn_type,
        )
    elif action == "close":
        with transaction.atomic():
            connection_log = scoped_logs.select_for_update().first()
            if not connection_log:
                return JsonResponse({"error": "Connection not found"}, status=404)
            if connection_log.conn_end is None:
                connection_log.conn_end = timezone.now()
                connection_log.save(update_fields=["conn_end"])
        _log_event(
            request,
            "api_audit_conn_close",
            level="info",
            username=user.username,
            conn_id=conn_id,
            peer_id=peer_id,
            session_id=session_id,
        )
    else:
        if action not in ("", "update"):
            return JsonResponse({"error": "Invalid action"}, status=400)
        updates = {}
        if "peer" in postdata:
            peer = postdata.get("peer", [])
            if not isinstance(peer, (list, tuple)) or len(peer) != 2:
                return JsonResponse({"error": "Invalid peer identity"}, status=400)
            from_id = _audit_rid(peer[0])
            if from_id is None:
                return JsonResponse({"error": "Invalid peer identity"}, status=400)
            updates["from_id"] = from_id
        if "type" in postdata:
            update_type = _audit_enum(postdata.get("type"), range(5))
            if update_type is None:
                return JsonResponse({"error": "Invalid connection type"}, status=400)
            updates["conn_type"] = update_type
        if "primary_auth" in postdata:
            primary_auth = _audit_enum(postdata.get("primary_auth"), range(1, 5))
            if primary_auth is None:
                return JsonResponse({"error": "Invalid primary authentication"}, status=400)
            updates["primary_auth"] = primary_auth
        if "two_factor" in postdata:
            two_factor = _audit_enum(postdata.get("two_factor"), range(1, 3))
            if two_factor is None:
                return JsonResponse({"error": "Invalid second factor"}, status=400)
            updates["two_factor"] = two_factor
        if "conn_audit_ref" in postdata:
            audit_ref = _bounded_audit_text(postdata.get("conn_audit_ref"), 256)
            if audit_ref is None:
                return JsonResponse({"error": "Invalid audit reference"}, status=400)
            updates["audit_ref"] = audit_ref
        if "note" in postdata:
            note = _bounded_audit_text(postdata.get("note"), MAX_AUDIT_NOTE_BYTES)
            if note is None:
                return JsonResponse({"error": "Invalid audit note"}, status=400)
            updates["note"] = note
        updated = scoped_logs.update(**updates) if updates else int(scoped_logs.exists())
        if updated != 1:
            return JsonResponse({"error": "Connection not found"}, status=404)
        _log_event(
            request,
            "api_audit_conn_update",
            level="debug",
            username=user.username,
            conn_id=conn_id,
            peer_id=peer_id,
            session_id=session_id,
        )
    return JsonResponse({"code": 1, "data": "ok"})


def _audit_file(request):
    postdata = _load_json_object(request)
    token, user, error = _audit_device_context(request, postdata)
    if error:
        return error
    if "is_file" not in postdata:
        return JsonResponse({"code": 1, "data": "ok"})
    info = postdata.get("info", "{}")
    if isinstance(info, str) and len(info.encode()) > MAX_AUDIT_INFO_BYTES:
        return JsonResponse({"error": "Audit information is too large"}, status=413)
    try:
        info_obj = json.loads(info) if isinstance(info, str) else info
    except (TypeError, ValueError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid audit information"}, status=400)
    if not isinstance(info_obj, dict):
        return JsonResponse({"error": "Invalid audit information"}, status=400)
    files = info_obj.get("files", [])
    total_size = 0
    if files:
        if not isinstance(files, list) or len(files) > MAX_AUDIT_FILES:
            return JsonResponse({"error": "Invalid audit files"}, status=400)
        for item in files:
            if not isinstance(item, (list, tuple)) or len(item) < 2:
                return JsonResponse({"error": "Invalid audit files"}, status=400)
            try:
                size = int(item[1])
            except (TypeError, ValueError):
                return JsonResponse({"error": "Invalid audit files"}, status=400)
            if size < 0 or size > settings.RECORD_UPLOAD_MAX_FILE_BYTES:
                return JsonResponse({"error": "Invalid audit files"}, status=400)
            total_size += size
    path = _bounded_audit_text(postdata.get("path", ""), 500)
    user_ip = _audit_ip(info_obj.get("ip", ""))
    remote_id = _audit_rid(postdata.get("peer_id", ""))
    direction = _audit_enum(postdata.get("type", 0), (0, 1))
    if path is None or user_ip is None or remote_id is None or direction is None:
        return JsonResponse({"error": "Invalid file audit"}, status=400)
    FileLog.objects.create(
        file=path,
        user_id=remote_id,
        user_ip=user_ip,
        remote_id=token.device.rid,
        filesize=total_size,
        direction=direction,
        logged_at=timezone.now(),
        details=info_obj,
        reporter=user,
        reporter_device_uuid=token.device.uuid,
    )
    _log_event(
        request,
        "api_audit_file",
        level="info",
        username=user.username,
        peer_id=remote_id,
        remote_id=token.device.rid,
        direction=direction,
        filesize=total_size,
    )
    return JsonResponse({"code": 1, "data": "ok"})


def _audit_alarm(request):
    postdata = _load_json_object(request)
    token, user, error = _audit_device_context(request, postdata)
    if error:
        return error
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
    conn_id_value = postdata.get("conn_id")
    conn_id = None if conn_id_value is None else _audit_connection_id(conn_id_value)
    if conn_id_value is not None and conn_id is None:
        return JsonResponse({"error": "Invalid connection identity"}, status=400)
    audit_ref = _bounded_audit_text(postdata.get("conn_audit_ref", ""), 256)
    if audit_ref is None:
        return JsonResponse({"error": "Invalid audit reference"}, status=400)
    AlarmLog.objects.create(
        typ=typ,
        info=info,
        reporter=user,
        reporter_device_id=token.device.rid,
        reporter_device_uuid=token.device.uuid,
        conn_id=conn_id,
        audit_ref=audit_ref,
    )
    _log_event(request, "api_audit_alarm", level="warning", username=user.username, typ=typ)
    return JsonResponse({"code": 1, "data": "ok"})


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
    target = _user_by_guid(guid)
    if not target:
        return JsonResponse({"error": "User not found"}, status=404)
    if target.id == admin_user.id and action == "disable":
        return JsonResponse({"error": "Cannot disable current user"}, status=400)
    target.is_active = action == "enable"
    target.save(update_fields=["is_active"])
    if not target.is_active:
        RemoteToken.objects.filter(device__owner=target).delete()
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
        RemoteToken.objects.filter(device__owner=target).delete()
        RemoteDevice.objects.filter(owner=target).update(
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
    deleted = RemoteToken.objects.filter(
        device__owner_id__in=guids,
    ).delete()[0]
    _log_event(request, "api_users_force_logout", username=admin_user.username, deleted=deleted)
    return JsonResponse({"result": "OK", "deleted": deleted})


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
    device = _device_by_guid(guid)
    if not device:
        return JsonResponse({"error": "Device not found"}, status=404)
    device.is_active = action == "enable"
    device.save(update_fields=["is_active", "update_time"])
    if not device.is_active:
        _revoke_device_tokens(device)
    _log_event(request, f"api_device_{action}", username=admin_user.username, rid=device.rid)
    return JsonResponse(_serialize_device(device))


def device_delete(request, guid):
    admin_user, error = _require_admin(request, "api_device_delete")
    if error:
        return error
    device = _device_by_guid(guid)
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
    with transaction.atomic():
        device = (
            RemoteDevice.objects.select_for_update(of=("self",)).select_related("owner").filter(pk=device_pk).first()
            if device_pk is not None
            else None
        )
        if not device:
            return JsonResponse({"error": "Device not found"}, status=404)
        if typ == "user_name":
            owner = _user_by_identifier(value, active_only=True)
            if not owner:
                return JsonResponse({"error": "Active user not found"}, status=404)
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
