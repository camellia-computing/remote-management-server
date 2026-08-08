import datetime
import hashlib
import ipaddress
from dataclasses import dataclass

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.utils import timezone

from api.models import LoginAdmissionLock, LoginAttempt
from api.username_identity import canonical_username

LOGIN_SCOPE = "login"
REGISTER_SCOPE = "register"
_MAX_SCOPE_TEXT = 150
_LOCK_ROW_REPLACED = object()


@dataclass(frozen=True, slots=True)
class LoginAdmission:
    attempt_id: int
    ip: str
    scope_hash: str


def _canonical_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return "0.0.0.0"  # noqa: S104 - non-routable rate-limit sentinel, not a bind address


def _bounded_scope_text(value):
    try:
        return canonical_username(value)[:_MAX_SCOPE_TEXT]
    except ValueError:
        value = value if isinstance(value, str) else str(value)
        return value.casefold()[:_MAX_SCOPE_TEXT]


def scope_hash(scope, username):
    if scope not in (LOGIN_SCOPE, REGISTER_SCOPE):
        raise ValueError("unsupported login admission scope")
    text = _bounded_scope_text(username)
    return hashlib.sha256(f"{scope}\0{text}".encode()).hexdigest()


def _audit_username(scope, username):
    text = _bounded_scope_text(username)
    if scope == REGISTER_SCOPE:
        text = f"register:{text}"
    return text[:150]


def _lock_ip_row(ip):
    try:
        LoginAdmissionLock.objects.bulk_create(
            [LoginAdmissionLock(ip=ip)],
            ignore_conflicts=True,
        )
        return LoginAdmissionLock.objects.select_for_update().get(ip=ip)
    except LoginAdmissionLock.DoesNotExist:
        return _LOCK_ROW_REPLACED
    except IntegrityError:
        return _LOCK_ROW_REPLACED


def _reserve_once(ip, scope, username):
    now = timezone.now()
    cutoff = now - datetime.timedelta(minutes=settings.LOGIN_ATTEMPT_RETENTION_MINUTES)
    hashed_scope = scope_hash(scope, username)
    with transaction.atomic():
        lock = _lock_ip_row(ip)
        if lock is _LOCK_ROW_REPLACED:
            return _LOCK_ROW_REPLACED
        LoginAttempt.objects.filter(ip=ip, created_at__lt=cutoff).delete()
        attempts = LoginAttempt.objects.filter(ip=ip, created_at__gte=cutoff)
        counts = attempts.aggregate(
            ip_count=Count("pk"),
            scope_count=Count("pk", filter=Q(scope_hash=hashed_scope)),
        )
        if counts["ip_count"] >= 100 or counts["scope_count"] >= 10:
            lock.updated_at = now
            lock.save(update_fields=["updated_at"])
            return None
        attempt = LoginAttempt.objects.create(
            ip=ip,
            username=_audit_username(scope, username),
            scope_hash=hashed_scope,
        )
        lock.updated_at = now
        lock.save(update_fields=["updated_at"])
        return LoginAdmission(attempt.id, ip, hashed_scope)


def reserve_login_attempt(ip, username, scope=LOGIN_SCOPE):
    canonical_ip = _canonical_ip(ip)
    for _ in range(3):
        admission = _reserve_once(canonical_ip, scope, username)
        if admission is not _LOCK_ROW_REPLACED:
            return admission
    raise RuntimeError("login admission lock row was replaced repeatedly")


def complete_login_success(admission):
    for _ in range(3):
        with transaction.atomic():
            lock = _lock_ip_row(admission.ip)
            if lock is _LOCK_ROW_REPLACED:
                continue
            # A later admission has a larger primary key. Clear only this
            # request and earlier failures, preserving concurrent later work.
            LoginAttempt.objects.filter(
                ip=admission.ip,
                scope_hash=admission.scope_hash,
                pk__lte=admission.attempt_id,
            ).delete()
            lock.updated_at = timezone.now()
            lock.save(update_fields=["updated_at"])
            return
    raise RuntimeError("login admission lock row was replaced repeatedly")
