"""Bounded, privacy-preserving request admission for the Management plane."""

import dataclasses
import datetime
import hashlib
import heapq
import ipaddress
import logging
import math
import re
import secrets
import threading
import time
from contextlib import nullcontext

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Count
from django.http import JsonResponse
from django.utils import timezone

from api.models import RequestRateBucket, RequestRateLease
from api.request_utils import client_ip
from camellia_remote_management.access_logging import REQUEST_ID_ENV, normalized_route

logger = logging.getLogger(__name__)

_LABEL_RE = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z", re.ASCII)
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_HASH_DOMAIN = b"camellia-management-rate-v1\0"
_WINDOW_SECONDS = 60
_BYTE_UNIT = 64 * 1024
_EXEMPT_PATHS = frozenset(("/health/live", "/health/ready"))


@dataclasses.dataclass(frozen=True)
class Admission:
    allowed: bool
    overloaded: bool = False
    scope: str = ""
    group: str = ""
    retry_after: int = 0
    limit: int = 0


@dataclasses.dataclass(frozen=True)
class Budget:
    scope: str
    group: str
    identity: str
    limit: int
    window_seconds: int = _WINDOW_SECONDS
    cost: int = 1

    def __post_init__(self):
        if not _LABEL_RE.fullmatch(self.scope) or not _LABEL_RE.fullmatch(self.group):
            raise ValueError("rate-limit scope and group must be bounded labels")
        if not isinstance(self.identity, str) or not self.identity or len(self.identity.encode()) > 1024:
            raise ValueError("rate-limit identity must be a bounded non-empty string")
        if not isinstance(self.limit, int) or self.limit < 1:
            raise ValueError("rate-limit limit must be positive")
        if not isinstance(self.window_seconds, int) or not 1 <= self.window_seconds <= 3600:
            raise ValueError("rate-limit window must be between 1 and 3600 seconds")
        if not isinstance(self.cost, int) or self.cost < 0:
            raise ValueError("rate-limit cost cannot be negative")

    @property
    def key_hash(self):
        material = f"{self.scope}\0{self.group}\0{self.identity}".encode()
        return hashlib.sha256(_HASH_DOMAIN + material).hexdigest()


@dataclasses.dataclass(frozen=True)
class ConcurrencyBudget:
    scope: str
    group: str
    identity: str
    limit: int

    def __post_init__(self):
        if not _LABEL_RE.fullmatch(self.scope) or not _LABEL_RE.fullmatch(self.group):
            raise ValueError("concurrency scope and group must be bounded labels")
        if not isinstance(self.identity, str) or not self.identity or len(self.identity.encode()) > 1024:
            raise ValueError("concurrency identity must be a bounded non-empty string")
        if not isinstance(self.limit, int) or self.limit < 1:
            raise ValueError("concurrency limit must be positive")

    @property
    def key_hash(self):
        material = f"concurrency\0{self.scope}\0{self.group}\0{self.identity}".encode()
        return hashlib.sha256(_HASH_DOMAIN + material).hexdigest()


class RateLimitRejected(RuntimeError):
    def __init__(self, admission):
        self.admission = admission
        super().__init__("request rate limit exceeded")


class RateLimitBackendUnavailable(RuntimeError):
    pass


class LocalWindowLimiter:
    """A fixed-capacity monotonic ingress guard that never stores raw keys."""

    def __init__(self, *, capacity, clock=time.monotonic):
        if not isinstance(capacity, int) or capacity < 1:
            raise ValueError("local rate-limit capacity must be positive")
        self.capacity = capacity
        self._clock = clock
        self._entries = {}
        self._expirations = []
        self._generation = 0
        self._lock = threading.Lock()

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._expirations.clear()

    def _prune(self, now):
        while self._expirations and self._expirations[0][0] <= now:
            expires_at, generation, key_hash = heapq.heappop(self._expirations)
            current = self._entries.get(key_hash)
            if current and current[2] == expires_at and current[3] == generation:
                del self._entries[key_hash]

    def reserve(self, budgets):
        budgets = _merge_budgets(tuple(budgets))
        if not budgets:
            return Admission(True)
        now = self._clock()
        with self._lock:
            self._prune(now)
            projected = []
            new_keys = 0
            for budget in budgets:
                key_hash = budget.key_hash
                current = self._entries.get(key_hash)
                if current is None or current[2] <= now:
                    used = 0
                    expires_at = now + budget.window_seconds
                    generation = None
                    new_keys += 1
                else:
                    used, window_seconds, expires_at, generation = current
                    if window_seconds != budget.window_seconds:
                        used = 0
                        expires_at = now + budget.window_seconds
                        generation = None
                if used + budget.cost > budget.limit:
                    return Admission(
                        False,
                        scope=budget.scope,
                        group=budget.group,
                        retry_after=max(1, min(budget.window_seconds, math.ceil(expires_at - now))),
                        limit=budget.limit,
                    )
                projected.append((budget, key_hash, used + budget.cost, expires_at, generation))
            if len(self._entries) + new_keys > self.capacity:
                return Admission(False, overloaded=True, scope="local", group="capacity", retry_after=1)
            for budget, key_hash, used, expires_at, generation in projected:
                if generation is None:
                    self._generation += 1
                    generation = self._generation
                    heapq.heappush(self._expirations, (expires_at, generation, key_hash))
                self._entries[key_hash] = (used, budget.window_seconds, expires_at, generation)
        return Admission(True)


def _merge_budgets(budgets):
    merged = {}
    order = []
    for budget in budgets:
        key_hash = budget.key_hash
        current = merged.get(key_hash)
        if current is None:
            merged[key_hash] = budget
            order.append(key_hash)
            continue
        if (
            current.scope,
            current.group,
            current.identity,
            current.limit,
            current.window_seconds,
        ) != (
            budget.scope,
            budget.group,
            budget.identity,
            budget.limit,
            budget.window_seconds,
        ):
            raise ValueError("one rate key cannot have conflicting policies")
        merged[key_hash] = dataclasses.replace(current, cost=current.cost + budget.cost)
    return tuple(merged[key_hash] for key_hash in order)


def _merge_concurrency_budgets(budgets):
    merged = {}
    order = []
    for budget in budgets:
        key_hash = budget.key_hash
        current = merged.get(key_hash)
        if current is None:
            merged[key_hash] = budget
            order.append(key_hash)
        elif current != budget:
            raise ValueError("one concurrency key cannot have conflicting policies")
    return tuple(merged[key_hash] for key_hash in order)


def _database_now():
    if connection.vendor != "postgresql":
        return timezone.now()
    with connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp()")
        return cursor.fetchone()[0]


def reserve_shared_budgets(budgets):
    """Atomically reserve every fixed-window budget or reserve none of them."""

    budgets = _merge_budgets(tuple(budgets))
    if not budgets:
        return Admission(True)
    lock_ordered_budgets = tuple(sorted(budgets, key=lambda budget: budget.key_hash))
    with transaction.atomic():
        now = _database_now()
        RequestRateBucket.objects.bulk_create(
            [
                RequestRateBucket(
                    key_hash=budget.key_hash,
                    scope=budget.scope,
                    group=budget.group,
                    window_seconds=budget.window_seconds,
                    used=0,
                    expires_at=now + datetime.timedelta(seconds=budget.window_seconds),
                )
                for budget in lock_ordered_budgets
            ],
            ignore_conflicts=True,
        )
        rows = {
            row.key_hash: row
            for row in RequestRateBucket.objects.select_for_update()
            .filter(key_hash__in=[budget.key_hash for budget in lock_ordered_budgets])
            .order_by("key_hash")
        }
        if len(rows) != len(budgets):
            missing = [budget for budget in lock_ordered_budgets if budget.key_hash not in rows]
            RequestRateBucket.objects.bulk_create(
                [
                    RequestRateBucket(
                        key_hash=budget.key_hash,
                        scope=budget.scope,
                        group=budget.group,
                        window_seconds=budget.window_seconds,
                        used=0,
                        expires_at=now + datetime.timedelta(seconds=budget.window_seconds),
                    )
                    for budget in missing
                ],
                ignore_conflicts=True,
            )
            rows.update(
                {
                    row.key_hash: row
                    for row in RequestRateBucket.objects.select_for_update()
                    .filter(key_hash__in=[budget.key_hash for budget in missing])
                    .order_by("key_hash")
                }
            )
            if len(rows) != len(budgets):
                raise RateLimitBackendUnavailable("rate-limit bucket initialization was incomplete")
        projected = []
        for budget in budgets:
            row = rows[budget.key_hash]
            if row.expires_at <= now or row.window_seconds != budget.window_seconds:
                used = 0
                expires_at = now + datetime.timedelta(seconds=budget.window_seconds)
            else:
                used = row.used
                expires_at = row.expires_at
            if used + budget.cost > budget.limit:
                retry_after = math.ceil((expires_at - now).total_seconds())
                return Admission(
                    False,
                    scope=budget.scope,
                    group=budget.group,
                    retry_after=max(1, min(budget.window_seconds, retry_after)),
                    limit=budget.limit,
                )
            projected.append((row, budget, used + budget.cost, expires_at))
        for row, budget, used, expires_at in projected:
            row.scope = budget.scope
            row.group = budget.group
            row.window_seconds = budget.window_seconds
            row.used = used
            row.expires_at = expires_at
            row.updated_at = now
        RequestRateBucket.objects.bulk_update(
            [item[0] for item in projected],
            ("scope", "group", "window_seconds", "used", "expires_at", "updated_at"),
        )
    return Admission(True)


_concurrency_process_lock = threading.Lock()


def _advisory_lock_key(key_hash):
    value = int.from_bytes(bytes.fromhex(key_hash[:16]), "big", signed=False)
    return value - (1 << 64) if value >= (1 << 63) else value


def acquire_shared_concurrency(budgets, request_id, *, lease_seconds):
    budgets = _merge_concurrency_budgets(tuple(budgets))
    if not budgets:
        return Admission(True)
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
        raise ValueError("concurrency lease requires a server request ID")
    if not isinstance(lease_seconds, int) or not 30 <= lease_seconds <= 3600:
        raise ValueError("concurrency lease duration is out of range")

    # The process lock supplies deterministic SQLite semantics. PostgreSQL must
    # not use it: sorted advisory transaction locks are the cross-process and
    # cross-replica authority, and keeping the local lock would both serialize
    # unrelated requests and prevent tests from exercising real lock races.
    process_lock = _concurrency_process_lock if connection.vendor != "postgresql" else nullcontext()
    with process_lock, transaction.atomic():
        if connection.vendor == "postgresql":
            with connection.cursor() as cursor:
                lock_keys = sorted(_advisory_lock_key(budget.key_hash) for budget in budgets)
                placeholders = ", ".join(["(%s)"] * len(lock_keys))
                cursor.execute(
                    f"SELECT pg_advisory_xact_lock(lock_key) FROM (VALUES {placeholders}) AS locks(lock_key) "  # noqa: S608 - placeholders hold every value
                    "ORDER BY lock_key",
                    lock_keys,
                )
        now = _database_now()
        active_counts = {
            item["key_hash"]: item["total"]
            for item in RequestRateLease.objects.filter(
                key_hash__in=[budget.key_hash for budget in budgets],
                expires_at__gt=now,
            )
            .values("key_hash")
            .annotate(total=Count("pk"))
        }
        for budget in budgets:
            active = active_counts.get(budget.key_hash, 0)
            if active >= budget.limit:
                return Admission(
                    False,
                    scope=budget.scope,
                    group=budget.group,
                    retry_after=1,
                    limit=budget.limit,
                )
        expires_at = now + datetime.timedelta(seconds=lease_seconds)
        RequestRateLease.objects.bulk_create(
            [
                RequestRateLease(
                    request_id=request_id,
                    key_hash=budget.key_hash,
                    scope=budget.scope,
                    group=budget.group,
                    expires_at=expires_at,
                )
                for budget in budgets
            ]
        )
    return Admission(True)


def release_shared_concurrency(request_id):
    if isinstance(request_id, str) and _REQUEST_ID_RE.fullmatch(request_id):
        RequestRateLease.objects.filter(request_id=request_id).delete()


def source_rate_identity(value):
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        address = ipaddress.ip_address("0.0.0.0")  # noqa: S104 - non-routable rate sentinel
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    prefix = 32 if isinstance(address, ipaddress.IPv4Address) else 64
    network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    return f"{network.network_address.compressed}/{prefix}"


def _bearer_identity(request):
    authorization = request.META.get("HTTP_AUTHORIZATION", "")
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        return ""
    raw_token = authorization[7:].strip()
    if not raw_token or len(raw_token) > 1024 or any(character.isspace() for character in raw_token):
        return ""
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _session_actor_identity(request):
    user = getattr(request, "user", None)
    if not user or not getattr(user, "is_authenticated", False):
        return ""
    return f"{user.pk}:{getattr(user, 'credential_generation', 0)}"


def _policy_defaults():
    global_limit = settings.REQUEST_RATE_LIMIT_GLOBAL_REQUESTS_PER_MINUTE
    source_limit = settings.REQUEST_RATE_LIMIT_SOURCE_REQUESTS_PER_MINUTE
    credential_limit = settings.REQUEST_RATE_LIMIT_CREDENTIAL_REQUESTS_PER_MINUTE
    record_units = math.ceil(settings.REQUEST_RATE_LIMIT_RECORD_BYTES_PER_MINUTE / _BYTE_UNIT)
    return {
        "authentication": {
            "global": min(global_limit, 600),
            "source": min(source_limit, 30),
            "credential": min(credential_limit, 30),
            "actor": min(credential_limit, 30),
            "device": min(credential_limit, 30),
            "concurrency": 4,
        },
        "oidc_poll": {
            "global": min(global_limit, 3_000),
            "source": min(source_limit, 300),
            "credential": min(credential_limit, 300),
            "actor": min(credential_limit, 300),
            "device": min(credential_limit, 300),
            "concurrency": 8,
        },
        "device": {
            "global": min(global_limit, 1_200),
            "source": min(source_limit, 120),
            "credential": min(credential_limit, 120),
            "actor": min(credential_limit, 120),
            "device": min(credential_limit, 120),
            "concurrency": 8,
        },
        "heartbeat": {
            "global": min(global_limit, 12_000),
            "source": min(source_limit, 2_400),
            "credential": min(credential_limit, 120),
            "actor": min(credential_limit, 600),
            "device": min(credential_limit, 120),
            "concurrency": 64,
        },
        "record": {
            "global": min(global_limit, 2_000),
            "source": min(source_limit, 600),
            "credential": min(credential_limit, 300),
            "actor": min(credential_limit, 600),
            "device": min(credential_limit, 300),
            "global_bytes": record_units * 8,
            "source_bytes": record_units * 2,
            "credential_bytes": record_units,
            "actor_bytes": record_units * 2,
            "device_bytes": record_units,
            "concurrency": 16,
        },
        "audit": {
            "global": min(global_limit, 6_000),
            "source": min(source_limit, 1_200),
            "credential": min(credential_limit, 240),
            "actor": min(credential_limit, 480),
            "device": min(credential_limit, 240),
            "concurrency": 32,
        },
        "export": {
            "global": min(global_limit, 300),
            "source": min(source_limit, 30),
            "credential": min(credential_limit, 10),
            "actor": min(credential_limit, 10),
            "device": min(credential_limit, 10),
            "concurrency": 4,
        },
        "mutation": {
            "global": min(global_limit, 3_000),
            "source": min(source_limit, 300),
            "credential": min(credential_limit, 120),
            "actor": min(credential_limit, 120),
            "device": min(credential_limit, 120),
            "concurrency": 16,
        },
        "read": {
            "global": min(global_limit, 6_000),
            "source": min(source_limit, 600),
            "credential": min(credential_limit, 600),
            "actor": min(credential_limit, 600),
            "device": min(credential_limit, 600),
            "concurrency": 64,
        },
        "public": {
            "global": min(global_limit, 1_200),
            "source": min(source_limit, 120),
            "credential": min(credential_limit, 120),
            "actor": min(credential_limit, 120),
            "device": min(credential_limit, 120),
            "concurrency": 16,
        },
    }


def _policy(group):
    policies = _policy_defaults()
    values = dict(policies[group])
    overrides = getattr(settings, "REQUEST_RATE_LIMIT_POLICY_OVERRIDES", {})
    override = overrides.get(group, {}) if isinstance(overrides, dict) else {}
    if not isinstance(override, dict):
        raise ValueError("rate-limit policy override must be a mapping")
    unknown = set(override) - set(values)
    if unknown:
        raise ValueError(f"unknown rate-limit policy fields: {sorted(unknown)}")
    for name, value in override.items():
        if not isinstance(value, int) or value < 1:
            raise ValueError("rate-limit policy values must be positive integers")
        values[name] = value
    return values


def _policy_group(request):
    route = normalized_route(getattr(request, "resolver_match", None))
    method = str(getattr(request, "method", "")).upper()
    if route in {
        "/api/login-options",
        "/api/login",
        "/api/oidc/auth",
        "/api/oidc/callback",
        "/api/user_action",
    } or route.startswith("/admin/login"):
        return "authentication"
    if route == "/api/oidc/auth-query":
        return "oidc_poll"
    if route in {
        "/api/devices/cli",
        "/api/devices/proof-challenge",
        "/api/devices/deploy",
        "/api/devices/verify-deployment",
    }:
        return "device"
    if route in {"/api/heartbeat", "/api/sysinfo", "/api/sysinfo_ver"}:
        return "heartbeat"
    if route == "/api/record":
        return "record"
    if route.startswith("/api/audit"):
        return "audit"
    if "export" in route or route == "/api/down_peers":
        return "export"
    if route in {
        "/api/currentUser",
        "/api/ab/settings",
        "/api/ab/personal",
        "/api/ab/shared/profiles",
        "/api/ab/shared/credential",
        "/api/ab/peers",
    }:
        return "read"
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "mutation"
    if route.startswith(("/api/", "/admin/", "/webui2/")) or route == "/":
        return "read"
    return "public"


def _content_byte_units(request):
    raw = request.META.get("CONTENT_LENGTH")
    try:
        length = int(raw)
    except (TypeError, ValueError):
        return 0
    if length <= 0:
        return 0
    return math.ceil(length / _BYTE_UNIT)


def _request_budgets(request, group, policy):
    source = source_rate_identity(client_ip(request))
    bearer = _bearer_identity(request)
    actor = _session_actor_identity(request)
    budgets = [
        Budget("global", "service", "management", settings.REQUEST_RATE_LIMIT_GLOBAL_REQUESTS_PER_MINUTE),
        Budget("global", group, "management", policy["global"]),
        Budget("source", "service", source, settings.REQUEST_RATE_LIMIT_SOURCE_REQUESTS_PER_MINUTE),
        Budget("source", group, source, policy["source"]),
    ]
    if bearer:
        budgets.extend(
            (
                Budget(
                    "credential",
                    "service",
                    bearer,
                    settings.REQUEST_RATE_LIMIT_CREDENTIAL_REQUESTS_PER_MINUTE,
                ),
                Budget("credential", group, bearer, policy["credential"]),
            )
        )
    if actor:
        budgets.extend(
            (
                Budget("actor", "service", actor, settings.REQUEST_RATE_LIMIT_CREDENTIAL_REQUESTS_PER_MINUTE),
                Budget("actor", group, actor, policy["actor"]),
            )
        )
    byte_units = _content_byte_units(request) if group == "record" else 0
    if byte_units:
        budgets.extend(
            (
                Budget("global_bytes", "record_bytes", "management", policy["global_bytes"], cost=byte_units),
                Budget("source_bytes", "record_bytes", source, policy["source_bytes"], cost=byte_units),
            )
        )
        if bearer:
            budgets.append(
                Budget(
                    "credential_bytes",
                    "record_bytes",
                    bearer,
                    policy["credential_bytes"],
                    cost=byte_units,
                )
            )
        if actor:
            budgets.append(Budget("actor_bytes", "record_bytes", actor, policy["actor_bytes"], cost=byte_units))
    return tuple(budgets)


def _request_concurrency_budgets(request, group, policy):
    source = source_rate_identity(client_ip(request))
    bearer = _bearer_identity(request)
    actor = _session_actor_identity(request)
    budgets = [
        ConcurrencyBudget("global", "service", "management", settings.REQUEST_RATE_LIMIT_GLOBAL_CONCURRENCY),
        ConcurrencyBudget(
            "global",
            group,
            "management",
            min(settings.REQUEST_RATE_LIMIT_GLOBAL_CONCURRENCY, policy["concurrency"]),
        ),
        ConcurrencyBudget("source", "service", source, settings.REQUEST_RATE_LIMIT_SOURCE_CONCURRENCY),
        ConcurrencyBudget(
            "source", group, source, min(settings.REQUEST_RATE_LIMIT_SOURCE_CONCURRENCY, policy["concurrency"])
        ),
    ]
    if bearer:
        budgets.append(
            ConcurrencyBudget(
                "credential",
                group,
                bearer,
                min(settings.REQUEST_RATE_LIMIT_CREDENTIAL_CONCURRENCY, policy["concurrency"]),
            )
        )
    if actor:
        budgets.append(
            ConcurrencyBudget(
                "actor",
                group,
                actor,
                min(settings.REQUEST_RATE_LIMIT_CREDENTIAL_CONCURRENCY, policy["concurrency"]),
            )
        )
    return tuple(budgets)


_local_config_lock = threading.Lock()
_local_limiter = None


def _get_local_limiter():
    global _local_limiter
    capacity = settings.REQUEST_RATE_LIMIT_LOCAL_CAPACITY
    with _local_config_lock:
        if _local_limiter is None or _local_limiter.capacity != capacity:
            _local_limiter = LocalWindowLimiter(capacity=capacity)
        return _local_limiter


def reset_local_rate_limit_state():
    with _local_config_lock:
        if _local_limiter is not None:
            _local_limiter.clear()


_sample_lock = threading.Lock()
_sampled_events = {}


def _sampled_log(event, *, scope, group):
    now = time.monotonic()
    key = (event, scope, group)
    with _sample_lock:
        previous = _sampled_events.get(key, 0)
        if now - previous < 60:
            return
        if len(_sampled_events) >= 128:
            _sampled_events.clear()
        _sampled_events[key] = now
    logger.warning("event=%s scope=%s group=%s", event, scope, group)


def rate_limit_response(admission):
    if admission.overloaded:
        response = JsonResponse(
            {"error": "Service admission is unavailable", "code": "rate_limit_unavailable", "retryable": True},
            status=503,
        )
        response["Retry-After"] = "1"
        response["Cache-Control"] = "no-store"
        _sampled_log("rate_limit_overloaded", scope=admission.scope or "unknown", group=admission.group or "unknown")
        return response
    retry_after = max(1, min(3600, int(admission.retry_after or 1)))
    response = JsonResponse(
        {
            "error": "Request rate limit exceeded",
            "code": "rate_limited",
            "scope": admission.scope,
            "retry_after": retry_after,
            "retryable": True,
        },
        status=429,
    )
    response["Retry-After"] = str(retry_after)
    response["Cache-Control"] = "no-store"
    if admission.limit:
        response["RateLimit-Limit"] = str(admission.limit)
    _sampled_log("rate_limited", scope=admission.scope, group=admission.group)
    return response


def rate_limit_backend_response():
    return rate_limit_response(Admission(False, overloaded=True, scope="backend", group="shared", retry_after=1))


def _request_id(request):
    value = request.META.get(REQUEST_ID_ENV, "")
    return value if isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value) else secrets.token_hex(16)


class IngressRateLimitMiddleware:
    """Reject coarse floods before URL resolution, sessions, CSRF or database work."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not settings.REQUEST_RATE_LIMIT_ENABLED:
            return self.get_response(request)
        source = source_rate_identity(client_ip(request))
        admission = _get_local_limiter().reserve(
            (
                Budget(
                    "global",
                    "ingress",
                    "management",
                    settings.REQUEST_RATE_LIMIT_GLOBAL_REQUESTS_PER_MINUTE,
                ),
                Budget(
                    "source",
                    "ingress",
                    source,
                    settings.REQUEST_RATE_LIMIT_SOURCE_REQUESTS_PER_MINUTE,
                ),
            )
        )
        if not admission.allowed:
            return rate_limit_response(admission)
        return self.get_response(request)


class RateLimitMiddleware:
    """Apply shared route budgets and release crash-bounded concurrency leases."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            return self.get_response(request)
        finally:
            request_id = getattr(request, "_camellia_rate_lease_request_id", "")
            if request_id:
                try:
                    release_shared_concurrency(request_id)
                except Exception as exc:  # noqa: BLE001 - the lease expires after a crash or backend outage
                    _sampled_log("rate_limit_lease_release_error", scope="backend", group=type(exc).__name__)

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not settings.REQUEST_RATE_LIMIT_ENABLED or request.path_info in _EXEMPT_PATHS:
            return None
        group = _policy_group(request)
        policy = _policy(group)
        request._camellia_rate_policy = (group, policy)
        request._camellia_rate_reserved_principals = set()
        try:
            admission = reserve_shared_budgets(_request_budgets(request, group, policy))
            if not admission.allowed:
                return rate_limit_response(admission)
            request_id = _request_id(request)
            admission = acquire_shared_concurrency(
                _request_concurrency_budgets(request, group, policy),
                request_id,
                lease_seconds=settings.REQUEST_RATE_LIMIT_CONCURRENCY_LEASE_SECONDS,
            )
            if not admission.allowed:
                return rate_limit_response(admission)
            request._camellia_rate_lease_request_id = request_id
            actor = _session_actor_identity(request)
            if actor:
                request._camellia_rate_reserved_principals.add(("actor", actor))
        except Exception as exc:  # noqa: BLE001 - admission backend failures fail closed
            _sampled_log("rate_limit_backend_error", scope="backend", group=type(exc).__name__)
            return rate_limit_backend_response()
        return None


def enforce_authenticated_rate_limit(request, user, device):
    """Aggregate valid bearer traffic by actor and immutable device generation."""

    policy_context = getattr(request, "_camellia_rate_policy", None)
    if not settings.REQUEST_RATE_LIMIT_ENABLED or not policy_context:
        return
    group, policy = policy_context
    actor = f"{user.pk}:{getattr(user, 'credential_generation', 0)}"
    device_identity = f"{device.pk}:{getattr(device, 'deployment_generation', 0)}"
    reserved = getattr(request, "_camellia_rate_reserved_principals", set())
    principal_keys = (("actor", actor), ("device", device_identity))
    if all(key in reserved for key in principal_keys):
        return
    budgets = []
    concurrency_budgets = []
    if ("actor", actor) not in reserved:
        budgets.extend(
            (
                Budget("actor", "service", actor, settings.REQUEST_RATE_LIMIT_CREDENTIAL_REQUESTS_PER_MINUTE),
                Budget("actor", group, actor, policy["actor"]),
            )
        )
        concurrency_budgets.append(
            ConcurrencyBudget(
                "actor",
                group,
                actor,
                min(settings.REQUEST_RATE_LIMIT_CREDENTIAL_CONCURRENCY, policy["concurrency"]),
            )
        )
    if ("device", device_identity) not in reserved:
        budgets.extend(
            (
                Budget(
                    "device",
                    "service",
                    device_identity,
                    settings.REQUEST_RATE_LIMIT_CREDENTIAL_REQUESTS_PER_MINUTE,
                ),
                Budget("device", group, device_identity, policy["device"]),
            )
        )
        concurrency_budgets.append(
            ConcurrencyBudget(
                "device",
                group,
                device_identity,
                min(settings.REQUEST_RATE_LIMIT_CREDENTIAL_CONCURRENCY, policy["concurrency"]),
            )
        )
    if group == "record":
        byte_units = _content_byte_units(request)
        if byte_units:
            if ("actor", actor) not in reserved:
                budgets.append(Budget("actor_bytes", "record_bytes", actor, policy["actor_bytes"], cost=byte_units))
            if ("device", device_identity) not in reserved:
                budgets.append(
                    Budget("device_bytes", "record_bytes", device_identity, policy["device_bytes"], cost=byte_units)
                )
    try:
        admission = reserve_shared_budgets(budgets)
        if not admission.allowed:
            raise RateLimitRejected(admission)
        request_id = getattr(request, "_camellia_rate_lease_request_id", "") or _request_id(request)
        admission = acquire_shared_concurrency(
            concurrency_budgets,
            request_id,
            lease_seconds=settings.REQUEST_RATE_LIMIT_CONCURRENCY_LEASE_SECONDS,
        )
        if not admission.allowed:
            raise RateLimitRejected(admission)
        request._camellia_rate_lease_request_id = request_id
        reserved.update(principal_keys)
        request._camellia_rate_reserved_principals = reserved
    except RateLimitRejected:
        raise
    except Exception as exc:  # noqa: BLE001 - authenticated admission must fail closed
        raise RateLimitBackendUnavailable from exc
