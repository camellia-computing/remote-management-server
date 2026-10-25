import concurrent.futures
import datetime
import hashlib
import ipaddress
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.db.models import Count
from django.db.utils import OperationalError
from django.test import Client, RequestFactory, TestCase, TransactionTestCase, override_settings
from django.urls import resolve
from django.utils import timezone

from api.models import RemoteDevice, RemoteToken, RequestRateBucket, RequestRateLease, UserProfile
from api.rate_limits import (
    Budget,
    ConcurrencyBudget,
    LocalWindowLimiter,
    _policy_group,
    _request_concurrency_budgets,
    acquire_shared_concurrency,
    release_shared_concurrency,
    reserve_shared_budgets,
    reset_local_rate_limit_state,
    source_rate_identity,
)


def _device(owner, rid, label):
    return RemoteDevice.objects.create(
        rid=rid,
        cpu="-",
        hostname=label,
        memory="-",
        os="linux",
        uuid=label,
        public_key_hash=hashlib.sha256(label.encode()).hexdigest(),
        username="tester",
        version="test",
        owner=owner,
    )


def _token(owner, device, raw):
    RemoteToken.objects.create(
        device=device,
        subject_user=owner,
        access_token=hashlib.sha256(raw.encode()).hexdigest(),
        credential_hash=owner.get_session_auth_hash(),
        expires_at=timezone.now() + datetime.timedelta(hours=1),
    )
    return raw


class LocalAdmissionTests(TestCase):
    def test_local_limiter_is_bounded_and_uses_monotonic_expiry(self):
        now = [100.0]
        limiter = LocalWindowLimiter(capacity=2, clock=lambda: now[0])
        first = Budget("source", "ingress", "192.0.2.1", 2, 60)
        second = Budget("source", "ingress", "192.0.2.2", 2, 60)
        third = Budget("source", "ingress", "192.0.2.3", 2, 60)

        self.assertTrue(limiter.reserve((first,)).allowed)
        self.assertTrue(limiter.reserve((second,)).allowed)
        self.assertTrue(limiter.reserve((first,)).allowed)
        self.assertFalse(limiter.reserve((first,)).allowed)
        self.assertTrue(limiter.reserve((third,)).overloaded)

        now[0] += 61
        self.assertTrue(limiter.reserve((third,)).allowed)

    def test_source_identity_normalizes_mapped_ipv4_and_ipv6_prefixes(self):
        self.assertEqual(source_rate_identity("::ffff:192.0.2.10"), "192.0.2.10/32")
        self.assertEqual(source_rate_identity("2001:db8:1:2::1234"), "2001:db8:1:2::/64")
        self.assertEqual(source_rate_identity("2001:db8:1:2::ffff"), "2001:db8:1:2::/64")
        self.assertEqual(source_rate_identity("not-an-ip"), "0.0.0.0/32")


@override_settings(
    REQUEST_RATE_LIMIT_ENABLED=True,
    REQUEST_RATE_LIMIT_GLOBAL_REQUESTS_PER_MINUTE=10_000,
    REQUEST_RATE_LIMIT_SOURCE_REQUESTS_PER_MINUTE=10_000,
    REQUEST_RATE_LIMIT_CREDENTIAL_REQUESTS_PER_MINUTE=10_000,
    REQUEST_RATE_LIMIT_LOCAL_CAPACITY=10_000,
)
class RequestRateLimitTests(TestCase):
    def setUp(self):
        reset_local_rate_limit_state()

    @override_settings(
        REQUEST_RATE_LIMIT_POLICY_OVERRIDES={
            "authentication": {"global": 100, "source": 2, "credential": 100, "concurrency": 8}
        }
    )
    def test_source_route_budget_returns_bounded_retry_after_without_identity(self):
        client = Client()
        self.assertEqual(client.get("/api/login-options", REMOTE_ADDR="198.51.100.10").status_code, 200)
        self.assertEqual(client.get("/api/login-options", REMOTE_ADDR="198.51.100.10").status_code, 200)
        limited = client.get("/api/login-options", REMOTE_ADDR="198.51.100.10")

        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["code"], "rate_limited")
        self.assertEqual(limited.json()["scope"], "source")
        self.assertGreaterEqual(int(limited.headers["Retry-After"]), 1)
        self.assertLessEqual(int(limited.headers["Retry-After"]), 60)
        self.assertNotIn("198.51.100.10", limited.content.decode())
        self.assertEqual(client.get("/api/login-options", REMOTE_ADDR="198.51.100.11").status_code, 200)

    @override_settings(
        TRUST_PROXY_HEADERS=True,
        TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.0/8"),),
        REQUEST_RATE_LIMIT_POLICY_OVERRIDES={
            "authentication": {"global": 100, "source": 1, "credential": 100, "concurrency": 8}
        },
    )
    def test_source_budget_accepts_forwarding_only_from_trusted_proxy_networks(self):
        client = Client()
        trusted = {"REMOTE_ADDR": "10.0.0.10", "HTTP_X_FORWARDED_FOR": "198.51.100.70"}
        self.assertEqual(client.get("/api/login-options", **trusted).status_code, 200)
        self.assertEqual(client.get("/api/login-options", **trusted).status_code, 429)
        self.assertEqual(
            client.get(
                "/api/login-options",
                REMOTE_ADDR="10.0.0.10",
                HTTP_X_FORWARDED_FOR="198.51.100.71",
            ).status_code,
            200,
        )

        self.assertEqual(
            client.get(
                "/api/login-options",
                REMOTE_ADDR="203.0.113.70",
                HTTP_X_FORWARDED_FOR="198.51.100.72",
            ).status_code,
            200,
        )
        self.assertEqual(
            client.get(
                "/api/login-options",
                REMOTE_ADDR="203.0.113.70",
                HTTP_X_FORWARDED_FOR="198.51.100.73",
            ).status_code,
            429,
        )

    def test_expensive_oidc_callback_is_not_classified_as_polling(self):
        factory = RequestFactory()
        callback = factory.get("/api/oidc/callback")
        callback.resolver_match = resolve("/api/oidc/callback")
        poll = factory.post("/api/oidc/auth-query")
        poll.resolver_match = resolve("/api/oidc/auth-query")

        self.assertEqual(_policy_group(callback), "authentication")
        self.assertEqual(_policy_group(poll), "oidc_poll")

    def test_route_concurrency_includes_a_global_operation_budget(self):
        request = RequestFactory().get("/api/login-options", REMOTE_ADDR="198.51.100.14")
        request.resolver_match = resolve("/api/login-options")
        policy = {
            "global": 100,
            "source": 100,
            "credential": 100,
            "actor": 100,
            "device": 100,
            "concurrency": 4,
        }

        budgets = _request_concurrency_budgets(request, "authentication", policy)

        self.assertIn(ConcurrencyBudget("global", "authentication", "management", 4), budgets)

    @override_settings(
        REQUEST_RATE_LIMIT_GLOBAL_REQUESTS_PER_MINUTE=1,
        REQUEST_RATE_LIMIT_SOURCE_REQUESTS_PER_MINUTE=1,
    )
    def test_health_endpoint_avoids_shared_state_but_remains_ingress_bounded(self):
        with patch("api.rate_limits.reserve_shared_budgets") as shared_reserve:
            first = Client().get("/health/live", REMOTE_ADDR="198.51.100.12")
            limited = Client().get("/health/live", REMOTE_ADDR="198.51.100.12")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(limited.status_code, 429)
        shared_reserve.assert_not_called()

    def test_csrf_rejection_is_shared_admitted_and_releases_its_lease(self):
        response = Client(enforce_csrf_checks=True).post(
            "/api/user_action",
            {"type": "login"},
            REMOTE_ADDR="198.51.100.13",
        )

        self.assertEqual(response.status_code, 403)
        self.assertTrue(RequestRateBucket.objects.filter(scope="source", group="authentication").exists())
        self.assertFalse(RequestRateLease.objects.exists())

    @override_settings(
        REQUEST_RATE_LIMIT_POLICY_OVERRIDES={
            "read": {
                "global": 100,
                "source": 100,
                "credential": 100,
                "actor": 2,
                "device": 100,
                "concurrency": 8,
            }
        }
    )
    def test_actor_budget_aggregates_multiple_device_tokens_and_generations(self):
        owner = UserProfile.objects.create_user("rate-owner", "rate-owner-password")
        first_token = _token(owner, _device(owner, "700000001", "rate-device-one"), "rate-token-one")
        second_token = _token(owner, _device(owner, "700000002", "rate-device-two"), "rate-token-two")
        client = Client()

        for raw in (first_token, second_token):
            response = client.post(
                "/api/currentUser",
                HTTP_AUTHORIZATION=f"Bearer {raw}",
                REMOTE_ADDR="198.51.100.20",
            )
            self.assertEqual(response.status_code, 200, response.content)
        limited = client.post(
            "/api/currentUser",
            HTTP_AUTHORIZATION=f"Bearer {first_token}",
            REMOTE_ADDR="198.51.100.20",
        )
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["scope"], "actor")

        UserProfile.objects.filter(pk=owner.pk).update(credential_generation=owner.credential_generation + 1)
        owner.refresh_from_db()
        replacement = _token(
            owner,
            _device(owner, "700000003", "rate-device-three"),
            "rate-token-three",
        )
        reset = client.post(
            "/api/currentUser",
            HTTP_AUTHORIZATION=f"Bearer {replacement}",
            REMOTE_ADDR="198.51.100.20",
        )
        self.assertEqual(reset.status_code, 200, reset.content)

    @override_settings(
        REQUEST_RATE_LIMIT_POLICY_OVERRIDES={
            "read": {
                "global": 100,
                "source": 100,
                "credential": 100,
                "actor": 100,
                "device": 2,
                "concurrency": 8,
            }
        }
    )
    def test_device_budget_resets_only_after_deployment_generation_changes(self):
        owner = UserProfile.objects.create_user("device-rate-owner", "device-rate-password")
        device = _device(owner, "700000004", "device-rate-target")
        raw_token = _token(owner, device, "device-rate-token-one")
        client = Client()

        for _index in range(2):
            response = client.post(
                "/api/currentUser",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
                REMOTE_ADDR="198.51.100.21",
            )
            self.assertEqual(response.status_code, 200, response.content)
        limited = client.post(
            "/api/currentUser",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            REMOTE_ADDR="198.51.100.21",
        )
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["scope"], "device")

        RemoteDevice.objects.filter(pk=device.pk).update(deployment_generation=device.deployment_generation + 1)
        replacement = "device-rate-token-two"
        RemoteToken.objects.filter(device=device).update(
            access_token=hashlib.sha256(replacement.encode()).hexdigest(),
            expires_at=timezone.now() + datetime.timedelta(hours=1),
        )
        reset = client.post(
            "/api/currentUser",
            HTTP_AUTHORIZATION=f"Bearer {replacement}",
            REMOTE_ADDR="198.51.100.21",
        )
        self.assertEqual(reset.status_code, 200, reset.content)

    @override_settings(
        REQUEST_RATE_LIMIT_POLICY_OVERRIDES={
            "record": {
                "global": 100,
                "source": 100,
                "credential": 100,
                "credential_bytes": 2,
                "source_bytes": 100,
                "global_bytes": 100,
                "concurrency": 8,
            }
        }
    )
    def test_record_byte_budget_rejects_before_token_lookup_or_body_processing(self):
        client = Client()
        body = b"x" * (64 * 1024)
        for _index in range(2):
            unauthorized = client.post(
                "/api/record?type=part&file=bounded.bin&offset=0&length=65536",
                data=body,
                content_type="application/octet-stream",
                HTTP_AUTHORIZATION="Bearer invalid-but-stable-record-token",
                REMOTE_ADDR="198.51.100.30",
            )
            self.assertEqual(unauthorized.status_code, 401)
        limited = client.post(
            "/api/record?type=part&file=bounded.bin&offset=0&length=65536",
            data=body,
            content_type="application/octet-stream",
            HTTP_AUTHORIZATION="Bearer invalid-but-stable-record-token",
            REMOTE_ADDR="198.51.100.30",
        )
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json()["scope"], "credential_bytes")
        serialized = "\n".join(
            f"{bucket.key_hash} {bucket.scope} {bucket.group}"
            for bucket in RequestRateBucket.objects.order_by("key_hash")
        )
        self.assertNotIn("invalid-but-stable-record-token", serialized)

    def test_rate_backend_failure_is_a_stable_fail_closed_503(self):
        with patch("api.rate_limits.reserve_shared_budgets", side_effect=OperationalError("secret backend detail")):
            response = Client().get("/api/login-options", REMOTE_ADDR="198.51.100.40")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "rate_limit_unavailable")
        self.assertEqual(response.headers["Retry-After"], "1")
        self.assertNotIn("secret backend detail", response.content.decode())

    def test_concurrency_lease_is_shared_and_release_is_idempotent(self):
        budget = ConcurrencyBudget("source", "mutation", "198.51.100.50/32", 1)
        first = acquire_shared_concurrency((budget,), "a" * 32, lease_seconds=60)
        second = acquire_shared_concurrency((budget,), "b" * 32, lease_seconds=60)
        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(second.scope, "source")
        self.assertEqual(RequestRateLease.objects.count(), 1)

        release_shared_concurrency("a" * 32)
        release_shared_concurrency("a" * 32)
        third = acquire_shared_concurrency((budget,), "c" * 32, lease_seconds=60)
        self.assertTrue(third.allowed)

    def test_fixed_window_reservation_is_all_or_none(self):
        exhausted = Budget("source", "read", "198.51.100.60/32", 1)
        untouched = Budget("credential", "read", "credential-a", 10)
        self.assertTrue(reserve_shared_budgets((exhausted,)).allowed)

        rejected = reserve_shared_budgets((exhausted, untouched))

        self.assertFalse(rejected.allowed)
        self.assertEqual(RequestRateBucket.objects.get(key_hash=exhausted.key_hash).used, 1)
        self.assertEqual(RequestRateBucket.objects.get(key_hash=untouched.key_hash).used, 0)


class PostgreSQLRateLimitConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        reset_local_rate_limit_state()

    def test_shared_budget_never_admits_more_than_limit(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row-lock semantics are authoritative")
        workers = 32
        barrier = __import__("threading").Barrier(workers)

        def attempt(_index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                admission = reserve_shared_budgets((Budget("source", "concurrency-test", "203.0.113.10/32", 7, 60),))
                return admission.allowed
            finally:
                close_old_connections()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(attempt, range(workers)))
        self.assertEqual(sum(results), 7)
        self.assertEqual(RequestRateBucket.objects.get().used, 7)

    def test_multiple_bucket_initialization_orders_do_not_deadlock_or_over_admit(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL row-lock semantics are authoritative")
        workers = 32
        barrier = __import__("threading").Barrier(workers)
        first = Budget("global", "initialization-race", "management", 7, 60)
        second = Budget("source", "initialization-race", "203.0.113.11/32", 7, 60)

        def attempt(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                budgets = (first, second) if index % 2 else (second, first)
                return reserve_shared_budgets(budgets).allowed
            finally:
                close_old_connections()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(attempt, range(workers)))
        self.assertEqual(sum(results), 7)
        self.assertEqual(
            list(RequestRateBucket.objects.order_by("key_hash").values_list("used", flat=True)),
            [7, 7],
        )

    def test_shared_concurrency_lease_never_oversubscribes(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL advisory-lock semantics are authoritative")
        workers = 32
        barrier = __import__("threading").Barrier(workers)

        def attempt(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                admission = acquire_shared_concurrency(
                    (ConcurrencyBudget("source", "lease-race", "203.0.113.20/32", 7),),
                    f"{index:032x}",
                    lease_seconds=60,
                )
                return admission.allowed
            finally:
                close_old_connections()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(attempt, range(workers)))
        self.assertEqual(sum(results), 7)
        self.assertEqual(RequestRateLease.objects.count(), 7)

    def test_multiple_advisory_locks_are_ordered_without_process_serialization(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL advisory-lock semantics are authoritative")
        workers = 32
        barrier = __import__("threading").Barrier(workers)
        first = ConcurrencyBudget("global", "service", "management", 7)
        second = ConcurrencyBudget("source", "mutation", "203.0.113.30/32", 7)

        def attempt(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                budgets = (first, second) if index % 2 else (second, first)
                admission = acquire_shared_concurrency(
                    budgets,
                    f"{index:032x}",
                    lease_seconds=60,
                )
                return admission.allowed
            finally:
                close_old_connections()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(attempt, range(workers)))
        self.assertEqual(sum(results), 7)
        self.assertEqual(
            list(
                RequestRateLease.objects.values("key_hash").annotate(total=Count("pk")).values_list("total", flat=True)
            ),
            [7, 7],
        )
