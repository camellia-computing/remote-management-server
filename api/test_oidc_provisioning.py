import concurrent.futures
import datetime
import threading
from unittest.mock import patch

from django.contrib import admin
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, OperationalError, close_old_connections, connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone

from api import views_api
from api.models import OidcIdentity, OidcPendingAuth, UserProfile
from api.views_api import _resolve_oidc_user
from camellia_remote_management.settings import (
    oidc_auto_provision_email_domains,
    oidc_auto_provision_required_claims,
)

ISSUER = "https://issuer.example.test"
PROVIDER_NAME = "example"


def provider(*, auto_provision=False, email_domains=(), required_claims=None):
    return {
        "issuer": ISSUER,
        "client_id": "oidc-client",
        "client_secret": "oidc-secret",
        "redirect_uri": "https://localhost/api/oidc/callback",
        "scope": "openid email profile",
        "allowed_hosts": ("issuer.example.test",),
        "auto_provision": auto_provision,
        "auto_provision_email_domains": email_domains,
        "auto_provision_required_claims": required_claims or {},
    }


def claims(subject="subject-1", **overrides):
    payload = {
        "iss": ISSUER,
        "sub": subject,
        "preferred_username": f"user-{subject}",
        "email": f"{subject}@example.test",
        "email_verified": True,
        "tid": "tenant-approved",
        "groups": ["remote-users"],
    }
    payload.update(overrides)
    return payload


class OidcPolicyParserTests(TestCase):
    def test_email_domains_are_exact_lowercase_dns_names(self):
        self.assertEqual(
            oidc_auto_provision_email_domains("Example.Test,staff.example.test;example.test"),
            ("example.test", "staff.example.test"),
        )
        for value in ("*.example.test", ".example.test", "example.test.", "single-label", "bad domain.test"):
            with self.subTest(value=value), self.assertRaises(ImproperlyConfigured):
                oidc_auto_provision_email_domains(value)

    def test_required_claim_policy_is_bounded_and_typed(self):
        parsed = oidc_auto_provision_required_claims(
            '{"tid":["tenant-approved"],"groups":["remote-users","support-users"]}'
        )
        self.assertEqual(parsed["tid"], ("tenant-approved",))
        self.assertEqual(parsed["groups"], ("remote-users", "support-users"))
        for value in (
            "[]",
            "{}",
            '{"bad claim":["value"]}',
            '{"tid":[]}',
            '{"tid":[1]}',
            '{"tid":[""]}',
        ):
            with self.subTest(value=value), self.assertRaises(ImproperlyConfigured):
                oidc_auto_provision_required_claims(value)


class OidcProvisioningTests(TestCase):
    def test_oidc_identity_is_registered_for_explicit_admin_prebinding(self):
        self.assertTrue(admin.site.is_registered(OidcIdentity))

    def test_processing_status_requires_a_complete_persistent_claim(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            OidcPendingAuth.objects.create(
                state="invalid-processing-claim",
                poll_code_hash="8" * 64,
                provider=PROVIDER_NAME,
                nonce="invalid-processing-nonce",
                code_verifier="invalid-processing-verifier",
                status=OidcPendingAuth.STATUS_PROCESSING,
            )

    def test_claim_generation_exhaustion_fails_before_external_exchange(self):
        pending = OidcPendingAuth.objects.create(
            state="callback-generation-exhaustion",
            poll_code_hash="7" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.247",
            rid="123456786",
            device_uuid="b2lkYy1nZW5lcmF0aW9uLWV4aGF1c3Rpb24=",
            nonce="callback-generation-nonce",
            code_verifier="callback-generation-verifier",
            callback_claim_generation=views_api.MAX_OIDC_CALLBACK_CLAIM_GENERATION,
        )
        with patch("api.views_api._oidc_metadata") as metadata:
            response = self.client.get(f"/api/oidc/callback?state={pending.pk}&code=provider-code")

        self.assertEqual(response.status_code, 409)
        metadata.assert_not_called()
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_ERROR)
        self.assertEqual(pending.error_code, "claim_generation_exhausted")

    @override_settings(OIDC_PROVIDERS={PROVIDER_NAME: provider()})
    def test_unknown_identity_is_denied_by_default_without_side_effects(self):
        with self.assertRaises(PermissionError):
            _resolve_oidc_user(PROVIDER_NAME, ISSUER, claims())

        self.assertFalse(UserProfile.objects.exists())
        self.assertFalse(OidcIdentity.objects.exists())

    @override_settings(OIDC_PROVIDERS={PROVIDER_NAME: provider()})
    def test_explicit_prebound_identity_is_allowed_without_auto_provision(self):
        user = UserProfile.objects.create_user("prebound-user", password=None)
        identity = OidcIdentity.objects.create(
            issuer=ISSUER,
            subject="subject-1",
            provider=PROVIDER_NAME,
            user=user,
        )

        resolved = _resolve_oidc_user(PROVIDER_NAME, ISSUER, claims())

        self.assertEqual(resolved, user)
        identity.refresh_from_db()
        self.assertFalse(identity.is_auto_provisioned)
        self.assertEqual(identity.last_username, "user-subject-1")
        self.assertEqual(identity.last_email, "subject-1@example.test")

    @override_settings(
        OIDC_PROVIDERS={
            PROVIDER_NAME: provider(
                auto_provision=True,
                email_domains=("example.test",),
                required_claims={"tid": ("tenant-approved",), "groups": ("remote-users",)},
            )
        }
    )
    def test_auto_provision_requires_every_policy_dimension(self):
        user = _resolve_oidc_user(PROVIDER_NAME, ISSUER, claims())

        self.assertTrue(user.is_active)
        identity = OidcIdentity.objects.get(user=user)
        self.assertTrue(identity.is_auto_provisioned)
        self.assertFalse(user.has_usable_password())

        denied_claims = (
            claims("unverified", email_verified=False),
            claims("wrong-domain", email="user@other.test"),
            claims("subdomain", email="user@staff.example.test"),
            claims("overlong-email", email=f"{'a' * 245}@example.test"),
            claims("wrong-tenant", tid="tenant-denied"),
            claims("missing-tenant", tid=None),
            claims("wrong-group", groups=["other-users"]),
        )
        for denied in denied_claims:
            with self.subTest(subject=denied["sub"]), self.assertRaises(PermissionError):
                _resolve_oidc_user(PROVIDER_NAME, ISSUER, denied)
        self.assertEqual(UserProfile.objects.count(), 1)
        self.assertEqual(OidcIdentity.objects.count(), 1)

    def test_policy_managed_identity_is_rechecked_on_every_login(self):
        enabled = provider(
            auto_provision=True,
            email_domains=("example.test",),
            required_claims={"tid": ("tenant-approved",)},
        )
        with override_settings(OIDC_PROVIDERS={PROVIDER_NAME: enabled}):
            user = _resolve_oidc_user(PROVIDER_NAME, ISSUER, claims())

        with override_settings(OIDC_PROVIDERS={PROVIDER_NAME: provider()}), self.assertRaises(PermissionError):
            _resolve_oidc_user(PROVIDER_NAME, ISSUER, claims())
        with (
            override_settings(OIDC_PROVIDERS={PROVIDER_NAME: enabled}),
            self.assertRaises(PermissionError),
        ):
            _resolve_oidc_user(PROVIDER_NAME, ISSUER, claims(tid="tenant-revoked"))

        self.assertTrue(UserProfile.objects.filter(pk=user.pk, is_active=True).exists())
        self.assertEqual(OidcIdentity.objects.filter(user=user, is_auto_provisioned=True).count(), 1)

    @override_settings(OIDC_PROVIDERS={PROVIDER_NAME: provider()})
    def test_callback_denies_unknown_identity_and_records_bounded_error(self):
        pending = OidcPendingAuth.objects.create(
            state="unknown-identity-state",
            poll_code_hash="f" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.240",
            rid="123456789",
            device_uuid="b2lkYy11bmtub3duLWRldmljZQ==",
            nonce="callback-nonce",
            code_verifier="callback-verifier",
        )
        oidc_client = type("OidcClient", (), {"fetch_token": lambda self, *_args, **_kwargs: {"id_token": "token"}})()
        with (
            patch("api.views_api._oidc_metadata", return_value={"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}),
            patch("api.views_api._oidc_client", return_value=oidc_client),
            patch("api.views_api._validate_oidc_id_token", return_value=claims()),
        ):
            response = self.client.get(f"/api/oidc/callback?state={pending.pk}&code=provider-code")

        self.assertEqual(response.status_code, 400)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_ERROR)
        self.assertEqual(pending.error_code, "verification_failed")
        self.assertFalse(UserProfile.objects.exists())
        self.assertFalse(OidcIdentity.objects.exists())

    @override_settings(
        OIDC_PROVIDERS={
            PROVIDER_NAME: provider(
                auto_provision=True,
                required_claims={"tid": ("tenant-approved",)},
            )
        }
    )
    def test_competing_provider_error_cannot_orphan_successful_provisioning(self):
        pending = OidcPendingAuth.objects.create(
            state="callback-provider-race",
            poll_code_hash="e" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.241",
            rid="123456780",
            device_uuid="b2lkYy1wcm92aWRlci1yYWNl",
            nonce="callback-race-nonce",
            code_verifier="callback-race-verifier",
        )
        oidc_client = type("OidcClient", (), {"fetch_token": lambda self, *_args, **_kwargs: {"id_token": "token"}})()
        competing = {}

        def resolve_with_denied_callback(provider_name, issuer, token_claims, **kwargs):
            user = _resolve_oidc_user(provider_name, issuer, token_claims, **kwargs)
            competing["response"] = self.client.get(f"/api/oidc/callback?state={pending.pk}&error=access_denied")
            return user

        with (
            patch("api.views_api._oidc_metadata", return_value={"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}),
            patch("api.views_api._oidc_client", return_value=oidc_client),
            patch("api.views_api._validate_oidc_id_token", return_value=claims("provider-race")),
            patch("api.views_api._resolve_oidc_user", side_effect=resolve_with_denied_callback),
        ):
            response = self.client.get(f"/api/oidc/callback?state={pending.pk}&code=provider-code")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(competing["response"].status_code, 409)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_DONE)
        self.assertIsNotNone(pending.authenticated_user_id)
        self.assertEqual(OidcIdentity.objects.filter(user_id=pending.authenticated_user_id).count(), 1)

    @override_settings(
        OIDC_PROVIDERS={
            PROVIDER_NAME: provider(
                auto_provision=True,
                required_claims={"tid": ("tenant-approved",)},
            )
        }
    )
    def test_same_state_reentry_cannot_exchange_the_provider_code_twice(self):
        pending = OidcPendingAuth.objects.create(
            state="callback-success-race",
            poll_code_hash="d" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.242",
            rid="123456781",
            device_uuid="b2lkYy1zdWNjZXNzLXJhY2U=",
            nonce="callback-success-nonce",
            code_verifier="callback-success-verifier",
        )
        callback_url = f"/api/oidc/callback?state={pending.pk}&code=provider-code"
        exchange = {"count": 0}

        class ReentrantOidcClient:
            def fetch_token(inner_self, *_args, **_kwargs):
                exchange["count"] += 1
                if exchange["count"] == 1:
                    exchange["nested_response"] = self.client.get(callback_url)
                return {"id_token": "token"}

        with (
            patch("api.views_api._oidc_metadata", return_value={"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}),
            patch("api.views_api._oidc_client", return_value=ReentrantOidcClient()),
            patch("api.views_api._validate_oidc_id_token", return_value=claims("success-race")),
        ):
            response = self.client.get(callback_url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(exchange["nested_response"].status_code, 409)
        self.assertEqual(exchange["count"], 1)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_DONE)
        self.assertEqual(OidcIdentity.objects.count(), 1)

    @override_settings(
        OIDC_PROVIDERS={
            PROVIDER_NAME: provider(
                auto_provision=True,
                required_claims={"tid": ("tenant-approved",)},
            )
        }
    )
    def test_provisioning_failure_rolls_back_user_and_identity_before_fenced_error(self):
        pending = OidcPendingAuth.objects.create(
            state="callback-provisioning-rollback",
            poll_code_hash="c" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.243",
            rid="123456782",
            device_uuid="b2lkYy1wcm92aXNpb24tcm9sbGJhY2s=",
            nonce="callback-rollback-nonce",
            code_verifier="callback-rollback-verifier",
        )
        oidc_client = type("OidcClient", (), {"fetch_token": lambda self, *_args, **_kwargs: {"id_token": "token"}})()

        def provision_then_fail(provider_name, issuer, token_claims, **kwargs):
            _resolve_oidc_user(provider_name, issuer, token_claims, **kwargs)
            raise RuntimeError("injected finalization failure")

        with (
            patch("api.views_api._oidc_metadata", return_value={"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}),
            patch("api.views_api._oidc_client", return_value=oidc_client),
            patch("api.views_api._validate_oidc_id_token", return_value=claims("provision-rollback")),
            patch("api.views_api._resolve_oidc_user", side_effect=provision_then_fail),
        ):
            response = self.client.get(f"/api/oidc/callback?state={pending.pk}&code=provider-code")

        self.assertEqual(response.status_code, 400)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_ERROR)
        self.assertEqual(pending.error_code, "verification_failed")
        self.assertFalse(UserProfile.objects.exists())
        self.assertFalse(OidcIdentity.objects.exists())

    @override_settings(
        OIDC_PROVIDERS={
            PROVIDER_NAME: provider(
                auto_provision=True,
                required_claims={"tid": ("tenant-approved",)},
            )
        }
    )
    def test_expired_claim_can_be_reclaimed_and_fences_the_late_worker(self):
        pending = OidcPendingAuth.objects.create(
            state="callback-lease-reclaim",
            poll_code_hash="b" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.244",
            rid="123456783",
            device_uuid="b2lkYy1sZWFzZS1yZWNsYWlt",
            nonce="callback-reclaim-nonce",
            code_verifier="callback-reclaim-verifier",
        )
        callback_url = f"/api/oidc/callback?state={pending.pk}&code=provider-code"
        metadata_calls = {"count": 0}
        metadata = {"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}

        def metadata_with_reclaim(*_args, **_kwargs):
            metadata_calls["count"] += 1
            if metadata_calls["count"] == 1:
                OidcPendingAuth.objects.filter(pk=pending.pk).update(
                    callback_claim_expires_at=timezone.now() - datetime.timedelta(seconds=1)
                )
                metadata_calls["nested_response"] = self.client.get(callback_url)
            return metadata

        oidc_client = type("OidcClient", (), {"fetch_token": lambda self, *_args, **_kwargs: {"id_token": "token"}})()
        with (
            patch("api.views_api._oidc_metadata", side_effect=metadata_with_reclaim),
            patch("api.views_api._oidc_client", return_value=oidc_client),
            patch("api.views_api._validate_oidc_id_token", return_value=claims("lease-reclaim")),
        ):
            response = self.client.get(callback_url)

        self.assertEqual(response.status_code, 409)
        self.assertEqual(metadata_calls["nested_response"].status_code, 200)
        self.assertEqual(metadata_calls["count"], 2)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_DONE)
        self.assertEqual(pending.callback_claim_generation, 2)
        self.assertIsNone(pending.callback_claim_owner)
        self.assertIsNone(pending.callback_claim_expires_at)
        self.assertEqual(OidcIdentity.objects.count(), 1)

    @override_settings(OIDC_PROVIDERS={PROVIDER_NAME: provider()})
    def test_callback_policy_rejection_revokes_credentials_after_atomic_rollback(self):
        user = UserProfile.objects.create_user("callback-policy-user", password=None)
        OidcIdentity.objects.create(
            issuer=ISSUER,
            subject="callback-policy-subject",
            provider=PROVIDER_NAME,
            user=user,
            is_auto_provisioned=True,
        )
        pending = OidcPendingAuth.objects.create(
            state="callback-policy-rejection",
            poll_code_hash="9" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.246",
            rid="123456785",
            device_uuid="b2lkYy1wb2xpY3ktcmVqZWN0aW9u",
            nonce="callback-policy-nonce",
            code_verifier="callback-policy-verifier",
        )
        oidc_client = type("OidcClient", (), {"fetch_token": lambda self, *_args, **_kwargs: {"id_token": "token"}})()
        with (
            patch("api.views_api._oidc_metadata", return_value={"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}),
            patch("api.views_api._oidc_client", return_value=oidc_client),
            patch(
                "api.views_api._validate_oidc_id_token",
                return_value=claims("callback-policy-subject"),
            ),
        ):
            response = self.client.get(f"/api/oidc/callback?state={pending.pk}&code=provider-code")

        self.assertEqual(response.status_code, 400)
        user.refresh_from_db()
        self.assertEqual(user.credential_generation, 1)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_ERROR)
        self.assertEqual(pending.error_code, "policy_rejected")
        self.assertIsNone(pending.callback_claim_owner)
        self.assertIsNone(pending.callback_claim_expires_at)

    @override_settings(OIDC_PROVIDERS={PROVIDER_NAME: provider()})
    def test_policy_revocation_failure_leaves_a_fenced_claim_retryable(self):
        user = UserProfile.objects.create_user("callback-policy-retry-user", password=None)
        OidcIdentity.objects.create(
            issuer=ISSUER,
            subject="callback-policy-retry-subject",
            provider=PROVIDER_NAME,
            user=user,
            is_auto_provisioned=True,
        )
        pending = OidcPendingAuth.objects.create(
            state="callback-policy-retry",
            poll_code_hash="6" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.248",
            rid="123456787",
            device_uuid="b2lkYy1wb2xpY3ktcmV0cnk=",
            nonce="callback-policy-retry-nonce",
            code_verifier="callback-policy-retry-verifier",
        )
        callback_url = f"/api/oidc/callback?state={pending.pk}&code=provider-code"
        oidc_client = type(
            "OidcClient",
            (),
            {"fetch_token": lambda self, *_args, **_kwargs: {"id_token": "token"}},
        )()

        def perform_callback():
            with (
                patch(
                    "api.views_api._oidc_metadata",
                    return_value={"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"},
                ),
                patch("api.views_api._oidc_client", return_value=oidc_client),
                patch(
                    "api.views_api._validate_oidc_id_token",
                    return_value=claims("callback-policy-retry-subject"),
                ),
            ):
                return self.client.get(callback_url)

        with patch("api.views_api.revoke_user_credentials", side_effect=OperationalError("injected")):
            first_response = perform_callback()

        self.assertEqual(first_response.status_code, 503)
        user.refresh_from_db()
        self.assertEqual(user.credential_generation, 0)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_PROCESSING)
        self.assertEqual(pending.callback_claim_generation, 1)
        self.assertIsNotNone(pending.callback_claim_owner)
        self.assertIsNotNone(pending.callback_claim_expires_at)

        OidcPendingAuth.objects.filter(pk=pending.pk).update(
            callback_claim_expires_at=timezone.now() - datetime.timedelta(seconds=1)
        )
        retry_response = perform_callback()

        self.assertEqual(retry_response.status_code, 400)
        user.refresh_from_db()
        self.assertEqual(user.credential_generation, 1)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_ERROR)
        self.assertEqual(pending.error_code, "policy_rejected")
        self.assertEqual(pending.callback_claim_generation, 2)
        self.assertIsNone(pending.callback_claim_owner)
        self.assertIsNone(pending.callback_claim_expires_at)


@override_settings(
    OIDC_PROVIDERS={
        PROVIDER_NAME: provider(
            auto_provision=True,
            required_claims={"tid": ("tenant-approved",)},
        )
    }
)
class PostgreSQLOidcProvisioningTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_first_login_creates_one_user_and_identity(self):
        workers = 16
        barrier = threading.Barrier(workers + 1)

        def resolve(_index):
            close_old_connections()
            try:
                barrier.wait(timeout=20)
                return _resolve_oidc_user(PROVIDER_NAME, ISSUER, claims()).pk
            finally:
                connections.close_all()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(resolve, index) for index in range(workers)]
            barrier.wait(timeout=20)
            user_ids = [future.result(timeout=60) for future in futures]

        self.assertEqual(len(set(user_ids)), 1)
        self.assertEqual(UserProfile.objects.count(), 1)
        self.assertEqual(OidcIdentity.objects.count(), 1)

    @skipUnlessDBFeature("has_select_for_update")
    def test_same_state_callbacks_have_one_exchange_owner(self):
        pending = OidcPendingAuth.objects.create(
            state="callback-concurrent-owner",
            poll_code_hash="a" * 64,
            provider=PROVIDER_NAME,
            request_ip="198.51.100.245",
            rid="123456784",
            device_uuid="b2lkYy1jb25jdXJyZW50LW93bmVy",
            nonce="callback-owner-nonce",
            code_verifier="callback-owner-verifier",
        )
        callback_url = f"/api/oidc/callback?state={pending.pk}&code=provider-code"
        claim_entry = threading.Barrier(2)
        fetch_started = threading.Event()
        contender_finished = threading.Event()
        release_fetch = threading.Event()
        exchange = {"count": 0}
        original_claim = views_api._claim_oidc_callback

        def synchronized_claim(state):
            claim_entry.wait(timeout=20)
            return original_claim(state)

        class BlockingOidcClient:
            def fetch_token(inner_self, *_args, **_kwargs):
                exchange["count"] += 1
                fetch_started.set()
                if not release_fetch.wait(timeout=20):
                    raise RuntimeError("exchange release timed out")
                return {"id_token": "token"}

        def callback():
            close_old_connections()
            try:
                response = self.client_class().get(callback_url)
                if response.status_code == 409:
                    contender_finished.set()
                return response.status_code
            finally:
                connections.close_all()

        metadata = {"issuer": ISSUER, "token_endpoint": f"{ISSUER}/token"}
        with (
            patch("api.views_api._claim_oidc_callback", side_effect=synchronized_claim),
            patch("api.views_api._oidc_metadata", return_value=metadata),
            patch("api.views_api._oidc_client", return_value=BlockingOidcClient()),
            patch("api.views_api._validate_oidc_id_token", return_value=claims("concurrent-owner")),
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(callback)
                second = executor.submit(callback)
                self.assertTrue(fetch_started.wait(timeout=20))
                self.assertTrue(contender_finished.wait(timeout=20))
                release_fetch.set()
                statuses = sorted((first.result(timeout=60), second.result(timeout=60)))

        self.assertEqual(statuses, [200, 409])
        self.assertEqual(exchange["count"], 1)
        pending.refresh_from_db()
        self.assertEqual(pending.status, OidcPendingAuth.STATUS_DONE)
        self.assertEqual(pending.callback_claim_generation, 1)
        self.assertEqual(OidcIdentity.objects.count(), 1)
