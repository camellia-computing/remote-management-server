import concurrent.futures
import threading
from unittest.mock import patch

from django.contrib import admin
from django.core.exceptions import ImproperlyConfigured
from django.db import close_old_connections, connections
from django.test import TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

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
