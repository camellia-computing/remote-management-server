import base64
import concurrent.futures
import json
import threading
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth import HASH_SESSION_KEY, SESSION_KEY
from django.db import close_old_connections, connections
from django.test import Client, RequestFactory, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils.crypto import salted_hmac

from api.admin_user import OidcIdentityAdmin, UserAdmin
from api.credential_sessions import MAX_CREDENTIAL_GENERATION, revoke_user_credentials
from api.models import OidcIdentity, RemoteDevice, RemoteToken, UserProfile
from api.views_api import _issue_access_token, _resolve_oidc_user

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def device_uuid(label):
    return base64.b64encode(label.encode()).decode()


@override_settings(STORAGES=TEST_STORAGES)
class CredentialRevocationTests(TestCase):
    def setUp(self):
        self.operator = UserProfile.objects.create_superuser("operator", "operator-pass")
        self.target = UserProfile.objects.create_superuser("target-admin", "target-pass")

    @staticmethod
    def post_json(client, path, payload, token=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
        return client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def login_token(self, user, password, label):
        response = self.post_json(
            Client(),
            "/api/login",
            {
                "username": user.username,
                "password": password,
                "id": label,
                "uuid": device_uuid(label),
                "deviceInfo": {"os": "linux", "type": "client", "name": label},
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["access_token"]

    def test_force_logout_revokes_bearers_web_and_admin_sessions(self):
        operator_token = self.login_token(self.operator, "operator-pass", "900000001")
        first_token = self.login_token(self.target, "target-pass", "800000001")
        second_token = self.login_token(self.target, "target-pass", "800000002")
        web_client = Client()
        admin_client = Client()
        web_client.force_login(self.target)
        admin_client.force_login(self.target)

        self.assertEqual(web_client.get("/api/home").status_code, 200)
        self.assertEqual(admin_client.get("/admin/").status_code, 200)

        response = self.post_json(
            Client(),
            "/api/users/force-logout",
            {"user_guids": [str(self.target.pk), str(self.target.pk), "999999999"]},
            token=operator_token,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["deleted"], 2)
        for token in (first_token, second_token):
            current = self.post_json(Client(), "/api/currentUser", {}, token=token)
            self.assertEqual(current.status_code, 401, current.content)
        self.assertEqual(web_client.get("/api/home").status_code, 302)
        self.assertEqual(admin_client.get("/admin/").status_code, 302)
        self.assertNotIn(SESSION_KEY, web_client.session)
        self.assertNotIn(SESSION_KEY, admin_client.session)
        self.assertEqual(response.json()["revoked_users"], 1)
        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, 1)
        self.assertFalse(RemoteToken.objects.filter(device__owner=self.target).exists())

        replacement = self.login_token(self.target, "target-pass", "800000001")
        current = self.post_json(Client(), "/api/currentUser", {}, token=replacement)
        self.assertEqual(current.status_code, 200, current.content)

    def test_password_change_invalidates_existing_bearer(self):
        token = self.login_token(self.target, "target-pass", "800000003")
        self.target.set_password("replacement-target-pass")
        self.target.save(update_fields=["password"])

        current = self.post_json(Client(), "/api/currentUser", {}, token=token)

        self.assertEqual(current.status_code, 401, current.content)
        self.assertFalse(RemoteToken.objects.filter(device__owner=self.target).exists())

    def test_pre_generation_credentials_fail_closed_after_migration(self):
        token = self.login_token(self.target, "target-pass", "800000010")
        RemoteToken.objects.filter(device__owner=self.target).update(credential_hash="")
        web_client = Client()
        web_client.force_login(self.target)
        legacy_session_hash = salted_hmac(
            "django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash",
            self.target.password,
            algorithm="sha256",
        ).hexdigest()
        session = web_client.session
        session[HASH_SESSION_KEY] = legacy_session_hash
        session.save()

        current = self.post_json(Client(), "/api/currentUser", {}, token=token)

        self.assertEqual(current.status_code, 401, current.content)
        self.assertEqual(web_client.get("/api/home").status_code, 302)
        self.assertFalse(RemoteToken.objects.filter(device__owner=self.target).exists())

    def test_disable_revokes_all_credential_types_in_the_same_transaction(self):
        operator_token = self.login_token(self.operator, "operator-pass", "900000005")
        target_token = self.login_token(self.target, "target-pass", "800000005")
        web_client = Client()
        web_client.force_login(self.target)

        disabled = self.post_json(
            Client(),
            f"/api/users/{self.target.pk}/disable",
            {},
            token=operator_token,
        )

        self.assertEqual(disabled.status_code, 200, disabled.content)
        self.target.refresh_from_db()
        self.assertFalse(self.target.is_active)
        self.assertEqual(self.target.credential_generation, 1)
        current = self.post_json(Client(), "/api/currentUser", {}, token=target_token)
        self.assertEqual(current.status_code, 401, current.content)
        self.assertEqual(web_client.get("/api/home").status_code, 302)

    def test_admin_disable_cannot_resurrect_an_unobserved_session(self):
        target_token = self.login_token(self.target, "target-pass", "800000007")
        web_client = Client()
        web_client.force_login(self.target)
        request = RequestFactory().post(f"/admin/api/userprofile/{self.target.pk}/change/")
        request.user = self.operator
        model_admin = UserAdmin(UserProfile, admin.site)

        self.target.is_active = False
        model_admin.save_model(request, self.target, form=None, change=True)
        self.target.is_active = True
        model_admin.save_model(request, self.target, form=None, change=True)

        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)
        self.assertEqual(self.target.credential_generation, 1)
        current = self.post_json(Client(), "/api/currentUser", {}, token=target_token)
        self.assertEqual(current.status_code, 401, current.content)
        self.assertEqual(web_client.get("/api/home").status_code, 302)

    @override_settings(
        OIDC_PROVIDERS={
            "example": {
                "issuer": "https://issuer.example.test",
                "auto_provision": False,
                "auto_provision_email_domains": (),
                "auto_provision_required_claims": {},
            }
        }
    )
    def test_oidc_policy_rejection_revokes_existing_credentials(self):
        token = self.login_token(self.target, "target-pass", "800000004")
        OidcIdentity.objects.create(
            provider="example",
            issuer="https://issuer.example.test",
            subject="target-subject",
            user=self.target,
            is_auto_provisioned=True,
        )

        with self.assertRaises(PermissionError):
            _resolve_oidc_user(
                "example",
                "https://issuer.example.test",
                {"sub": "target-subject"},
            )

        current = self.post_json(Client(), "/api/currentUser", {}, token=token)
        self.assertEqual(current.status_code, 401, current.content)
        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, 1)

    def test_admin_oidc_rebind_revokes_the_previous_and_new_subjects(self):
        target_token = self.login_token(self.target, "target-pass", "800000008")
        replacement = UserProfile.objects.create_user("replacement-user", "replacement-pass")
        identity = OidcIdentity.objects.create(
            provider="example",
            issuer="https://issuer.example.test",
            subject="admin-rebind-subject",
            user=self.target,
            is_auto_provisioned=False,
        )
        request = RequestFactory().post(f"/admin/api/oidcidentity/{identity.pk}/change/")
        request.user = self.operator
        model_admin = OidcIdentityAdmin(OidcIdentity, admin.site)

        identity.user = replacement
        model_admin.save_model(request, identity, form=None, change=True)

        self.target.refresh_from_db()
        replacement.refresh_from_db()
        self.assertEqual(self.target.credential_generation, 1)
        self.assertEqual(replacement.credential_generation, 1)
        current = self.post_json(Client(), "/api/currentUser", {}, token=target_token)
        self.assertEqual(current.status_code, 401, current.content)

    def test_admin_oidc_delete_revokes_the_bound_subject(self):
        target_token = self.login_token(self.target, "target-pass", "800000009")
        web_client = Client()
        web_client.force_login(self.target)
        identity = OidcIdentity.objects.create(
            provider="example",
            issuer="https://issuer.example.test",
            subject="admin-delete-subject",
            user=self.target,
            is_auto_provisioned=False,
        )
        request = RequestFactory().post(f"/admin/api/oidcidentity/{identity.pk}/delete/")
        request.user = self.operator
        model_admin = OidcIdentityAdmin(OidcIdentity, admin.site)
        identity_pk = identity.pk

        model_admin.delete_model(request, identity)

        self.assertFalse(OidcIdentity.objects.filter(pk=identity_pk).exists())
        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, 1)
        current = self.post_json(Client(), "/api/currentUser", {}, token=target_token)
        self.assertEqual(current.status_code, 401, current.content)
        self.assertEqual(web_client.get("/api/home").status_code, 302)

    def test_stale_user_save_cannot_restore_a_revoked_generation(self):
        stale_target = UserProfile.objects.get(pk=self.target.pk)

        revoke_user_credentials((self.target.pk,))
        stale_target.note = "ordinary stale update"
        stale_target.save(update_fields=["note"])

        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, 1)
        self.assertEqual(self.target.note, "ordinary stale update")

    def test_revocation_is_atomic_when_token_cleanup_fails(self):
        with patch("api.credential_sessions.RemoteToken.objects.filter") as token_filter:
            token_filter.return_value.delete.side_effect = RuntimeError("injected cleanup failure")
            with self.assertRaisesRegex(RuntimeError, "injected cleanup failure"):
                revoke_user_credentials((self.target.pk,))

        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, 0)

    def test_generation_exhaustion_returns_an_explicit_failure(self):
        operator_token = self.login_token(self.operator, "operator-pass", "900000006")
        UserProfile.objects.filter(pk=self.target.pk).update(credential_generation=MAX_CREDENTIAL_GENERATION)

        response = self.post_json(
            Client(),
            "/api/users/force-logout",
            {"user_guids": [str(self.target.pk)]},
            token=operator_token,
        )

        self.assertEqual(response.status_code, 409, response.content)
        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, MAX_CREDENTIAL_GENERATION)


@override_settings(STORAGES=TEST_STORAGES)
class PostgreSQLCredentialRevocationTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_issuance_never_leaves_a_stale_generation_token(self):
        user = UserProfile.objects.create_user("concurrent-target", "target-pass")
        devices = [
            RemoteDevice.objects.create(
                rid=f"7000000{index:02d}",
                uuid=device_uuid(f"concurrent-device-{index}"),
                cpu="-",
                hostname=f"device-{index}",
                memory="-",
                os="linux",
                username="",
                version="-",
                owner=user,
            )
            for index in range(8)
        ]
        barrier = threading.Barrier(len(devices) + 2)

        def issue(device_pk):
            close_old_connections()
            try:
                thread_user = UserProfile.objects.get(pk=user.pk)
                device = RemoteDevice.objects.get(pk=device_pk)
                barrier.wait(timeout=20)
                return _issue_access_token(thread_user, device)[1]
            finally:
                connections.close_all()

        def revoke():
            close_old_connections()
            try:
                barrier.wait(timeout=20)
                return revoke_user_credentials((user.pk,))
            finally:
                connections.close_all()

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(devices) + 1) as executor:
            issued = [executor.submit(issue, device.pk) for device in devices]
            revoked = executor.submit(revoke)
            barrier.wait(timeout=20)
            raw_tokens = [future.result(timeout=60) for future in issued]
            revocation = revoked.result(timeout=60)

        user.refresh_from_db()
        self.assertEqual(user.credential_generation, 1)
        self.assertEqual(revocation.revoked_users, 1)
        expected_hash = user.get_session_auth_hash()
        self.assertFalse(RemoteToken.objects.exclude(credential_hash=expected_hash).exists())
        statuses = [
            CredentialRevocationTests.post_json(Client(), "/api/currentUser", {}, token=token).status_code
            for token in raw_tokens
        ]
        self.assertTrue(all(status in (200, 401) for status in statuses))
        self.assertEqual(statuses.count(200), RemoteToken.objects.count())
