import base64
import concurrent.futures
import datetime
import json
import threading
import uuid
from unittest.mock import patch

from django.contrib import admin
from django.db import close_old_connections, connection, connections
from django.db.migrations.executor import MigrationExecutor
from django.test import (
    Client,
    RequestFactory,
    TestCase,
    TransactionTestCase,
    override_settings,
    skipUnlessDBFeature,
)
from django.utils import timezone

from api.admin_user import RemoteDeviceAdminCustom
from api.models import RemoteDevice, RemoteToken, UserProfile
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def device_uuid(label):
    return base64.b64encode(label.encode()).decode()


@override_settings(STORAGES=TEST_STORAGES)
class TokenSubjectIntegrityTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser("subject-admin", "admin-pass")
        self.alice = UserProfile.objects.create_user("subject-alice", "alice-pass")
        self.bob = UserProfile.objects.create_user("subject-bob", "bob-pass")

    @staticmethod
    def post_json(path, payload, token=None):
        headers = {
            "HTTP_IDEMPOTENCY_KEY": str(uuid.uuid4()),
            **({"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}),
        }
        return Client().post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def login_token(self, user, password, rid, label):
        response = self.post_json(
            "/api/login",
            {
                "username": user.username,
                "password": password,
                "id": rid,
                "uuid": device_uuid(label),
                "deviceInfo": {"os": "linux", "type": "client", "name": label},
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["access_token"]

    def test_owner_change_never_rebinds_an_existing_token_subject(self):
        admin_token = self.login_token(self.admin, "admin-pass", "900000011", "subject-admin-device")
        alice_token = self.login_token(self.alice, "alice-pass", "800000011", "subject-alice-device")
        device = RemoteDevice.objects.get(rid="800000011")
        self.assertEqual(RemoteToken.objects.get(device=device).subject_user_id, self.alice.pk)
        UserProfile.objects.filter(pk=self.bob.pk).update(password=self.alice.password)

        with patch("api.views_api._revoke_device_tokens", return_value=0):
            assigned = self.post_json(
                f"/api/devices/{device.pk}/assign",
                {"type": "user_name", "value": self.bob.username},
                token=admin_token,
            )

        self.assertEqual(assigned.status_code, 200, assigned.content)
        current = self.post_json("/api/currentUser", {}, token=alice_token)
        self.assertEqual(current.status_code, 401, current.content)
        device.refresh_from_db()
        self.assertEqual(device.owner_id, self.bob.pk)

    def test_disabled_device_token_fails_closed_when_cleanup_is_skipped(self):
        admin_token = self.login_token(self.admin, "admin-pass", "900000012", "disable-admin-device")
        alice_token = self.login_token(self.alice, "alice-pass", "800000012", "disable-alice-device")
        device = RemoteDevice.objects.get(rid="800000012")

        with patch("api.views_api._revoke_device_tokens", return_value=0):
            disabled = self.post_json(f"/api/devices/{device.pk}/disable", {}, token=admin_token)

        self.assertEqual(disabled.status_code, 200, disabled.content)
        self.assertEqual(self.post_json("/api/currentUser", {}, token=alice_token).status_code, 401)

    def test_owner_change_rolls_back_when_token_cleanup_fails(self):
        admin_token = self.login_token(self.admin, "admin-pass", "900000013", "rollback-admin-device")
        alice_token = self.login_token(self.alice, "alice-pass", "800000013", "rollback-alice-device")
        device = RemoteDevice.objects.get(rid="800000013")

        with patch("api.views_api._revoke_device_tokens", side_effect=RuntimeError("injected cleanup failure")):
            with self.assertRaisesRegex(RuntimeError, "injected cleanup failure"):
                self.post_json(
                    f"/api/devices/{device.pk}/assign",
                    {"type": "user_name", "value": self.bob.username},
                    token=admin_token,
                )

        device.refresh_from_db()
        self.assertEqual(device.owner_id, self.alice.pk)
        self.assertTrue(RemoteToken.objects.filter(device=device).exists())
        current = self.post_json("/api/currentUser", {}, token=alice_token)
        self.assertEqual(current.status_code, 200, current.content)
        self.assertEqual(current.json()["name"], self.alice.username)

    def test_disable_rolls_back_when_token_cleanup_fails(self):
        admin_token = self.login_token(self.admin, "admin-pass", "900000014", "status-admin-device")
        alice_token = self.login_token(self.alice, "alice-pass", "800000014", "status-alice-device")
        device = RemoteDevice.objects.get(rid="800000014")

        with patch("api.views_api._revoke_device_tokens", side_effect=RuntimeError("injected cleanup failure")):
            with self.assertRaisesRegex(RuntimeError, "injected cleanup failure"):
                self.post_json(f"/api/devices/{device.pk}/disable", {}, token=admin_token)

        device.refresh_from_db()
        self.assertTrue(device.is_active)
        self.assertTrue(RemoteToken.objects.filter(device=device).exists())
        self.assertEqual(self.post_json("/api/currentUser", {}, token=alice_token).status_code, 200)

    def test_admin_owner_change_revokes_the_old_device_subject(self):
        alice_token = self.login_token(self.alice, "alice-pass", "800000015", "admin-owner-device")
        device = RemoteDevice.objects.get(rid="800000015")
        request = RequestFactory().post(f"/admin/api/remotedevice/{device.pk}/change/")
        request.user = self.admin
        model_admin = RemoteDeviceAdminCustom(RemoteDevice, admin.site)

        device.owner = self.bob
        model_admin.save_model(request, device, form=None, change=True)

        device.refresh_from_db()
        self.assertEqual(device.owner_id, self.bob.pk)
        self.assertFalse(RemoteToken.objects.filter(device=device).exists())
        self.assertEqual(self.post_json("/api/currentUser", {}, token=alice_token).status_code, 401)

    def test_admin_owner_change_rolls_back_when_cleanup_fails(self):
        alice_token = self.login_token(self.alice, "alice-pass", "800000019", "admin-rollback-device")
        device = RemoteDevice.objects.get(rid="800000019")
        request = RequestFactory().post(f"/admin/api/remotedevice/{device.pk}/change/")
        request.user = self.admin
        model_admin = RemoteDeviceAdminCustom(RemoteDevice, admin.site)
        device.owner = self.bob

        with patch(
            "api.admin_user.revoke_device_credentials",
            side_effect=RuntimeError("injected admin cleanup failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected admin cleanup failure"):
                model_admin.save_model(request, device, form=None, change=True)

        device.refresh_from_db()
        self.assertEqual(device.owner_id, self.alice.pk)
        self.assertTrue(RemoteToken.objects.filter(device=device).exists())
        self.assertEqual(self.post_json("/api/currentUser", {}, token=alice_token).status_code, 200)


@override_settings(STORAGES=TEST_STORAGES)
class PostgreSQLTokenSubjectIntegrityTests(TransactionTestCase):
    @staticmethod
    def post_json(path, payload, token=None):
        return TokenSubjectIntegrityTests.post_json(path, payload, token)

    @staticmethod
    def login_token(user, password, rid, label):
        response = TokenSubjectIntegrityTests.post_json(
            "/api/login",
            {
                "username": user.username,
                "password": password,
                "id": rid,
                "uuid": device_uuid(label),
                "deviceInfo": {"os": "linux", "type": "client", "name": label},
            },
        )
        if response.status_code != 200:
            raise AssertionError(response.content)
        return response.json()["access_token"]

    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_owner_change_cannot_leave_an_old_subject_token(self):
        admin_user = UserProfile.objects.create_superuser("concurrent-subject-admin", "admin-pass")
        alice = UserProfile.objects.create_user("concurrent-subject-alice", "alice-pass")
        bob = UserProfile.objects.create_user("concurrent-subject-bob", "bob-pass")
        admin_token = self.login_token(admin_user, "admin-pass", "900000016", "concurrent-admin-device")
        first_token = self.login_token(alice, "alice-pass", "800000016", "concurrent-alice-device")
        device = RemoteDevice.objects.get(rid="800000016")
        issuer_count = 8
        barrier = threading.Barrier(issuer_count + 2)

        def issue():
            close_old_connections()
            try:
                thread_user = UserProfile.objects.get(pk=alice.pk)
                thread_device = RemoteDevice.objects.get(pk=device.pk)
                barrier.wait(timeout=20)
                try:
                    return _issue_access_token(thread_user, thread_device)[1]
                except PermissionError:
                    return None
            finally:
                connections.close_all()

        def assign():
            close_old_connections()
            try:
                barrier.wait(timeout=20)
                return self.post_json(
                    f"/api/devices/{device.pk}/assign",
                    {"type": "user_name", "value": bob.username},
                    token=admin_token,
                )
            finally:
                connections.close_all()

        with concurrent.futures.ThreadPoolExecutor(max_workers=issuer_count + 1) as executor:
            issued = [executor.submit(issue) for _ in range(issuer_count)]
            assigned = executor.submit(assign)
            barrier.wait(timeout=20)
            raw_tokens = [first_token, *(future.result(timeout=60) for future in issued)]
            response = assigned.result(timeout=60)

        self.assertEqual(response.status_code, 200, response.content)
        device.refresh_from_db()
        self.assertEqual(device.owner_id, bob.pk)
        self.assertFalse(RemoteToken.objects.filter(device=device).exists())
        for raw_token in (token for token in raw_tokens if token):
            current = self.post_json("/api/currentUser", {}, token=raw_token)
            self.assertEqual(current.status_code, 401, current.content)


class TokenSubjectMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0005_credential_generation")
    migrate_to = ("api", "0006_remotetoken_subject_user")

    def test_existing_owned_tokens_are_bound_and_ownerless_tokens_are_removed(self):
        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_from])
        old_apps = executor.loader.project_state([self.migrate_from]).apps
        OldUser = old_apps.get_model("api", "UserProfile")
        OldDevice = old_apps.get_model("api", "RemoteDevice")
        OldToken = old_apps.get_model("api", "RemoteToken")
        user = OldUser.objects.create(username="migration-subject", is_active=True)
        owned_device = OldDevice.objects.create(
            rid="800000017",
            cpu="-",
            hostname="owned",
            memory="-",
            os="linux",
            uuid=device_uuid("migration-owned-device"),
            username="",
            version="-",
            owner_id=user.pk,
        )
        ownerless_device = OldDevice.objects.create(
            rid="800000018",
            cpu="-",
            hostname="ownerless",
            memory="-",
            os="linux",
            uuid=device_uuid("migration-ownerless-device"),
            username="",
            version="-",
            owner_id=None,
        )
        expires_at = timezone.now() + datetime.timedelta(hours=1)
        OldToken.objects.create(
            device_id=owned_device.pk,
            access_token="a" * 64,
            credential_hash="b" * 64,
            expires_at=expires_at,
        )
        OldToken.objects.create(
            device_id=ownerless_device.pk,
            access_token="c" * 64,
            credential_hash="d" * 64,
            expires_at=expires_at,
        )

        executor = MigrationExecutor(connection)
        executor.migrate([self.migrate_to])
        new_apps = executor.loader.project_state([self.migrate_to]).apps
        NewToken = new_apps.get_model("api", "RemoteToken")

        migrated = NewToken.objects.get(access_token="a" * 64)
        self.assertEqual(migrated.subject_user_id, user.pk)
        self.assertFalse(NewToken.objects.filter(access_token="c" * 64).exists())
