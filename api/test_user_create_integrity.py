import base64
import concurrent.futures
import json
import threading
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.db import IntegrityError, close_old_connections, connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from api.models import RemoteDevice, UserProfile
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


@override_settings(STORAGES=TEST_STORAGES)
class UserCreateIntegrityClassificationTests(TestCase):
    password = "Valid-user-create-9!password"  # noqa: S105 - isolated test credential

    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "user-create-integrity-admin",
            "user-create-integrity-admin-password",  # noqa: S106 - isolated test credential
        )
        device = RemoteDevice.objects.create(
            rid="764000001",
            uuid=base64.b64encode(b"user-create-integrity-admin-device").decode(),
            owner=self.admin,
            is_active=True,
            cpu="-",
            hostname="user-create-integrity-admin-device",
            memory="-",
            os="Linux",
            username=self.admin.username,
            version="test",
        )
        _token, self.bearer = _issue_access_token(self.admin, device)
        self.client = Client(raise_request_exception=False)

    def create_user(self, username, *, group_name=""):
        return self.client.post(
            "/api/users",
            data=json.dumps(
                {
                    "username": username,
                    "password": self.password,
                    "group_name": group_name,
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
        )

    def test_canonical_username_collision_has_a_stable_machine_code(self):
        UserProfile.objects.create_user("Straße-Race", self.password)

        response = self.create_user("STRASSE-RACE")

        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(
            response.json(),
            {
                "error": "User already exists",
                "code": "username_conflict",
            },
        )

    def test_unknown_user_insert_integrity_error_remains_a_server_error(self):
        with patch.object(
            UserProfile.objects,
            "create_user",
            side_effect=IntegrityError("synthetic unrelated user constraint"),
        ):
            response = self.create_user("unrelated-user-integrity")

        self.assertEqual(response.status_code, 500, response.content)
        self.assertNotIn(b"User already exists", response.content)
        self.assertFalse(UserProfile.objects.by_username("unrelated-user-integrity").exists())

    def test_group_create_integrity_error_is_not_reported_as_a_username_conflict(self):
        with patch.object(
            Group.objects,
            "create",
            side_effect=IntegrityError("synthetic group constraint"),
        ):
            response = self.create_user(
                "group-integrity-user",
                group_name="new-concurrent-group",
            )

        self.assertEqual(response.status_code, 500, response.content)
        self.assertNotIn(b"User already exists", response.content)
        self.assertFalse(UserProfile.objects.by_username("group-integrity-user").exists())
        self.assertFalse(Group.objects.filter(name="new-concurrent-group").exists())

    def test_membership_integrity_error_is_not_reported_as_a_username_conflict(self):
        group = Group.objects.create(name="membership-integrity-group")
        related_manager_class = type(self.admin.groups)
        with patch.object(
            related_manager_class,
            "add",
            side_effect=IntegrityError("synthetic membership constraint"),
        ):
            response = self.create_user(
                "membership-integrity-user",
                group_name=group.name,
            )

        self.assertEqual(response.status_code, 500, response.content)
        self.assertNotIn(b"User already exists", response.content)
        self.assertFalse(UserProfile.objects.by_username("membership-integrity-user").exists())
        self.assertTrue(Group.objects.filter(pk=group.pk).exists())


@override_settings(STORAGES=TEST_STORAGES)
class PostgreSQLUserCreateConcurrencyTests(TransactionTestCase):
    password = "F6!zQ2@vT7#mL4$xR8&k"  # noqa: S105 - isolated test credential

    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "concurrent-user-create-admin",
            "concurrent-user-create-admin-password",  # noqa: S106 - isolated test credential
        )
        device = RemoteDevice.objects.create(
            rid="764000002",
            uuid=base64.b64encode(b"concurrent-user-create-admin-device").decode(),
            owner=self.admin,
            is_active=True,
            cpu="-",
            hostname="concurrent-user-create-admin-device",
            memory="-",
            os="Linux",
            username=self.admin.username,
            version="test",
        )
        _token, self.bearer = _issue_access_token(self.admin, device)

    def create_user(self, username, *, group_name=""):
        close_old_connections()
        try:
            return Client(raise_request_exception=False).post(
                "/api/users",
                data=json.dumps(
                    {
                        "username": username,
                        "password": self.password,
                        "group_name": group_name,
                    }
                ),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
            )
        finally:
            connections.close_all()

    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_distinct_users_share_one_new_group_without_false_conflict(self):
        barrier = threading.Barrier(2)
        original_create = Group.objects.create

        def create_group(*args, **kwargs):
            barrier.wait(timeout=20)
            return original_create(*args, **kwargs)

        with (
            patch.object(Group.objects, "create", side_effect=create_group),
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            responses = list(
                executor.map(
                    lambda username: self.create_user(
                        username,
                        group_name="shared-concurrent-group",
                    ),
                    ("concurrent-group-user-a", "concurrent-group-user-b"),
                )
            )

        self.assertEqual([response.status_code for response in responses], [200, 200])
        group = Group.objects.get(name="shared-concurrent-group")
        self.assertEqual(
            set(group.user_set.values_list("username", flat=True)),
            {"concurrent-group-user-a", "concurrent-group-user-b"},
        )

    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_canonical_username_collision_has_one_stable_winner(self):
        barrier = threading.Barrier(2)
        original_create_user = UserProfile.objects.create_user

        def create_user(*args, **kwargs):
            barrier.wait(timeout=20)
            return original_create_user(*args, **kwargs)

        with (
            patch.object(UserProfile.objects, "create_user", side_effect=create_user),
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            responses = list(
                executor.map(
                    self.create_user,
                    ("Ä-Concurrent-Race", "ä-CONCURRENT-RACE"),
                )
            )

        self.assertEqual(sorted(response.status_code for response in responses), [200, 409])
        conflict = next(response for response in responses if response.status_code == 409)
        self.assertEqual(conflict.json()["code"], "username_conflict")
        self.assertEqual(UserProfile.objects.by_username("ä-concurrent-race").count(), 1)
