import base64
import hashlib
import json
from unittest.mock import patch

from django.contrib import auth
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from api.login_admission import scope_hash
from api.migration_test_support import restore_latest_migration_state
from api.models import RemoteDevice, UserProfile
from api.username_identity import (
    POSTGRES_COLLATION_VERSION,
    POSTGRES_ENCODING,
    POSTGRES_LOCALE,
    POSTGRES_LOCALE_PROVIDER,
    UsernameIdentityError,
    canonical_username,
    canonical_username_key,
    check_username_identity,
)
from api.views_api import _oidc_local_username, _user_by_identifier
from api.views_front import _find_user


class UsernameIdentityTests(TestCase):
    password = "canonical-username-password"  # noqa: S105 - isolated test credential

    def setUp(self):
        self.user = UserProfile.objects.create_user(username="Äster", password=self.password)

    def test_unicode_corpus_has_one_versioned_backend_independent_result(self):
        expected = {
            "ASCII": "ascii",
            "Ä": "ä",
            "ä": "ä",
            "ß": "ss",
            "SS": "ss",
            "İ": "i\u0307",
            "i": "i",
            "Σ": "σ",
            "σ": "σ",
            "ς": "σ",
            "Ａｌｉｃｅ": "alice",
            "é": "é",
            "e\u0301": "é",
        }
        self.assertEqual({value: canonical_username(value) for value in expected}, expected)
        self.assertNotEqual(canonical_username_key("İ"), canonical_username_key("i"))

    def test_create_login_and_identity_lookup_share_the_binary_authority(self):
        self.assertEqual(self.user.username, "Äster")
        self.assertEqual(bytes(self.user.username_canonical), canonical_username_key("äSTER"))
        self.assertEqual(auth.authenticate(username="äSTER", password=self.password), self.user)
        self.assertEqual(_user_by_identifier("äster"), self.user)
        self.assertEqual(_find_user("äSTER"), self.user)
        self.assertEqual(scope_hash("login", "Äster"), scope_hash("login", "äSTER"))

        with self.assertRaises((IntegrityError, ValidationError)), transaction.atomic():
            UserProfile.objects.create_user(username="äSTER", password=self.password)

    def test_api_front_and_admin_login_consume_the_same_canonical_key(self):
        device_uuid = base64.b64encode(b"canonical-device").decode()
        api_response = self.client.post(
            "/api/login",
            data=json.dumps(
                {
                    "username": "äSTER",
                    "password": self.password,
                    "id": "123456789",
                    "uuid": device_uuid,
                    "type": "client",
                    "deviceInfo": {"os": "linux", "type": "client", "name": "canonical"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(api_response.status_code, 200, api_response.content)
        user_token = api_response.json()["access_token"]
        RemoteDevice.objects.filter(rid="123456789", uuid=device_uuid).update(
            public_key_hash=hashlib.sha256(b"canonical-device-public-key").hexdigest()
        )

        device_update = self.client.post(
            "/api/devices/cli",
            data=json.dumps(
                {
                    "id": "123456789",
                    "uuid": device_uuid,
                    "user_name": "äSTER",
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {user_token}",
        )
        self.assertEqual(device_update.status_code, 200, device_update.content)

        front_response = self.client.post(
            "/api/user_action?action=login",
            {"account": "äSTER", "password": self.password},
        )
        self.assertEqual(front_response.status_code, 200, front_response.content)
        self.assertEqual(front_response.json()["code"], 1)

        admin = UserProfile.objects.create_superuser("StraßeAdmin", self.password)
        admin_response = self.client_class().post(
            "/admin/login/",
            {"username": "STRASSEADMIN", "password": self.password, "next": "/admin/"},
        )
        self.assertEqual(admin_response.status_code, 302, admin_response.content)
        self.assertEqual(admin_response.url, "/admin/")
        self.assertTrue(admin.is_admin)

        admin_api = self.client_class()
        admin_login = admin_api.post(
            "/api/login",
            data=json.dumps(
                {
                    "username": "STRASSEADMIN",
                    "password": self.password,
                    "id": "987654321",
                    "uuid": base64.b64encode(b"canonical-admin-device").decode(),
                    "deviceInfo": {"os": "linux", "type": "client", "name": "admin"},
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(admin_login.status_code, 200, admin_login.content)
        token = admin_login.json()["access_token"]
        created = admin_api.post(
            "/api/users",
            data=json.dumps({"username": "ＳtraßeNew", "password": self.password}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(created.status_code, 200, created.content)
        collision = admin_api.post(
            "/api/users",
            data=json.dumps({"username": "STRASSENEW", "password": self.password}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(collision.status_code, 409, collision.content)
        normalization_overflow = admin_api.post(
            "/api/users",
            data=json.dumps({"username": "ﬃ" * 20, "password": self.password}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(normalization_overflow.status_code, 400, normalization_overflow.content)

    def test_display_name_is_nfkc_normalized_and_casefold_collisions_are_rejected(self):
        full_width = UserProfile.objects.create_user(username="ＦｕｌｌＷｉｄｔｈ", password=self.password)
        self.assertEqual(full_width.username, "FullWidth")
        self.assertEqual(bytes(full_width.username_canonical), b"fullwidth")

        street = UserProfile.objects.create_user(username="Straße", password=self.password)
        with self.assertRaises((IntegrityError, ValidationError)), transaction.atomic():
            UserProfile.objects.create_user(username="STRASSE", password=self.password)
        self.assertEqual(auth.authenticate(username="STRASSE", password=self.password), street)

    @override_settings(ALLOW_REGISTRATION=True)
    def test_front_registration_uses_the_same_normalized_unique_authority(self):
        collision = self.client.post(
            "/api/user_action?action=register",
            {"user": "äSTER", "pwd": self.password, "repassword": self.password},
        )
        self.assertEqual(collision.status_code, 409, collision.content)

        created = self.client.post(
            "/api/user_action?action=register",
            {"user": "ＮｅｗＵｓｅｒ", "pwd": self.password, "repassword": self.password},
        )
        self.assertEqual(created.status_code, 200, created.content)
        user = UserProfile.objects.get(username_canonical=b"newuser")
        self.assertEqual(user.username, "NewUser")

    def test_oidc_allocator_never_returns_a_canonical_collision(self):
        claims = {"preferred_username": "äSTER", "sub": "subject-a"}
        allocated = _oidc_local_username(claims, "https://issuer.example", "subject-a")
        self.assertNotEqual(canonical_username_key(allocated), bytes(self.user.username_canonical))
        self.assertRegex(allocated, r"^äSTER-[0-9a-f]{10}$")

    def test_queryset_and_bulk_paths_cannot_split_display_and_authority(self):
        UserProfile.objects.filter(pk=self.user.pk).update(username="Ｓtraße")
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, "Straße")
        self.assertEqual(bytes(self.user.username_canonical), b"strasse")

        bulk = UserProfile(username="Ｂulk")
        UserProfile.objects.bulk_create([bulk])
        bulk.refresh_from_db()
        self.assertEqual(bulk.username, "Bulk")
        self.assertEqual(bytes(bulk.username_canonical), b"bulk")

        bulk.username = "Σigma"
        UserProfile.objects.bulk_update([bulk], ["username"])
        bulk.refresh_from_db()
        self.assertEqual(bytes(bulk.username_canonical), canonical_username_key("ςIGMA"))

        with self.assertRaisesMessage(ValueError, "cannot be updated independently"):
            UserProfile.objects.filter(pk=self.user.pk).update(username_canonical=b"attacker-controlled")
        with self.assertRaisesMessage(ValueError, "cannot be updated independently"):
            UserProfile.objects.bulk_update([bulk], ["username_canonical"])

    def test_full_identity_check_detects_raw_drift_without_logging_username(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE api_userprofile SET username_canonical = %s WHERE id = %s",
                [b"raw-drift", self.user.pk],
            )
        with self.assertRaises(UsernameIdentityError) as captured:
            check_username_identity(full=True)
        self.assertIn(f"id={self.user.pk}", str(captured.exception))
        self.assertNotIn(self.user.username, str(captured.exception))

        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE api_userprofile SET username_canonical = %s WHERE id = %s",
                [canonical_username_key(self.user.username), self.user.pk],
            )
        call_command("check_username_identity", verbosity=0)

    def test_database_authority_rejects_a_null_canonical_key(self):
        with self.assertRaises(IntegrityError), transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                "UPDATE api_userprofile SET username_canonical = NULL WHERE id = %s",
                [self.user.pk],
            )

    def test_readiness_fails_closed_when_identity_contract_fails(self):
        from api import views_api

        with patch.object(
            views_api,
            "check_username_identity",
            side_effect=UsernameIdentityError("drift"),
        ) as identity_check:
            response = self.client.get("/health/ready")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"status": "not_ready"})
        identity_check.assert_called_once_with(full=False)

    def test_fast_identity_check_validates_the_database_authority(self):
        with (
            patch.object(connection.introspection, "get_constraints", return_value={}),
            self.assertRaisesMessage(UsernameIdentityError, "database authority is invalid"),
        ):
            check_username_identity(full=False)


class PostgreSQLUsernameIdentityContractTests(TestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_database_uses_the_frozen_builtin_collation_contract(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL-only database contract")
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    current_setting('server_encoding'),
                    datlocprovider,
                    datlocale,
                    datcollversion,
                    pg_database_collation_actual_version(oid)
                FROM pg_database
                WHERE datname = current_database()
                """
            )
            observed = cursor.fetchone()
        self.assertEqual(
            observed,
            (
                POSTGRES_ENCODING,
                POSTGRES_LOCALE_PROVIDER,
                POSTGRES_LOCALE,
                POSTGRES_COLLATION_VERSION,
                POSTGRES_COLLATION_VERSION,
            ),
        )
        check_username_identity(full=True)


class UsernameIdentityMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0025_oidc_callback_claims")
    migrate_to = ("api", "0026_username_canonical_identity")

    def test_migration_reports_collisions_without_merging_or_disclosing_names(self):
        executor = MigrationExecutor(connection)
        first_id = None
        second_id = None
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            LegacyUser = old_apps.get_model("api", "UserProfile")
            first = LegacyUser._base_manager.create(username="Straße")
            second = LegacyUser._base_manager.create(username="STRASSE")
            first_id = first.pk
            second_id = second.pk

            with self.assertRaises(RuntimeError) as captured:
                MigrationExecutor(connection).migrate([self.migrate_to])
            message = str(captured.exception)
            self.assertIn(f"{first_id},{second_id}", message)
            self.assertIn("collisions=1", message)
            self.assertNotIn("Straße", message)
            self.assertNotIn("STRASSE", message)
            self.assertEqual(LegacyUser._base_manager.filter(pk__in=(first_id, second_id)).count(), 2)

            LegacyUser._base_manager.filter(pk=second_id).delete()
            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            current_apps = executor.loader.project_state([self.migrate_to]).apps
            migrated = current_apps.get_model("api", "UserProfile")._base_manager.get(pk=first_id)
            self.assertEqual(bytes(migrated.username_canonical), b"strasse")
        finally:
            restore_latest_migration_state()
