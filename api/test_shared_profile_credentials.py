import json
from io import StringIO

from django.conf import settings as project_settings
from django.core.management import call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext

from api.encrypted_fields import FIELD_PREFIX
from api.models import AddressBookProfile, AddressBookShare, RemoteDevice, RemotePeer, UserProfile
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


@override_settings(STORAGES=TEST_STORAGES)
class SharedProfileCredentialTests(TestCase):
    def setUp(self):
        self.owner = UserProfile.objects.create_user(username="credential-owner", password="owner-pass")
        self.reader = UserProfile.objects.create_user(username="credential-reader", password="reader-pass")
        self.outsider = UserProfile.objects.create_user(username="credential-outsider", password="outsider-pass")
        self.owner_token = self._token(self.owner, "730000001", "owner-device")
        self.reader_token = self._token(self.reader, "730000002", "reader-device")
        self.outsider_token = self._token(self.outsider, "730000003", "outsider-device")

    @staticmethod
    def _token(user, rid, uuid_value):
        device = RemoteDevice.objects.create(
            rid=rid,
            uuid=uuid_value,
            owner=user,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="linux",
            username="",
            version="-",
        )
        return _issue_access_token(user, device)[1]

    def post_json(self, path, payload, token):
        return self.client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    def put_json(self, path, payload, token):
        return self.client.put(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    def assert_never_stored(self, response):
        self.assertEqual(response.headers.get("Cache-Control"), "no-store, private")
        self.assertEqual(response.headers.get("Pragma"), "no-cache")
        self.assertEqual(response.headers.get("Expires"), "0")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")

    def create_profile(self, *, name="Encrypted team", password=None):
        if password is None:
            password = "default-password-canary"
        response = self.post_json(
            "/api/ab/shared/add",
            {
                "name": name,
                "note": "credential regression",
                "info": {"theme": "dark"},
                "default_password": password,
            },
            self.owner_token,
        )
        self.assertEqual(response.status_code, 200, response.content)
        return AddressBookProfile.objects.get(guid=response.json()["guid"])

    def test_default_password_is_encrypted_at_rest_and_absent_from_profile_lists(self):
        canary = "shared-default-password-canary"
        profile = self.create_profile(password=canary)

        self.assertEqual(profile.default_password, canary)
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT info, default_password FROM api_addressbookprofile WHERE id = %s",
                [profile.pk],
            )
            raw_info, raw_password = cursor.fetchone()
        self.assertNotIn(canary, json.dumps(raw_info, sort_keys=True))
        self.assertTrue(raw_password.startswith(f"{FIELD_PREFIX}{project_settings.DATA_ENCRYPTION_PRIMARY_KEY_ID}:"))
        self.assertNotIn(canary, raw_password)

        with CaptureQueriesContext(connection) as captured:
            profiles = self.post_json("/api/ab/shared/profiles", {}, self.owner_token)
        self.assertEqual(profiles.status_code, 200, profiles.content)
        self.assertNotIn(canary.encode(), profiles.content)
        self.assertEqual(profiles.json()["data"][0]["info"], {"theme": "dark"})
        selected_sql = "\n".join(query["sql"] for query in captured.captured_queries)
        self.assertNotIn('"api_addressbookprofile"."default_password"', selected_sql)
        self.assert_never_stored(profiles)

    def test_generic_info_rejects_credential_keys_at_any_depth(self):
        forbidden_values = (
            {"password": "top-level-secret"},
            {"nested": {"credential": "nested-secret"}},
            [{"TOKEN": "case-insensitive-secret"}],
        )
        for index, info in enumerate(forbidden_values):
            with self.subTest(info=info):
                name = f"Forbidden credentials {index}"
                response = self.post_json(
                    "/api/ab/shared/add",
                    {"name": name, "info": info},
                    self.owner_token,
                )
                self.assertEqual(response.status_code, 400, response.content)
                self.assertFalse(AddressBookProfile.objects.filter(owner=self.owner, name=name).exists())

    def test_default_password_update_has_keep_replace_and_clear_semantics(self):
        profile = self.create_profile(password="initial-default-password")

        kept = self.put_json(
            "/api/ab/shared/update/profile",
            {"guid": profile.guid, "note": "keep the credential", "info": {"theme": "light"}},
            self.owner_token,
        )
        self.assertEqual(kept.status_code, 200, kept.content)
        profile.refresh_from_db()
        self.assertEqual(profile.default_password, "initial-default-password")
        self.assertEqual(profile.info, {"theme": "light"})

        replaced = self.put_json(
            "/api/ab/shared/update/profile",
            {"guid": profile.guid, "default_password": "replacement-default-password"},
            self.owner_token,
        )
        self.assertEqual(replaced.status_code, 200, replaced.content)
        profile.refresh_from_db()
        self.assertEqual(profile.default_password, "replacement-default-password")

        cleared = self.put_json(
            "/api/ab/shared/update/profile",
            {"guid": profile.guid, "default_password": ""},
            self.owner_token,
        )
        self.assertEqual(cleared.status_code, 200, cleared.content)
        profile.refresh_from_db()
        self.assertEqual(profile.default_password, "")
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT default_password FROM api_addressbookprofile WHERE id = %s",
                [profile.pk],
            )
            self.assertEqual(cursor.fetchone()[0], "")

    def test_target_bound_runtime_retrieval_rechecks_current_profile_access(self):
        canary = "target-bound-default-password"
        profile = self.create_profile(password=canary)
        RemotePeer.objects.create(profile=profile, rid="740000001", alias="allowed target")

        outsider = self.post_json(
            "/api/ab/shared/credential",
            {"guid": profile.guid, "id": "740000001"},
            self.outsider_token,
        )
        self.assertEqual(outsider.status_code, 403, outsider.content)
        self.assertNotIn(canary.encode(), outsider.content)
        self.assert_never_stored(outsider)

        AddressBookShare.objects.create(profile=profile, user=self.reader, rule=1)
        missing_target = self.post_json(
            "/api/ab/shared/credential",
            {"guid": profile.guid, "id": "740000002"},
            self.reader_token,
        )
        self.assertEqual(missing_target.status_code, 404, missing_target.content)
        self.assertNotIn(canary.encode(), missing_target.content)

        retrieved = self.post_json(
            "/api/ab/shared/credential",
            {"guid": profile.guid, "id": "740000001"},
            self.reader_token,
        )
        self.assertEqual(retrieved.status_code, 200, retrieved.content)
        self.assertEqual(retrieved.json(), {"password": canary})
        self.assert_never_stored(retrieved)

        AddressBookShare.objects.filter(profile=profile, user=self.reader).delete()
        revoked = self.post_json(
            "/api/ab/shared/credential",
            {"guid": profile.guid, "id": "740000001"},
            self.reader_token,
        )
        self.assertEqual(revoked.status_code, 403, revoked.content)
        self.assertNotIn(canary.encode(), revoked.content)

    def test_runtime_retrieval_fails_closed_for_empty_or_tampered_credentials(self):
        profile = self.create_profile(password="")
        RemotePeer.objects.create(profile=profile, rid="750000001")
        empty = self.post_json(
            "/api/ab/shared/credential",
            {"guid": profile.guid, "id": "750000001"},
            self.owner_token,
        )
        self.assertEqual(empty.status_code, 404, empty.content)

        profile.default_password = "authenticated-password"
        profile.save(update_fields=("default_password", "updated_at"))
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE api_addressbookprofile SET default_password = %s WHERE id = %s",
                [f"{FIELD_PREFIX}{project_settings.DATA_ENCRYPTION_PRIMARY_KEY_ID}:AAAA", profile.pk],
            )
        previous = self.client.raise_request_exception
        self.client.raise_request_exception = False
        try:
            tampered = self.post_json(
                "/api/ab/shared/credential",
                {"guid": profile.guid, "id": "750000001"},
                self.owner_token,
            )
        finally:
            self.client.raise_request_exception = previous
        self.assertEqual(tampered.status_code, 500, tampered.content)
        self.assertNotIn(b"authenticated-password", tampered.content)

    def test_admin_never_renders_the_decrypted_default_password(self):
        profile = self.create_profile(password="admin-form-password-canary")
        admin_user = UserProfile.objects.create_superuser(username="credential-admin", password="admin-pass")
        self.client.force_login(admin_user)

        response = self.client.get(f"/admin/api/addressbookprofile/{profile.pk}/change/")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotContains(response, "admin-form-password-canary")
        self.assertContains(response, 'autocomplete="new-password"')

    def test_key_rotation_includes_shared_profile_default_password(self):
        profile = self.create_profile(password="rotation-profile-password")
        old_key_id = project_settings.DATA_ENCRYPTION_PRIMARY_KEY_ID
        old_key = project_settings.DATA_ENCRYPTION_KEYS[old_key_id]
        new_key_id = "profile-credential-rotation"
        new_key = b"q" * 32

        with override_settings(
            DATA_ENCRYPTION_KEY_BYTES=new_key,
            DATA_ENCRYPTION_KEYS={old_key_id: old_key, new_key_id: new_key},
            DATA_ENCRYPTION_PRIMARY_KEY_ID=new_key_id,
            DATA_ENCRYPTION_V1_KEY_ID=old_key_id,
        ):
            call_command("rotate_data_encryption", stdout=StringIO())

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT default_password FROM api_addressbookprofile WHERE id = %s",
                [profile.pk],
            )
            raw_password = cursor.fetchone()[0]
        self.assertTrue(raw_password.startswith(f"{FIELD_PREFIX}{new_key_id}:"))
        self.assertNotIn("rotation-profile-password", raw_password)


class SharedProfileCredentialMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0009_addressbookprofile_authorization_generation")
    migrate_to = ("api", "0010_addressbookprofile_default_password")

    def test_forward_and_reverse_migration_move_legacy_json_password_without_plaintext_storage(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            OldUser = old_apps.get_model("api", "UserProfile")
            OldProfile = old_apps.get_model("api", "AddressBookProfile")
            owner = OldUser.objects.create(username="legacy-profile-owner", is_active=True)
            profile = OldProfile.objects.create(
                owner_id=owner.pk,
                guid="legacy-default-credential",
                name="Legacy default credential",
                info={"password": "legacy-json-password", "theme": "dark"},
                rule=3,
            )

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            NewProfile = new_apps.get_model("api", "AddressBookProfile")
            migrated = NewProfile.objects.get(pk=profile.pk)
            self.assertEqual(migrated.info, {"theme": "dark"})
            self.assertEqual(migrated.default_password, "legacy-json-password")
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT info, default_password FROM api_addressbookprofile WHERE id = %s",
                    [profile.pk],
                )
                raw_info, raw_password = cursor.fetchone()
            self.assertNotIn("legacy-json-password", json.dumps(raw_info, sort_keys=True))
            self.assertTrue(raw_password.startswith(FIELD_PREFIX))
            self.assertNotIn("legacy-json-password", raw_password)

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_from])
            restored_apps = executor.loader.project_state([self.migrate_from]).apps
            RestoredProfile = restored_apps.get_model("api", "AddressBookProfile")
            self.assertEqual(
                RestoredProfile.objects.get(pk=profile.pk).info,
                {"password": "legacy-json-password", "theme": "dark"},
            )
        finally:
            MigrationExecutor(connection).migrate([self.migrate_to])
