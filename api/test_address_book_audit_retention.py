import json
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.db import connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase, override_settings

from api.models import AddressBookProfile, AddressBookRuleAudit, AddressBookShare, RemoteDevice, UserProfile
from api.views_api import _audit_ab_rule, _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


@override_settings(STORAGES=TEST_STORAGES)
class AddressBookAuditRetentionTests(TestCase):
    def setUp(self):
        self.owner = UserProfile.objects.create_user(  # noqa: S106 - isolated test credential
            username="audit-retention-owner",
            password="owner-pass",  # noqa: S106
        )
        self.target = UserProfile.objects.create_user(  # noqa: S106 - isolated test credential
            username="audit-retention-target",
            password="target-pass",  # noqa: S106
        )
        self.profile = AddressBookProfile.objects.create(
            guid="audit-retention-profile",
            name="Retention profile",
            owner=self.owner,
            rule=3,
        )
        device = RemoteDevice.objects.create(
            rid="760000001",
            uuid="audit-retention-device",
            owner=self.owner,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="linux",
            username="",
            version="-",
        )
        self.token = _issue_access_token(self.owner, device)[1]

    def post_json(self, path, payload):
        return self.client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    def delete_json(self, path, payload):
        return self.client.delete(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    def test_audit_snapshots_profile_and_accepts_max_group_name(self):
        group_name = "g" * 150
        group = Group.objects.create(name=group_name)

        _audit_ab_rule(
            self.profile,
            self.owner,
            "rule_add",
            "group",
            group.name,
            1,
            {"source": "retention-test"},
        )

        audit = AddressBookRuleAudit.objects.get(action="rule_add")
        self.assertEqual(audit.profile_guid, self.profile.guid)
        self.assertEqual(audit.profile_name, self.profile.name)
        self.assertEqual(audit.profile_owner_name, self.owner.username)
        self.assertEqual(audit.target_name, group_name)

    def test_profile_delete_preserves_history_and_writes_tombstone(self):
        _audit_ab_rule(self.profile, self.owner, "rule_add", "user", self.target.username, 2)
        profile_pk = self.profile.pk
        profile_guid = self.profile.guid
        self.profile._audit_actor = self.owner
        self.profile.delete()

        audits = list(AddressBookRuleAudit.objects.order_by("action", "pk"))
        self.assertEqual([audit.action for audit in audits], ["profile_delete", "rule_add"])
        for audit in audits:
            self.assertIsNone(audit.profile_id)
            self.assertEqual(audit.profile_guid, profile_guid)
            self.assertEqual(audit.profile_name, "Retention profile")
            self.assertEqual(audit.profile_owner_name, self.owner.username)
        tombstone = next(audit for audit in audits if audit.action == "profile_delete")
        self.assertEqual(tombstone.actor_id, self.owner.pk)
        self.assertEqual(tombstone.target_type, "profile")
        self.assertEqual(tombstone.target_name, "Retention profile")
        self.assertFalse(AddressBookProfile.objects.filter(pk=profile_pk).exists())

    def test_api_profile_delete_records_actor_and_snapshot(self):
        response = self.delete_json("/api/ab/shared", [self.profile.guid])
        self.assertEqual(response.status_code, 200, response.content)
        tombstone = AddressBookRuleAudit.objects.get(action="profile_delete")
        self.assertEqual(tombstone.actor_id, self.owner.pk)
        self.assertEqual(tombstone.profile_guid, "audit-retention-profile")
        self.assertIsNone(tombstone.profile_id)

    def test_web_profile_delete_records_actor_and_snapshot(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            "/api/ab_books",
            {"action": "delete_book", "guid": self.profile.guid},
        )

        self.assertEqual(response.status_code, 302, response.content)
        tombstone = AddressBookRuleAudit.objects.get(action="profile_delete")
        self.assertEqual(tombstone.actor_id, self.owner.pk)
        self.assertEqual(tombstone.profile_guid, "audit-retention-profile")
        self.assertIsNone(tombstone.profile_id)

    def test_owner_cascade_delete_still_preserves_profile_tombstone(self):
        cascade_owner = UserProfile.objects.create_user(username="audit-cascade-owner")
        cascade_profile = AddressBookProfile.objects.create(
            guid="audit-cascade-profile",
            name="Cascade profile",
            owner=cascade_owner,
            rule=3,
        )

        cascade_owner.delete()

        tombstone = AddressBookRuleAudit.objects.get(action="profile_delete", profile_guid=cascade_profile.guid)
        self.assertIsNone(tombstone.profile_id)
        self.assertIsNone(tombstone.actor_id)
        self.assertEqual(tombstone.profile_name, "Cascade profile")
        self.assertEqual(tombstone.profile_owner_name, "audit-cascade-owner")

    def test_acl_audit_failure_rolls_back_share_mutation(self):
        with patch("api.views_api._audit_ab_rule", side_effect=RuntimeError("audit sink unavailable")):
            previous = self.client.raise_request_exception
            self.client.raise_request_exception = False
            try:
                response = self.post_json(
                    "/api/ab/rule",
                    {"guid": self.profile.guid, "user": self.target.username, "rule": 2},
                )
            finally:
                self.client.raise_request_exception = previous

        self.assertEqual(response.status_code, 500, response.content)
        self.assertFalse(AddressBookShare.objects.filter(profile=self.profile, user=self.target).exists())
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 0)

    def test_profile_delete_audit_failure_rolls_back_profile_delete(self):
        with patch("api.address_book_authorization.record_profile_tombstone", side_effect=OSError("audit unavailable")):
            with transaction.atomic(), self.assertRaises(OSError):
                self.profile.delete()

        self.assertTrue(AddressBookProfile.objects.filter(pk=self.profile.pk).exists())

    def test_admin_can_view_but_cannot_mutate_audit_history(self):
        _audit_ab_rule(self.profile, self.owner, "rule_add", "user", self.target.username, 1)
        audit = AddressBookRuleAudit.objects.get(action="rule_add")
        admin_user = UserProfile.objects.create_superuser(
            username="audit-retention-admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
        )
        self.client.force_login(admin_user)

        path = f"/admin/api/addressbookruleaudit/{audit.pk}/change/"
        view_response = self.client.get(path)
        mutation_response = self.client.post(path, {"action": "rule_delete"})

        self.assertEqual(view_response.status_code, 200, view_response.content)
        self.assertEqual(mutation_response.status_code, 403, mutation_response.content)
        audit.refresh_from_db()
        self.assertEqual(audit.action, "rule_add")


class AddressBookAuditMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0010_addressbookprofile_default_password")
    migrate_to = ("api", "0011_remove_addressbookruleaudit_valid_address_book_audit_target_and_more")

    def test_migration_backfills_snapshots_and_retains_history_after_profile_delete(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            OldUser = old_apps.get_model("api", "UserProfile")
            OldProfile = old_apps.get_model("api", "AddressBookProfile")
            OldAudit = old_apps.get_model("api", "AddressBookRuleAudit")
            owner = OldUser.objects.create(username="audit-migration-owner", is_active=True)
            profile = OldProfile.objects.create(
                owner_id=owner.pk,
                guid="audit-migration-profile",
                name="Migrated profile",
                rule=3,
            )
            audit = OldAudit.objects.create(
                profile_id=profile.pk,
                actor_id=owner.pk,
                action="rule_add",
                target_type="user",
                target_name="legacy-target",
                rule=1,
            )

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            NewProfile = new_apps.get_model("api", "AddressBookProfile")
            NewAudit = new_apps.get_model("api", "AddressBookRuleAudit")
            migrated = NewAudit.objects.get(pk=audit.pk)
            self.assertEqual(migrated.profile_guid, "audit-migration-profile")
            self.assertEqual(migrated.profile_name, "Migrated profile")
            self.assertEqual(migrated.profile_owner_name, "audit-migration-owner")

            NewProfile.objects.get(pk=profile.pk).delete()
            retained = NewAudit.objects.get(pk=audit.pk)
            self.assertIsNone(retained.profile_id)
            self.assertEqual(retained.profile_guid, "audit-migration-profile")
        finally:
            MigrationExecutor(connection).migrate([self.migrate_to])
