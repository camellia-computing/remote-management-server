from django.contrib.auth.hashers import make_password
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from api.migration_test_support import restore_latest_migration_state


class AddressBookRuleTargetMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0027_address_book_scope_authority")
    migrate_to = ("api", "0028_address_book_rule_target_authority")

    def test_pollution_is_reported_and_clean_rules_gain_reversible_target_authority(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            User = old_apps.get_model("api", "UserProfile")
            Profile = old_apps.get_model("api", "AddressBookProfile")
            Rule = old_apps.get_model("api", "AddressBookRule")
            Group = old_apps.get_model("auth", "Group")

            owner = User.objects.create(
                username="rule-migration-owner",
                username_canonical=b"rule-migration-owner",
                password=make_password(None),
            )
            target_user = User.objects.create(
                username="rule-migration-user",
                username_canonical=b"rule-migration-user",
                password=make_password(None),
            )
            group = Group.objects.create(name="rule-migration-group")
            profile = Profile.objects.create(
                owner=owner,
                guid="rule-migration-profile",
                name="Rule migration profile",
            )

            stale_user = Rule.objects.create(
                profile=profile,
                user=target_user,
                rule=1,
                target_key="stale-user",
            )
            duplicate_user = Rule.objects.create(
                profile=profile,
                user=target_user,
                rule=3,
                target_key=f"user:{target_user.pk}",
            )
            stale_group = Rule.objects.create(
                profile=profile,
                group=group,
                rule=1,
                target_key="stale-group",
            )
            duplicate_group = Rule.objects.create(
                profile=profile,
                group=group,
                rule=3,
                target_key=f"group:{group.pk}",
            )
            stale_everyone = Rule.objects.create(
                profile=profile,
                is_everyone=True,
                rule=1,
                target_key="stale-everyone",
            )
            duplicate_everyone = Rule.objects.create(
                profile=profile,
                is_everyone=True,
                rule=3,
                target_key="everyone",
            )

            with self.assertRaises(RuntimeError) as captured:
                MigrationExecutor(connection).migrate([self.migrate_to])
            message = str(captured.exception)
            for row in (stale_user, stale_group, stale_everyone):
                self.assertIn(str(row.pk), message)
            self.assertIn(f"duplicate_user_ids={duplicate_user.pk}", message)
            self.assertIn(f"duplicate_group_ids={duplicate_group.pk}", message)
            self.assertIn(f"duplicate_everyone_ids={duplicate_everyone.pk}", message)
            self.assertNotIn(owner.username, message)
            self.assertNotIn(target_user.username, message)
            self.assertNotIn(group.name, message)

            Rule.objects.filter(pk__in=(stale_user.pk, stale_group.pk, stale_everyone.pk)).delete()
            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            current_apps = executor.loader.project_state([self.migrate_to]).apps
            CurrentRule = current_apps.get_model("api", "AddressBookRule")
            self.assertNotIn("target_key", {field.name for field in CurrentRule._meta.fields})
            self._assert_target_constraints(CurrentRule, profile, target_user, group)

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_from])
            restored_apps = executor.loader.project_state([self.migrate_from]).apps
            RestoredRule = restored_apps.get_model("api", "AddressBookRule")
            self.assertEqual(
                RestoredRule.objects.get(pk=duplicate_user.pk).target_key,
                f"user:{target_user.pk}",
            )
            self.assertEqual(
                RestoredRule.objects.get(pk=duplicate_group.pk).target_key,
                f"group:{group.pk}",
            )
            self.assertEqual(
                RestoredRule.objects.get(pk=duplicate_everyone.pk).target_key,
                "everyone",
            )
            with connection.cursor() as cursor:
                columns = {
                    column.name
                    for column in connection.introspection.get_table_description(cursor, "api_addressbookrule")
                }
            self.assertIn("target_key", columns)

            MigrationExecutor(connection).migrate([self.migrate_to])
        finally:
            restore_latest_migration_state()

    def _assert_target_constraints(self, Rule, profile, target_user, group):
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(cursor, "api_addressbookrule")
            columns = {
                column.name for column in connection.introspection.get_table_description(cursor, "api_addressbookrule")
            }
        self.assertNotIn("target_key", columns)
        for name in (
            "unique_ab_rule_profile_user",
            "unique_ab_rule_profile_group",
            "unique_ab_rule_profile_everyone",
        ):
            self.assertIn(name, constraints)
            self.assertTrue(constraints[name]["unique"])

        cases = (
            {"user_id": target_user.pk},
            {"group_id": group.pk},
            {"is_everyone": True},
        )
        for target_fields in cases:
            with self.assertRaises(IntegrityError):
                with transaction.atomic():
                    Rule.objects.bulk_create(
                        [
                            Rule(
                                profile_id=profile.pk,
                                rule=2,
                                **target_fields,
                            )
                        ]
                    )
