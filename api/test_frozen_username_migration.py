import importlib

from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from api.migration_test_support import restore_latest_migration_state
from api.models import UserProfile
from api.username_identity import UsernameIdentityError, canonical_username_key, check_username_identity


class FrozenUsernameMigrationTests(TransactionTestCase):
    old_target = ("api", "0033_mutation_generations")
    new_target = ("api", "0034_frozen_username_identity")

    def setUp(self):
        super().setUp()
        executor = MigrationExecutor(connection)
        executor.migrate([self.old_target])
        self.LegacyUser = executor.loader.project_state([self.old_target]).apps.get_model("api", "UserProfile")
        self.created_ids = []

    def tearDown(self):
        self.LegacyUser._base_manager.filter(pk__in=self.created_ids).delete()
        restore_latest_migration_state()
        super().tearDown()

    def create_legacy(self, username, key, **fields):
        user = self.LegacyUser._base_manager.create(username=username, username_canonical=key, **fields)
        self.created_ids.append(user.pk)
        return user

    def test_repairs_arbitrary_key_swaps_without_changing_principal_or_generation(self):
        alpha = self.create_legacy("Alpha", b"beta", credential_generation=3, mutation_generation=9)
        beta = self.create_legacy("Beta", b"alpha")
        original_principal_id = alpha.pk
        with self.assertRaisesMessage(UsernameIdentityError, "migration is not applied"):
            check_username_identity()
        MigrationExecutor(connection).migrate([self.new_target])
        alpha = UserProfile._base_manager.get(pk=alpha.pk)
        beta = UserProfile._base_manager.get(pk=beta.pk)
        self.assertEqual(bytes(alpha.username_canonical), b"alpha")
        self.assertEqual(bytes(beta.username_canonical), b"beta")
        self.assertEqual(alpha.pk, original_principal_id)
        self.assertEqual((alpha.credential_generation, alpha.mutation_generation), (3, 9))
        check_username_identity(full=True)
        MigrationExecutor(connection).migrate([self.old_target])
        self.assertEqual(bytes(self.LegacyUser._base_manager.get(pk=alpha.pk).username_canonical), b"alpha")
        MigrationExecutor(connection).migrate([self.new_target])
        check_username_identity(full=True)

    def test_collision_preflight_preserves_all_rows_and_can_be_reentered_after_explicit_resolution(self):
        untouched = self.create_legacy("Untouched", b"old-untouched")
        first = self.create_legacy("\u1c89", b"old-upper")
        second = self.create_legacy("\u1c8a", b"old-lower")
        with self.assertRaises(RuntimeError) as captured:
            MigrationExecutor(connection).migrate([self.new_target])
        message = str(captured.exception)
        self.assertIn("collisions=1", message)
        self.assertIn(f"{first.pk},{second.pk}", message)
        self.assertNotIn("\u1c89", message)
        self.assertNotIn("\u1c8a", message)
        self.assertEqual(bytes(self.LegacyUser._base_manager.get(pk=untouched.pk).username_canonical), b"old-untouched")
        self.assertEqual(bytes(self.LegacyUser._base_manager.get(pk=first.pk).username_canonical), b"old-upper")
        self.assertTrue(self.LegacyUser._base_manager.filter(pk=second.pk).exists())
        self.LegacyUser._base_manager.filter(pk=second.pk).delete()
        MigrationExecutor(connection).migrate([self.new_target])
        self.assertEqual(
            bytes(UserProfile._base_manager.get(pk=first.pk).username_canonical), canonical_username_key("\u1c89")
        )
        check_username_identity(full=True)

    def test_invalid_or_unnormalized_display_name_is_not_silently_changed(self):
        valid = self.create_legacy("Valid", b"old-valid")
        invalid = self.create_legacy("Ａlice", b"old-invalid")
        with self.assertRaises(RuntimeError) as captured:
            MigrationExecutor(connection).migrate([self.new_target])
        self.assertIn("invalid=1", str(captured.exception))
        self.assertNotIn("Ａlice", str(captured.exception))
        self.assertEqual(bytes(self.LegacyUser._base_manager.get(pk=valid.pk).username_canonical), b"old-valid")
        self.assertEqual(self.LegacyUser._base_manager.get(pk=invalid.pk).username, "Ａlice")

    def test_collision_in_later_batch_is_detected_before_any_existing_key_changes(self):
        first = self.create_legacy("First", b"old-first")
        # Keep the real production batch size: detect both cross-batch lookup
        # failures and SQLite parameter limits rather than mocking the batcher.
        for index in range(500):
            self.create_legacy(f"User{index}", f"old-{index}".encode())
        last = self.create_legacy("FIRST", b"old-last")
        with self.assertRaises(RuntimeError) as captured:
            MigrationExecutor(connection).migrate([self.new_target])
        self.assertIn("collisions=1", str(captured.exception))
        self.assertIn(f"{first.pk},{last.pk}", str(captured.exception))
        self.assertEqual(bytes(self.LegacyUser._base_manager.get(pk=first.pk).username_canonical), b"old-first")
        self.LegacyUser._base_manager.filter(pk=last.pk).delete()
        MigrationExecutor(connection).migrate([self.new_target])
        check_username_identity(full=True)

    def test_schema_failure_rolls_back_keys_unique_authority_and_migration_record(self):
        user = self.create_legacy("Atomic", b"old-atomic")

        def fail_recreate(execute, sql, params, many, context):
            if '"unique_username_canonical_binary"' in sql and (
                sql.startswith("CREATE UNIQUE INDEX") or sql.startswith("ALTER TABLE") and "ADD CONSTRAINT" in sql
            ):
                raise RuntimeError("injected unique authority failure")
            return execute(sql, params, many, context)

        with connection.execute_wrapper(fail_recreate), self.assertRaisesMessage(RuntimeError, "injected unique"):
            MigrationExecutor(connection).migrate([self.new_target])
        self.assertEqual(bytes(self.LegacyUser._base_manager.get(pk=user.pk).username_canonical), b"old-atomic")
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(cursor, "api_userprofile")
            self.assertTrue(constraints["unique_username_canonical_binary"]["unique"])
            cursor.execute("SELECT 1 FROM django_migrations WHERE app = %s AND name = %s", self.new_target)
            self.assertIsNone(cursor.fetchone())
        with self.assertRaises(IntegrityError), transaction.atomic():
            self.create_legacy("DuplicateKey", b"old-atomic")
        MigrationExecutor(connection).migrate([self.new_target])
        check_username_identity(full=True)

    def test_noop_repair_keeps_authority_and_requires_frozen_data_even_for_empty_table(self):
        from unittest.mock import patch

        migration = importlib.import_module("api.migrations.0034_frozen_username_identity")
        self.assertFalse(self.LegacyUser._base_manager.exists())
        with (
            patch.object(migration, "require_unicode_version", side_effect=UsernameIdentityError("bad data")),
            self.assertRaisesMessage(UsernameIdentityError, "bad data"),
        ):
            MigrationExecutor(connection).migrate([self.new_target])
        MigrationExecutor(connection).migrate([self.new_target])
        check_username_identity(full=True)
