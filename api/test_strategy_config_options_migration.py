import json
import uuid

from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

from api.migration_test_support import restore_latest_migration_state


class StrategyConfigOptionsMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0028_address_book_rule_target_authority")
    migrate_to = ("api", "0029_strategy_config_options_authority")

    def test_pollution_is_reported_and_clean_schema_gains_reversible_authority(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            Strategy = old_apps.get_model("api", "StrategyProfile")
            invalid_rows = [
                Strategy.objects.create(
                    name="migration-invalid-list",
                    config_options=["not-an-object"],
                ),
                Strategy.objects.create(
                    name="migration-invalid-value",
                    config_options={"private-option": ["private-value"]},
                ),
                Strategy.objects.create(
                    name="migration-invalid-items",
                    config_options={f"key-{index}": "value" for index in range(513)},
                ),
                Strategy.objects.create(
                    name="migration-invalid-bytes",
                    config_options={f"key-{index}": "v" * 4096 for index in range(16)},
                ),
            ]

            with self.assertRaises(RuntimeError) as captured:
                MigrationExecutor(connection).migrate([self.migrate_to])
            message = str(captured.exception)
            for strategy in invalid_rows:
                self.assertIn(str(strategy.pk), message)
                self.assertNotIn(strategy.name, message)
            self.assertNotIn("private-option", message)
            self.assertNotIn("private-value", message)

            Strategy.objects.filter(pk__in=[strategy.pk for strategy in invalid_rows]).delete()
            valid = Strategy.objects.create(
                name="migration-valid-boundary",
                config_options={
                    "😀" * 128: "😀" * 4096,
                    **{f"key-{index}": "value" for index in range(511)},
                },
            )
            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            self._assert_authority_installed()
            self._assert_invalid_raw_writes_are_rejected()

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_from])
            self._assert_authority_removed()
            self._insert_raw("migration-reverse-invalid", {"mode": ["allowed-after-reverse"]})
            restored_apps = executor.loader.project_state([self.migrate_from]).apps
            RestoredStrategy = restored_apps.get_model("api", "StrategyProfile")
            RestoredStrategy.objects.filter(name="migration-reverse-invalid").delete()
            self.assertEqual(
                RestoredStrategy.objects.get(pk=valid.pk).config_options["😀" * 128],
                "😀" * 4096,
            )

            MigrationExecutor(connection).migrate([self.migrate_to])
        finally:
            restore_latest_migration_state()

    def _assert_authority_installed(self):
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute(
                    """
                    SELECT constraint_name
                    FROM information_schema.table_constraints
                    WHERE table_schema = 'public'
                      AND table_name = 'api_strategyprofile'
                      AND constraint_name = 'valid_strategy_config_options_v1'
                      AND constraint_type = 'CHECK'
                    """
                )
                self.assertEqual(cursor.fetchone(), ("valid_strategy_config_options_v1",))
                cursor.execute(
                    """
                    SELECT convalidated
                    FROM pg_constraint
                    WHERE conname = 'valid_strategy_config_options_v1'
                      AND conrelid = 'public.api_strategyprofile'::regclass
                    """
                )
                self.assertEqual(cursor.fetchone(), (True,))
            else:
                cursor.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'trigger'
                      AND name IN (
                          'api_strategy_options_insert_guard',
                          'api_strategy_options_update_guard'
                      )
                    ORDER BY name
                    """
                )
                self.assertEqual(
                    cursor.fetchall(),
                    [
                        ("api_strategy_options_insert_guard",),
                        ("api_strategy_options_update_guard",),
                    ],
                )

    def _assert_authority_removed(self):
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute(
                    """
                    SELECT count(*)
                    FROM pg_constraint
                    WHERE conname = 'valid_strategy_config_options_v1'
                      AND conrelid = 'public.api_strategyprofile'::regclass
                    """
                )
                self.assertEqual(cursor.fetchone(), (0,))
                cursor.execute(
                    """
                    SELECT count(*)
                    FROM pg_proc
                    WHERE proname = 'camellia_strategy_options_valid_v1'
                      AND pronamespace = 'public'::regnamespace
                    """
                )
                self.assertEqual(cursor.fetchone(), (0,))
            else:
                cursor.execute(
                    """
                    SELECT count(*)
                    FROM sqlite_master
                    WHERE type = 'trigger'
                      AND name IN (
                          'api_strategy_options_insert_guard',
                          'api_strategy_options_update_guard'
                      )
                    """
                )
                self.assertEqual(cursor.fetchone(), (0,))

    def _assert_invalid_raw_writes_are_rejected(self):
        invalid_documents = (
            ["not-an-object"],
            {"mode": ["not-a-string"]},
            {"": "value"},
            {"control\x01key": "value"},
            {"k" * 129: "value"},
            {"key": "v" * 4097},
            {f"key-{index}": "value" for index in range(513)},
            {f"key-{index}": "v" * 4096 for index in range(16)},
        )
        for index, document in enumerate(invalid_documents):
            with self.subTest(index=index):
                with self.assertRaises(IntegrityError):
                    with transaction.atomic():
                        self._insert_raw(f"migration-raw-invalid-{index}", document)

    @staticmethod
    def _insert_raw(name, config_options):
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO api_strategyprofile (
                    guid,
                    name,
                    config_options,
                    enabled,
                    updated_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                [
                    uuid.uuid4().hex,
                    name,
                    json.dumps(config_options, ensure_ascii=False),
                    True,
                    timezone.now(),
                ],
            )
