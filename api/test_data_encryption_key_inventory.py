import json
import tempfile
from io import StringIO
from pathlib import Path

from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db.migrations.recorder import MigrationRecorder
from django.test import TestCase, TransactionTestCase, override_settings

from api.encrypted_fields import EncryptedTextField, key_fingerprint, verify_key_canary
from api.management.commands.rotate_data_encryption import ENCRYPTED_COLUMNS
from api.models import DataEncryptionKeyState
from api.test_support import reset_data_encryption_key_inventory


class DataEncryptionKeyInventoryFixtureTests(TestCase):
    def test_rotation_allowlist_covers_every_encrypted_model_field(self):
        model_fields = {
            (
                model._meta.db_table,
                model._meta.pk.column,
                field.column,
                model._meta.label,
                tuple(field.context_fields),
            )
            for model in apps.get_app_config("api").get_models()
            for field in model._meta.concrete_fields
            if isinstance(field, EncryptedTextField)
        }
        rotation_fields = {
            (
                column.table,
                column.pk_column,
                column.encrypted_column,
                column.model_label,
                column.context_columns,
            )
            for column in ENCRYPTED_COLUMNS
        }

        self.assertEqual(rotation_fields, model_fields)

    def test_fixture_restores_an_empty_or_stale_inventory_idempotently(self):
        DataEncryptionKeyState.objects.all().delete()
        first = reset_data_encryption_key_inventory()
        self.assert_inventory_matches_settings(first)

        DataEncryptionKeyState.objects.create(
            key_id="stale-test-key",
            key_fingerprint="f" * 64,
            encrypted_canary="invalid-test-canary",
            is_primary=False,
        )
        second = reset_data_encryption_key_inventory()
        self.assert_inventory_matches_settings(second)
        self.assertFalse(DataEncryptionKeyState.objects.filter(key_id="stale-test-key").exists())

    def test_fixture_uses_the_active_test_keyring_and_primary(self):
        primary_key = b"p" * 32
        legacy_key = b"l" * 32
        with override_settings(
            DATA_ENCRYPTION_KEY_BYTES=primary_key,
            DATA_ENCRYPTION_KEYS={"fixture-primary": primary_key, "fixture-legacy": legacy_key},
            DATA_ENCRYPTION_PRIMARY_KEY_ID="fixture-primary",
            DATA_ENCRYPTION_V1_KEY_ID="fixture-legacy",
        ):
            states = reset_data_encryption_key_inventory()
            self.assertEqual([state.key_id for state in states], ["fixture-legacy", "fixture-primary"])
            self.assertEqual([state.key_id for state in states if state.is_primary], ["fixture-primary"])
            self.assertTrue(
                all(verify_key_canary(state.key_id, state.key_fingerprint, state.encrypted_canary) for state in states)
            )

    def test_fixture_rejects_a_keyring_without_its_declared_primary(self):
        with (
            override_settings(
                DATA_ENCRYPTION_KEYS={"configured-key": b"k" * 32},
                DATA_ENCRYPTION_PRIMARY_KEY_ID="missing-key",
            ),
            self.assertRaisesMessage(AssertionError, "no configured primary key"),
        ):
            reset_data_encryption_key_inventory()

    def assert_inventory_matches_settings(self, states):
        self.assertEqual([state.key_id for state in states], sorted(settings.DATA_ENCRYPTION_KEYS))
        self.assertEqual(
            [state.key_id for state in states if state.is_primary],
            [settings.DATA_ENCRYPTION_PRIMARY_KEY_ID],
        )
        self.assertTrue(
            all(
                state.key_fingerprint == key_fingerprint(settings.DATA_ENCRYPTION_KEYS[state.key_id])
                and verify_key_canary(
                    state.key_id,
                    state.key_fingerprint,
                    state.encrypted_canary,
                )
                for state in states
            )
        )


class DataEncryptionKeyInventoryFlushRecoveryTests(TransactionTestCase):
    @override_settings(
        DEVICE_VERIFICATION_TOKEN="v" * 48,
        SECURE_SSL_REDIRECT=False,
        RECORD_UPLOAD_REQUIRE_MOUNT=False,
        RECORD_UPLOAD_VOLUME_RESERVE_BYTES=0,
        RECORD_UPLOAD_VOLUME_RESERVE_INODES=0,
        RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=0,
    )
    def test_explicit_fixture_recovers_inventory_without_replaying_migrations(self):
        self.assertTrue(
            MigrationRecorder.Migration.objects.filter(
                app="api",
                name="0002_dataencryptionkeystate",
            ).exists()
        )

        call_command("flush", interactive=False, verbosity=0)

        self.assertTrue(
            MigrationRecorder.Migration.objects.filter(
                app="api",
                name="0002_dataencryptionkeystate",
            ).exists()
        )
        self.assertFalse(DataEncryptionKeyState.objects.exists())
        with tempfile.TemporaryDirectory(prefix="camellia-key-inventory-") as recording_root:
            with override_settings(RECORD_UPLOAD_ROOT=Path(recording_root)):
                self.assertEqual(self.client.get("/health/ready").status_code, 503)
                with self.assertRaisesMessage(CommandError, "inventory is empty"):
                    call_command("rotate_data_encryption", dry_run=True, stdout=StringIO())

                states = reset_data_encryption_key_inventory()
                self.assertEqual([state.key_id for state in states], sorted(settings.DATA_ENCRYPTION_KEYS))
                self.assertEqual(
                    [state.key_id for state in states if state.is_primary],
                    [settings.DATA_ENCRYPTION_PRIMARY_KEY_ID],
                )
                self.assertEqual(self.client.get("/health/ready").status_code, 200)
                output = StringIO()
                call_command("rotate_data_encryption", dry_run=True, stdout=output)
                self.assertEqual(json.loads(output.getvalue())["remaining"], 0)
