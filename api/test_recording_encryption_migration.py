import importlib
import uuid

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from api import recording_crypto


class RecordingEncryptionMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0015_persistent_ingestion_governance")
    migrate_to = ("api", "0016_recording_encryption")

    def test_empty_recording_inventory_migrates_to_required_encryption_fields(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            self.assertFalse(old_apps.get_model("api", "RecordingUpload").objects.exists())

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            fields = {field.name: field for field in new_apps.get_model("api", "RecordingUpload")._meta.get_fields()}
            self.assertFalse(fields["encryption_version"].null)
            self.assertFalse(fields["encrypted_data_key"].null)
            self.assertFalse(fields["storage_offset"].null)
            migration = importlib.import_module("api.migrations.0016_recording_encryption")
            self.assertEqual(migration.RECORDING_HEADER_SIZE, recording_crypto.HEADER_SIZE)
        finally:
            MigrationExecutor(connection).migrate([self.migrate_to])

    def test_legacy_recording_rows_block_migration_instead_of_being_marked_encrypted(self):
        executor = MigrationExecutor(connection)
        old_upload_model = None
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            old_upload_model = old_apps.get_model("api", "RecordingUpload")
            old_upload_model.objects.create(
                create_id=uuid.uuid4(),
                device_id=None,
                device_id_at_create=1,
                owner_id_at_create=1,
                deployment_generation=0,
                storage_namespace="a" * 64,
                filename="legacy-plaintext.webm",
            )

            executor = MigrationExecutor(connection)
            with self.assertRaisesRegex(RuntimeError, "quarantine or securely destroy legacy plaintext"):
                executor.migrate([self.migrate_to])
            self.assertEqual(old_upload_model.objects.count(), 1)
        finally:
            if old_upload_model is not None:
                old_upload_model.objects.all().delete()
            MigrationExecutor(connection).migrate([self.migrate_to])
