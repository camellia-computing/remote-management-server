import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.core.management import call_command
from django.db import connection, transaction
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.recorder import MigrationRecorder
from django.test import TestCase, override_settings

from api import release_schema
from api.release_schema import ReleaseSchemaError, check_release_schema, load_release_schema_manifest


class ReleaseSchemaContractTests(TestCase):
    def setUp(self):
        self.recording_root = tempfile.TemporaryDirectory(prefix="camellia-release-schema-")
        self.settings_override = override_settings(
            DEVICE_VERIFICATION_TOKEN="v" * 48,
            SECURE_SSL_REDIRECT=False,
            RECORD_UPLOAD_ROOT=Path(self.recording_root.name),
            RECORD_UPLOAD_REQUIRE_MOUNT=False,
            RECORD_UPLOAD_VOLUME_RESERVE_BYTES=0,
            RECORD_UPLOAD_VOLUME_RESERVE_INODES=0,
            RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=0,
        )
        self.settings_override.enable()

    def tearDown(self):
        self.settings_override.disable()
        self.recording_root.cleanup()

    def test_manifest_exactly_matches_code_and_current_database(self):
        manifest = load_release_schema_manifest()
        loader = MigrationLoader(connection, ignore_no_migrations=True)
        self.assertEqual(frozenset(loader.disk_migrations), manifest["migrations"])
        self.assertEqual(frozenset(loader.graph.leaf_nodes()), manifest["leaf_migrations"])
        self.assertEqual(
            check_release_schema(),
            {
                "migration_count": 49,
                "schema_generation": "management-schema-0031-v1",
                "schema_manifest_version": 1,
            },
        )

    def test_missing_non_leaf_migration_record_fails_readiness_closed(self):
        MigrationRecorder.Migration.objects.filter(app="api", name="0001_initial").delete()
        with self.assertRaisesMessage(ReleaseSchemaError, "missing=api/0001_initial"):
            check_release_schema()
        response = self.client.get("/health/ready")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "not_ready")
        self.assertEqual(response.json()["code"], "http_503_health_ready")

    def test_extra_or_forked_migration_record_fails_closed(self):
        MigrationRecorder.Migration.objects.create(app="api", name="9999_untrusted_branch")
        with self.assertRaisesMessage(ReleaseSchemaError, "extra=api/9999_untrusted_branch"):
            check_release_schema()

    def test_missing_relation_or_column_capability_fails_closed(self):
        if connection.vendor == "postgresql":
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute("ALTER TABLE api_remotedevice RENAME TO api_remotedevice_missing")
                with self.assertRaisesMessage(ReleaseSchemaError, "relation is missing: api_remotedevice"):
                    check_release_schema()
                transaction.set_rollback(True)
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "ALTER TABLE api_remotedevice RENAME COLUMN policy_generation TO policy_generation_missing"
                )
                with self.assertRaisesMessage(ReleaseSchemaError, "policy_generation"):
                    check_release_schema()
                transaction.set_rollback(True)
            return
        with patch.object(
            connection.introspection,
            "table_names",
            return_value=[name for name in connection.introspection.table_names() if name != "api_remotedevice"],
        ):
            with self.assertRaisesMessage(ReleaseSchemaError, "relation is missing: api_remotedevice"):
                check_release_schema()

    def test_missing_postgresql_constraint_and_index_fail_closed(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL schema capability authority")
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("ALTER TABLE api_strategyprofile DROP CONSTRAINT valid_strategy_config_options_v1")
            with self.assertRaisesMessage(ReleaseSchemaError, "valid_strategy_config_options_v1"):
                check_release_schema()
            transaction.set_rollback(True)
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("DROP INDEX device_owner_rid_idx")
            with self.assertRaisesMessage(ReleaseSchemaError, "device_owner_rid_idx"):
                check_release_schema()
            transaction.set_rollback(True)
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("DROP INDEX dev_host_search_trgm_idx")
            with self.assertRaisesMessage(ReleaseSchemaError, "dev_host_search_trgm_idx"):
                check_release_schema()
            transaction.set_rollback(True)

    def test_management_command_reports_manifest_generation(self):
        output = StringIO()
        call_command("check_release_schema", stdout=output)
        self.assertIn('"schema_generation": "management-schema-0031-v1"', output.getvalue())


class ReleaseSchemaManifestValidationTests(TestCase):
    def test_manifest_loader_rejects_a_code_manifest_mismatch(self):
        manifest = dict(load_release_schema_manifest())
        manifest["migrations"] = manifest["migrations"] - {("api", "0030_bigint_primary_key_capacity")}
        with patch.object(release_schema, "load_release_schema_manifest", return_value=manifest):
            with self.assertRaisesMessage(ReleaseSchemaError, "does not match code migrations"):
                check_release_schema()
