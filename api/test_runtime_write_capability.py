from django.db import connection
from django.test import TestCase

from api.release_schema import (
    RuntimeWriteCapabilityError,
    check_runtime_write_capability,
    load_release_schema_manifest,
)


class RuntimeWriteCapabilityTests(TestCase):
    def test_release_manifest_declares_runtime_table_and_sequence_authority(self):
        capability = load_release_schema_manifest()["postgresql_runtime_dml"]
        self.assertEqual(
            capability,
            {
                "tables": {"api_remotedevice": ("DELETE", "INSERT", "SELECT", "UPDATE")},
                "sequences": {"api_remotedevice_id_seq": ("SELECT", "UPDATE", "USAGE")},
            },
        )

    def test_sqlite_read_only_mode_is_not_ready(self):
        if connection.vendor != "sqlite":
            self.skipTest("SQLite query_only is a development-only readiness contract")
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA query_only=ON")
        try:
            with self.assertRaisesMessage(RuntimeWriteCapabilityError, "sqlite_query_only"):
                check_runtime_write_capability()
        finally:
            with connection.cursor() as cursor:
                cursor.execute("PRAGMA query_only=OFF")

    def test_sqlite_writable_mode_is_ready(self):
        if connection.vendor != "sqlite":
            self.skipTest("SQLite query_only is a development-only readiness contract")
        self.assertEqual(check_runtime_write_capability(), {"vendor": "sqlite", "runtime_write": True})

    def test_health_ready_rejects_sqlite_query_only(self):
        if connection.vendor != "sqlite":
            self.skipTest("SQLite query_only is a development-only readiness contract")
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA query_only=ON")
        try:
            response = self.client.get("/health/ready")
        finally:
            with connection.cursor() as cursor:
                cursor.execute("PRAGMA query_only=OFF")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["status"], "not_ready")
