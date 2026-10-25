import datetime
import uuid

from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

from api.migration_test_support import restore_latest_migration_state


class AuditEvidenceReceiptMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0022_device_inventory_indexes")
    migrate_to = ("api", "0023_audit_evidence_receipts")

    def test_legacy_events_remain_readable_and_constraints_survive_rollback_forward(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            UserProfile = old_apps.get_model("api", "UserProfile")
            RemoteDevice = old_apps.get_model("api", "RemoteDevice")
            ConnLog = old_apps.get_model("api", "ConnLog")
            ConnectionAuditEvent = old_apps.get_model("api", "ConnectionAuditEvent")

            owner = UserProfile.objects.create(username="legacy-evidence-owner")
            device = RemoteDevice.objects.create(
                rid="111111111",
                cpu="cpu",
                hostname="legacy-host",
                memory="memory",
                os="linux",
                uuid="legacy-evidence-device",
                username="user",
                version="1.0.0",
                owner=owner,
            )
            observed_at = timezone.now() - datetime.timedelta(minutes=1)
            audit = ConnLog.objects.create(
                audit_version=3,
                create_id=uuid.uuid4(),
                host_device=device,
                host_device_id_at_create=device.pk,
                host_device_generation=device.deployment_generation,
                owner_id_at_create=owner.pk,
                event_revision=1,
                state="active",
                state_revision=1,
                last_seen_at=observed_at,
                lease_expires_at=observed_at + datetime.timedelta(seconds=90),
                conn_id=7,
                from_ip="192.0.2.10",
                rid=device.rid,
                conn_start=observed_at,
                session_id="99",
                uuid=device.uuid,
                conn_type=0,
                actor=owner,
                reporter=owner,
            )
            legacy_event = ConnectionAuditEvent.objects.create(
                event_id=uuid.uuid4(),
                connection=audit,
                sequence=1,
                kind="opened",
                actor=owner,
                actor_id_at_event=owner.pk,
                reporter_device_uuid=device.uuid,
                created_at=observed_at,
            )

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            MigratedEvent = new_apps.get_model("api", "ConnectionAuditEvent")
            migrated = MigratedEvent.objects.get(pk=legacy_event.pk)
            self.assertIsNone(migrated.reporter_device_id_at_event)
            self.assertIsNone(migrated.reporter_device_generation)
            self.assertIsNone(migrated.reporter_sequence)
            self.assertEqual(migrated.payload_digest, "")
            self.assertEqual(migrated.acknowledgement, {})

            migrated.reporter_device_id_at_event = device.pk
            migrated.reporter_device_generation = device.deployment_generation
            migrated.reporter_sequence = 1
            migrated.payload_digest = "a" * 64
            migrated.acknowledgement = {"receipt_version": 1}
            migrated.save()
            with self.assertRaises(IntegrityError), transaction.atomic():
                MigratedEvent.objects.create(
                    event_id=uuid.uuid4(),
                    connection_id=audit.pk,
                    sequence=2,
                    kind="alarm",
                    actor_id=owner.pk,
                    actor_id_at_event=owner.pk,
                    reporter_device_uuid=device.uuid,
                    reporter_device_id_at_event=device.pk,
                    reporter_device_generation=device.deployment_generation,
                    reporter_sequence=1,
                    payload_digest="b" * 64,
                    acknowledgement={"receipt_version": 1},
                    details={},
                )
            with self.assertRaises(IntegrityError), transaction.atomic():
                MigratedEvent.objects.filter(pk=legacy_event.pk).update(reporter_sequence=0)

            with connection.cursor() as cursor:
                constraints = connection.introspection.get_constraints(
                    cursor,
                    MigratedEvent._meta.db_table,
                )
            self.assertTrue(constraints["positive_audit_reporter_sequence"]["check"])
            reporter_unique = constraints["unique_audit_reporter_sequence"]
            self.assertTrue(reporter_unique["unique"])
            self.assertEqual(
                reporter_unique["columns"],
                ["connection_id", "reporter_sequence"],
            )
            with connection.cursor() as cursor:
                if connection.vendor == "postgresql":
                    cursor.execute(
                        """
                        SELECT
                            pg_get_expr(index.indpred, index.indrelid),
                            index.indisvalid,
                            index.indisready
                        FROM pg_index AS index
                        JOIN pg_class AS relation ON relation.oid = index.indexrelid
                        WHERE relation.relname = %s
                        """,
                        ["unique_audit_reporter_sequence"],
                    )
                    predicate, index_valid, index_ready = cursor.fetchone()
                    self.assertTrue(index_valid)
                    self.assertTrue(index_ready)
                else:
                    cursor.execute(
                        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = %s",
                        ["unique_audit_reporter_sequence"],
                    )
                    predicate = cursor.fetchone()[0]
            self.assertIn("reporter_sequence", predicate)
            self.assertIn("IS NOT NULL", predicate)

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_from])
            restored_apps = executor.loader.project_state([self.migrate_from]).apps
            restored = restored_apps.get_model("api", "ConnectionAuditEvent").objects.get(pk=legacy_event.pk)
            self.assertEqual(restored.event_id, legacy_event.event_id)
            with connection.cursor() as cursor:
                rolled_back = connection.introspection.get_constraints(
                    cursor,
                    restored._meta.db_table,
                )
            self.assertNotIn("positive_audit_reporter_sequence", rolled_back)
            self.assertNotIn("unique_audit_reporter_sequence", rolled_back)

            MigrationExecutor(connection).migrate([self.migrate_to])
            with connection.cursor() as cursor:
                forwarded = connection.introspection.get_constraints(
                    cursor,
                    MigratedEvent._meta.db_table,
                )
            self.assertIn("positive_audit_reporter_sequence", forwarded)
            self.assertIn("unique_audit_reporter_sequence", forwarded)
        finally:
            restore_latest_migration_state()
