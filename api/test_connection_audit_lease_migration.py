import datetime
import uuid

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone


class ConnectionAuditLeaseMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0017_recording_inventory_backup")
    migrate_to = ("api", "0018_connection_audit_lease")

    def test_open_v2_session_becomes_expired_without_forging_close_or_leaking_reserved_event(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            UserProfile = old_apps.get_model("api", "UserProfile")
            RemoteDevice = old_apps.get_model("api", "RemoteDevice")
            ConnLog = old_apps.get_model("api", "ConnLog")
            ConnectionAuditEvent = old_apps.get_model("api", "ConnectionAuditEvent")
            PersistentIngestionUsage = old_apps.get_model("api", "PersistentIngestionUsage")

            owner = UserProfile.objects.create(username="legacy-audit-owner")
            device = RemoteDevice.objects.create(
                rid="111111111",
                cpu="cpu",
                hostname="host",
                memory="memory",
                os="linux",
                uuid="legacy-audit-device",
                username="user",
                version="1.0.0",
                owner=owner,
            )
            opened_at = timezone.now() - datetime.timedelta(minutes=10)
            event_id = uuid.uuid4()
            audit = ConnLog.objects.create(
                audit_version=2,
                create_id=event_id,
                host_device=device,
                host_device_id_at_create=device.pk,
                host_device_generation=device.deployment_generation,
                owner_id_at_create=owner.pk,
                event_revision=1,
                conn_id=7,
                from_ip="192.0.2.10",
                rid=device.rid,
                conn_start=opened_at,
                session_id="99",
                uuid=device.uuid,
                conn_type=0,
                reporter=owner,
            )
            ConnectionAuditEvent.objects.create(
                event_id=event_id,
                connection=audit,
                sequence=1,
                kind="opened",
                actor=owner,
                actor_id_at_event=owner.pk,
                reporter_device_uuid=device.uuid,
                created_at=opened_at,
            )
            for scope, subject_id in (("global", 0), ("owner", owner.pk), ("device", device.pk)):
                PersistentIngestionUsage.objects.create(
                    kind="audit",
                    scope=scope,
                    subject_id=subject_id,
                    items=1,
                    events=2,
                )

            closed_owner = UserProfile.objects.create(username="legacy-closed-audit-owner")
            closed_device = RemoteDevice.objects.create(
                rid="333333333",
                cpu="cpu",
                hostname="closed-host",
                memory="memory",
                os="linux",
                uuid="legacy-closed-audit-device",
                username="user",
                version="1.0.0",
                owner=closed_owner,
            )
            closed_event_id = uuid.uuid4()
            closed_at = opened_at + datetime.timedelta(minutes=5)
            closed_audit = ConnLog.objects.create(
                audit_version=2,
                create_id=closed_event_id,
                host_device=closed_device,
                host_device_id_at_create=closed_device.pk,
                host_device_generation=closed_device.deployment_generation,
                owner_id_at_create=closed_owner.pk,
                event_revision=2,
                conn_id=8,
                from_ip="192.0.2.11",
                rid=closed_device.rid,
                conn_start=opened_at,
                conn_end=closed_at,
                session_id="100",
                uuid=closed_device.uuid,
                conn_type=0,
                reporter=closed_owner,
            )
            ConnectionAuditEvent.objects.create(
                event_id=closed_event_id,
                connection=closed_audit,
                sequence=1,
                kind="opened",
                actor=closed_owner,
                actor_id_at_event=closed_owner.pk,
                reporter_device_uuid=closed_device.uuid,
                created_at=opened_at,
            )
            ConnectionAuditEvent.objects.create(
                event_id=uuid.uuid4(),
                connection=closed_audit,
                sequence=2,
                kind="closed",
                actor=closed_owner,
                actor_id_at_event=closed_owner.pk,
                reporter_device_uuid=closed_device.uuid,
                created_at=closed_at,
            )
            for scope, subject_id in (
                ("owner", closed_owner.pk),
                ("device", closed_device.pk),
            ):
                PersistentIngestionUsage.objects.create(
                    kind="audit",
                    scope=scope,
                    subject_id=subject_id,
                    items=1,
                    events=2,
                )
            PersistentIngestionUsage.objects.filter(kind="audit", scope="global").update(items=2, events=4)

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            migrated = new_apps.get_model("api", "ConnLog").objects.get(pk=audit.pk)
            events = list(
                new_apps.get_model("api", "ConnectionAuditEvent")
                .objects.filter(connection_id=audit.pk)
                .order_by("sequence")
            )

            self.assertEqual(migrated.state, "expired")
            self.assertEqual(migrated.state_revision, 1)
            self.assertEqual(migrated.event_revision, 2)
            self.assertIsNone(migrated.conn_end)
            self.assertEqual(migrated.terminal_reason, "legacy_telemetry_unknown")
            self.assertEqual([event.kind for event in events], ["opened", "expired"])
            self.assertEqual([event.sequence for event in events], [1, 2])

            migrated_closed = new_apps.get_model("api", "ConnLog").objects.get(pk=closed_audit.pk)
            closed_events = list(
                new_apps.get_model("api", "ConnectionAuditEvent")
                .objects.filter(connection_id=closed_audit.pk)
                .order_by("sequence")
            )
            self.assertEqual(migrated_closed.state, "closed")
            self.assertEqual(migrated_closed.state_revision, 2)
            self.assertEqual(migrated_closed.event_revision, 2)
            self.assertEqual(migrated_closed.conn_end, closed_at)
            self.assertEqual(migrated_closed.terminal_at, closed_at)
            self.assertEqual(migrated_closed.terminal_reason, "legacy_closed")
            self.assertEqual([event.kind for event in closed_events], ["opened", "closed"])
            self.assertEqual([event.sequence for event in closed_events], [1, 2])
            for usage in new_apps.get_model("api", "PersistentIngestionUsage").objects.filter(kind="audit"):
                expected = (2, 4) if usage.scope == "global" else (1, 2)
                self.assertEqual((usage.items, usage.events), expected)
        finally:
            MigrationExecutor(connection).migrate([self.migrate_to])
