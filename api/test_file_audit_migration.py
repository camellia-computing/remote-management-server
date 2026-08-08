import datetime
import uuid

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

from api.migration_test_support import restore_latest_migration_state


class FileAuditLifecycleMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0018_connection_audit_lease")
    migrate_to = ("api", "0019_file_audit_lifecycle")

    def test_v3_top_ten_snapshot_remains_explicitly_legacy(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            UserProfile = old_apps.get_model("api", "UserProfile")
            RemoteDevice = old_apps.get_model("api", "RemoteDevice")
            ConnLog = old_apps.get_model("api", "ConnLog")
            ConnectionAuditEvent = old_apps.get_model("api", "ConnectionAuditEvent")
            FileLog = old_apps.get_model("api", "FileLog")

            owner = UserProfile.objects.create(username="legacy-file-owner")
            device = RemoteDevice.objects.create(
                rid="111111111",
                cpu="cpu",
                hostname="host",
                memory="memory",
                os="linux",
                uuid="legacy-file-device",
                username="user",
                version="1.0.0",
                owner=owner,
            )
            observed_at = timezone.now() - datetime.timedelta(minutes=1)
            connection_log = ConnLog.objects.create(
                audit_version=3,
                create_id=uuid.uuid4(),
                host_device=device,
                host_device_id_at_create=device.pk,
                host_device_generation=device.deployment_generation,
                owner_id_at_create=owner.pk,
                event_revision=2,
                state="active",
                state_revision=1,
                last_seen_at=observed_at,
                lease_expires_at=observed_at + datetime.timedelta(seconds=90),
                conn_id=7,
                from_ip="192.0.2.10",
                from_id="222222222",
                rid=device.rid,
                conn_start=observed_at,
                session_id="99",
                uuid=device.uuid,
                conn_type=0,
                reporter=owner,
            )
            ConnectionAuditEvent.objects.create(
                event_id=connection_log.create_id,
                connection=connection_log,
                sequence=1,
                kind="opened",
                actor=owner,
                actor_id_at_event=owner.pk,
                reporter_device_uuid=device.uuid,
                details={},
                created_at=observed_at,
            )
            event = ConnectionAuditEvent.objects.create(
                event_id=uuid.uuid4(),
                connection=connection_log,
                sequence=2,
                kind="file",
                actor=owner,
                actor_id_at_event=owner.pk,
                reporter_device_uuid=device.uuid,
                details={"legacy": True},
                created_at=observed_at,
            )
            legacy = FileLog.objects.create(
                audit_version=3,
                connection=connection_log,
                event=event,
                file="/documents",
                remote_id=device.rid,
                user_id="222222222",
                user_ip="192.0.2.10",
                filesize=10,
                direction=0,
                details={
                    "num": 100,
                    "files": [[f"sample-{index}.bin", 1] for index in range(10)],
                },
                reporter=owner,
                reporter_device_uuid=device.uuid,
            )

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            migrated = new_apps.get_model("api", "FileLog").objects.get(pk=legacy.pk)

            self.assertEqual(migrated.audit_version, 3)
            self.assertIsNone(migrated.transfer_id)
            self.assertEqual(migrated.transfer_revision, 0)
            self.assertEqual(migrated.state, "unknown")
            self.assertEqual(migrated.filesize, 10)
            self.assertEqual(migrated.planned_bytes, 0)
            self.assertEqual(migrated.transferred_bytes, 0)
            self.assertIsNone(migrated.started_at)
            self.assertIsNone(migrated.terminal_at)
            self.assertEqual(migrated.details["num"], 100)
            self.assertEqual(
                new_apps.get_model("api", "FileTransferAuditEvent").objects.count(),
                0,
            )
        finally:
            restore_latest_migration_state()
