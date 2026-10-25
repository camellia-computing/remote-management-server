import datetime
import uuid

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

from api.migration_test_support import restore_latest_migration_state


class AuditDisplaySnapshotMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0019_file_audit_lifecycle")
    migrate_to = ("api", "0020_connection_device_name_snapshots")

    def test_existing_connections_remain_unknown_instead_of_borrowing_current_device_names(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            UserProfile = old_apps.get_model("api", "UserProfile")
            RemoteDevice = old_apps.get_model("api", "RemoteDevice")
            ConnLog = old_apps.get_model("api", "ConnLog")

            host_owner = UserProfile.objects.create(username="legacy-display-host")
            controller_owner = UserProfile.objects.create(username="legacy-display-controller")
            host = RemoteDevice.objects.create(
                rid="111111111",
                cpu="cpu",
                hostname="CURRENT-HOST-MUST-NOT-BE-BACKFILLED",
                memory="memory",
                os="linux",
                uuid="legacy-display-host-device",
                username="user",
                version="1.0.0",
                owner=host_owner,
            )
            controller = RemoteDevice.objects.create(
                rid="222222222",
                cpu="cpu",
                hostname="CURRENT-CONTROLLER-MUST-NOT-BE-BACKFILLED",
                memory="memory",
                os="linux",
                uuid="legacy-display-controller-device",
                username="user",
                version="1.0.0",
                owner=controller_owner,
            )
            observed_at = timezone.now() - datetime.timedelta(minutes=1)
            connection_log = ConnLog.objects.create(
                audit_version=3,
                create_id=uuid.uuid4(),
                host_device=host,
                host_device_id_at_create=host.pk,
                host_device_generation=host.deployment_generation,
                owner_id_at_create=host_owner.pk,
                controller_device=controller,
                controller_device_id_at_bind=controller.pk,
                controller_device_generation=controller.deployment_generation,
                controller_owner_id_at_bind=controller_owner.pk,
                event_revision=2,
                state="active",
                state_revision=1,
                last_seen_at=observed_at,
                lease_expires_at=observed_at + datetime.timedelta(seconds=90),
                conn_id=7,
                from_ip="192.0.2.10",
                from_id=controller.rid,
                rid=host.rid,
                conn_start=observed_at,
                session_id="99",
                uuid=host.uuid,
                conn_type=0,
                actor=controller_owner,
                reporter=host_owner,
            )

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            migrated = new_apps.get_model("api", "ConnLog").objects.get(pk=connection_log.pk)

            self.assertEqual(migrated.host_device_name_at_create, "")
            self.assertEqual(migrated.controller_device_name_at_bind, "")
        finally:
            restore_latest_migration_state()
