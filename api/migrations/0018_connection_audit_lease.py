import uuid

from django.db import migrations, models
from django.utils import timezone


def populate_connection_lifecycle(apps, schema_editor):
    ConnLog = apps.get_model("api", "ConnLog")
    ConnectionAuditEvent = apps.get_model("api", "ConnectionAuditEvent")
    now = timezone.now()
    pending_connections = []
    pending_events = []
    fields = (
        "state",
        "state_revision",
        "last_seen_at",
        "lease_expires_at",
        "terminal_at",
        "terminal_reason",
        "terminal_source",
        "event_revision",
    )
    for connection in ConnLog.objects.order_by("pk").iterator(chunk_size=2000):
        connection.state_revision = max(connection.event_revision, 1)
        connection.last_seen_at = connection.conn_end or connection.conn_start
        connection.lease_expires_at = connection.conn_end or connection.conn_start
        connection.terminal_at = connection.conn_end or now
        connection.terminal_source = "protocol_v3_migration"
        if connection.conn_end is not None:
            connection.state = "closed"
            connection.terminal_reason = "legacy_closed"
        else:
            connection.state = "expired"
            connection.terminal_reason = "legacy_telemetry_unknown"
            if connection.audit_version == 2:
                connection.event_revision += 1
                pending_events.append(
                    ConnectionAuditEvent(
                        event_id=uuid.uuid4(),
                        connection_id=connection.pk,
                        sequence=connection.event_revision,
                        kind="expired",
                        actor_id=connection.reporter_id,
                        actor_id_at_event=connection.owner_id_at_create,
                        reporter_device_uuid=connection.uuid,
                        details={
                            "expired_at": now.isoformat(),
                            "last_seen_at": connection.last_seen_at.isoformat(),
                            "reason": "legacy_telemetry_unknown",
                            "source": "protocol_v3_migration",
                        },
                        created_at=now,
                    )
                )
        pending_connections.append(connection)
        if len(pending_connections) >= 2000:
            ConnLog.objects.bulk_update(pending_connections, fields)
            ConnectionAuditEvent.objects.bulk_create(pending_events)
            pending_connections.clear()
            pending_events.clear()
    if pending_connections:
        ConnLog.objects.bulk_update(pending_connections, fields)
        ConnectionAuditEvent.objects.bulk_create(pending_events)


class Migration(migrations.Migration):
    dependencies = [("api", "0017_recording_inventory_backup")]

    operations = [
        migrations.AddField(
            model_name="connlog",
            name="heartbeat_revision",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name="connlog",
            name="last_heartbeat_id",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="connlog",
            name="last_seen_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="connlog",
            name="lease_expires_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="connlog",
            name="state",
            field=models.CharField(
                choices=[
                    ("starting", "Starting"),
                    ("active", "Active"),
                    ("closed", "Closed"),
                    ("aborted", "Aborted"),
                    ("expired", "Expired"),
                ],
                default="expired",
                editable=False,
                max_length=12,
            ),
        ),
        migrations.AddField(
            model_name="connlog",
            name="state_revision",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name="connlog",
            name="terminal_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="connlog",
            name="terminal_reason",
            field=models.CharField(blank=True, default="", editable=False, max_length=64),
        ),
        migrations.AddField(
            model_name="connlog",
            name="terminal_source",
            field=models.CharField(blank=True, default="", editable=False, max_length=32),
        ),
        migrations.AlterField(
            model_name="connectionauditevent",
            name="kind",
            field=models.CharField(
                choices=[
                    ("opened", "Opened"),
                    ("authorized", "Authorized"),
                    ("controller_bound", "Controller bound"),
                    ("note", "Note"),
                    ("file", "File"),
                    ("alarm", "Alarm"),
                    ("closed", "Closed"),
                    ("aborted", "Aborted"),
                    ("expired", "Expired"),
                ],
                editable=False,
                max_length=24,
            ),
        ),
        migrations.RunPython(populate_connection_lifecycle, migrations.RunPython.noop),
        migrations.RemoveConstraint(model_name="connlog", name="unique_connection_audit_create"),
        migrations.RemoveConstraint(model_name="connlog", name="valid_connection_audit_authority"),
        migrations.RemoveConstraint(model_name="filelog", name="valid_file_audit_binding"),
        migrations.RemoveConstraint(model_name="alarmlog", name="valid_alarm_audit_binding"),
        migrations.RemoveIndex(model_name="connlog", name="connection_retention_idx"),
        migrations.AddConstraint(
            model_name="connlog",
            constraint=models.UniqueConstraint(
                condition=models.Q(audit_version__in=(2, 3)),
                fields=("host_device", "create_id"),
                name="unique_connection_audit_create",
            ),
        ),
        migrations.AddConstraint(
            model_name="connlog",
            constraint=models.CheckConstraint(
                condition=models.Q(audit_version=1)
                | models.Q(
                    audit_version__in=(2, 3),
                    create_id__isnull=False,
                    event_revision__gte=1,
                    host_device_id_at_create__isnull=False,
                    owner_id_at_create__isnull=False,
                ),
                name="valid_connection_audit_authority",
            ),
        ),
        migrations.AddConstraint(
            model_name="connlog",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(
                        state__in=("starting", "active"),
                        state_revision__gte=1,
                        last_seen_at__isnull=False,
                        lease_expires_at__isnull=False,
                        terminal_at__isnull=True,
                        terminal_reason="",
                        terminal_source="",
                        conn_end__isnull=True,
                    )
                    | models.Q(
                        state__in=("closed", "aborted"),
                        state_revision__gte=1,
                        last_seen_at__isnull=False,
                        lease_expires_at__isnull=False,
                        terminal_at__isnull=False,
                        terminal_reason__gt="",
                        terminal_source__gt="",
                        conn_end__isnull=False,
                    )
                    | models.Q(
                        state="expired",
                        state_revision__gte=1,
                        last_seen_at__isnull=False,
                        lease_expires_at__isnull=False,
                        terminal_at__isnull=False,
                        terminal_reason__gt="",
                        terminal_source__gt="",
                        conn_end__isnull=True,
                    )
                ),
                name="valid_connection_audit_lifecycle",
            ),
        ),
        migrations.AddConstraint(
            model_name="connlog",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(heartbeat_revision=0, last_heartbeat_id__isnull=True)
                    | models.Q(heartbeat_revision__gte=1, last_heartbeat_id__isnull=False)
                ),
                name="valid_connection_heartbeat_identity",
            ),
        ),
        migrations.AddConstraint(
            model_name="filelog",
            constraint=models.CheckConstraint(
                condition=models.Q(audit_version=1)
                | models.Q(audit_version__in=(2, 3), connection__isnull=False, event__isnull=False),
                name="valid_file_audit_binding",
            ),
        ),
        migrations.AddConstraint(
            model_name="alarmlog",
            constraint=models.CheckConstraint(
                condition=models.Q(audit_version=1)
                | models.Q(audit_version__in=(2, 3), connection__isnull=False, event__isnull=False),
                name="valid_alarm_audit_binding",
            ),
        ),
        migrations.AddIndex(
            model_name="connlog",
            index=models.Index(fields=["state", "lease_expires_at"], name="connection_lease_idx"),
        ),
        migrations.AddIndex(
            model_name="connlog",
            index=models.Index(fields=["retention_hold", "terminal_at"], name="connection_terminal_idx"),
        ),
    ]
