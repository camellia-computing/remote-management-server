import hashlib

import django.db.models.deletion
from django.db import migrations, models


def _flush_usage_rows(PersistentIngestionUsage, rows):
    pending = []
    for row in rows:
        pending.append(PersistentIngestionUsage(**row))
        if len(pending) >= 2000:
            PersistentIngestionUsage.objects.bulk_create(pending)
            pending.clear()
    if pending:
        PersistentIngestionUsage.objects.bulk_create(pending)


def _recording_usage_rows(RecordingUpload):
    retained = RecordingUpload.objects.filter(state__in=("active", "finalized"))
    aggregates = {
        "items": models.Count("pk"),
        "active_items": models.Count("pk", filter=models.Q(state="active")),
        "committed_bytes": models.Sum("committed_offset", default=0),
    }
    global_usage = retained.aggregate(**aggregates)
    if global_usage["items"]:
        yield {
            "kind": "recording",
            "scope": "global",
            "subject_id": 0,
            **global_usage,
        }
    for scope, subject_field in (("owner", "owner_id_at_create"), ("device", "device_id_at_create")):
        grouped = retained.values(subject_field).annotate(**aggregates).order_by(subject_field)
        for usage in grouped.iterator(chunk_size=2000):
            subject_id = usage.pop(subject_field)
            if subject_id is None:
                raise RuntimeError("Recording quota snapshot is incomplete")
            yield {
                "kind": "recording",
                "scope": scope,
                "subject_id": subject_id,
                **usage,
            }


def _audit_usage_rows(ConnLog):
    retained = ConnLog.objects.filter(audit_version=2)
    aggregates = {
        "items": models.Count("pk"),
        "actual_events": models.Sum("event_revision", default=0),
        "close_reservations": models.Count("pk", filter=models.Q(conn_end__isnull=True)),
    }
    global_usage = retained.aggregate(**aggregates)
    if global_usage["items"]:
        yield {
            "kind": "audit",
            "scope": "global",
            "subject_id": 0,
            "items": global_usage["items"],
            "events": global_usage["actual_events"] + global_usage["close_reservations"],
        }
    for scope, subject_field in (("owner", "owner_id_at_create"), ("device", "host_device_id_at_create")):
        grouped = retained.values(subject_field).annotate(**aggregates).order_by(subject_field)
        for usage in grouped.iterator(chunk_size=2000):
            subject_id = usage.pop(subject_field)
            if subject_id is None:
                raise RuntimeError("Audit quota snapshot is incomplete")
            yield {
                "kind": "audit",
                "scope": scope,
                "subject_id": subject_id,
                "items": usage["items"],
                "events": usage["actual_events"] + usage["close_reservations"],
            }


def populate_ingestion_authority(apps, schema_editor):
    RecordingUpload = apps.get_model("api", "RecordingUpload")
    ConnLog = apps.get_model("api", "ConnLog")
    PersistentIngestionUsage = apps.get_model("api", "PersistentIngestionUsage")

    uploads = RecordingUpload.objects.select_related("device").only(
        "pk",
        "owner_id_at_create",
        "device__id",
        "device__rid",
        "device__uuid",
    )
    pending = []
    for upload in uploads.iterator(chunk_size=2000):
        device = upload.device
        if device is None:
            raise RuntimeError("Recording device snapshot is incomplete")
        upload.device_id_at_create = device.pk
        upload.storage_namespace = hashlib.sha256(
            f"{upload.owner_id_at_create}\0{device.rid}\0{device.uuid}".encode()
        ).hexdigest()
        pending.append(upload)
        if len(pending) >= 2000:
            RecordingUpload.objects.bulk_update(
                pending,
                ("device_id_at_create", "storage_namespace"),
            )
            pending.clear()
    if pending:
        RecordingUpload.objects.bulk_update(
            pending,
            ("device_id_at_create", "storage_namespace"),
        )

    _flush_usage_rows(PersistentIngestionUsage, _recording_usage_rows(RecordingUpload))
    _flush_usage_rows(PersistentIngestionUsage, _audit_usage_rows(ConnLog))


class Migration(migrations.Migration):
    dependencies = [("api", "0014_connection_audit_state_machine")]

    operations = [
        migrations.AddField(
            model_name="connlog",
            name="retention_hold",
            field=models.BooleanField(db_index=True, default=False, editable=False),
        ),
        migrations.AddField(
            model_name="connlog",
            name="retention_hold_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="connlog",
            name="retention_hold_reason",
            field=models.CharField(blank=True, default="", editable=False, max_length=512),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="device_id_at_create",
            field=models.PositiveBigIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="retention_hold",
            field=models.BooleanField(db_index=True, default=False, editable=False),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="retention_hold_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="retention_hold_reason",
            field=models.CharField(blank=True, default="", editable=False, max_length=512),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="storage_namespace",
            field=models.CharField(default="", editable=False, max_length=64),
            preserve_default=False,
        ),
        migrations.AddIndex(
            model_name="connlog",
            index=models.Index(
                fields=["retention_hold", "conn_end"],
                name="connection_retention_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="filelog",
            index=models.Index(
                fields=["connection", "logged_at"],
                name="file_legacy_retention_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="alarmlog",
            index=models.Index(
                fields=["connection", "created_at"],
                name="alarm_legacy_ret_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="recordingupload",
            index=models.Index(
                fields=["state", "retention_hold", "heartbeat_at"],
                name="recording_active_ret_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="recordingupload",
            index=models.Index(
                fields=["state", "retention_hold", "finalized_at"],
                name="recording_final_ret_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="recordingupload",
            index=models.Index(
                fields=["state", "retention_hold", "aborted_at"],
                name="recording_abort_ret_idx",
            ),
        ),
        migrations.CreateModel(
            name="PersistentIngestionUsage",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "kind",
                    models.CharField(
                        choices=[("recording", "Recording"), ("audit", "Audit")], editable=False, max_length=12
                    ),
                ),
                (
                    "scope",
                    models.CharField(
                        choices=[("global", "Global"), ("owner", "Owner"), ("device", "Device")],
                        editable=False,
                        max_length=8,
                    ),
                ),
                ("subject_id", models.PositiveBigIntegerField(default=0, editable=False)),
                ("items", models.PositiveBigIntegerField(default=0, editable=False)),
                ("active_items", models.PositiveBigIntegerField(default=0, editable=False)),
                ("committed_bytes", models.PositiveBigIntegerField(default=0, editable=False)),
                ("events", models.PositiveBigIntegerField(default=0, editable=False)),
                ("updated_at", models.DateTimeField(auto_now=True, editable=False)),
            ],
            options={"ordering": ("kind", "scope", "subject_id")},
        ),
        migrations.AddConstraint(
            model_name="persistentingestionusage",
            constraint=models.UniqueConstraint(
                fields=("kind", "scope", "subject_id"),
                name="unique_ingestion_usage_scope",
            ),
        ),
        migrations.AddConstraint(
            model_name="persistentingestionusage",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(("scope", "global"), ("subject_id", 0))
                    | models.Q(("scope__in", ("owner", "device")), ("subject_id__gte", 1))
                ),
                name="valid_ingestion_usage_subject",
            ),
        ),
        migrations.RunPython(populate_ingestion_authority, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="recordingupload",
            name="device_id_at_create",
            field=models.PositiveBigIntegerField(editable=False),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="device",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="recording_uploads",
                to="api.remotedevice",
            ),
        ),
    ]
