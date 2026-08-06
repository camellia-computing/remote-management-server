import uuid

from django.db import migrations, models
import django.db.models.deletion


RECORDING_STORAGE_VERSION = 2


def reject_pre_inventory_recordings(apps, schema_editor):
    RecordingUpload = apps.get_model("api", "RecordingUpload")
    if RecordingUpload.objects.exists():
        raise RuntimeError(
            "Recording inventory migration requires an empty encrypted recording inventory; "
            "finish or abort development uploads and rebuild the unpublished database/volume pair"
        )


def create_backup_control(apps, schema_editor):
    RecordingBackupControl = apps.get_model("api", "RecordingBackupControl")
    RecordingBackupControl.objects.create(singleton=1)


class Migration(migrations.Migration):
    dependencies = [("api", "0016_recording_encryption")]

    operations = [
        migrations.RunPython(reject_pre_inventory_recordings, migrations.RunPython.noop),
        migrations.AddField(
            model_name="recordingupload",
            name="ciphertext_digest",
            field=models.CharField(blank=True, default="", editable=False, max_length=64),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="ciphertext_size",
            field=models.PositiveBigIntegerField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="data_key_kek_id",
            field=models.CharField(editable=False, max_length=32, null=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="device_rid_at_create",
            field=models.CharField(editable=False, max_length=16, null=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="device_uuid_at_create",
            field=models.CharField(editable=False, max_length=344, null=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="storage_object_id",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="storage_version",
            field=models.PositiveSmallIntegerField(default=RECORDING_STORAGE_VERSION, editable=False),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="data_key_kek_id",
            field=models.CharField(editable=False, max_length=32),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="device_rid_at_create",
            field=models.CharField(editable=False, max_length=16),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="device_uuid_at_create",
            field=models.CharField(editable=False, max_length=344),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="storage_namespace",
            field=models.CharField(editable=False, max_length=64, unique=True),
        ),
        migrations.AddConstraint(
            model_name="recordingupload",
            constraint=models.CheckConstraint(
                condition=models.Q(storage_version=RECORDING_STORAGE_VERSION),
                name="valid_recording_storage_version",
            ),
        ),
        migrations.AddConstraint(
            model_name="recordingupload",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(
                        state="finalized",
                        ciphertext_size=models.F("storage_offset"),
                    )
                    & ~models.Q(ciphertext_digest="")
                    | ~models.Q(state="finalized") & models.Q(ciphertext_size__isnull=True, ciphertext_digest="")
                ),
                name="valid_recording_ciphertext_inventory",
            ),
        ),
        migrations.CreateModel(
            name="RecordingBackupEpoch",
            fields=[
                ("epoch_id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("backup_id", models.CharField(editable=False, max_length=32, unique=True)),
                ("manifest_version", models.PositiveSmallIntegerField(default=1, editable=False)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("preparing", "Preparing"),
                            ("ready", "Ready"),
                            ("complete", "Complete"),
                            ("restored", "Restored"),
                        ],
                        default="preparing",
                        editable=False,
                        max_length=12,
                    ),
                ),
                ("requested_at", models.DateTimeField(editable=False)),
                ("prepared_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("completed_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("inventory_count", models.PositiveBigIntegerField(default=0, editable=False)),
                ("object_count", models.PositiveBigIntegerField(default=0, editable=False)),
                ("inventory_digest", models.CharField(blank=True, default="", editable=False, max_length=64)),
            ],
            options={"ordering": ("-requested_at", "epoch_id")},
        ),
        migrations.AddConstraint(
            model_name="recordingbackupepoch",
            constraint=models.CheckConstraint(
                condition=models.Q(manifest_version=1),
                name="valid_recording_backup_manifest_version",
            ),
        ),
        migrations.CreateModel(
            name="RecordingBackupObject",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("upload_id", models.UUIDField(editable=False)),
                ("storage_object_id", models.UUIDField(editable=False)),
                ("storage_version", models.PositiveSmallIntegerField(editable=False)),
                ("storage_relative_path", models.CharField(blank=True, default="", editable=False, max_length=192)),
                ("object_present", models.BooleanField(editable=False)),
                ("state", models.CharField(editable=False, max_length=12)),
                ("owner_id_at_create", models.PositiveBigIntegerField(editable=False)),
                ("device_id_at_create", models.PositiveBigIntegerField(editable=False)),
                ("device_rid_at_create", models.CharField(editable=False, max_length=16)),
                ("device_uuid_at_create", models.CharField(editable=False, max_length=344)),
                ("deployment_generation", models.PositiveBigIntegerField(editable=False)),
                ("encryption_version", models.PositiveSmallIntegerField(editable=False)),
                ("data_key_kek_id", models.CharField(editable=False, max_length=32)),
                ("plaintext_size", models.PositiveBigIntegerField(editable=False)),
                ("plaintext_digest", models.CharField(blank=True, default="", editable=False, max_length=64)),
                ("ciphertext_size", models.PositiveBigIntegerField(editable=False)),
                ("ciphertext_digest", models.CharField(blank=True, default="", editable=False, max_length=64)),
                ("retention_hold", models.BooleanField(editable=False)),
                ("retention_hold_reason", models.CharField(blank=True, default="", editable=False, max_length=512)),
                ("retention_hold_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("created_at", models.DateTimeField(editable=False)),
                ("finalized_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("aborted_at", models.DateTimeField(blank=True, editable=False, null=True)),
                (
                    "epoch",
                    models.ForeignKey(
                        editable=False,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="inventory_objects",
                        to="api.recordingbackupepoch",
                    ),
                ),
            ],
            options={"ordering": ("epoch_id", "upload_id")},
        ),
        migrations.AddConstraint(
            model_name="recordingbackupobject",
            constraint=models.UniqueConstraint(
                fields=("epoch", "upload_id"),
                name="unique_recording_backup_upload",
            ),
        ),
        migrations.AddConstraint(
            model_name="recordingbackupobject",
            constraint=models.UniqueConstraint(
                fields=("epoch", "storage_object_id"),
                name="unique_recording_backup_object",
            ),
        ),
        migrations.AddConstraint(
            model_name="recordingbackupobject",
            constraint=models.UniqueConstraint(
                condition=~models.Q(storage_relative_path=""),
                fields=("epoch", "storage_relative_path"),
                name="unique_recording_backup_path",
            ),
        ),
        migrations.CreateModel(
            name="RecordingBackupControl",
            fields=[
                (
                    "singleton",
                    models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False),
                ),
                ("updated_at", models.DateTimeField(auto_now=True, editable=False)),
                (
                    "active_epoch",
                    models.OneToOneField(
                        blank=True,
                        editable=False,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="active_control",
                        to="api.recordingbackupepoch",
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name="recordingbackupcontrol",
            constraint=models.CheckConstraint(
                condition=models.Q(singleton=1),
                name="recording_backup_control_singleton",
            ),
        ),
        migrations.RunPython(create_backup_control, migrations.RunPython.noop),
    ]
