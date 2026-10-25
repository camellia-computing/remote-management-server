from django.db import migrations, models

import api.encrypted_fields


RECORDING_ENCRYPTION_VERSION = 1
RECORDING_HEADER_SIZE = 119


def reject_legacy_plaintext_recordings(apps, schema_editor):
    RecordingUpload = apps.get_model("api", "RecordingUpload")
    if RecordingUpload.objects.exists():
        raise RuntimeError(
            "Recording encryption migration requires an empty recording inventory; "
            "quarantine or securely destroy legacy plaintext recordings before upgrading"
        )


class Migration(migrations.Migration):
    dependencies = [("api", "0015_persistent_ingestion_governance")]

    operations = [
        migrations.RunPython(reject_legacy_plaintext_recordings, migrations.RunPython.noop),
        migrations.AddField(
            model_name="recordingupload",
            name="encrypted_data_key",
            field=api.encrypted_fields.EncryptedTextField(
                blank=True,
                editable=False,
                max_length=44,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="encryption_version",
            field=models.PositiveSmallIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="recordingupload",
            name="storage_offset",
            field=models.PositiveBigIntegerField(editable=False, null=True),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="encrypted_data_key",
            field=api.encrypted_fields.EncryptedTextField(editable=False, max_length=44),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="encryption_version",
            field=models.PositiveSmallIntegerField(editable=False),
        ),
        migrations.AlterField(
            model_name="recordingupload",
            name="storage_offset",
            field=models.PositiveBigIntegerField(editable=False),
        ),
        migrations.AddConstraint(
            model_name="recordingupload",
            constraint=models.CheckConstraint(
                condition=models.Q(encryption_version=RECORDING_ENCRYPTION_VERSION) & ~models.Q(encrypted_data_key=""),
                name="valid_recording_crypto_format",
            ),
        ),
        migrations.AddConstraint(
            model_name="recordingupload",
            constraint=models.CheckConstraint(
                condition=models.Q(storage_offset__gte=RECORDING_HEADER_SIZE)
                & models.Q(storage_offset__gt=models.F("committed_offset")),
                name="recording_ciphertext_offset",
            ),
        ),
    ]
