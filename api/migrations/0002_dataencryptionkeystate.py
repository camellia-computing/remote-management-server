import base64
import hashlib

from django.conf import settings
from django.db import migrations, models
from nacl.secret import SecretBox

CANARY_PLAINTEXT = b"camellia-data-encryption-canary-v1"


def initialize_key_inventory(apps, schema_editor):
    key_state = apps.get_model("api", "DataEncryptionKeyState")
    primary_key_id = settings.DATA_ENCRYPTION_PRIMARY_KEY_ID
    for key_id, key in settings.DATA_ENCRYPTION_KEYS.items():
        encrypted = SecretBox(key).encrypt(CANARY_PLAINTEXT)
        envelope = f"secretbox:v2:{key_id}:{base64.b64encode(bytes(encrypted)).decode('ascii')}"
        key_state.objects.create(
            key_id=key_id,
            key_fingerprint=hashlib.sha256(key).hexdigest(),
            encrypted_canary=envelope,
            is_primary=key_id == primary_key_id,
        )


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="DataEncryptionKeyState",
            fields=[
                ("key_id", models.CharField(max_length=32, primary_key=True, serialize=False)),
                ("key_fingerprint", models.CharField(max_length=64, unique=True)),
                ("encrypted_canary", models.TextField()),
                ("is_primary", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ("key_id",),
                "constraints": [
                    models.UniqueConstraint(
                        condition=models.Q(("is_primary", True)),
                        fields=("is_primary",),
                        name="one_primary_data_encryption_key",
                    ),
                ],
            },
        ),
        migrations.RunPython(initialize_key_inventory, migrations.RunPython.noop),
    ]
