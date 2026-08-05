from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0007_device_identity_proof"),
    ]

    operations = [
        migrations.AddField(
            model_name="remotedevice",
            name="policy_generation",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
    ]
