from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0004_oidcidentity_auto_provisioned"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="credential_generation",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
        migrations.AddField(
            model_name="remotetoken",
            name="credential_hash",
            field=models.CharField(default="", editable=False, max_length=64),
        ),
    ]
