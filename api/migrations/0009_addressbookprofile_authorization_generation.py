from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0008_remotedevice_policy_generation"),
    ]

    operations = [
        migrations.AddField(
            model_name="addressbookprofile",
            name="authorization_generation",
            field=models.PositiveBigIntegerField(default=0, editable=False),
        ),
    ]
