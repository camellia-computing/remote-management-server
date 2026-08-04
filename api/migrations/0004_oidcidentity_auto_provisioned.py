from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0003_loginadmissionlock_loginattempt_scope"),
    ]

    operations = [
        migrations.AddField(
            model_name="oidcidentity",
            name="is_auto_provisioned",
            field=models.BooleanField(default=True, verbose_name="Policy-managed auto provision"),
        ),
        migrations.AlterField(
            model_name="oidcidentity",
            name="is_auto_provisioned",
            field=models.BooleanField(default=False, verbose_name="Policy-managed auto provision"),
        ),
    ]
