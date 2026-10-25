from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def bind_existing_token_subjects(apps, schema_editor):
    from django.db.models import OuterRef, Subquery

    RemoteDevice = apps.get_model("api", "RemoteDevice")
    RemoteToken = apps.get_model("api", "RemoteToken")
    device_owner = RemoteDevice.objects.filter(pk=OuterRef("device_id")).values("owner_id")[:1]
    RemoteToken.objects.update(subject_user_id=Subquery(device_owner))
    RemoteToken.objects.filter(subject_user_id__isnull=True).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0005_credential_generation"),
    ]

    operations = [
        migrations.AddField(
            model_name="remotetoken",
            name="subject_user",
            field=models.ForeignKey(
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="remote_tokens",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.RunPython(bind_existing_token_subjects, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="remotetoken",
            name="subject_user",
            field=models.ForeignKey(
                editable=False,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="remote_tokens",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
