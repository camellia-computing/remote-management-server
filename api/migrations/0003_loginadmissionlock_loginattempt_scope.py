import hashlib

from django.db import migrations, models


def populate_scope_hash(apps, schema_editor):
    login_attempt = apps.get_model("api", "LoginAttempt")
    for attempt in login_attempt.objects.all().only("pk", "username").iterator():
        scope = "register" if attempt.username.startswith("register:") else "login"
        username = attempt.username.removeprefix("register:") if scope == "register" else attempt.username
        normalized = username.casefold()[:150]
        attempt.scope_hash = hashlib.sha256(f"{scope}\0{normalized}".encode()).hexdigest()
        attempt.save(update_fields=["scope_hash"])


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0002_dataencryptionkeystate"),
    ]

    operations = [
        migrations.CreateModel(
            name="LoginAdmissionLock",
            fields=[
                (
                    "ip",
                    models.GenericIPAddressField(primary_key=True, serialize=False, verbose_name="IP"),
                ),
                ("updated_at", models.DateTimeField(auto_now=True, db_index=True)),
            ],
            options={
                "verbose_name": "登录准入锁",
                "verbose_name_plural": "登录准入锁列表",
            },
        ),
        migrations.AddField(
            model_name="loginattempt",
            name="scope_hash",
            field=models.CharField(default="", max_length=64, verbose_name="Rate Scope Hash"),
        ),
        migrations.RunPython(populate_scope_hash, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name="loginattempt",
            index=models.Index(
                fields=["ip", "scope_hash", "-created_at"],
                name="login_attempt_atomic_scope",
            ),
        ),
    ]
