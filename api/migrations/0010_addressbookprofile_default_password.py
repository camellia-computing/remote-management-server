from django.db import migrations

from api.encrypted_fields import EncryptedTextField

_FORBIDDEN_KEYS = frozenset(
    {
        "credential",
        "credentials",
        "password",
        "rhash",
        "secret",
        "token",
    }
)
_MAX_PASSWORD_BYTES = 240
_MAX_PASSWORD_CHARS = 60


def _contains_forbidden_key(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key.casefold() in _FORBIDDEN_KEYS:
                return True
            if _contains_forbidden_key(child):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_key(child) for child in value)
    return False


def move_legacy_profile_passwords(apps, schema_editor):
    profile_model = apps.get_model("api", "AddressBookProfile")
    for profile in profile_model.objects.order_by("pk").iterator():
        info = profile.info
        password = ""
        if isinstance(info, dict) and "password" in info:
            password = info["password"]
            info = {key: value for key, value in info.items() if key != "password"}
        if _contains_forbidden_key(info):
            raise RuntimeError(f"AddressBookProfile {profile.pk} contains a credential key in info")
        if password is None:
            password = ""
        if (
            not isinstance(password, str)
            or len(password) > _MAX_PASSWORD_CHARS
            or len(password.encode()) > _MAX_PASSWORD_BYTES
        ):
            raise RuntimeError(f"AddressBookProfile {profile.pk} contains an invalid default credential")
        profile.info = info
        profile.default_password = password
        profile.save(update_fields=("info", "default_password"))


def restore_legacy_profile_passwords(apps, schema_editor):
    profile_model = apps.get_model("api", "AddressBookProfile")
    for profile in profile_model.objects.order_by("pk").iterator():
        info = profile.info
        if _contains_forbidden_key(info):
            raise RuntimeError(f"AddressBookProfile {profile.pk} contains a credential key in info")
        if not isinstance(info, dict):
            raise RuntimeError(f"AddressBookProfile {profile.pk} has a non-object info value")
        if profile.default_password:
            info = {**info, "password": profile.default_password}
        profile.info = info
        profile.save(update_fields=("info",))


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0009_addressbookprofile_authorization_generation"),
    ]

    operations = [
        migrations.AddField(
            model_name="addressbookprofile",
            name="default_password",
            field=EncryptedTextField(
                blank=True,
                default="",
                max_length=60,
                verbose_name="默认共享密码",
            ),
        ),
        migrations.RunPython(move_legacy_profile_passwords, restore_legacy_profile_passwords),
    ]
