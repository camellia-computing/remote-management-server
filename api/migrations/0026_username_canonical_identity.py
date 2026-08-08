import hashlib
import unicodedata

from django.db import migrations, models

EXPECTED_UNICODE_DATA_VERSION = "16.0.0"
MAX_USERNAME_LENGTH = 50
MAX_CANONICAL_BYTES = 1024
MAX_REPORTED_ERRORS = 20


def _username_identity(value):
    if unicodedata.unidata_version != EXPECTED_UNICODE_DATA_VERSION:
        raise RuntimeError(
            "username canonical migration requires Unicode data "
            f"{EXPECTED_UNICODE_DATA_VERSION}, found {unicodedata.unidata_version}"
        )
    normalized = unicodedata.normalize("NFKC", str(value or "").strip())
    if not normalized or len(normalized) > MAX_USERNAME_LENGTH:
        raise ValueError("invalid normalized username")
    canonical = unicodedata.normalize("NFKC", normalized.casefold()).encode("utf-8")
    if not canonical or len(canonical) > MAX_CANONICAL_BYTES:
        raise ValueError("invalid canonical username")
    return normalized, canonical


def populate_username_canonical(apps, schema_editor):
    UserProfile = apps.get_model("api", "UserProfile")
    database = schema_editor.connection.alias
    observed = {}
    collisions = []
    collision_count = 0
    invalid = []
    invalid_count = 0
    manager = UserProfile._base_manager.using(database)
    for user in manager.order_by("pk").iterator(chunk_size=1000):
        try:
            _normalized, canonical = _username_identity(user.username)
        except ValueError:
            invalid_count += 1
            if len(invalid) < MAX_REPORTED_ERRORS:
                invalid.append(str(user.pk))
            continue
        first_user_id = observed.setdefault(canonical, user.pk)
        if first_user_id != user.pk:
            collision_count += 1
            if len(collisions) < MAX_REPORTED_ERRORS:
                digest = hashlib.sha256(canonical).hexdigest()[:16]
                collisions.append(f"{first_user_id},{user.pk}:{digest}")
            continue

    if invalid_count or collision_count:
        details = []
        if invalid:
            details.append(f"invalid ids (first {len(invalid)}): {','.join(invalid)}")
        if collisions:
            details.append(f"collision ids:digest (first {len(collisions)}): {','.join(collisions)}")
        raise RuntimeError(
            "username canonical migration refused historical identity conflicts; "
            f"invalid={invalid_count}, collisions={collision_count}; " + "; ".join(details)
        )

    users = []
    for user in manager.order_by("pk").iterator(chunk_size=1000):
        user.username, user.username_canonical = _username_identity(user.username)
        users.append(user)
        if len(users) == 500:
            manager.bulk_update(users, ["username", "username_canonical"], batch_size=500)
            users.clear()
    if users:
        manager.bulk_update(users, ["username", "username_canonical"], batch_size=500)


def finalize_username_canonical_authority(apps, schema_editor):
    quote = schema_editor.connection.ops.quote_name
    table = quote("api_userprofile")
    column = quote("username_canonical")
    constraint = quote("unique_username_canonical_binary")
    with schema_editor.connection.cursor() as cursor:
        if schema_editor.connection.vendor == "postgresql":
            cursor.execute(f"ALTER TABLE {table} ALTER COLUMN {column} SET NOT NULL")
            cursor.execute(f"ALTER TABLE {table} ADD CONSTRAINT {constraint} UNIQUE ({column})")
        elif schema_editor.connection.vendor == "sqlite":
            cursor.execute(f"CREATE UNIQUE INDEX {constraint} ON {table} ({column})")
            cursor.execute(
                f"""
                CREATE TRIGGER api_userprofile_username_canonical_insert_guard
                BEFORE INSERT ON {table}
                WHEN NEW.{column} IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'username_canonical must not be null');
                END
                """
            )
            cursor.execute(
                f"""
                CREATE TRIGGER api_userprofile_username_canonical_update_guard
                BEFORE UPDATE OF {column} ON {table}
                WHEN NEW.{column} IS NULL
                BEGIN
                    SELECT RAISE(ABORT, 'username_canonical must not be null');
                END
                """
            )
        else:
            raise RuntimeError(f"unsupported username identity database backend: {schema_editor.connection.vendor}")


def remove_username_canonical_authority(apps, schema_editor):
    quote = schema_editor.connection.ops.quote_name
    table = quote("api_userprofile")
    column = quote("username_canonical")
    constraint = quote("unique_username_canonical_binary")
    with schema_editor.connection.cursor() as cursor:
        if schema_editor.connection.vendor == "postgresql":
            cursor.execute(f"ALTER TABLE {table} DROP CONSTRAINT {constraint}")
            cursor.execute(f"ALTER TABLE {table} ALTER COLUMN {column} DROP NOT NULL")
        elif schema_editor.connection.vendor == "sqlite":
            cursor.execute("DROP TRIGGER api_userprofile_username_canonical_insert_guard")
            cursor.execute("DROP TRIGGER api_userprofile_username_canonical_update_guard")
            cursor.execute(f"DROP INDEX {constraint}")
        else:
            raise RuntimeError(f"unsupported username identity database backend: {schema_editor.connection.vendor}")


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0025_oidc_callback_claims"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="username_canonical",
            field=models.BinaryField(blank=True, editable=False, max_length=1024, null=True),
        ),
        migrations.RunPython(populate_username_canonical, migrations.RunPython.noop),
        migrations.RemoveConstraint(
            model_name="userprofile",
            name="unique_username_case_insensitive",
        ),
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    finalize_username_canonical_authority,
                    remove_username_canonical_authority,
                ),
            ],
            state_operations=[
                migrations.AlterField(
                    model_name="userprofile",
                    name="username_canonical",
                    field=models.BinaryField(blank=True, editable=False, max_length=1024, unique=True),
                ),
            ],
        ),
    ]
