"""Repair interpreter-dependent v1 keys without rewriting migration history."""

import hashlib

from django.db import migrations, models
from django.db.models.functions import Length, Substr

from api.username_unicode16 import canonical_username_key, normalize_username, require_unicode_version
from api.username_validators import Unicode16UsernameValidator

_BATCH_SIZE = 500
_MAX_REPORTED = 20


def _stage_batch(cursor, scratch, table, primary_key, column, rows):
    keys = list(dict.fromkeys(key for _user_id, key in rows))
    placeholders = ",".join(["%s"] * len(keys))
    cursor.execute(f"SELECT canonical, user_id FROM {scratch} WHERE canonical IN ({placeholders})", keys)
    observed = {bytes(key): user_id for key, user_id in cursor.fetchall()}
    inserts = []
    collisions = []
    for user_id, key in rows:
        first_id = observed.get(key)
        if first_id is not None:
            collisions.append((first_id, user_id, hashlib.sha256(key).hexdigest()[:16]))
            continue
        observed[key] = user_id
        # Comparison stays in the database: do not fetch possibly corrupt,
        # oversized historical binary keys into Python's bounded row batch.
        inserts.append((key, key, user_id))
    if inserts:
        cursor.executemany(
            f"INSERT INTO {scratch} (user_id, canonical, needs_update) "
            f"SELECT {primary_key}, %s, CASE WHEN {column} = %s THEN FALSE ELSE TRUE END "
            f"FROM {table} WHERE {primary_key} = %s",
            inserts,
        )
    return collisions


def repair_username_identity(apps, schema_editor):
    require_unicode_version()
    connection = schema_editor.connection
    if not connection.in_atomic_block:
        raise RuntimeError("username repair requires an atomic migration")
    if connection.vendor not in {"postgresql", "sqlite"}:
        raise RuntimeError("unsupported username identity database backend")

    User = apps.get_model("api", "UserProfile")
    quote = connection.ops.quote_name
    table = quote(User._meta.db_table)
    primary_key = quote(User._meta.pk.column)
    column = quote("username_canonical")
    constraint = quote("unique_username_canonical_binary")
    scratch = quote("camellia_username_unicode16_rekey")
    binary_type = "BYTEA" if connection.vendor == "postgresql" else "BLOB"
    on_commit = " ON COMMIT DROP" if connection.vendor == "postgresql" else ""
    invalid = []
    invalid_count = 0
    collisions = []
    collision_count = 0

    with connection.cursor() as cursor:
        if connection.vendor == "postgresql":
            cursor.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE")
        else:
            # SQLite is debug-only. Acquire its writer reservation before the
            # snapshot so another connection cannot rename/insert during staging.
            cursor.execute(f"UPDATE {table} SET {column} = {column} WHERE 0 = 1")
        constraints = connection.introspection.get_constraints(cursor, User._meta.db_table)
        authority = {
            name
            for name, definition in constraints.items()
            if definition.get("unique") and definition.get("columns") == ["username_canonical"]
        }
        if authority != {"unique_username_canonical_binary"}:
            raise RuntimeError("username repair requires the original binary authority")
        cursor.execute(
            f"CREATE TEMPORARY TABLE {scratch} "
            f"(user_id BIGINT PRIMARY KEY, canonical {binary_type} NOT NULL UNIQUE, needs_update BOOLEAN NOT NULL)"
            f"{on_commit}"
        )
        rows = (
            User._base_manager.using(connection.alias)
            .order_by("pk")
            .annotate(_identity_length=Length("username"), _identity_prefix=Substr("username", 1, 51))
            .values_list("pk", "_identity_length", "_identity_prefix")
        )
        batch = []
        for user_id, length, username in rows.iterator(chunk_size=_BATCH_SIZE):
            try:
                if length is None or length > 50 or normalize_username(username) != username:
                    raise ValueError
                key = canonical_username_key(username)
            except ValueError:
                invalid_count += 1
                if len(invalid) < _MAX_REPORTED:
                    invalid.append(str(user_id))
                continue
            batch.append((user_id, key))
            if len(batch) == _BATCH_SIZE:
                found = _stage_batch(cursor, scratch, table, primary_key, column, batch)
                collision_count += len(found)
                collisions.extend(found[: max(0, _MAX_REPORTED - len(collisions))])
                batch.clear()
        if batch:
            found = _stage_batch(cursor, scratch, table, primary_key, column, batch)
            collision_count += len(found)
            collisions.extend(found[: max(0, _MAX_REPORTED - len(collisions))])

        if invalid_count or collision_count:
            cursor.execute(f"DROP TABLE {scratch}")
            details = ",".join(f"{first},{second}:{digest}" for first, second, digest in collisions)
            raise RuntimeError(
                "username repair refused existing identities; "
                f"invalid={invalid_count}, collisions={collision_count}; "
                f"invalid ids={','.join(invalid)}; collision ids:digest={details}"
            )

        cursor.execute(f"SELECT COUNT(*) FROM {scratch} WHERE needs_update")
        changed = cursor.fetchone()[0]
        if changed:
            # All final keys are already unique in the transaction-owned staging
            # table. Remove the old unique authority only inside the exclusive
            # atomic transaction; arbitrary old key swaps can then be repaired.
            if connection.vendor == "postgresql":
                cursor.execute(f"ALTER TABLE {table} DROP CONSTRAINT {constraint}")
            else:
                cursor.execute(f"DROP INDEX {constraint}")
            cursor.execute(
                f"UPDATE {table} SET {column} = "
                f"(SELECT canonical FROM {scratch} WHERE user_id = {table}.{primary_key}) "
                f"WHERE {primary_key} IN (SELECT user_id FROM {scratch} WHERE needs_update)"
            )
            if connection.vendor == "postgresql":
                cursor.execute(f"ALTER TABLE {table} ADD CONSTRAINT {constraint} UNIQUE ({column})")
            else:
                cursor.execute(f"CREATE UNIQUE INDEX {constraint} ON {table} ({column})")
        cursor.execute(f"DROP TABLE {scratch}")


class Migration(migrations.Migration):
    atomic = True
    dependencies = [("api", "0033_mutation_generations")]
    operations = [
        # Reverse keeps repaired keys. It must never restore an interpreter-
        # dependent identity; rollback is coordinated with the pinned runtime.
        migrations.RunPython(repair_username_identity, migrations.RunPython.noop),
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="userprofile",
                    name="username",
                    field=models.CharField(
                        max_length=50, unique=True, validators=[Unicode16UsernameValidator()], verbose_name="用户名"
                    ),
                )
            ],
        ),
    ]
