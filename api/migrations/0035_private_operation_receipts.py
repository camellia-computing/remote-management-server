"""Retire guessable v1 receipts; retain their IDs as non-replayable tombstones.

Never restore a weak digest or expose a v2 private binding during rollback.
Native ALTER statements avoid rebuilding SQLite tables with PostgreSQL indexes.
"""

from django.db import migrations, models

_ZERO_DIGEST = "0" * 64


def _connection(schema_editor):
    connection = schema_editor.connection
    if connection.vendor not in {"postgresql", "sqlite"} or not connection.in_atomic_block:
        raise RuntimeError("private operation receipts require an atomic PostgreSQL or debug SQLite migration")
    return connection


def _retire(cursor, table, *, versioned):
    version = ", receipt_version = 0" if versioned else ""
    cursor.execute(
        f"UPDATE {table} SET request_digest = %s, status_code = 410, secret_response = ''{version}",
        [_ZERO_DIGEST],
    )


def install_private_receipts(apps, schema_editor):
    connection = _connection(schema_editor)
    table = connection.ops.quote_name("api_managementbatchoperation")
    authority = connection.ops.quote_name("valid_mgmt_receipt_version")
    check = (
        f"((receipt_version = 0 AND request_digest = '{_ZERO_DIGEST}' "
        "AND status_code = 410 AND secret_response = '') "
        "OR (receipt_version = 2 AND secret_response <> ''))"
    )
    with connection.cursor() as cursor:
        if connection.vendor == "postgresql":
            cursor.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE")
        _retire(cursor, table, versioned=False)
        # Database default 0 is deliberately fail-closed for raw inserts. ORM
        # creates explicitly supply the current version and encrypted binding.
        cursor.execute(
            f"ALTER TABLE {table} ADD COLUMN receipt_version SMALLINT NOT NULL DEFAULT 0 "
            f"CONSTRAINT {authority} CHECK {check}"
        )
        cursor.execute(f"ALTER TABLE {table} DROP COLUMN response")


def uninstall_private_receipts(apps, schema_editor):
    connection = _connection(schema_editor)
    table = connection.ops.quote_name("api_managementbatchoperation")
    response_type = "JSONB" if connection.vendor == "postgresql" else "TEXT"
    with connection.cursor() as cursor:
        if connection.vendor == "postgresql":
            cursor.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE")
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN response {response_type} NOT NULL DEFAULT '{{}}'")
        # The old reader treated decrypted secret_response as the public body.
        # Destroy private keys before it can read the downgraded schema.
        _retire(cursor, table, versioned=True)
        cursor.execute(f"ALTER TABLE {table} DROP COLUMN receipt_version")


class Migration(migrations.Migration):
    atomic = True
    dependencies = [("api", "0034_frozen_username_identity")]
    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[migrations.RunPython(install_private_receipts, uninstall_private_receipts)],
            state_operations=[
                migrations.AddField(
                    model_name="managementbatchoperation",
                    name="receipt_version",
                    field=models.PositiveSmallIntegerField(default=2, editable=False),
                ),
                migrations.RemoveField(model_name="managementbatchoperation", name="response"),
                migrations.AddConstraint(
                    model_name="managementbatchoperation",
                    constraint=models.CheckConstraint(
                        condition=(
                            models.Q(
                                receipt_version=0, request_digest=_ZERO_DIGEST, status_code=410, secret_response=""
                            )
                            | (models.Q(receipt_version=2) & ~models.Q(secret_response=""))
                        ),
                        name="valid_mgmt_receipt_version",
                    ),
                ),
            ],
        )
    ]
