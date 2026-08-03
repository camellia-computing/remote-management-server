import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from api.encrypted_fields import (
    FIELD_PREFIX,
    LEGACY_FIELD_PREFIX,
    decrypt_text,
    encrypt_text,
    key_canary,
    key_fingerprint,
    verify_key_canary,
)
from api.models import DataEncryptionKeyState

ENCRYPTED_COLUMNS = (
    ("api_remotepeer", "id", "rhash"),
    ("api_remotepeer", "id", "password"),
    ("api_remotedevice", "id", "address_book_password"),
    ("api_oidcpendingauth", "state", "nonce"),
    ("api_oidcpendingauth", "state", "code_verifier"),
)
MAX_REPORTED_ERRORS = 20


def _envelope_key_id(envelope):
    if envelope.startswith(FIELD_PREFIX):
        key_id, separator, _encoded = envelope.removeprefix(FIELD_PREFIX).partition(":")
        return key_id if separator else ""
    if envelope.startswith(LEGACY_FIELD_PREFIX):
        return settings.DATA_ENCRYPTION_V1_KEY_ID
    return ""


class Command(BaseCommand):
    help = "Re-encrypt protected database fields with the configured primary key."

    def add_arguments(self, parser):
        parser.add_argument("--batch-size", type=int, default=100)
        parser.add_argument("--max-batches", type=int)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--retire-key-id")

    def handle(self, *args, **options):
        batch_size = options["batch_size"]
        max_batches = options["max_batches"]
        dry_run = bool(options["dry_run"])
        if batch_size < 1 or batch_size > 1_000:
            raise CommandError("--batch-size must be between 1 and 1000")
        if max_batches is not None and max_batches < 1:
            raise CommandError("--max-batches must be positive")

        primary_key_id = settings.DATA_ENCRYPTION_PRIMARY_KEY_ID
        retire_key_id = (options["retire_key_id"] or "").strip().lower()
        if retire_key_id == primary_key_id:
            raise CommandError("The primary data-encryption key cannot be retired")
        if retire_key_id and retire_key_id not in settings.DATA_ENCRYPTION_KEYS:
            raise CommandError("The key requested for retirement is not configured")
        self._validate_and_switch_inventory(primary_key_id, dry_run=dry_run)

        result = {
            "batches": 0,
            "dry_run": dry_run,
            "primary_key_id": primary_key_id,
            "rewritten": 0,
            "validated": 0,
        }
        for table, pk_column, encrypted_column in ENCRYPTED_COLUMNS:
            if max_batches is not None and result["batches"] >= max_batches:
                break
            self._rotate_column(
                table,
                pk_column,
                encrypted_column,
                batch_size=batch_size,
                max_batches=max_batches,
                result=result,
            )

        if max_batches is None or retire_key_id:
            result["validated"], result["remaining"] = self._validate_all_values(primary_key_id)
        else:
            result["remaining"] = self._count_non_primary_values(primary_key_id)
        if not dry_run and max_batches is None and result["remaining"]:
            raise CommandError(
                f"Data-encryption rotation left {result['remaining']} values outside the primary key domain"
            )

        if retire_key_id:
            if result["remaining"]:
                references = self._count_key_references(retire_key_id)
                if references:
                    raise CommandError(
                        f"Data-encryption key {retire_key_id} is still referenced by "
                        f"{references} database values"
                    )
                raise CommandError(
                    "A data-encryption key cannot be retired while database values remain outside "
                    "the primary key domain"
                )
            self._retire_key(retire_key_id, dry_run=dry_run)
            result["retired_key_id"] = retire_key_id
        self.stdout.write(json.dumps(result, sort_keys=True))

    def _validate_and_switch_inventory(self, primary_key_id, *, dry_run):
        with transaction.atomic():
            states = list(DataEncryptionKeyState.objects.select_for_update().order_by("key_id"))
            if not states:
                raise CommandError("The data-encryption key inventory is empty")
            for state in states:
                if not verify_key_canary(
                    state.key_id,
                    state.key_fingerprint,
                    state.encrypted_canary,
                ):
                    raise CommandError(f"The configured key cannot verify inventory entry {state.key_id}")
            if primary_key_id not in {state.key_id for state in states}:
                key = settings.DATA_ENCRYPTION_KEYS[primary_key_id]
                if not dry_run:
                    DataEncryptionKeyState.objects.create(
                        key_id=primary_key_id,
                        key_fingerprint=key_fingerprint(key),
                        encrypted_canary=key_canary(primary_key_id),
                        is_primary=False,
                    )
            if not dry_run:
                DataEncryptionKeyState.objects.filter(is_primary=True).update(is_primary=False)
                updated = DataEncryptionKeyState.objects.filter(key_id=primary_key_id).update(is_primary=True)
                if updated != 1:
                    raise CommandError("Unable to set the primary data-encryption key inventory entry")

    def _rotate_column(
        self,
        table,
        pk_column,
        encrypted_column,
        *,
        batch_size,
        max_batches,
        result,
    ):
        quote = connection.ops.quote_name
        table_name = quote(table)
        pk_name = quote(pk_column)
        field_name = quote(encrypted_column)
        last_pk = None
        primary_prefix = f"{FIELD_PREFIX}{settings.DATA_ENCRYPTION_PRIMARY_KEY_ID}:"
        while max_batches is None or result["batches"] < max_batches:
            with transaction.atomic():
                where = (
                    f"{field_name} IS NOT NULL AND {field_name} <> %s "
                    f"AND SUBSTR({field_name}, 1, %s) <> %s"
                )
                params = ["", len(primary_prefix), primary_prefix]
                if last_pk is not None:
                    where += f" AND {pk_name} > %s"
                    params.append(last_pk)
                statement = (
                    f"SELECT {pk_name}, {field_name} FROM {table_name} "  # noqa: S608 - fixed allowlist
                    f"WHERE {where} ORDER BY {pk_name} LIMIT %s"
                )
                params.append(batch_size)
                if connection.features.has_select_for_update:
                    statement += " FOR UPDATE"
                with connection.cursor() as cursor:
                    cursor.execute(statement, params)
                    rows = cursor.fetchall()
                if not rows:
                    return

                changes = []
                errors = []
                for row_pk, envelope in rows:
                    try:
                        plaintext = decrypt_text(envelope)
                        result["validated"] += 1
                        if _envelope_key_id(envelope) != settings.DATA_ENCRYPTION_PRIMARY_KEY_ID:
                            changes.append((row_pk, envelope, encrypt_text(plaintext)))
                    except ValidationError as exc:
                        errors.append(f"{table}.{encrypted_column}[{row_pk!r}]: {exc.message}")
                        if len(errors) >= MAX_REPORTED_ERRORS:
                            break
                if errors:
                    raise CommandError("Data-encryption rotation stopped: " + "; ".join(errors))

                if not result["dry_run"]:
                    with connection.cursor() as cursor:
                        for row_pk, old_envelope, new_envelope in changes:
                            cursor.execute(
                                f"UPDATE {table_name} SET {field_name} = %s "  # noqa: S608 - fixed allowlist
                                f"WHERE {pk_name} = %s AND {field_name} = %s",
                                [new_envelope, row_pk, old_envelope],
                            )
                            if cursor.rowcount != 1:
                                raise CommandError(
                                    f"Concurrent update detected for {table}.{encrypted_column}[{row_pk!r}]"
                                )
                result["rewritten"] += len(changes)
                result["batches"] += 1
                last_pk = rows[-1][0]

    def _retire_key(self, key_id, *, dry_run):
        if key_id == settings.DATA_ENCRYPTION_PRIMARY_KEY_ID:
            raise CommandError("The primary data-encryption key cannot be retired")
        if key_id not in settings.DATA_ENCRYPTION_KEYS:
            raise CommandError("The key requested for retirement is not configured")
        references = self._count_key_references(key_id)
        if references:
            raise CommandError(f"Data-encryption key {key_id} is still referenced by {references} database values")
        if not dry_run:
            deleted, _details = DataEncryptionKeyState.objects.filter(key_id=key_id, is_primary=False).delete()
            if deleted != 1:
                raise CommandError("The data-encryption key inventory entry could not be retired")

    def _count_key_references(self, key_id):
        quote = connection.ops.quote_name
        v2_prefix = f"{FIELD_PREFIX}{key_id}:"
        references = 0
        for table, _pk_column, encrypted_column in ENCRYPTED_COLUMNS:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT COUNT(*) FROM {quote(table)} "  # noqa: S608 - fixed allowlist
                    f"WHERE SUBSTR({quote(encrypted_column)}, 1, %s) = %s",
                    [len(v2_prefix), v2_prefix],
                )
                references += cursor.fetchone()[0]
        if key_id == settings.DATA_ENCRYPTION_V1_KEY_ID:
            legacy_prefix = LEGACY_FIELD_PREFIX
            for table, _pk_column, encrypted_column in ENCRYPTED_COLUMNS:
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT COUNT(*) FROM {quote(table)} "  # noqa: S608 - fixed allowlist
                        f"WHERE SUBSTR({quote(encrypted_column)}, 1, %s) = %s",
                        [len(legacy_prefix), legacy_prefix],
                    )
                    references += cursor.fetchone()[0]
        return references

    def _count_non_primary_values(self, primary_key_id):
        quote = connection.ops.quote_name
        primary_prefix = f"{FIELD_PREFIX}{primary_key_id}:"
        references = 0
        for table, _pk_column, encrypted_column in ENCRYPTED_COLUMNS:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT COUNT(*) FROM {quote(table)} "  # noqa: S608 - fixed allowlist
                    f"WHERE {quote(encrypted_column)} IS NOT NULL "
                    f"AND {quote(encrypted_column)} <> %s "
                    f"AND SUBSTR({quote(encrypted_column)}, 1, %s) <> %s",
                    ["", len(primary_prefix), primary_prefix],
                )
                references += cursor.fetchone()[0]
        return references

    def _validate_all_values(self, primary_key_id):
        quote = connection.ops.quote_name
        validated = 0
        remaining = 0
        for table, pk_column, encrypted_column in ENCRYPTED_COLUMNS:
            table_name = quote(table)
            pk_name = quote(pk_column)
            field_name = quote(encrypted_column)
            last_pk = None
            while True:
                where = f"{field_name} IS NOT NULL AND {field_name} <> %s"
                params = [""]
                if last_pk is not None:
                    where += f" AND {pk_name} > %s"
                    params.append(last_pk)
                params.append(1_000)
                with connection.cursor() as cursor:
                    cursor.execute(
                        f"SELECT {pk_name}, {field_name} FROM {table_name} "  # noqa: S608 - fixed allowlist
                        f"WHERE {where} ORDER BY {pk_name} LIMIT %s",
                        params,
                    )
                    rows = cursor.fetchall()
                if not rows:
                    break
                errors = []
                for row_pk, envelope in rows:
                    try:
                        decrypt_text(envelope)
                        validated += 1
                        if _envelope_key_id(envelope) != primary_key_id:
                            remaining += 1
                    except ValidationError as exc:
                        errors.append(f"{table}.{encrypted_column}[{row_pk!r}]: {exc.message}")
                        if len(errors) >= MAX_REPORTED_ERRORS:
                            break
                if errors:
                    raise CommandError("Data-encryption validation stopped: " + "; ".join(errors))
                last_pk = rows[-1][0]
        return validated, remaining
