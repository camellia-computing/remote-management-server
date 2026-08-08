import hashlib
import unicodedata

from django.db import connections

USERNAME_CANONICAL_VERSION = 1
USERNAME_CANONICAL_ALGORITHM = "unicode-16.0.0-nfkc-casefold-nfkc-strip-v1"
USERNAME_UNICODE_DATA_VERSION = "16.0.0"
USERNAME_MAX_LENGTH = 50
USERNAME_MAX_INPUT_LENGTH = 200
USERNAME_CANONICAL_MAX_BYTES = 1024
USERNAME_MIGRATION = "0026_username_canonical_identity"

POSTGRES_ENCODING = "UTF8"
POSTGRES_LOCALE_PROVIDER = "b"
POSTGRES_LOCALE = "C.UTF-8"
POSTGRES_COLLATION_VERSION = "1"

MAX_IDENTITY_ERRORS = 20


class UsernameIdentityError(RuntimeError):
    pass


def require_username_unicode_version():
    if unicodedata.unidata_version != USERNAME_UNICODE_DATA_VERSION:
        raise UsernameIdentityError(
            "username canonicalization requires Unicode data "
            f"{USERNAME_UNICODE_DATA_VERSION}, found {unicodedata.unidata_version}"
        )


def normalize_username(value):
    require_username_unicode_version()
    if not isinstance(value, str) or len(value) > USERNAME_MAX_INPUT_LENGTH:
        raise ValueError("username is not a bounded string")
    normalized = unicodedata.normalize("NFKC", value.strip())
    if not normalized or len(normalized) > USERNAME_MAX_LENGTH:
        raise ValueError("username has an invalid normalized length")
    return normalized


def canonical_username(value):
    normalized = normalize_username(value)
    canonical = unicodedata.normalize("NFKC", normalized.casefold())
    if not canonical:
        raise ValueError("username has an empty canonical form")
    return canonical


def canonical_username_key(value):
    key = canonical_username(value).encode("utf-8")
    if len(key) > USERNAME_CANONICAL_MAX_BYTES:
        raise ValueError("username canonical form is too large")
    return key


def canonical_username_digest(key):
    return hashlib.sha256(bytes(key)).hexdigest()[:16]


def _check_postgresql_contract(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT
                current_setting('server_encoding'),
                database.datlocprovider,
                database.datlocale,
                database.datcollate,
                database.datctype,
                database.datcollversion,
                pg_database_collation_actual_version(database.oid)
            FROM pg_database AS database
            WHERE database.datname = current_database()
            """
        )
        row = cursor.fetchone()
    expected = (
        POSTGRES_ENCODING,
        POSTGRES_LOCALE_PROVIDER,
        POSTGRES_LOCALE,
        POSTGRES_LOCALE,
        POSTGRES_LOCALE,
        POSTGRES_COLLATION_VERSION,
        POSTGRES_COLLATION_VERSION,
    )
    if row != expected:
        raise UsernameIdentityError(
            "PostgreSQL database identity contract mismatch: expected UTF8/builtin/C.UTF-8 "
            "with recorded and actual collation version 1"
        )


def _check_schema(connection):
    quoted_table = connection.ops.quote_name("api_userprofile")
    quoted_column = connection.ops.quote_name("username_canonical")
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM django_migrations WHERE app = %s AND name = %s",
                ["api", USERNAME_MIGRATION],
            )
            if cursor.fetchone() is None:
                raise UsernameIdentityError("username canonical schema migration is not applied")
            cursor.execute(f"SELECT {quoted_column} FROM {quoted_table} WHERE 1 = 0")  # noqa: S608
            constraints = connection.introspection.get_constraints(cursor, "api_userprofile")
            description = connection.introspection.get_table_description(cursor, "api_userprofile")
            canonical_column = next(
                (column for column in description if column.name == "username_canonical"),
                None,
            )
            sqlite_null_guards = set()
            if connection.vendor == "sqlite" and canonical_column is not None and canonical_column.null_ok:
                cursor.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'trigger'
                      AND tbl_name = 'api_userprofile'
                      AND name IN (
                          'api_userprofile_username_canonical_insert_guard',
                          'api_userprofile_username_canonical_update_guard'
                      )
                    """
                )
                sqlite_null_guards = {row[0] for row in cursor.fetchall()}
    except UsernameIdentityError:
        raise
    except Exception as exc:
        raise UsernameIdentityError("username canonical schema is unavailable") from exc

    unique_constraints = [
        name
        for name, constraint in constraints.items()
        if constraint.get("unique") and constraint.get("columns") == ["username_canonical"]
    ]
    if len(unique_constraints) != 1 or "unique_username_case_insensitive" in constraints:
        raise UsernameIdentityError("username canonical database authority is invalid")
    expected_sqlite_null_guards = {
        "api_userprofile_username_canonical_insert_guard",
        "api_userprofile_username_canonical_update_guard",
    }
    if canonical_column is None or (canonical_column.null_ok and sqlite_null_guards != expected_sqlite_null_guards):
        raise UsernameIdentityError("username canonical null authority is invalid")


def check_username_identity(*, using="default", full=False):
    require_username_unicode_version()
    connection = connections[using]
    if connection.vendor == "postgresql":
        _check_postgresql_contract(connection)
    elif connection.vendor != "sqlite":
        raise UsernameIdentityError(f"unsupported username identity database backend: {connection.vendor}")
    _check_schema(connection)
    if not full:
        return

    from api.models import UserProfile

    errors = []
    error_count = 0
    rows = UserProfile.objects.using(using).order_by("pk").values_list("pk", "username", "username_canonical")
    for user_id, username, stored_key in rows.iterator(chunk_size=1000):
        try:
            expected_key = canonical_username_key(username)
        except UsernameIdentityError, ValueError:
            error_count += 1
            if len(errors) < MAX_IDENTITY_ERRORS:
                errors.append(f"id={user_id}:invalid")
            continue
        stored_key = bytes(stored_key or b"")
        if stored_key != expected_key:
            error_count += 1
            if len(errors) < MAX_IDENTITY_ERRORS:
                errors.append(f"id={user_id}:canonical={canonical_username_digest(expected_key)}")
    if error_count:
        suffix = f"; first {len(errors)}: " + ", ".join(errors) if errors else ""
        raise UsernameIdentityError(f"username canonical identity check found {error_count} error(s){suffix}")
