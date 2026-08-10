import json

from django.db import migrations

MAX_POLICY_OPTIONS = 512
MAX_POLICY_OPTIONS_BYTES = 64 * 1024
MAX_POLICY_KEY_CHARACTERS = 128
MAX_POLICY_KEY_BYTES = 512
MAX_POLICY_VALUE_CHARACTERS = 4096
MAX_POLICY_VALUE_BYTES = 16 * 1024
MAX_REPORTED_VIOLATIONS = 20

POSTGRESQL_FUNCTION = r"""
CREATE FUNCTION public.camellia_strategy_options_valid_v1(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT CASE
        WHEN jsonb_typeof(candidate) <> 'object' THEN FALSE
        ELSE (
            SELECT
                count(*) <= 512
                AND COALESCE(
                    bool_and(
                        option_key <> ''
                        AND char_length(option_key) <= 128
                        AND octet_length(option_key) <= 512
                        AND option_key !~ E'[\u0001-\u001F]'
                        AND jsonb_typeof(option_value) = 'string'
                        AND char_length(option_value #>> '{}') <= 4096
                        AND octet_length(option_value #>> '{}') <= 16384
                    ),
                    TRUE
                )
                AND (
                    2
                    + CASE WHEN count(*) = 0 THEN 0 ELSE count(*) - 1 END
                    + COALESCE(
                        sum(
                            octet_length(to_jsonb(option_key)::text)
                            + 1
                            + octet_length(option_value::text)
                        ),
                        0
                    )
                ) <= 65536
            FROM jsonb_each(candidate) AS options(option_key, option_value)
        )
    END
$function$
"""

POSTGRESQL_CONSTRAINT = """
ALTER TABLE public.api_strategyprofile
ADD CONSTRAINT valid_strategy_config_options_v1
CHECK (public.camellia_strategy_options_valid_v1(config_options))
NOT VALID
"""

SQLITE_INVALID_PREDICATE = """
    json_type(NEW.config_options) IS NOT 'object'
    OR (SELECT count(*) FROM json_each(NEW.config_options)) > 512
    OR (
        SELECT count(*) <> count(DISTINCT key)
        FROM json_each(NEW.config_options)
    )
    OR EXISTS (
        SELECT 1
        FROM json_each(NEW.config_options)
        WHERE
            type <> 'text'
            OR key IS NULL
            OR key = ''
            OR length(key) > 128
            OR length(CAST(key AS BLOB)) > 512
            OR key GLOB ('*[' || char(1) || '-' || char(31) || ']*')
            OR length(value) > 4096
            OR length(CAST(value AS BLOB)) > 16384
    )
    OR (
        SELECT
            2
            + CASE WHEN count(*) = 0 THEN 0 ELSE count(*) - 1 END
            + COALESCE(
                sum(
                    length(CAST(json_quote(key) AS BLOB))
                    + 1
                    + length(CAST(json_quote(value) AS BLOB))
                ),
                0
            )
        FROM json_each(NEW.config_options)
    ) > 65536
"""

SQLITE_INSTALL = (
    f"""
    CREATE TRIGGER api_strategy_options_insert_guard
    BEFORE INSERT ON api_strategyprofile
    FOR EACH ROW
    WHEN {SQLITE_INVALID_PREDICATE}
    BEGIN
        SELECT RAISE(ABORT, 'strategy_config_options_invalid');
    END
    """,
    f"""
    CREATE TRIGGER api_strategy_options_update_guard
    BEFORE UPDATE ON api_strategyprofile
    FOR EACH ROW
    WHEN {SQLITE_INVALID_PREDICATE}
    BEGIN
        SELECT RAISE(ABORT, 'strategy_config_options_invalid');
    END
    """,
)


def _valid_policy_options(value):
    if not isinstance(value, dict) or len(value) > MAX_POLICY_OPTIONS:
        return False
    for key, option_value in value.items():
        try:
            key_bytes = key.encode("utf-8") if isinstance(key, str) else b""
            value_bytes = option_value.encode("utf-8") if isinstance(option_value, str) else b""
        except UnicodeEncodeError:
            return False
        if (
            not isinstance(key, str)
            or not key
            or len(key) > MAX_POLICY_KEY_CHARACTERS
            or len(key_bytes) > MAX_POLICY_KEY_BYTES
            or any(ord(character) < 32 for character in key)
            or not isinstance(option_value, str)
            or len(option_value) > MAX_POLICY_VALUE_CHARACTERS
            or len(value_bytes) > MAX_POLICY_VALUE_BYTES
        ):
            return False
    try:
        canonical = json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except TypeError, ValueError, UnicodeEncodeError:
        return False
    return len(canonical) <= MAX_POLICY_OPTIONS_BYTES


def _describe_ids(values):
    suffix = ",..." if len(values) > MAX_REPORTED_VIOLATIONS else ""
    return ",".join(str(value) for value in values[:MAX_REPORTED_VIOLATIONS]) + suffix


def refuse_polluted_strategy_options(apps, schema_editor):
    Strategy = apps.get_model("api", "StrategyProfile")
    database = schema_editor.connection.alias
    invalid_ids = []
    rows = Strategy.objects.using(database).order_by("pk").values_list("pk", "config_options").iterator(chunk_size=1000)
    for row_id, config_options in rows:
        if not _valid_policy_options(config_options):
            invalid_ids.append(row_id)
            if len(invalid_ids) > MAX_REPORTED_VIOLATIONS:
                break
    if invalid_ids:
        raise RuntimeError(
            "strategy config-options migration refused polluted rows; "
            f"invalid_strategy_ids={_describe_ids(invalid_ids)}; "
            "repair each reported strategy explicitly and rerun the migration"
        )


def install_strategy_options_authority(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    with schema_editor.connection.cursor() as cursor:
        if vendor == "postgresql":
            cursor.execute(POSTGRESQL_FUNCTION)
            cursor.execute(POSTGRESQL_CONSTRAINT)
            cursor.execute(
                "ALTER TABLE public.api_strategyprofile VALIDATE CONSTRAINT valid_strategy_config_options_v1"
            )
        elif vendor == "sqlite":
            for statement in SQLITE_INSTALL:
                cursor.execute(statement)
        else:
            raise RuntimeError(f"unsupported strategy database backend: {vendor}")


def remove_strategy_options_authority(apps, schema_editor):
    vendor = schema_editor.connection.vendor
    with schema_editor.connection.cursor() as cursor:
        if vendor == "postgresql":
            cursor.execute("ALTER TABLE public.api_strategyprofile DROP CONSTRAINT valid_strategy_config_options_v1")
            cursor.execute("DROP FUNCTION public.camellia_strategy_options_valid_v1(jsonb)")
        elif vendor == "sqlite":
            cursor.execute("DROP TRIGGER api_strategy_options_update_guard")
            cursor.execute("DROP TRIGGER api_strategy_options_insert_guard")
        else:
            raise RuntimeError(f"unsupported strategy database backend: {vendor}")


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0028_address_book_rule_target_authority"),
    ]

    operations = [
        migrations.RunPython(
            refuse_polluted_strategy_options,
            migrations.RunPython.noop,
        ),
        migrations.RunPython(
            install_strategy_options_authority,
            remove_strategy_options_authority,
        ),
    ]
