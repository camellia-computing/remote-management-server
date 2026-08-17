import functools
import json
import re
from pathlib import Path

from django.db import DatabaseError, connections
from django.db.migrations.loader import MigrationLoader

MANIFEST_PATH = Path(__file__).with_name("release_schema_manifest.json")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
_MIGRATION_NAME = re.compile(r"[A-Za-z0-9_]{1,128}\Z")


class ReleaseSchemaError(RuntimeError):
    """The database cannot safely serve the schema expected by this release."""


def _migration_nodes(value, field):
    if not isinstance(value, list):
        raise ReleaseSchemaError(f"release schema manifest {field} must be a list")
    nodes = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            or not _IDENTIFIER.fullmatch(item[0])
            or not _MIGRATION_NAME.fullmatch(item[1])
        ):
            raise ReleaseSchemaError(f"release schema manifest {field} contains an invalid migration node")
        nodes.append((item[0], item[1]))
    if nodes != sorted(set(nodes)):
        raise ReleaseSchemaError(f"release schema manifest {field} must be sorted and unique")
    return frozenset(nodes)


def _identifier_list(value, field):
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not _IDENTIFIER.fullmatch(item) for item in value)
        or value != sorted(set(value))
    ):
        raise ReleaseSchemaError(f"release schema manifest {field} must be a sorted unique identifier list")
    return tuple(value)


def _privilege_map(value, field, allowed):
    if not isinstance(value, dict) or list(value) != sorted(value):
        raise ReleaseSchemaError(f"release schema manifest {field} must be a sorted privilege map")
    normalized = {}
    for relation, privileges in value.items():
        if not isinstance(relation, str) or not _IDENTIFIER.fullmatch(relation):
            raise ReleaseSchemaError(f"release schema manifest {field} contains an invalid object")
        if not isinstance(privileges, list) or not privileges or privileges != sorted(set(privileges)):
            raise ReleaseSchemaError(f"release schema manifest {field}.{relation} must be sorted and unique")
        if any(not isinstance(privilege, str) or privilege not in allowed for privilege in privileges):
            raise ReleaseSchemaError(f"release schema manifest {field}.{relation} contains an invalid privilege")
        normalized[relation] = tuple(privileges)
    if not normalized:
        raise ReleaseSchemaError(f"release schema manifest {field} must not be empty")
    return normalized


@functools.lru_cache(maxsize=1)
def load_release_schema_manifest():
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseSchemaError("release schema manifest cannot be loaded") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ReleaseSchemaError("release schema manifest version is unsupported")
    generation = manifest.get("schema_generation")
    if not isinstance(generation, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", generation):
        raise ReleaseSchemaError("release schema manifest generation is invalid")

    migrations = _migration_nodes(manifest.get("migrations"), "migrations")
    leaf_migrations = _migration_nodes(manifest.get("leaf_migrations"), "leaf_migrations")
    if not leaf_migrations.issubset(migrations):
        raise ReleaseSchemaError("release schema manifest leaves must belong to the migration set")

    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ReleaseSchemaError("release schema manifest capabilities are invalid")
    relations = capabilities.get("relations")
    if not isinstance(relations, dict) or not relations:
        raise ReleaseSchemaError("release schema manifest relations are invalid")
    normalized_relations = {}
    for relation, columns in relations.items():
        if not isinstance(relation, str) or not _IDENTIFIER.fullmatch(relation):
            raise ReleaseSchemaError("release schema manifest contains an invalid relation")
        normalized_relations[relation] = _identifier_list(columns, f"relations.{relation}")
    if list(relations) != sorted(relations):
        raise ReleaseSchemaError("release schema manifest relations must be sorted")

    postgresql = capabilities.get("postgresql")
    if not isinstance(postgresql, dict):
        raise ReleaseSchemaError("release schema manifest PostgreSQL capabilities are invalid")
    constraints = postgresql.get("constraints")
    indexes = postgresql.get("indexes")
    not_null = postgresql.get("not_null")
    column_types = postgresql.get("column_types")
    runtime_dml = postgresql.get("runtime_dml")
    for field, values in (("constraints", constraints), ("indexes", indexes), ("not_null", not_null)):
        if not isinstance(values, dict) or list(values) != sorted(values):
            raise ReleaseSchemaError(f"release schema manifest PostgreSQL {field} are invalid")
        for relation, names in values.items():
            if relation not in normalized_relations:
                raise ReleaseSchemaError(f"release schema manifest PostgreSQL {field} references an unknown relation")
            normalized_names = _identifier_list(names, f"postgresql.{field}.{relation}")
            if field == "not_null" and not set(normalized_names).issubset(normalized_relations[relation]):
                raise ReleaseSchemaError("release schema manifest PostgreSQL not-null column is unavailable")
    if not isinstance(column_types, dict) or list(column_types) != sorted(column_types):
        raise ReleaseSchemaError("release schema manifest PostgreSQL column types are invalid")
    for relation, expected_types in column_types.items():
        if relation not in normalized_relations or not isinstance(expected_types, dict):
            raise ReleaseSchemaError("release schema manifest PostgreSQL column type relation is invalid")
        if list(expected_types) != sorted(expected_types):
            raise ReleaseSchemaError("release schema manifest PostgreSQL column types must be sorted")
        for column, type_name in expected_types.items():
            if (
                column not in normalized_relations[relation]
                or not isinstance(type_name, str)
                or not re.fullmatch(r"[a-z0-9_ ()\[\]]{1,64}", type_name)
            ):
                raise ReleaseSchemaError("release schema manifest contains an invalid PostgreSQL column type")
    if not isinstance(runtime_dml, dict) or list(runtime_dml) != ["sequences", "tables"]:
        raise ReleaseSchemaError("release schema manifest PostgreSQL runtime DML capabilities are invalid")
    runtime_tables = _privilege_map(
        runtime_dml.get("tables"),
        "postgresql.runtime_dml.tables",
        {"DELETE", "INSERT", "SELECT", "UPDATE"},
    )
    runtime_sequences = _privilege_map(
        runtime_dml.get("sequences"),
        "postgresql.runtime_dml.sequences",
        {"SELECT", "UPDATE", "USAGE"},
    )
    if any(relation not in normalized_relations for relation in runtime_tables):
        raise ReleaseSchemaError("release schema manifest runtime DML table is not a declared relation")

    return {
        "schema_version": 1,
        "schema_generation": generation,
        "migrations": migrations,
        "leaf_migrations": leaf_migrations,
        "relations": normalized_relations,
        "postgresql_constraints": {key: tuple(value) for key, value in constraints.items()},
        "postgresql_indexes": {key: tuple(value) for key, value in indexes.items()},
        "postgresql_not_null": {key: tuple(value) for key, value in not_null.items()},
        "postgresql_column_types": column_types,
        "postgresql_runtime_dml": {
            "tables": runtime_tables,
            "sequences": runtime_sequences,
        },
    }


def _format_nodes(nodes):
    return ",".join(f"{app}/{name}" for app, name in sorted(nodes))


@functools.lru_cache(maxsize=1)
def _code_migration_state():
    loader = MigrationLoader(None, ignore_no_migrations=True)
    return frozenset(loader.disk_migrations), frozenset(loader.graph.leaf_nodes())


def _check_migrations(database, manifest):
    code_migrations, code_leaves = _code_migration_state()
    if code_migrations != manifest["migrations"]:
        missing = manifest["migrations"] - code_migrations
        extra = code_migrations - manifest["migrations"]
        raise ReleaseSchemaError(
            "release schema manifest does not match code migrations; "
            f"missing={_format_nodes(missing) or '-'} extra={_format_nodes(extra) or '-'}"
        )
    if code_leaves != manifest["leaf_migrations"]:
        raise ReleaseSchemaError("release schema manifest does not match code migration leaves")

    try:
        with database.cursor() as cursor:
            cursor.execute("SELECT app, name FROM django_migrations")
            applied = frozenset(cursor.fetchall())
    except DatabaseError as exc:
        raise ReleaseSchemaError("database migration ledger is unavailable") from exc
    if applied != manifest["migrations"]:
        missing = manifest["migrations"] - applied
        extra = applied - manifest["migrations"]
        raise ReleaseSchemaError(
            "database migration ledger does not match this release; "
            f"missing={_format_nodes(missing) or '-'} extra={_format_nodes(extra) or '-'}"
        )


def _check_relations(database, manifest):
    with database.cursor() as cursor:
        available_relations = frozenset(database.introspection.table_names(cursor))
        for relation, required_columns in manifest["relations"].items():
            if relation not in available_relations:
                raise ReleaseSchemaError(f"required schema relation is missing: {relation}")
            description = database.introspection.get_table_description(cursor, relation)
            available_columns = {column.name for column in description}
            missing_columns = set(required_columns) - available_columns
            if missing_columns:
                raise ReleaseSchemaError(
                    f"required schema columns are missing from {relation}: {','.join(sorted(missing_columns))}"
                )


def _check_postgresql_capabilities(database, manifest):
    relations = manifest["relations"]
    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT relation.relname,
                   attribute.attname,
                   pg_catalog.format_type(attribute.atttypid, attribute.atttypmod),
                   attribute.attnotnull
              FROM pg_catalog.pg_class relation
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
              JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid = relation.oid
             WHERE namespace.nspname = current_schema()
               AND relation.relname = ANY(%s)
               AND attribute.attnum > 0
               AND NOT attribute.attisdropped
            """,
            [list(relations)],
        )
        observed_columns = {}
        observed_not_null = {}
        for relation, column, type_name, not_null in cursor.fetchall():
            observed_columns.setdefault(relation, {})[column] = type_name
            observed_not_null.setdefault(relation, {})[column] = not_null
        for relation, required_columns in relations.items():
            if relation not in observed_columns:
                raise ReleaseSchemaError(f"required schema relation is missing: {relation}")
            missing_columns = set(required_columns) - set(observed_columns[relation])
            if missing_columns:
                raise ReleaseSchemaError(
                    f"required schema columns are missing from {relation}: {','.join(sorted(missing_columns))}"
                )
        for relation, expected_types in manifest["postgresql_column_types"].items():
            for column, expected_type in expected_types.items():
                if observed_columns[relation].get(column) != expected_type:
                    raise ReleaseSchemaError(f"required schema column type is invalid: {relation}.{column}")
        for relation, expected_columns in manifest["postgresql_not_null"].items():
            for column in expected_columns:
                if observed_not_null.get(relation, {}).get(column) is not True:
                    raise ReleaseSchemaError(f"required non-null schema column is missing: {relation}.{column}")

        cursor.execute(
            """
            SELECT relation.relname,
                   schema_constraint.conname,
                   schema_constraint.convalidated
              FROM pg_catalog.pg_constraint schema_constraint
              JOIN pg_catalog.pg_class relation ON relation.oid = schema_constraint.conrelid
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = current_schema()
               AND relation.relname = ANY(%s)
            """,
            [list(relations)],
        )
        constraints = {}
        for relation, constraint, validated in cursor.fetchall():
            constraints.setdefault(relation, {})[constraint] = validated
        for relation, expected_constraints in manifest["postgresql_constraints"].items():
            for constraint in expected_constraints:
                if constraints.get(relation, {}).get(constraint) is not True:
                    raise ReleaseSchemaError(
                        f"required validated schema constraint is missing: {relation}.{constraint}"
                    )

        cursor.execute(
            """
            SELECT relation.relname,
                   index_relation.relname,
                   schema_index.indisvalid AND schema_index.indisready
              FROM pg_catalog.pg_index schema_index
              JOIN pg_catalog.pg_class relation ON relation.oid = schema_index.indrelid
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
              JOIN pg_catalog.pg_class index_relation ON index_relation.oid = schema_index.indexrelid
             WHERE namespace.nspname = current_schema()
               AND relation.relname = ANY(%s)
            """,
            [list(relations)],
        )
        indexes = {}
        for relation, index, ready in cursor.fetchall():
            indexes.setdefault(relation, {})[index] = ready
        for relation, expected_indexes in manifest["postgresql_indexes"].items():
            for index in expected_indexes:
                if indexes.get(relation, {}).get(index) is not True:
                    raise ReleaseSchemaError(f"required ready schema index is missing: {relation}.{index}")


def check_release_schema(*, using="default"):
    manifest = load_release_schema_manifest()
    database = connections[using]
    if database.vendor not in {"postgresql", "sqlite"}:
        raise ReleaseSchemaError("release schema checks support only PostgreSQL or debug SQLite")
    _check_migrations(database, manifest)
    if database.vendor == "postgresql":
        _check_postgresql_capabilities(database, manifest)
    else:
        _check_relations(database, manifest)
    return {
        "migration_count": len(manifest["migrations"]),
        "schema_generation": manifest["schema_generation"],
        "schema_manifest_version": manifest["schema_version"],
    }


class RuntimeWriteCapabilityError(RuntimeError):
    """The runtime credential cannot safely accept mutation traffic."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def check_runtime_write_capability(*, using="default"):
    """Verify the current runtime session can serve mutation routes.

    PostgreSQL's recovery/read-only flags and explicit ACL checks provide a
    no-WAL proof for the runtime role. A readiness request must not mutate a
    business row merely to prove that the node is writable.
    """

    manifest = load_release_schema_manifest()
    database = connections[using]
    if database.vendor == "sqlite":
        with database.cursor() as cursor:
            cursor.execute("PRAGMA query_only")
            row = cursor.fetchone()
        if not row or int(row[0]) != 0:
            raise RuntimeWriteCapabilityError("sqlite_query_only")
        return {"vendor": "sqlite", "runtime_write": True}
    if database.vendor != "postgresql":
        raise RuntimeWriteCapabilityError("unsupported_database")

    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT current_setting('transaction_read_only'),
                   current_setting('default_transaction_read_only'),
                   pg_catalog.pg_is_in_recovery()
            """
        )
        transaction_read_only, default_read_only, in_recovery = cursor.fetchone()
        if transaction_read_only != "off":
            raise RuntimeWriteCapabilityError("transaction_read_only")
        if default_read_only != "off":
            raise RuntimeWriteCapabilityError("default_transaction_read_only")
        if in_recovery:
            raise RuntimeWriteCapabilityError("primary_in_recovery")

        for relation, privileges in manifest["postgresql_runtime_dml"]["tables"].items():
            qualified_relation = f"public.{relation}"
            for privilege in privileges:
                cursor.execute(
                    "SELECT pg_catalog.has_table_privilege(current_user, %s, %s)",
                    [qualified_relation, privilege],
                )
                if cursor.fetchone()[0] is not True:
                    raise RuntimeWriteCapabilityError(f"table_acl:{relation}:{privilege}")
        for sequence, privileges in manifest["postgresql_runtime_dml"]["sequences"].items():
            qualified_sequence = f"public.{sequence}"
            for privilege in privileges:
                cursor.execute(
                    "SELECT pg_catalog.has_sequence_privilege(current_user, %s, %s)",
                    [qualified_sequence, privilege],
                )
                if cursor.fetchone()[0] is not True:
                    raise RuntimeWriteCapabilityError(f"sequence_acl:{sequence}:{privilege}")
        cursor.execute(
            """
            SELECT relation.relname
              FROM pg_catalog.pg_class relation
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = current_schema()
               AND relation.relkind IN ('r', 'p')
               AND relation.relname <> 'django_migrations'
               AND (
                   NOT pg_catalog.has_table_privilege(current_user, relation.oid, 'SELECT')
                   OR NOT pg_catalog.has_table_privilege(current_user, relation.oid, 'INSERT')
                   OR NOT pg_catalog.has_table_privilege(current_user, relation.oid, 'UPDATE')
                   OR NOT pg_catalog.has_table_privilege(current_user, relation.oid, 'DELETE')
               )
             ORDER BY relation.relname
            """
        )
        missing_table_privilege = cursor.fetchone()
        if missing_table_privilege:
            raise RuntimeWriteCapabilityError(f"table_acl:{missing_table_privilege[0]}")
        cursor.execute(
            """
            SELECT sequence.relname
              FROM pg_catalog.pg_class sequence
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = sequence.relnamespace
             WHERE namespace.nspname = current_schema()
               AND sequence.relkind = 'S'
               AND (
                   NOT pg_catalog.has_sequence_privilege(current_user, sequence.oid, 'USAGE')
                   OR NOT pg_catalog.has_sequence_privilege(current_user, sequence.oid, 'SELECT')
                   OR NOT pg_catalog.has_sequence_privilege(current_user, sequence.oid, 'UPDATE')
               )
             ORDER BY sequence.relname
            """
        )
        missing_sequence_privilege = cursor.fetchone()
        if missing_sequence_privilege:
            raise RuntimeWriteCapabilityError(f"sequence_acl:{missing_sequence_privilege[0]}")
    return {"vendor": "postgresql", "runtime_write": True}
