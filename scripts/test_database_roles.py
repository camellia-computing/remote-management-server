#!/usr/bin/env python3
"""Regression and optional destructive integration tests for database roles.

Set CAMELLIA_REMOTE_DATABASE_ROLE_TEST_CONFIRM to the documented sentinel only
for an ephemeral PostgreSQL database. The integration class deliberately
changes database/schema/object ownership and role ACLs.
"""

import os
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yaml"
CONTROLLER = ROOT / "deploy" / "start-management-stack.sh"
BOOTSTRAP = ROOT / "deploy" / "bootstrap-postgres-roles.sh"
BACKUP = ROOT / "deploy" / "backup-postgres.sh"
RESTORE = ROOT / "deploy" / "restore-postgres.sh"
INTEGRATION_SENTINEL = "ephemeral-database-will-be-mutated"


def compose_service(name):
    lines = COMPOSE.read_text().splitlines()
    start = lines.index(f"  {name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("  ") and not lines[index].startswith("    ") and lines[index].endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def sql_identifier(value):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", value):
        raise ValueError(f"unsafe PostgreSQL test identifier: {value!r}")
    return f'"{value}"'


def sql_literal(value):
    if "\x00" in value:
        raise ValueError("PostgreSQL test literals must not contain NUL")
    return "'" + value.replace("'", "''") + "'"


class DatabaseRoleContractTests(unittest.TestCase):
    def test_compose_never_gives_bootstrap_or_migration_credentials_to_runtime(self):
        postgres = compose_service("postgres")
        migration = compose_service("migrate")
        management = compose_service("management")

        self.assertIn("CAMELLIA_REMOTE_DATABASE_BOOTSTRAP_USER", postgres)
        self.assertIn("CAMELLIA_REMOTE_DATABASE_MIGRATION_USER", migration)
        self.assertIn("CAMELLIA_REMOTE_DATABASE_RUNTIME_USER", management)
        for forbidden in ("DATABASE_BOOTSTRAP", "DATABASE_MIGRATION"):
            self.assertNotIn(forbidden, management)

        for service in ("database-bootstrap", "database-backup", "database-restore", "database-probe"):
            service_text = compose_service(service)
            self.assertIn("read_only: true", COMPOSE.read_text())
            self.assertIn(f"  {service}:", COMPOSE.read_text())
            self.assertIn("database-operations", service_text)

    def test_controller_converges_and_verifies_roles_around_migration(self):
        controller = CONTROLLER.read_text()
        first = controller.index("database-bootstrap")
        migration = controller.index("migrate", first)
        second = controller.index("database-bootstrap", first + len("database-bootstrap"))
        probe = controller.index("database-probe", second)
        application = controller.index("management", probe)
        self.assertLess(first, migration)
        self.assertLess(migration, second)
        self.assertLess(second, probe)
        self.assertLess(probe, application)

    def test_operations_use_only_their_limited_client_services(self):
        backup = BACKUP.read_text()
        restore = RESTORE.read_text()
        self.assertIn("database-backup", backup)
        self.assertNotIn("exec -T postgres", backup)
        self.assertIn("database-restore", restore)
        self.assertNotIn("exec -T postgres", restore)
        self.assertGreaterEqual(restore.count("database-bootstrap"), 2)
        self.assertIn("database-probe", restore)

    def test_bootstrap_script_enforces_flags_ownership_acl_and_membership(self):
        script = BOOTSTRAP.read_text()
        for required in (
            "NOSUPERUSER",
            "NOCREATEDB",
            "NOCREATEROLE",
            "NOREPLICATION",
            "NOBYPASSRLS",
            "REVOKE",
            "ALTER DEFAULT PRIVILEGES",
            "pg_advisory_xact_lock",
            "pg_auth_members",
            "log_parameter_max_length",
            "\\bind :runtime_role :runtime_password",
            "ALTER DATABASE",
            "ALTER SCHEMA",
            "CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD",
            "CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD",
            "CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD",
        ):
            self.assertIn(required, script)


@unittest.skipUnless(
    os.environ.get("CAMELLIA_REMOTE_DATABASE_ROLE_TEST_CONFIRM") == INTEGRATION_SENTINEL,
    "real role tests require an explicitly confirmed ephemeral PostgreSQL database",
)
class PostgreSQLRoleBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = os.environ["CAMELLIA_REMOTE_DATABASE_ROLE_TEST_HOST"]
        cls.port = os.environ.get("CAMELLIA_REMOTE_DATABASE_ROLE_TEST_PORT", "5432")
        cls.database = os.environ["CAMELLIA_REMOTE_DATABASE_ROLE_TEST_NAME"]
        cls.bootstrap_user = os.environ["CAMELLIA_REMOTE_DATABASE_ROLE_TEST_BOOTSTRAP_USER"]
        cls.bootstrap_password = os.environ["CAMELLIA_REMOTE_DATABASE_ROLE_TEST_BOOTSTRAP_PASSWORD"]
        cls.roles = {
            "migration": os.environ.get("CAMELLIA_REMOTE_DATABASE_ROLE_TEST_MIGRATION_USER", "role_test_migration"),
            "runtime": os.environ.get("CAMELLIA_REMOTE_DATABASE_ROLE_TEST_RUNTIME_USER", "role_test_runtime"),
            "backup": os.environ.get("CAMELLIA_REMOTE_DATABASE_ROLE_TEST_BACKUP_USER", "role_test_backup"),
            "probe": os.environ.get("CAMELLIA_REMOTE_DATABASE_ROLE_TEST_PROBE_USER", "role_test_probe"),
        }
        cls.passwords = {
            "migration": "migration-role-test-password-02",
            "runtime": "runtime role test:@/%# password 03",
            "backup": "backup-role-test-password-04",
            "probe": "probe-role-test-password-05",
        }
        cls.rotated_passwords = {
            "migration": "migration-role-rotated-password-12",
            "runtime": "runtime role rotated:@/%# password 13",
            "backup": "backup-role-rotated-password-14",
            "probe": "probe-role-rotated-password-15",
        }
        for value in (cls.database, cls.bootstrap_user, *cls.roles.values()):
            sql_identifier(value)
        suffix = f"auth023_{os.getpid()}"
        cls.legacy_type = f"{suffix}_legacy_state"
        cls.legacy_table = f"{suffix}_legacy_items"
        cls.rls_table = f"{suffix}_rls_items"
        cls.legacy_function = f"{suffix}_legacy_count"
        cls.future_type = f"{suffix}_future_state"
        cls.future_table = f"{suffix}_future_items"
        cls.future_function = f"{suffix}_future_count"
        cls.stale_parent = f"{suffix}_stale_parent"
        cls.stale_member = f"{suffix}_stale_member"
        for value in (
            cls.legacy_type,
            cls.legacy_table,
            cls.rls_table,
            cls.legacy_function,
            cls.future_type,
            cls.future_table,
            cls.future_function,
            cls.stale_parent,
            cls.stale_member,
        ):
            sql_identifier(value)

        target_role_setup = []
        for name, role in cls.roles.items():
            attributes = (
                "SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS CONNECTION LIMIT 0"
                if name == "runtime"
                else "CREATEDB"
            )
            target_role_setup.append(
                f"SELECT format('CREATE ROLE %I LOGIN', {sql_literal(role)}) "
                f"WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname={sql_literal(role)})\\gexec\n"
                f"ALTER ROLE {sql_identifier(role)} WITH LOGIN PASSWORD "
                f"{sql_literal('legacy-' + cls.passwords[name])} {attributes};"
            )
        cls.psql(
            cls.bootstrap_user,
            cls.bootstrap_password,
            "\n".join(target_role_setup)
            + f"\nCREATE ROLE {sql_identifier(cls.stale_parent)};"
            + f"\nCREATE ROLE {sql_identifier(cls.stale_member)} LOGIN;"
            + f"\nGRANT {sql_identifier(cls.stale_parent)} TO {sql_identifier(cls.roles['runtime'])};"
            + f"\nGRANT {sql_identifier(cls.roles['backup'])} TO {sql_identifier(cls.stale_member)};"
            + f"\nALTER ROLE {sql_identifier(cls.roles['runtime'])} IN DATABASE "
            + f"{sql_identifier(cls.database)} SET search_path TO pg_catalog;",
        )
        cls.psql(
            cls.bootstrap_user,
            cls.bootstrap_password,
            f"""
            CREATE TYPE public.{sql_identifier(cls.legacy_type)} AS ENUM ('ready', 'stopped');
            CREATE TABLE public.{sql_identifier(cls.legacy_table)} (
                id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                state public.{sql_identifier(cls.legacy_type)} NOT NULL,
                secret text NOT NULL
            );
            INSERT INTO public.{sql_identifier(cls.legacy_table)}(state, secret)
                VALUES ('ready', 'legacy-canary');
            CREATE FUNCTION public.{sql_identifier(cls.legacy_function)}() RETURNS bigint
                LANGUAGE sql STABLE AS 'SELECT count(*) FROM public.{sql_identifier(cls.legacy_table)}';
            CREATE TABLE public.{sql_identifier(cls.rls_table)} (
                id integer PRIMARY KEY,
                visible boolean NOT NULL,
                value text NOT NULL
            );
            ALTER TABLE public.{sql_identifier(cls.rls_table)} ENABLE ROW LEVEL SECURITY;
            CREATE POLICY visible_rows ON public.{sql_identifier(cls.rls_table)}
                USING (visible) WITH CHECK (visible);
            INSERT INTO public.{sql_identifier(cls.rls_table)} VALUES
                (1, true, 'visible'), (2, false, 'hidden');
            GRANT ALL ON public.{sql_identifier(cls.legacy_table)} TO PUBLIC;
            """,
        )
        cls.run_bootstrap(cls.passwords)

    @classmethod
    def connection_environment(cls, password):
        return os.environ | {
            "PGHOST": cls.host,
            "PGPORT": cls.port,
            "PGDATABASE": cls.database,
            "PGPASSWORD": password,
            "PGCONNECT_TIMEOUT": "5",
        }

    @classmethod
    def psql(cls, user, password, sql, check=True):
        return subprocess.run(
            [
                "psql",
                "--no-psqlrc",
                "--username",
                user,
                "--set",
                "ON_ERROR_STOP=1",
                "--tuples-only",
                "--no-align",
            ],
            input=sql,
            env=cls.connection_environment(password),
            text=True,
            capture_output=True,
            check=check,
        )

    @classmethod
    def run_bootstrap(cls, passwords):
        env = cls.connection_environment(cls.bootstrap_password) | {
            "PGUSER": cls.bootstrap_user,
            "CAMELLIA_REMOTE_DATABASE_MIGRATION_USER": cls.roles["migration"],
            "CAMELLIA_REMOTE_DATABASE_MIGRATION_PASSWORD": passwords["migration"],
            "CAMELLIA_REMOTE_DATABASE_RUNTIME_USER": cls.roles["runtime"],
            "CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD": passwords["runtime"],
            "CAMELLIA_REMOTE_DATABASE_BACKUP_USER": cls.roles["backup"],
            "CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD": passwords["backup"],
            "CAMELLIA_REMOTE_DATABASE_PROBE_USER": cls.roles["probe"],
            "CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD": passwords["probe"],
        }
        return subprocess.run(
            ["/bin/sh", str(BOOTSTRAP)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )

    def assert_denied(self, role_name, password, statement):
        result = self.psql(role_name, password, statement, check=False)
        self.assertNotEqual(result.returncode, 0, f"unexpectedly allowed SQL: {statement}")

    def test_real_legacy_conversion_default_acl_password_rotation_and_denials(self):
        flags = self.psql(
            self.bootstrap_user,
            self.bootstrap_password,
            "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolreplication, "
            "rolbypassrls, rolconnlimit "
            "FROM pg_roles WHERE rolname IN ("
            + ",".join(sql_literal(role) for role in self.roles.values())
            + ") ORDER BY rolname;",
        ).stdout.splitlines()
        self.assertEqual(len(flags), 4)
        self.assertTrue(all(line.endswith("|f|f|f|f|f|f|-1") for line in flags), flags)

        owners = self.psql(
            self.bootstrap_user,
            self.bootstrap_password,
            "SELECT DISTINCT pg_get_userbyid(relowner) FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            f"WHERE n.nspname='public' AND c.relname IN ({sql_literal(self.legacy_table)}, "
            f"{sql_literal(self.legacy_table + '_id_seq')}, {sql_literal(self.rls_table)});",
        ).stdout.splitlines()
        self.assertEqual(owners, [self.roles["migration"]])

        migration_sql = f"""
            CREATE TYPE public.{sql_identifier(self.future_type)} AS ENUM ('new', 'done');
            CREATE TABLE public.{sql_identifier(self.future_table)} (
                id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                state public.{sql_identifier(self.future_type)} NOT NULL,
                value text NOT NULL
            );
            CREATE FUNCTION public.{sql_identifier(self.future_function)}() RETURNS bigint
                LANGUAGE sql STABLE AS 'SELECT count(*) FROM public.{sql_identifier(self.future_table)}';
        """
        self.psql(self.roles["migration"], self.passwords["migration"], migration_sql)

        runtime_sql = f"""
            SELECT secret FROM public.{sql_identifier(self.legacy_table)} WHERE id=1;
            INSERT INTO public.{sql_identifier(self.future_table)}(state, value)
                VALUES ('new', 'runtime-canary');
            UPDATE public.{sql_identifier(self.future_table)} SET state='done' WHERE value='runtime-canary';
            SELECT public.{sql_identifier(self.future_function)}();
            DELETE FROM public.{sql_identifier(self.future_table)} WHERE value='runtime-canary';
            SELECT count(*) FROM public.{sql_identifier(self.rls_table)};
        """
        runtime = self.psql(self.roles["runtime"], self.passwords["runtime"], runtime_sql)
        self.assertEqual(runtime.stdout.splitlines()[-1], "1", runtime.stdout)

        runtime_denials = (
            "COPY (SELECT 1) TO PROGRAM 'true';",
            "ALTER SYSTEM SET log_statement = 'all';",
            f"ALTER ROLE {sql_identifier(self.roles['probe'])} CREATEDB;",
            f"CREATE DATABASE {sql_identifier(self.future_table + '_database')};",
            "CREATE EXTENSION file_fdw;",
            f"CREATE SCHEMA {sql_identifier(self.future_table + '_schema')};",
            f"CREATE TABLE public.{sql_identifier(self.future_table + '_forbidden')}(id integer);",
            f"ALTER TABLE public.{sql_identifier(self.legacy_table)} OWNER TO {sql_identifier(self.roles['runtime'])};",
            f"SET ROLE {sql_identifier(self.stale_parent)};",
            f"SET row_security=off; SELECT * FROM public.{sql_identifier(self.rls_table)};",
        )
        for statement in runtime_denials:
            with self.subTest(statement=statement):
                self.assert_denied(self.roles["runtime"], self.passwords["runtime"], statement)

        backup_read = self.psql(
            self.roles["backup"],
            self.passwords["backup"],
            f"SELECT secret FROM public.{sql_identifier(self.legacy_table)} WHERE id=1;",
        )
        self.assertEqual(backup_read.stdout.strip(), "legacy-canary")
        self.assert_denied(
            self.roles["backup"],
            self.passwords["backup"],
            f"INSERT INTO public.{sql_identifier(self.legacy_table)}(state, secret) VALUES ('ready', 'denied');",
        )

        self.assertEqual(
            self.psql(self.roles["probe"], self.passwords["probe"], "SELECT 1;").stdout.strip(),
            "1",
        )
        self.assert_denied(
            self.roles["probe"],
            self.passwords["probe"],
            f"SELECT * FROM public.{sql_identifier(self.legacy_table)};",
        )

        membership_count = self.psql(
            self.bootstrap_user,
            self.bootstrap_password,
            "SELECT count(*) FROM pg_auth_members membership "
            "JOIN pg_roles granted ON granted.oid=membership.roleid "
            "JOIN pg_roles member ON member.oid=membership.member "
            "WHERE granted.rolname IN ("
            + ",".join(sql_literal(role) for role in self.roles.values())
            + ") OR member.rolname IN ("
            + ",".join(sql_literal(role) for role in self.roles.values())
            + ");",
        )
        self.assertEqual(membership_count.stdout.strip(), "0")

        migration_ledger_exists = self.psql(
            self.bootstrap_user,
            self.bootstrap_password,
            "SELECT to_regclass('public.django_migrations') IS NOT NULL;",
        ).stdout.strip()
        if migration_ledger_exists == "t":
            self.assert_denied(
                self.roles["runtime"],
                self.passwords["runtime"],
                "DELETE FROM public.django_migrations;",
            )

        duplicate_passwords = self.passwords | {"probe": self.passwords["backup"]}
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_bootstrap(duplicate_passwords)
        self.assertEqual(
            self.psql(self.roles["probe"], self.passwords["probe"], "SELECT 1;").stdout.strip(),
            "1",
        )

        self.run_bootstrap(self.rotated_passwords)
        self.run_bootstrap(self.rotated_passwords)
        for role_kind, role_name in self.roles.items():
            with self.subTest(rotation=role_kind):
                old_connection = self.psql(role_name, self.passwords[role_kind], "SELECT 1;", check=False)
                self.assertNotEqual(old_connection.returncode, 0)
                new_connection = self.psql(role_name, self.rotated_passwords[role_kind], "SELECT 1;")
                self.assertEqual(new_connection.stdout.strip(), "1")


if __name__ == "__main__":
    unittest.main()
