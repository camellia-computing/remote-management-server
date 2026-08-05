#!/bin/sh
set -eu

umask 077

newline='
'
carriage_return="$(printf '\r')"

die() {
    echo "database role bootstrap error: $*" >&2
    exit 1
}

require_value() {
    variable_name="$1"
    eval "variable_value=\${$variable_name-}"
    [ -n "$variable_value" ] || die "$variable_name is required"
}

require_identifier() {
    variable_name="$1"
    eval "variable_value=\${$variable_name-}"
    case "$variable_value" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) die "$variable_name must be a PostgreSQL identifier" ;;
    esac
    [ "${#variable_value}" -le 63 ] || die "$variable_name exceeds PostgreSQL's identifier limit"
}

require_password() {
    variable_name="$1"
    eval "variable_value=\${$variable_name-}"
    [ "${#variable_value}" -ge 16 ] || die "$variable_name must contain at least 16 characters"
    [ "${#variable_value}" -le 1024 ] || die "$variable_name exceeds the supported password length"
    case "$variable_value" in
        *"$newline"*|*"$carriage_return"*) die "$variable_name must not contain line breaks" ;;
    esac
}

require_distinct() {
    first_name="$1"
    second_name="$2"
    first_value=
    second_value=
    eval "first_value=\${$first_name-}"
    eval "second_value=\${$second_name-}"
    [ "$first_value" != "$second_value" ] || die "$first_name and $second_name must be independent"
}

require_identifier PGUSER
require_identifier PGDATABASE
require_value PGHOST
require_value PGPORT
case "$PGPORT" in
    ''|*[!0-9]*) die "PGPORT must be a decimal port" ;;
esac
if [ "$PGPORT" -lt 1 ] || [ "$PGPORT" -gt 65535 ]; then
    die "PGPORT is outside 1..65535"
fi
require_password PGPASSWORD

for role_variable in \
    CAMELLIA_REMOTE_DATABASE_MIGRATION_USER \
    CAMELLIA_REMOTE_DATABASE_RUNTIME_USER \
    CAMELLIA_REMOTE_DATABASE_BACKUP_USER \
    CAMELLIA_REMOTE_DATABASE_PROBE_USER
do
    require_identifier "$role_variable"
done

for password_variable in \
    CAMELLIA_REMOTE_DATABASE_MIGRATION_PASSWORD \
    CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD \
    CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD \
    CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD
do
    require_password "$password_variable"
done

for target_role in \
    CAMELLIA_REMOTE_DATABASE_MIGRATION_USER \
    CAMELLIA_REMOTE_DATABASE_RUNTIME_USER \
    CAMELLIA_REMOTE_DATABASE_BACKUP_USER \
    CAMELLIA_REMOTE_DATABASE_PROBE_USER
do
    require_distinct PGUSER "$target_role"
done
require_distinct CAMELLIA_REMOTE_DATABASE_MIGRATION_USER CAMELLIA_REMOTE_DATABASE_RUNTIME_USER
require_distinct CAMELLIA_REMOTE_DATABASE_MIGRATION_USER CAMELLIA_REMOTE_DATABASE_BACKUP_USER
require_distinct CAMELLIA_REMOTE_DATABASE_MIGRATION_USER CAMELLIA_REMOTE_DATABASE_PROBE_USER
require_distinct CAMELLIA_REMOTE_DATABASE_RUNTIME_USER CAMELLIA_REMOTE_DATABASE_BACKUP_USER
require_distinct CAMELLIA_REMOTE_DATABASE_RUNTIME_USER CAMELLIA_REMOTE_DATABASE_PROBE_USER
require_distinct CAMELLIA_REMOTE_DATABASE_BACKUP_USER CAMELLIA_REMOTE_DATABASE_PROBE_USER

for first_password in \
    PGPASSWORD \
    CAMELLIA_REMOTE_DATABASE_MIGRATION_PASSWORD \
    CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD \
    CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD
do
    case "$first_password" in
        PGPASSWORD)
            remaining_passwords="CAMELLIA_REMOTE_DATABASE_MIGRATION_PASSWORD CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD"
            ;;
        CAMELLIA_REMOTE_DATABASE_MIGRATION_PASSWORD)
            remaining_passwords="CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD"
            ;;
        CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD)
            remaining_passwords="CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD"
            ;;
        CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD)
            remaining_passwords="CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD"
            ;;
    esac
    for second_password in $remaining_passwords; do
        require_distinct "$first_password" "$second_password"
    done
done

bootstrap_attempts="${CAMELLIA_REMOTE_DATABASE_BOOTSTRAP_ATTEMPTS:-30}"
bootstrap_interval="${CAMELLIA_REMOTE_DATABASE_BOOTSTRAP_INTERVAL_SECONDS:-2}"
case "$bootstrap_attempts:$bootstrap_interval" in
    *[!0-9:]*) die "bootstrap retry settings must be decimal integers" ;;
esac
if [ "$bootstrap_attempts" -lt 1 ] || [ "$bootstrap_attempts" -gt 120 ]; then
    die "bootstrap attempts are outside 1..120"
fi
if [ "$bootstrap_interval" -lt 1 ] || [ "$bootstrap_interval" -gt 10 ]; then
    die "bootstrap interval is outside 1..10 seconds"
fi

export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-5}"
attempt=1
while ! psql --no-psqlrc --quiet --tuples-only --no-align --command 'SELECT 1' >/dev/null 2>&1; do
    if [ "$attempt" -ge "$bootstrap_attempts" ]; then
        die "PostgreSQL did not accept the bootstrap credential within the bounded retry window"
    fi
    attempt=$((attempt + 1))
    sleep "$bootstrap_interval"
done

# Target passwords are imported by psql from the environment. They never enter
# this script's argv. The transaction-level advisory lock makes convergence
# single-flight across concurrent controllers and restore operations.
psql --no-psqlrc --set=ON_ERROR_STOP=1 <<'SQL'
\set QUIET on
\getenv database_name PGDATABASE
\getenv bootstrap_role PGUSER
\getenv migration_role CAMELLIA_REMOTE_DATABASE_MIGRATION_USER
\getenv migration_password CAMELLIA_REMOTE_DATABASE_MIGRATION_PASSWORD
\getenv runtime_role CAMELLIA_REMOTE_DATABASE_RUNTIME_USER
\getenv runtime_password CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD
\getenv backup_role CAMELLIA_REMOTE_DATABASE_BACKUP_USER
\getenv backup_password CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD
\getenv probe_role CAMELLIA_REMOTE_DATABASE_PROBE_USER
\getenv probe_password CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD

BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('camellia-remote-postgres-role-bootstrap-v1', 0));

DO $verify_bootstrap$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_roles
         WHERE rolname = current_user
           AND rolsuper
    ) THEN
        RAISE EXCEPTION 'the configured bootstrap role must remain a PostgreSQL superuser';
    END IF;
END
$verify_bootstrap$;

SELECT format(
           'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1',
           :'migration_role'
       )
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'migration_role')
\gexec
SELECT format(
           'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1',
           :'runtime_role'
       )
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_role')
\gexec
SELECT format(
           'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1',
           :'backup_role'
       )
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'backup_role')
\gexec
SELECT format(
           'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1',
           :'probe_role'
       )
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'probe_role')
\gexec

-- Send plaintext passwords only as extended-query bind parameters. Suppress
-- parameter values for this transaction before calling a session-local helper;
-- neither statement logging nor an error contains the target password.
SET LOCAL log_parameter_max_length = 0;
SET LOCAL log_parameter_max_length_on_error = 0;
CREATE FUNCTION pg_temp.camellia_set_role_password(target_role name, target_password text)
RETURNS void
LANGUAGE plpgsql
AS $password_function$
BEGIN
    EXECUTE format('ALTER ROLE %I PASSWORD %L', target_role, target_password);
END
$password_function$;

SELECT pg_temp.camellia_set_role_password($1::name, $2::text)
\bind :migration_role :migration_password
\g
SELECT pg_temp.camellia_set_role_password($1::name, $2::text)
\bind :runtime_role :runtime_password
\g
SELECT pg_temp.camellia_set_role_password($1::name, $2::text)
\bind :backup_role :backup_password
\g
SELECT pg_temp.camellia_set_role_password($1::name, $2::text)
\bind :probe_role :probe_password
\g

ALTER ROLE :"migration_role" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
ALTER ROLE :"runtime_role" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
ALTER ROLE :"backup_role" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';
ALTER ROLE :"probe_role" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1 VALID UNTIL 'infinity';

-- Remove both directions of every target-role membership. This prevents a
-- target from SET ROLE escalation and removes stale delegation to other roles.
SELECT DISTINCT format('REVOKE %I FROM %I', granted.rolname, member.rolname)
  FROM pg_auth_members memberships
  JOIN pg_roles granted ON granted.oid = memberships.roleid
  JOIN pg_roles member ON member.oid = memberships.member
 WHERE granted.rolname IN (:'migration_role', :'runtime_role', :'backup_role', :'probe_role')
    OR member.rolname IN (:'migration_role', :'runtime_role', :'backup_role', :'probe_role')
 ORDER BY 1
\gexec

SELECT format('ALTER ROLE %I RESET ALL', role_name)
  FROM (VALUES (:'migration_role'), (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
 ORDER BY role_name
\gexec
SELECT format('ALTER ROLE %I IN DATABASE %I RESET ALL', role_name, :'database_name')
  FROM (VALUES (:'migration_role'), (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
 ORDER BY role_name
\gexec
-- With pg_catalog omitted it remains implicitly searched before public, while
-- unqualified migration DDL creates objects in the first explicit schema.
SELECT format('ALTER ROLE %I SET search_path TO public', role_name)
  FROM (VALUES (:'migration_role'), (:'runtime_role'), (:'backup_role')) AS target(role_name)
 ORDER BY role_name
\gexec
SELECT format('ALTER ROLE %I SET search_path TO pg_catalog', :'probe_role')
\gexec

SELECT format('ALTER DATABASE %I OWNER TO %I', :'database_name', :'migration_role')
\gexec
SELECT format('ALTER SCHEMA public OWNER TO %I', :'migration_role')
\gexec

-- Move all existing application objects away from an old bootstrap owner. New
-- migration-created objects are covered by ALTER DEFAULT PRIVILEGES below.
SELECT format(
           'ALTER %s %I.%I OWNER TO %I',
           CASE object.relkind
               WHEN 'r' THEN 'TABLE'
               WHEN 'p' THEN 'TABLE'
               WHEN 'v' THEN 'VIEW'
               WHEN 'm' THEN 'MATERIALIZED VIEW'
               WHEN 'S' THEN 'SEQUENCE'
               WHEN 'f' THEN 'FOREIGN TABLE'
           END,
           namespace.nspname,
           object.relname,
           :'migration_role'
       )
  FROM pg_class object
  JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
 WHERE namespace.nspname = 'public'
   AND object.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
   AND object.relowner <> (SELECT oid FROM pg_roles WHERE rolname = :'migration_role')
 ORDER BY CASE
              WHEN object.relkind IN ('r', 'p') THEN 0
              WHEN object.relkind = 'S' THEN 2
              ELSE 1
          END,
          object.relname
\gexec

SELECT format(
           'ALTER %s %I.%I(%s) OWNER TO %I',
           CASE routine.prokind
               WHEN 'p' THEN 'PROCEDURE'
               WHEN 'a' THEN 'AGGREGATE'
               ELSE 'FUNCTION'
           END,
           namespace.nspname,
           routine.proname,
           pg_get_function_identity_arguments(routine.oid),
           :'migration_role'
       )
  FROM pg_proc routine
  JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
 WHERE namespace.nspname = 'public'
   AND routine.proowner <> (SELECT oid FROM pg_roles WHERE rolname = :'migration_role')
 ORDER BY routine.proname, pg_get_function_identity_arguments(routine.oid)
\gexec

SELECT format(
           'ALTER %s %I.%I OWNER TO %I',
           CASE WHEN type.typtype = 'd' THEN 'DOMAIN' ELSE 'TYPE' END,
           namespace.nspname,
           type.typname,
           :'migration_role'
       )
  FROM pg_type type
  JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
 WHERE namespace.nspname = 'public'
   AND type.typrelid = 0
   AND NOT (type.typelem <> 0 AND type.typlen = -1)
   AND type.typowner <> (SELECT oid FROM pg_roles WHERE rolname = :'migration_role')
 ORDER BY type.typname
\gexec

REVOKE ALL PRIVILEGES ON DATABASE :"database_name" FROM PUBLIC;
SELECT format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I', :'database_name', role_name)
  FROM (VALUES (:'migration_role'), (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
\gexec
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I', :'database_name', :'migration_role')
\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'database_name', role_name)
  FROM (VALUES (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
\gexec

REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
SELECT format('REVOKE ALL PRIVILEGES ON SCHEMA public FROM %I', role_name)
  FROM (VALUES (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
\gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', role_name)
  FROM (VALUES (:'runtime_role'), (:'backup_role')) AS target(role_name)
\gexec

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC;
SELECT format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I', role_name)
  FROM (VALUES (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
\gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'runtime_role')
\gexec
SELECT format('REVOKE INSERT, UPDATE, DELETE ON TABLE public.django_migrations FROM %I', :'runtime_role')
 WHERE to_regclass('public.django_migrations') IS NOT NULL
\gexec
SELECT format('GRANT SELECT ON ALL TABLES IN SCHEMA public TO %I', :'backup_role')
\gexec

REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
SELECT format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I', role_name)
  FROM (VALUES (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
\gexec
SELECT format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO %I', :'runtime_role')
\gexec
SELECT format('GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'backup_role')
\gexec

REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
SELECT format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM %I', role_name)
  FROM (VALUES (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
\gexec
SELECT format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO %I', :'runtime_role')
\gexec

SELECT format('REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM PUBLIC', namespace.nspname, type.typname)
  FROM pg_type type
  JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
 WHERE namespace.nspname = 'public'
   AND type.typrelid = 0
   AND NOT (type.typelem <> 0 AND type.typlen = -1)
 ORDER BY type.typname
\gexec
SELECT format('REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM %I', namespace.nspname, type.typname, role_name)
  FROM pg_type type
  JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
 CROSS JOIN (VALUES (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
 WHERE namespace.nspname = 'public'
   AND type.typrelid = 0
   AND NOT (type.typelem <> 0 AND type.typlen = -1)
 ORDER BY type.typname, role_name
\gexec
SELECT format('GRANT USAGE ON TYPE %I.%I TO %I', namespace.nspname, type.typname, :'runtime_role')
  FROM pg_type type
  JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
 WHERE namespace.nspname = 'public'
   AND type.typrelid = 0
   AND NOT (type.typelem <> 0 AND type.typlen = -1)
 ORDER BY type.typname
\gexec

SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC', :'migration_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC', :'migration_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC', :'migration_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TYPES FROM PUBLIC', :'migration_role')
\gexec
SELECT format(
           'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON %s FROM %I',
           :'migration_role', object_kind, role_name
       )
  FROM (VALUES ('TABLES'), ('SEQUENCES'), ('FUNCTIONS'), ('TYPES')) AS object_kinds(object_kind)
 CROSS JOIN (VALUES (:'runtime_role'), (:'backup_role'), (:'probe_role')) AS target(role_name)
 ORDER BY object_kind, role_name
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', :'migration_role', :'runtime_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO %I', :'migration_role', :'backup_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I', :'migration_role', :'runtime_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON SEQUENCES TO %I', :'migration_role', :'backup_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO %I', :'migration_role', :'runtime_role')
\gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE ON TYPES TO %I', :'migration_role', :'runtime_role')
\gexec

SELECT set_config('camellia.database_name', :'database_name', true);
SELECT set_config('camellia.migration_role', :'migration_role', true);
SELECT set_config('camellia.runtime_role', :'runtime_role', true);
SELECT set_config('camellia.backup_role', :'backup_role', true);
SELECT set_config('camellia.probe_role', :'probe_role', true);

DO $verify_roles$
DECLARE
    invalid_roles integer;
    membership_count integer;
    wrong_object_owners integer;
    unsafe_acl_count integer;
    object_acl_mismatches integer;
    default_acl_mismatches integer;
BEGIN
    SELECT count(*)
      INTO invalid_roles
      FROM pg_roles
     WHERE rolname IN (
               current_setting('camellia.migration_role'),
               current_setting('camellia.runtime_role'),
               current_setting('camellia.backup_role'),
               current_setting('camellia.probe_role')
           )
       AND (
           NOT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit
           OR rolreplication OR rolbypassrls OR rolconnlimit <> -1
       );
    IF invalid_roles <> 0 OR (
        SELECT count(*) FROM pg_roles
         WHERE rolname IN (
                   current_setting('camellia.migration_role'),
                   current_setting('camellia.runtime_role'),
                   current_setting('camellia.backup_role'),
                   current_setting('camellia.probe_role')
               )
    ) <> 4 THEN
        RAISE EXCEPTION 'target role flags did not converge';
    END IF;

    SELECT count(*)
      INTO membership_count
      FROM pg_auth_members membership
      JOIN pg_roles granted ON granted.oid = membership.roleid
      JOIN pg_roles member ON member.oid = membership.member
     WHERE granted.rolname IN (
               current_setting('camellia.migration_role'),
               current_setting('camellia.runtime_role'),
               current_setting('camellia.backup_role'),
               current_setting('camellia.probe_role')
           )
        OR member.rolname IN (
               current_setting('camellia.migration_role'),
               current_setting('camellia.runtime_role'),
               current_setting('camellia.backup_role'),
               current_setting('camellia.probe_role')
           );
    IF membership_count <> 0 THEN
        RAISE EXCEPTION 'target role memberships did not converge';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_db_role_setting settings
         WHERE settings.setdatabase = (
                   SELECT oid FROM pg_database WHERE datname = current_setting('camellia.database_name')
               )
           AND settings.setrole IN (
               SELECT oid FROM pg_roles WHERE rolname IN (
                   current_setting('camellia.migration_role'),
                   current_setting('camellia.runtime_role'),
                   current_setting('camellia.backup_role'),
                   current_setting('camellia.probe_role')
               )
           )
    ) THEN
        RAISE EXCEPTION 'target database-specific role settings did not converge';
    END IF;

    IF (SELECT pg_get_userbyid(datdba) FROM pg_database
         WHERE datname = current_setting('camellia.database_name'))
           <> current_setting('camellia.migration_role')
       OR (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public')
           <> current_setting('camellia.migration_role') THEN
        RAISE EXCEPTION 'database or public schema owner did not converge';
    END IF;

    SELECT count(*)
      INTO wrong_object_owners
      FROM (
          SELECT object.relowner AS owner
            FROM pg_class object
            JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
           WHERE namespace.nspname = 'public'
             AND object.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          UNION ALL
          SELECT routine.proowner
            FROM pg_proc routine
            JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
           WHERE namespace.nspname = 'public'
          UNION ALL
          SELECT type.typowner
            FROM pg_type type
            JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
           WHERE namespace.nspname = 'public'
             AND type.typrelid = 0
             AND NOT (type.typelem <> 0 AND type.typlen = -1)
      ) owners
     WHERE owners.owner <> (
               SELECT oid FROM pg_roles WHERE rolname = current_setting('camellia.migration_role')
           );
    IF wrong_object_owners <> 0 THEN
        RAISE EXCEPTION 'public application object owner did not converge';
    END IF;

    SELECT count(*)
      INTO unsafe_acl_count
      FROM pg_database database
      CROSS JOIN LATERAL aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) acl
     WHERE database.datname = current_setting('camellia.database_name')
       AND acl.grantee = 0;
    IF unsafe_acl_count <> 0 THEN
        RAISE EXCEPTION 'PUBLIC retains database privileges';
    END IF;

    SELECT count(*)
      INTO unsafe_acl_count
      FROM pg_namespace namespace
      CROSS JOIN LATERAL aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) acl
     WHERE namespace.nspname = 'public'
       AND acl.grantee = 0;
    IF unsafe_acl_count <> 0 THEN
        RAISE EXCEPTION 'PUBLIC retains public-schema privileges';
    END IF;

    IF has_schema_privilege(current_setting('camellia.probe_role'), 'public', 'USAGE')
       OR NOT has_schema_privilege(current_setting('camellia.runtime_role'), 'public', 'USAGE')
       OR NOT has_schema_privilege(current_setting('camellia.backup_role'), 'public', 'USAGE')
       OR has_schema_privilege(current_setting('camellia.runtime_role'), 'public', 'CREATE')
       OR has_schema_privilege(current_setting('camellia.backup_role'), 'public', 'CREATE')
       OR has_database_privilege(
           current_setting('camellia.runtime_role'), current_setting('camellia.database_name'), 'CREATE'
       )
       OR has_database_privilege(
           current_setting('camellia.backup_role'), current_setting('camellia.database_name'), 'CREATE'
       )
       OR has_database_privilege(
           current_setting('camellia.probe_role'), current_setting('camellia.database_name'), 'CREATE'
       )
       OR has_database_privilege(
           current_setting('camellia.runtime_role'), current_setting('camellia.database_name'), 'TEMPORARY'
       )
       OR has_database_privilege(
           current_setting('camellia.backup_role'), current_setting('camellia.database_name'), 'TEMPORARY'
       )
       OR has_database_privilege(
           current_setting('camellia.probe_role'), current_setting('camellia.database_name'), 'TEMPORARY'
       )
       OR NOT has_database_privilege(
           current_setting('camellia.runtime_role'), current_setting('camellia.database_name'), 'CONNECT'
       )
       OR NOT has_database_privilege(
           current_setting('camellia.backup_role'), current_setting('camellia.database_name'), 'CONNECT'
       )
       OR NOT has_database_privilege(
           current_setting('camellia.probe_role'), current_setting('camellia.database_name'), 'CONNECT'
       ) THEN
        RAISE EXCEPTION 'a limited role retains schema or database creation privilege';
    END IF;

    SELECT count(*)
      INTO object_acl_mismatches
      FROM pg_class object
      JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
     WHERE namespace.nspname = 'public'
       AND object.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND (
           NOT has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'SELECT')
           OR (
               object.relname <> 'django_migrations'
               AND NOT has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'INSERT')
           )
           OR (
               object.relname <> 'django_migrations'
               AND NOT has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'UPDATE')
           )
           OR (
               object.relname <> 'django_migrations'
               AND NOT has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'DELETE')
           )
           OR (
               object.relname = 'django_migrations'
               AND (
                   has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'INSERT')
                   OR has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'UPDATE')
                   OR has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'DELETE')
               )
           )
           OR has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'TRUNCATE')
           OR has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'REFERENCES')
           OR has_table_privilege(current_setting('camellia.runtime_role'), object.oid, 'TRIGGER')
           OR NOT has_table_privilege(current_setting('camellia.backup_role'), object.oid, 'SELECT')
           OR has_table_privilege(current_setting('camellia.backup_role'), object.oid, 'INSERT')
           OR has_table_privilege(current_setting('camellia.backup_role'), object.oid, 'UPDATE')
           OR has_table_privilege(current_setting('camellia.backup_role'), object.oid, 'DELETE')
           OR has_table_privilege(current_setting('camellia.backup_role'), object.oid, 'TRUNCATE')
           OR has_table_privilege(current_setting('camellia.backup_role'), object.oid, 'REFERENCES')
           OR has_table_privilege(current_setting('camellia.backup_role'), object.oid, 'TRIGGER')
           OR has_table_privilege(current_setting('camellia.probe_role'), object.oid, 'SELECT')
           OR has_table_privilege(current_setting('camellia.probe_role'), object.oid, 'INSERT')
           OR has_table_privilege(current_setting('camellia.probe_role'), object.oid, 'UPDATE')
           OR has_table_privilege(current_setting('camellia.probe_role'), object.oid, 'DELETE')
       );
    IF object_acl_mismatches <> 0 THEN
        RAISE EXCEPTION 'table privileges did not converge';
    END IF;

    SELECT count(*)
      INTO object_acl_mismatches
      FROM pg_class object
      JOIN pg_namespace namespace ON namespace.oid = object.relnamespace
     WHERE namespace.nspname = 'public'
       AND object.relkind = 'S'
       AND (
           NOT has_sequence_privilege(current_setting('camellia.runtime_role'), object.oid, 'USAGE')
           OR NOT has_sequence_privilege(current_setting('camellia.runtime_role'), object.oid, 'SELECT')
           OR NOT has_sequence_privilege(current_setting('camellia.runtime_role'), object.oid, 'UPDATE')
           OR NOT has_sequence_privilege(current_setting('camellia.backup_role'), object.oid, 'SELECT')
           OR has_sequence_privilege(current_setting('camellia.backup_role'), object.oid, 'USAGE')
           OR has_sequence_privilege(current_setting('camellia.backup_role'), object.oid, 'UPDATE')
           OR has_sequence_privilege(current_setting('camellia.probe_role'), object.oid, 'USAGE')
           OR has_sequence_privilege(current_setting('camellia.probe_role'), object.oid, 'SELECT')
           OR has_sequence_privilege(current_setting('camellia.probe_role'), object.oid, 'UPDATE')
       );
    IF object_acl_mismatches <> 0 THEN
        RAISE EXCEPTION 'sequence privileges did not converge';
    END IF;

    SELECT count(*)
      INTO object_acl_mismatches
      FROM pg_proc routine
      JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
     WHERE namespace.nspname = 'public'
       AND (
           NOT has_function_privilege(current_setting('camellia.runtime_role'), routine.oid, 'EXECUTE')
           OR has_function_privilege(current_setting('camellia.backup_role'), routine.oid, 'EXECUTE')
           OR has_function_privilege(current_setting('camellia.probe_role'), routine.oid, 'EXECUTE')
       );
    IF object_acl_mismatches <> 0 THEN
        RAISE EXCEPTION 'routine privileges did not converge';
    END IF;

    SELECT count(*)
      INTO object_acl_mismatches
      FROM pg_type type
      JOIN pg_namespace namespace ON namespace.oid = type.typnamespace
     WHERE namespace.nspname = 'public'
       AND type.typrelid = 0
       AND NOT (type.typelem <> 0 AND type.typlen = -1)
       AND (
           NOT has_type_privilege(current_setting('camellia.runtime_role'), type.oid, 'USAGE')
           OR has_type_privilege(current_setting('camellia.backup_role'), type.oid, 'USAGE')
           OR has_type_privilege(current_setting('camellia.probe_role'), type.oid, 'USAGE')
       );
    IF object_acl_mismatches <> 0 THEN
        RAISE EXCEPTION 'type privileges did not converge';
    END IF;

    WITH actual AS (
        SELECT defaults.defaclobjtype::text AS object_kind,
               CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END AS grantee,
               acl.privilege_type
          FROM pg_default_acl defaults
          CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl
         WHERE defaults.defaclrole = (
                   SELECT oid FROM pg_roles WHERE rolname = current_setting('camellia.migration_role')
               )
           AND defaults.defaclnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
           AND (
               acl.grantee = 0
               OR acl.grantee IN (
                   SELECT oid FROM pg_roles WHERE rolname IN (
                       current_setting('camellia.runtime_role'),
                       current_setting('camellia.backup_role'),
                       current_setting('camellia.probe_role')
                   )
               )
           )
    ), expected(object_kind, grantee, privilege_type) AS (
        VALUES
            ('r', current_setting('camellia.runtime_role'), 'SELECT'),
            ('r', current_setting('camellia.runtime_role'), 'INSERT'),
            ('r', current_setting('camellia.runtime_role'), 'UPDATE'),
            ('r', current_setting('camellia.runtime_role'), 'DELETE'),
            ('r', current_setting('camellia.backup_role'), 'SELECT'),
            ('S', current_setting('camellia.runtime_role'), 'USAGE'),
            ('S', current_setting('camellia.runtime_role'), 'SELECT'),
            ('S', current_setting('camellia.runtime_role'), 'UPDATE'),
            ('S', current_setting('camellia.backup_role'), 'SELECT'),
            ('f', current_setting('camellia.runtime_role'), 'EXECUTE'),
            ('T', current_setting('camellia.runtime_role'), 'USAGE')
    )
    SELECT count(*)
      INTO default_acl_mismatches
      FROM actual
      FULL OUTER JOIN expected USING (object_kind, grantee, privilege_type)
     WHERE actual.object_kind IS NULL OR expected.object_kind IS NULL;
    IF default_acl_mismatches <> 0 THEN
        RAISE EXCEPTION 'migration default privileges did not converge';
    END IF;
END
$verify_roles$;

COMMIT;
SQL

echo "database-roles-converged"
