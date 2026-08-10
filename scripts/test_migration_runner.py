#!/usr/bin/env python3
"""Destructive migration-lease regression for an explicitly empty PostgreSQL database."""

import os
import pathlib
import subprocess
import sys
import time

import psycopg

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api.migration_lease import LOCK_TIMEOUT_EXIT_CODE, MIGRATION_LOCK_KEY  # noqa: E402
from api.release_schema import load_release_schema_manifest  # noqa: E402

SENTINEL = "ephemeral-empty-database-will-be-migrated"


def fail(message):
    raise RuntimeError(message)


def command(*arguments):
    return [sys.executable, "manage.py", "migrate_with_lease", "--noinput", *arguments]


def run(*arguments, timeout=180):
    return subprocess.run(  # noqa: S603 - fixed local management command
        command(*arguments),
        cwd=ROOT,
        env=os.environ,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def assert_empty_database(database_url):
    with psycopg.connect(database_url, autocommit=True) as database, database.cursor() as cursor:
        cursor.execute(
            """
            SELECT count(*)
              FROM pg_catalog.pg_class relation
              JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
             WHERE namespace.nspname = 'public'
               AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
            """
        )
        count = cursor.fetchone()[0]
    if count:
        fail(f"migration runner test requires an empty public schema, found {count} objects")


def concurrent_fresh_migration(database_url):
    processes = [
        subprocess.Popen(  # noqa: S603 - fixed local management command
            command(
                "--actor",
                f"ci-concurrent-{index}",
                "--release-revision",
                "migration-runner-test",
            ),
            cwd=ROOT,
            env=os.environ,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for index in range(10)
    ]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=180)
        results.append((process.returncode, stdout, stderr))
    failures = [result for result in results if result[0] != 0]
    if failures:
        fail(f"leased concurrent migrations failed: {failures}")
    ddl_runners = [stdout for _status, stdout, _stderr in results if "Applying " in stdout]
    if len(ddl_runners) != 1:
        fail(f"expected exactly one DDL runner, observed {len(ddl_runners)}")
    for status, stdout, _stderr in results:
        if (
            status != 0
            or '"event": "migration_lease_acquired"' not in stdout
            or '"event": "migration_lease_released"' not in stdout
        ):
            fail("every follower must acquire, rebuild its plan, and release the lease")

    expected_count = len(load_release_schema_manifest()["migrations"])
    with psycopg.connect(database_url, autocommit=True) as database, database.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM public.django_migrations")
        observed_count = cursor.fetchone()[0]
    if observed_count != expected_count:
        fail(f"migration ledger count is {observed_count}, expected {expected_count}")
    print(f"concurrent-migration-ok runners=10 ddl_runners=1 migrations={observed_count}")


def timeout_and_holder_takeover(database_url):
    holder = psycopg.connect(database_url, autocommit=True)
    killer = psycopg.connect(database_url, autocommit=True)
    try:
        with holder.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid(), pg_try_advisory_lock(%s)", [MIGRATION_LOCK_KEY])
            holder_pid, acquired = cursor.fetchone()
        if not acquired:
            fail("test holder could not acquire the migration lock")

        timed_out = run(
            "--lock-timeout-seconds",
            "1",
            "--actor",
            "ci-timeout-follower",
            "--release-revision",
            "migration-runner-test",
            timeout=30,
        )
        if timed_out.returncode != LOCK_TIMEOUT_EXIT_CODE:
            fail(f"lock timeout returned {timed_out.returncode}: {timed_out.stderr}")
        if '"event": "migration_lease_timeout"' not in timed_out.stdout:
            fail("lock timeout did not emit structured holder evidence")

        follower = subprocess.Popen(  # noqa: S603 - fixed local management command
            command(
                "--lock-timeout-seconds",
                "10",
                "--actor",
                "ci-takeover-follower",
                "--release-revision",
                "migration-runner-test",
            ),
            cwd=ROOT,
            env=os.environ,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(0.75)
        with killer.cursor() as cursor:
            cursor.execute("SELECT pg_terminate_backend(%s)", [holder_pid])
            if cursor.fetchone()[0] is not True:
                fail("holder backend could not be terminated")
        stdout, stderr = follower.communicate(timeout=30)
        if follower.returncode != 0:
            fail(f"follower did not take over after holder termination: {stderr}")
        if '"event": "migration_lease_waiting"' not in stdout or '"event": "migration_lease_acquired"' not in stdout:
            fail("takeover follower did not report wait and acquisition")
        print("holder-takeover-ok timeout_exit=75 holder_terminated=true")
    finally:
        killer.close()
        holder.close()


def migration_failure_releases(database_url):
    failed = run(
        "api",
        "9999_missing_migration",
        "--actor",
        "ci-failure-holder",
        "--release-revision",
        "migration-runner-test",
        timeout=30,
    )
    if failed.returncode == 0:
        fail("invalid migration target unexpectedly succeeded")
    if (
        '"event": "migration_lease_acquired"' not in failed.stdout
        or '"event": "migration_lease_released"' not in failed.stdout
    ):
        fail("a failed migration plan did not release its session lease")
    follower = run(
        "--lock-timeout-seconds",
        "2",
        "--actor",
        "ci-post-failure-follower",
        "--release-revision",
        "migration-runner-test",
        timeout=30,
    )
    if follower.returncode != 0:
        fail(f"follower could not acquire after migration failure: {follower.stderr}")
    print("migration-failure-release-ok")


def main():
    if os.environ.get("CAMELLIA_REMOTE_MIGRATION_TEST_CONFIRM") != SENTINEL:
        fail("set CAMELLIA_REMOTE_MIGRATION_TEST_CONFIRM for an ephemeral empty PostgreSQL database")
    database_url = os.environ.get("CAMELLIA_REMOTE_DATABASE_URL", "")
    if not database_url:
        fail("CAMELLIA_REMOTE_DATABASE_URL is required")
    assert_empty_database(database_url)
    concurrent_fresh_migration(database_url)
    timeout_and_holder_takeover(database_url)
    migration_failure_releases(database_url)


if __name__ == "__main__":
    main()
