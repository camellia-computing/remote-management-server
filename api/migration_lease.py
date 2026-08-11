import json
import re
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

from django.db import DatabaseError

# The signed 64-bit value of the ASCII namespace "CAMELLIA". This lock is
# process/session scoped and deliberately separate from every business lock.
MIGRATION_LOCK_KEY = 0x43414D454C4C4941
LOCK_TIMEOUT_EXIT_CODE = 75
_IDENTITY = re.compile(r"[A-Za-z0-9._:@/-]{1,128}\Z")


class MigrationLeaseError(RuntimeError):
    pass


class MigrationLeaseTimeout(MigrationLeaseError):
    pass


def migration_identity(value, field):
    normalized = str(value or "").strip()
    if not _IDENTITY.fullmatch(normalized) or len(normalized.encode("utf-8")) > 128:
        raise MigrationLeaseError(f"migration {field} must be a bounded non-secret identifier")
    return normalized


def _emit(output, event, **fields):
    output.write(
        json.dumps(
            {
                "event": event,
                "lock_namespace": "CAMELLIA",
                "schema_version": 1,
                **fields,
            },
            sort_keys=True,
        )
    )


def _holder_state(database):
    with database.cursor() as cursor:
        cursor.execute(
            """
            SELECT activity.pid,
                   activity.application_name,
                   activity.backend_start,
                   activity.state,
                   activity.state_change
              FROM pg_catalog.pg_locks lock
              JOIN pg_catalog.pg_stat_activity activity ON activity.pid = lock.pid
             WHERE lock.locktype = 'advisory'
               AND lock.granted
               AND lock.objsubid = 1
               AND ((lock.classid::bigint << 32) | lock.objid::bigint) = %s
             ORDER BY activity.pid
             LIMIT 1
            """,
            [MIGRATION_LOCK_KEY],
        )
        row = cursor.fetchone()
    if row is None:
        return None
    pid, application_name, backend_start, state, state_change = row
    return {
        "application_name": application_name,
        "backend_pid": pid,
        "backend_start": backend_start.isoformat() if backend_start else None,
        "state": state,
        "state_change": state_change.isoformat() if state_change else None,
    }


@contextmanager
def migration_lease(
    database,
    *,
    timeout_seconds,
    actor,
    release_revision,
    output,
    poll_seconds=0.2,
):
    if database.vendor != "postgresql":
        raise MigrationLeaseError("production migration leases require PostgreSQL")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 900:
        raise MigrationLeaseError("migration lock timeout must be between 1 and 900 seconds")
    actor = migration_identity(actor, "actor")
    release_revision = migration_identity(release_revision, "release revision")
    operation_id = uuid.uuid4().hex
    application_name = f"camellia-migrate:{operation_id[:12]}:{release_revision[:24]}"[:63]
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    deadline = started + timeout_seconds
    acquired = False
    next_wait_heartbeat = started
    backend_pid = None
    if database.in_atomic_block:
        raise MigrationLeaseError("migration lease cannot reuse an application transaction")
    database.ensure_connection()
    if not database.get_autocommit():
        raise MigrationLeaseError("migration lease requires a dedicated autocommit session")
    try:
        with database.cursor() as cursor:
            cursor.execute("SELECT pg_catalog.set_config('application_name', %s, false)", [application_name])
            cursor.execute("SELECT pg_catalog.pg_backend_pid()")
            backend_pid = cursor.fetchone()[0]
        while True:
            with database.cursor() as cursor:
                cursor.execute("SELECT pg_catalog.pg_try_advisory_lock(%s)", [MIGRATION_LOCK_KEY])
                acquired = bool(cursor.fetchone()[0])
            if acquired:
                break
            now = time.monotonic()
            if now >= next_wait_heartbeat:
                _emit(
                    output,
                    "migration_lease_waiting",
                    actor=actor,
                    holder=_holder_state(database),
                    operation_id=operation_id,
                    release_revision=release_revision,
                    started_at=started_at,
                    timeout_seconds=timeout_seconds,
                    waited_milliseconds=round((now - started) * 1000),
                )
                next_wait_heartbeat = now + 5.0
            if now >= deadline:
                _emit(
                    output,
                    "migration_lease_timeout",
                    actor=actor,
                    holder=_holder_state(database),
                    operation_id=operation_id,
                    release_revision=release_revision,
                    started_at=started_at,
                    waited_milliseconds=round((now - started) * 1000),
                )
                raise MigrationLeaseTimeout("migration lease acquisition timed out")
            time.sleep(min(poll_seconds, max(0.0, deadline - now)))

        _emit(
            output,
            "migration_lease_acquired",
            actor=actor,
            backend_pid=backend_pid,
            operation_id=operation_id,
            release_revision=release_revision,
            started_at=started_at,
            waited_milliseconds=round((time.monotonic() - started) * 1000),
        )
        yield {
            "actor": actor,
            "backend_pid": backend_pid,
            "operation_id": operation_id,
            "release_revision": release_revision,
            "started_at": started_at,
        }
    finally:
        if acquired:
            try:
                with database.cursor() as cursor:
                    cursor.execute("SELECT pg_catalog.pg_advisory_unlock(%s)", [MIGRATION_LOCK_KEY])
                    released = bool(cursor.fetchone()[0])
                _emit(
                    output,
                    "migration_lease_released",
                    actor=actor,
                    backend_pid=backend_pid,
                    operation_id=operation_id,
                    release_revision=release_revision,
                    released=released,
                    started_at=started_at,
                )
            except DatabaseError:
                # Session locks are released by PostgreSQL when a failed or
                # terminated connection disappears. Never mask migration failure.
                database.close()
