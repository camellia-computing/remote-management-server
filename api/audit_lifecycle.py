import datetime
import uuid

from django.conf import settings
from django.db import connection
from django.utils import timezone

from api import ingestion_governance
from api.models import ConnectionAuditEvent, ConnLog, FileLog, FileTransferAuditEvent


def database_now():
    """Return the database authority's current time in production."""

    if connection.vendor != "postgresql":
        return timezone.now()
    with connection.cursor() as cursor:
        cursor.execute("SELECT clock_timestamp()")
        return cursor.fetchone()[0]


def lease_deadline(now):
    return now + datetime.timedelta(seconds=settings.AUDIT_CONNECTION_LEASE_SECONDS)


def refresh_host_lease(connection_log, now):
    connection_log.last_seen_at = now
    connection_log.lease_expires_at = lease_deadline(now)


def reconcile_open_file_transfers(connection_log, connection_event, terminal_at, *, reason):
    """Append an unknown terminal fact for every transfer lacking a trusted result."""

    transfers = list(
        FileLog.objects.select_for_update()
        .filter(
            connection=connection_log,
            audit_version=4,
            state__in=FileLog.OPEN_STATES,
        )
        .order_by("pk")
    )
    for transfer in transfers:
        if transfer.transfer_revision >= 9_223_372_036_854_775_807:
            raise RuntimeError("File transfer revision exhausted")
        revision = transfer.transfer_revision + 1
        terminal_reason = f"connection_{reason}"
        FileTransferAuditEvent.objects.create(
            transfer=transfer,
            connection_event=connection_event,
            revision=revision,
            state=FileLog.STATE_UNKNOWN,
            transferred_bytes=transfer.transferred_bytes,
            terminal_reason=terminal_reason,
            source_kind=transfer.source_kind,
            created_at=terminal_at,
        )
        transfer.transfer_revision = revision
        transfer.state = FileLog.STATE_UNKNOWN
        transfer.terminal_at = terminal_at
        transfer.terminal_reason = terminal_reason
        transfer.save(
            update_fields=(
                "transfer_revision",
                "state",
                "terminal_at",
                "terminal_reason",
            )
        )


def expire_locked_connection(connection_log, now, *, source):
    """Move one row-locked, stale open session to the telemetry-lost terminal state."""

    if connection_log.state not in ConnLog.OPEN_STATES or connection_log.lease_expires_at > now:
        return False
    if connection_log.event_revision >= 9_223_372_036_854_775_807:
        raise RuntimeError("Connection audit event revision exhausted")
    if connection_log.state_revision >= 9_223_372_036_854_775_807:
        raise RuntimeError("Connection audit state revision exhausted")
    ingestion_governance.reserve_audit_event(
        connection_log.owner_id_at_create,
        connection_log.host_device_id_at_create,
        connection_log.event_revision,
        closes_connection=True,
    )
    sequence = connection_log.event_revision + 1
    terminal_event = ConnectionAuditEvent.objects.create(
        event_id=uuid.uuid4(),
        connection=connection_log,
        sequence=sequence,
        kind=ConnectionAuditEvent.KIND_EXPIRED,
        actor=connection_log.reporter,
        actor_id_at_event=connection_log.owner_id_at_create,
        reporter_device_uuid=connection_log.uuid,
        details={
            "expired_at": now.isoformat(),
            "last_seen_at": connection_log.last_seen_at.isoformat(),
            "lease_expires_at": connection_log.lease_expires_at.isoformat(),
            "reason": "telemetry_lost",
            "source": source,
        },
    )
    connection_log.event_revision = sequence
    connection_log.state = ConnLog.STATE_EXPIRED
    connection_log.state_revision += 1
    connection_log.terminal_at = now
    connection_log.terminal_reason = "telemetry_lost"
    connection_log.terminal_source = source
    connection_log.save(
        update_fields=(
            "event_revision",
            "state",
            "state_revision",
            "terminal_at",
            "terminal_reason",
            "terminal_source",
        )
    )
    reconcile_open_file_transfers(
        connection_log,
        terminal_event,
        now,
        reason="telemetry_lost",
    )
    return True
