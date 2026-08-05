import os
import stat
import threading
import time
import uuid

from django.conf import settings
from django.db.models import Q
from django.http import JsonResponse
from django.utils import timezone

from api.models import PersistentIngestionUsage


class IngestionQuotaExceeded(Exception):
    def __init__(self, kind, scope, metric, limit):
        super().__init__(f"{kind} {scope} {metric} quota exceeded")
        self.kind = kind
        self.scope = scope
        self.metric = metric
        self.limit = limit


class RecordingStorageUnavailable(Exception):
    def __init__(self, message, *, status=503, code="recording_storage_unavailable"):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


def quota_response(error):
    response = JsonResponse(
        {
            "error": "Persistent ingestion quota exceeded",
            "code": f"{error.kind}_quota_exceeded",
            "scope": error.scope,
            "metric": error.metric,
            "limit": error.limit,
            "retryable": True,
        },
        status=507,
    )
    response["Retry-After"] = "300"
    response["Cache-Control"] = "no-store"
    return response


def storage_error_response(error):
    response = JsonResponse(
        {
            "error": error.message,
            "code": error.code,
            "retryable": True,
        },
        status=error.status,
    )
    response["Retry-After"] = "30"
    response["Cache-Control"] = "no-store"
    return response


def _usage_identities(kind, owner_id, device_id):
    return (
        (kind, PersistentIngestionUsage.SCOPE_GLOBAL, 0),
        (kind, PersistentIngestionUsage.SCOPE_OWNER, int(owner_id)),
        (kind, PersistentIngestionUsage.SCOPE_DEVICE, int(device_id)),
    )


def _locked_usage(kind, owner_id, device_id):
    identities = _usage_identities(kind, owner_id, device_id)
    PersistentIngestionUsage.objects.bulk_create(
        [
            PersistentIngestionUsage(kind=row_kind, scope=scope, subject_id=subject_id)
            for row_kind, scope, subject_id in identities
        ],
        ignore_conflicts=True,
    )
    query = Q()
    for row_kind, scope, subject_id in identities:
        query |= Q(kind=row_kind, scope=scope, subject_id=subject_id)
    rows = list(PersistentIngestionUsage.objects.select_for_update().filter(query).order_by("scope", "subject_id"))
    if len(rows) != len(identities):
        raise RuntimeError("Persistent ingestion usage authority is incomplete")
    return {row.scope: row for row in rows}


def _limits(prefix, metric):
    if not metric.endswith("_PER"):
        raise ValueError("Scoped ingestion quota setting must end in _PER")
    global_metric = metric.removesuffix("_PER")
    return {
        PersistentIngestionUsage.SCOPE_DEVICE: getattr(settings, f"{prefix}_{metric}_DEVICE"),
        PersistentIngestionUsage.SCOPE_OWNER: getattr(settings, f"{prefix}_{metric}_OWNER"),
        PersistentIngestionUsage.SCOPE_GLOBAL: getattr(settings, f"{prefix}_{global_metric}_GLOBAL"),
    }


def _apply(rows, *, items=0, active_items=0, committed_bytes=0, events=0):
    fields = ("items", "active_items", "committed_bytes", "events")
    deltas = (items, active_items, committed_bytes, events)
    for row in rows.values():
        for field, delta in zip(fields, deltas, strict=True):
            value = getattr(row, field) + delta
            if value < 0:
                raise RuntimeError("Persistent ingestion usage would become negative")
            setattr(row, field, value)
        row.updated_at = timezone.now()
    PersistentIngestionUsage.objects.bulk_update(tuple(rows.values()), fields + ("updated_at",))


def _check(rows, kind, metric, delta, limits):
    field = {
        "files": "items",
        "active": "active_items",
        "bytes": "committed_bytes",
        "connections": "items",
        "events": "events",
    }[metric]
    for scope, row in rows.items():
        limit = limits[scope]
        if getattr(row, field) + delta > limit:
            raise IngestionQuotaExceeded(kind, scope, metric, limit)


def lock_recording_create_usage(owner_id, device_id):
    """Lock the complete create authority before its idempotency recheck."""

    return _locked_usage(PersistentIngestionUsage.KIND_RECORDING, owner_id, device_id)


def reserve_locked_recording_create(rows):
    _check(rows, "recording", "files", 1, _limits("RECORD_UPLOAD", "MAX_FILES_PER"))
    _check(rows, "recording", "active", 1, _limits("RECORD_UPLOAD", "MAX_ACTIVE_PER"))
    _apply(rows, items=1, active_items=1)


def reserve_recording_bytes(owner_id, device_id, byte_count):
    if byte_count <= 0:
        raise ValueError("Recording byte reservation must be positive")
    rows = _locked_usage(PersistentIngestionUsage.KIND_RECORDING, owner_id, device_id)
    _check(rows, "recording", "bytes", byte_count, _limits("RECORD_UPLOAD", "MAX_BYTES_PER"))
    _apply(rows, committed_bytes=byte_count)


def finalize_recording_usage(owner_id, device_id):
    rows = _locked_usage(PersistentIngestionUsage.KIND_RECORDING, owner_id, device_id)
    _apply(rows, active_items=-1)


def release_active_recording_usage(owner_id, device_id, byte_count):
    rows = _locked_usage(PersistentIngestionUsage.KIND_RECORDING, owner_id, device_id)
    _apply(rows, items=-1, active_items=-1, committed_bytes=-int(byte_count))


def release_finalized_recording_usage(owner_id, device_id, byte_count):
    rows = _locked_usage(PersistentIngestionUsage.KIND_RECORDING, owner_id, device_id)
    _apply(rows, items=-1, committed_bytes=-int(byte_count))


def reserve_audit_connection(owner_id, device_id):
    rows = _locked_usage(PersistentIngestionUsage.KIND_AUDIT, owner_id, device_id)
    _check(rows, "audit", "connections", 1, _limits("AUDIT", "MAX_CONNECTIONS_PER"))
    # Reserve both the opening event and one eventual close event. Without a
    # durable close reservation, a valid device can fill the retained-event
    # quota and make its active connection permanently impossible to close or
    # age into closed-session retention.
    _check(rows, "audit", "events", 2, _limits("AUDIT", "MAX_EVENTS_PER"))
    _apply(rows, items=1, events=2)


def reserve_audit_event(owner_id, device_id, connection_revision, *, closes_connection=False):
    next_revision = connection_revision + 1
    if not closes_connection and next_revision >= settings.AUDIT_MAX_EVENTS_PER_CONNECTION:
        raise IngestionQuotaExceeded(
            "audit",
            "connection",
            "events",
            settings.AUDIT_MAX_EVENTS_PER_CONNECTION,
        )
    if closes_connection:
        # The event is already represented by the reservation taken when the
        # connection was created. Transaction rollback preserves that
        # reservation if the close event itself does not commit.
        return
    rows = _locked_usage(PersistentIngestionUsage.KIND_AUDIT, owner_id, device_id)
    _check(rows, "audit", "events", 1, _limits("AUDIT", "MAX_EVENTS_PER"))
    _apply(rows, events=1)


def release_audit_connection(owner_id, device_id, event_count):
    rows = _locked_usage(PersistentIngestionUsage.KIND_AUDIT, owner_id, device_id)
    _apply(rows, items=-1, events=-int(event_count))


def recording_namespace(owner_id, rid, device_uuid):
    import hashlib

    return hashlib.sha256(f"{owner_id}\0{rid}\0{device_uuid}".encode()).hexdigest()


def _decode_mount_path(value):
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
        value = value.replace(encoded, decoded)
    return value


def _mount_identity(path):
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as mountinfo:
            for line in mountinfo:
                fields = line.rstrip("\n").split(" ")
                if len(fields) >= 10 and _decode_mount_path(fields[4]) == path:
                    separator = fields.index("-")
                    return (fields[2], fields[3], fields[separator + 1], fields[separator + 2])
    except (OSError, ValueError, IndexError):
        return None
    return None


_capability_lock = threading.Lock()
_capability_cache = {}
_mount_baselines = {}


def reset_recording_storage_capability_cache():
    with _capability_lock:
        _capability_cache.clear()
        _mount_baselines.clear()


def check_recording_storage_capability(required_bytes=0, *, force=False):
    if not isinstance(required_bytes, int) or required_bytes < 0:
        raise ValueError("required recording bytes must be a nonnegative integer")
    root = os.path.abspath(os.fspath(settings.RECORD_UPLOAD_ROOT))
    cache_seconds = settings.RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS
    require_mount = settings.RECORD_UPLOAD_REQUIRE_MOUNT
    cache_key = (
        root,
        require_mount,
        settings.RECORD_UPLOAD_VOLUME_RESERVE_BYTES,
        settings.RECORD_UPLOAD_VOLUME_RESERVE_INODES,
    )
    now = time.monotonic()
    with _capability_lock:
        cached = _capability_cache.get(cache_key)
        if not force and required_bytes == 0 and cached is not None and now - cached < cache_seconds:
            return
    probe = None
    mount_identity = None
    try:
        root_stat = os.lstat(root)
        if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
            raise OSError("recording root is not a real directory")
        if os.path.realpath(root) != root:
            raise OSError("recording root resolves through a symlink")
        if require_mount:
            mount_identity = _mount_identity(root)
            if mount_identity is None:
                raise OSError("recording root is not a dedicated mount")
            with _capability_lock:
                baseline = _mount_baselines.get(root)
            if baseline is not None and baseline != mount_identity:
                raise OSError("recording root mount identity changed")
        filesystem = os.statvfs(root)
        available_bytes = filesystem.f_bavail * filesystem.f_frsize
        if available_bytes - required_bytes < settings.RECORD_UPLOAD_VOLUME_RESERVE_BYTES:
            raise RecordingStorageUnavailable(
                "Recording volume free-space reserve is exhausted",
                status=507,
                code="recording_volume_full",
            )
        if filesystem.f_favail < settings.RECORD_UPLOAD_VOLUME_RESERVE_INODES:
            raise RecordingStorageUnavailable(
                "Recording volume inode reserve is exhausted",
                status=507,
                code="recording_volume_inodes_exhausted",
            )
        probe = os.path.join(root, f".capability-{os.getpid()}-{uuid.uuid4()}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(probe, flags, 0o600)
        try:
            os.write(fd, b"1")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.unlink(probe)
        probe = None
        directory_fd = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except RecordingStorageUnavailable:
        raise
    except OSError as error:
        if probe is not None:
            try:
                os.unlink(probe)
            except OSError:
                pass
        raise RecordingStorageUnavailable("Recording storage is unavailable") from error
    with _capability_lock:
        if mount_identity is not None:
            baseline = _mount_baselines.setdefault(root, mount_identity)
            if baseline != mount_identity:
                raise RecordingStorageUnavailable("Recording storage mount identity changed")
        _capability_cache[cache_key] = now
