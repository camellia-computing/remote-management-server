import datetime
import logging
import os
import stat
import uuid

from django.conf import settings
from django.db import transaction

from api import audit_lifecycle, ingestion_governance, recording_inventory, recording_uploads
from api.models import AlarmLog, ConnLog, FileLog, RecordingUpload

logger = logging.getLogger(__name__)
_NAMESPACE_LENGTH = 64
_NAMESPACE_CHARACTERS = frozenset("0123456789abcdef")
_QUARANTINE_SUFFIX = ".quarantined"


def _unlink_tomb(path):
    if path is None:
        return
    try:
        os.unlink(path)
        recording_uploads._fsync_directory(os.path.dirname(path))
    except FileNotFoundError:
        pass
    except OSError:
        logger.exception("event=ingestion_retention_tomb_cleanup_failed")


def _existing_recording_base(upload):
    base_dir = recording_uploads._record_upload_dir(upload)
    base_stat = os.lstat(base_dir)
    if not stat.S_ISDIR(base_stat.st_mode) or stat.S_ISLNK(base_stat.st_mode):
        raise OSError("Recording retention directory is not a real directory")
    return base_dir


def _stale_active(upload, cutoff):
    return upload.state == RecordingUpload.STATE_ACTIVE and not upload.retention_hold and upload.heartbeat_at < cutoff


def _expired_finalized(upload, cutoff):
    return (
        upload.state == RecordingUpload.STATE_FINALIZED
        and not upload.retention_hold
        and upload.finalized_at is not None
        and upload.finalized_at < cutoff
    )


def _expired_aborted(upload, cutoff):
    return (
        upload.state == RecordingUpload.STATE_ABORTED
        and not upload.retention_hold
        and upload.aborted_at is not None
        and upload.aborted_at < cutoff
    )


def _expire_active_upload(upload_id, cutoff, now):
    tomb_path = None
    with transaction.atomic():
        recording_inventory.lock_recording_mutation()
        upload = RecordingUpload.objects.select_for_update().defer("encrypted_data_key").filter(pk=upload_id).first()
        if upload is None or not _stale_active(upload, cutoff):
            return False
        base_dir = _existing_recording_base(upload)
        with recording_uploads._record_file_lock(base_dir):
            stage_path = recording_uploads._stage_path(base_dir, upload.storage_object_id)
            final_path = recording_uploads._final_path(base_dir, upload)
            tomb_path = recording_uploads._aborted_path(base_dir, upload.storage_object_id)
            existing = [path for path in (stage_path, final_path, tomb_path) if os.path.lexists(path)]
            if len(existing) > 1:
                raise OSError("Stale recording has conflicting storage states")
            if existing and existing[0] != tomb_path:
                os.rename(existing[0], tomb_path)
                recording_uploads._fsync_directory(os.path.dirname(existing[0]))
                recording_uploads._fsync_directory(os.path.dirname(tomb_path))
            elif not existing and (upload.committed_offset != 0 or upload.revision != 0):
                raise OSError("Stale recording bytes are missing")
            ingestion_governance.release_active_recording_usage(
                upload.owner_id_at_create,
                upload.device_id_at_create,
                upload.committed_offset,
            )
            upload.state = RecordingUpload.STATE_ABORTED
            upload.aborted_at = now
            upload.heartbeat_at = now
            upload.save(update_fields=("state", "aborted_at", "heartbeat_at", "updated_at"))
    _unlink_tomb(tomb_path)
    return True


def _purge_finalized_upload(upload_id, cutoff):
    tomb_path = None
    with transaction.atomic():
        recording_inventory.lock_recording_mutation()
        upload = RecordingUpload.objects.select_for_update().defer("encrypted_data_key").filter(pk=upload_id).first()
        if upload is None or not _expired_finalized(upload, cutoff):
            return False
        base_dir = _existing_recording_base(upload)
        with recording_uploads._record_file_lock(base_dir):
            final_path = recording_uploads._final_path(base_dir, upload)
            tomb_path = recording_uploads._deleting_path(base_dir, upload.storage_object_id)
            final_exists = os.path.lexists(final_path)
            tomb_exists = os.path.lexists(tomb_path)
            if final_exists and tomb_exists:
                raise OSError("Expired recording has both published and deleting files")
            if final_exists:
                os.rename(final_path, tomb_path)
                recording_uploads._fsync_directory(os.path.dirname(final_path))
                recording_uploads._fsync_directory(os.path.dirname(tomb_path))
            elif not tomb_exists:
                raise OSError("Expired finalized recording is missing")
            ingestion_governance.release_finalized_recording_usage(
                upload.owner_id_at_create,
                upload.device_id_at_create,
                upload.committed_offset,
            )
            upload.delete()
    _unlink_tomb(tomb_path)
    return True


def _purge_aborted_upload(upload_id, cutoff):
    with transaction.atomic():
        recording_inventory.lock_recording_mutation()
        upload = RecordingUpload.objects.select_for_update().defer("encrypted_data_key").filter(pk=upload_id).first()
        if upload is None or not _expired_aborted(upload, cutoff):
            return False
        upload.delete()
    return True


def purge_recording_retention(now, *, batch_size, dry_run=False):
    active_cutoff = now - datetime.timedelta(minutes=settings.RECORD_UPLOAD_ACTIVE_TIMEOUT_MINUTES)
    finalized_cutoff = now - datetime.timedelta(days=settings.RECORD_UPLOAD_RETENTION_DAYS)
    aborted_cutoff = now - datetime.timedelta(days=settings.RECORD_UPLOAD_ABORTED_RETENTION_DAYS)
    querysets = {
        "recording_active_expired": RecordingUpload.objects.filter(
            state=RecordingUpload.STATE_ACTIVE,
            retention_hold=False,
            heartbeat_at__lt=active_cutoff,
        ).order_by("heartbeat_at", "upload_id"),
        "recording_finalized_purged": RecordingUpload.objects.filter(
            state=RecordingUpload.STATE_FINALIZED,
            retention_hold=False,
            finalized_at__lt=finalized_cutoff,
        ).order_by("finalized_at", "upload_id"),
        "recording_aborted_purged": RecordingUpload.objects.filter(
            state=RecordingUpload.STATE_ABORTED,
            retention_hold=False,
            aborted_at__lt=aborted_cutoff,
        ).order_by("aborted_at", "upload_id"),
    }
    handlers = {
        "recording_active_expired": lambda pk: _expire_active_upload(pk, active_cutoff, now),
        "recording_finalized_purged": lambda pk: _purge_finalized_upload(pk, finalized_cutoff),
        "recording_aborted_purged": lambda pk: _purge_aborted_upload(pk, aborted_cutoff),
    }
    result = {}
    for name, queryset in querysets.items():
        identifiers = list(queryset.values_list("pk", flat=True)[:batch_size])
        if dry_run:
            result[name] = len(identifiers)
        else:
            result[name] = sum(bool(handlers[name](identifier)) for identifier in identifiers)
    result.update(_purge_recording_orphans(now, batch_size=batch_size, dry_run=dry_run))
    return result


def _purge_recording_orphans(now, *, batch_size, dry_run):
    cutoff = now - datetime.timedelta(minutes=settings.RECORD_UPLOAD_ACTIVE_TIMEOUT_MINUTES)
    quarantine_cutoff = now - datetime.timedelta(days=settings.RECORD_UPLOAD_ORPHAN_QUARANTINE_DAYS)
    root = os.path.abspath(os.fspath(settings.RECORD_UPLOAD_ROOT))
    root_stat = os.lstat(root)
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise OSError("Recording root is not a real directory")
    candidates = []
    for namespace_entry in os.scandir(root):
        if len(candidates) >= batch_size:
            break
        if len(namespace_entry.name) != _NAMESPACE_LENGTH or any(
            character not in _NAMESPACE_CHARACTERS for character in namespace_entry.name
        ):
            continue
        if not namespace_entry.is_dir(follow_symlinks=False):
            continue
        scan_directories = ((namespace_entry.path, (".recording",)),)
        upload_dir = os.path.join(namespace_entry.path, ".uploads")
        try:
            upload_dir_stat = os.lstat(upload_dir)
        except FileNotFoundError:
            upload_dir_stat = None
        if upload_dir_stat is not None:
            if not stat.S_ISDIR(upload_dir_stat.st_mode) or stat.S_ISLNK(upload_dir_stat.st_mode):
                raise OSError("Recording orphan staging path is not a real directory")
            scan_directories += ((upload_dir, (".part", ".aborted", ".deleting")),)
        for directory, allowed_suffixes in scan_directories:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if len(candidates) >= batch_size:
                        break
                    suffix = next((candidate for candidate in allowed_suffixes if entry.name.endswith(candidate)), None)
                    if suffix is None:
                        continue
                    try:
                        object_id = uuid.UUID(entry.name.removesuffix(suffix))
                        entry_stat = entry.stat(follow_symlinks=False)
                    except (ValueError, OSError):
                        continue
                    if object_id.version != 4 or str(object_id) != entry.name.removesuffix(suffix):
                        continue
                    if not stat.S_ISREG(entry_stat.st_mode):
                        raise OSError("Recording orphan candidate is not a regular file")
                    modified_at = datetime.datetime.fromtimestamp(entry_stat.st_mtime, tz=datetime.UTC)
                    if modified_at >= cutoff or RecordingUpload.objects.filter(storage_object_id=object_id).exists():
                        continue
                    candidates.append(
                        (
                            namespace_entry.name,
                            namespace_entry.path,
                            object_id,
                            suffix,
                            entry.path,
                            entry_stat.st_dev,
                            entry_stat.st_ino,
                            entry_stat.st_mtime_ns,
                        )
                    )
                if len(candidates) >= batch_size:
                    break

    quarantine_dir = os.path.join(root, ".quarantine")
    quarantine_candidates = []
    try:
        quarantine_stat = os.lstat(quarantine_dir)
    except FileNotFoundError:
        quarantine_stat = None
    if quarantine_stat is not None:
        if not stat.S_ISDIR(quarantine_stat.st_mode) or stat.S_ISLNK(quarantine_stat.st_mode):
            raise OSError("Recording quarantine path is not a real directory")
        with os.scandir(quarantine_dir) as entries:
            for entry in entries:
                if len(candidates) + len(quarantine_candidates) >= batch_size:
                    break
                entry_stat = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(entry_stat.st_mode) or stat.S_ISLNK(entry_stat.st_mode):
                    raise OSError("Recording quarantine candidate is not a regular file")
                modified_at = datetime.datetime.fromtimestamp(entry_stat.st_mtime, tz=datetime.UTC)
                if not entry.name.endswith(_QUARANTINE_SUFFIX) or modified_at >= quarantine_cutoff:
                    continue
                quarantine_candidates.append((entry.path, entry_stat.st_dev, entry_stat.st_ino, entry_stat.st_mtime_ns))

    if dry_run:
        return {
            "recording_orphans_quarantined": len(candidates),
            "recording_quarantine_purged": len(quarantine_candidates),
        }

    quarantined = 0
    for namespace, base_dir, object_id, suffix, path, device, inode, modified_ns in candidates:
        with transaction.atomic():
            recording_inventory.lock_recording_mutation()
            if RecordingUpload.objects.select_for_update().filter(storage_object_id=object_id).exists():
                continue
            base_stat = os.lstat(base_dir)
            if not stat.S_ISDIR(base_stat.st_mode) or stat.S_ISLNK(base_stat.st_mode):
                raise OSError("Recording orphan namespace changed type")
            with recording_uploads._record_file_lock(base_dir):
                try:
                    file_stat = os.lstat(path)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(file_stat.st_mode) or stat.S_ISLNK(file_stat.st_mode):
                    raise OSError("Recording orphan candidate changed type")
                if (
                    file_stat.st_dev != device
                    or file_stat.st_ino != inode
                    or file_stat.st_mtime_ns != modified_ns
                    or datetime.datetime.fromtimestamp(file_stat.st_mtime, tz=datetime.UTC) >= cutoff
                ):
                    continue
                recording_uploads._secure_directory(quarantine_dir)
                quarantine_name = f"{namespace}.{object_id}{suffix}.{uuid.uuid4()}{_QUARANTINE_SUFFIX}"
                destination = os.path.join(quarantine_dir, quarantine_name)
                os.rename(path, destination)
                os.utime(destination, None, follow_symlinks=False)
                recording_uploads._fsync_directory(os.path.dirname(path))
                recording_uploads._fsync_directory(quarantine_dir)
                quarantined += 1

    purged = 0
    for path, device, inode, modified_ns in quarantine_candidates:
        with transaction.atomic():
            recording_inventory.lock_recording_mutation()
            try:
                file_stat = os.lstat(path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(file_stat.st_mode) or stat.S_ISLNK(file_stat.st_mode):
                raise OSError("Recording quarantine candidate changed type")
            if (
                file_stat.st_dev != device
                or file_stat.st_ino != inode
                or file_stat.st_mtime_ns != modified_ns
                or datetime.datetime.fromtimestamp(file_stat.st_mtime, tz=datetime.UTC) >= quarantine_cutoff
            ):
                continue
            os.unlink(path)
            recording_uploads._fsync_directory(quarantine_dir)
            purged += 1
    return {
        "recording_orphans_quarantined": quarantined,
        "recording_quarantine_purged": purged,
    }


def _purge_connection(connection_id, cutoff):
    with transaction.atomic():
        connection = ConnLog.objects.select_for_update().filter(pk=connection_id).first()
        if (
            connection is None
            or connection.retention_hold
            or connection.terminal_at is None
            or connection.terminal_at >= cutoff
        ):
            return False
        if connection.audit_version in (2, 3):
            event_count = connection.events.count()
            if event_count != connection.event_revision:
                raise RuntimeError("Connection audit event ledger is inconsistent")
            ingestion_governance.release_audit_connection(
                connection.owner_id_at_create,
                connection.host_device_id_at_create,
                event_count,
            )
        FileLog.objects.filter(connection=connection).delete()
        AlarmLog.objects.filter(connection=connection).delete()
        connection.delete()
    return True


def _expire_connection(connection_id, now):
    with transaction.atomic():
        connection = ConnLog.objects.select_for_update().filter(pk=connection_id).first()
        if connection is None:
            return False
        return audit_lifecycle.expire_locked_connection(connection, now, source="cleanup_reconciler")


def purge_audit_retention(now, *, batch_size, dry_run=False):
    cutoff = now - datetime.timedelta(days=settings.AUDIT_RETENTION_DAYS)
    lease_now = audit_lifecycle.database_now()
    stale_connection_ids = list(
        ConnLog.objects.filter(
            state__in=ConnLog.OPEN_STATES,
            lease_expires_at__lte=lease_now,
        )
        .order_by("lease_expires_at", "pk")
        .values_list("pk", flat=True)[:batch_size]
    )
    connection_ids = list(
        ConnLog.objects.filter(retention_hold=False, terminal_at__lt=cutoff)
        .order_by("terminal_at", "pk")
        .values_list("pk", flat=True)[:batch_size]
    )
    legacy_file_ids = list(
        FileLog.objects.filter(connection__isnull=True, logged_at__lt=cutoff)
        .order_by("logged_at", "pk")
        .values_list("pk", flat=True)[:batch_size]
    )
    legacy_alarm_ids = list(
        AlarmLog.objects.filter(connection__isnull=True, created_at__lt=cutoff)
        .order_by("created_at", "pk")
        .values_list("pk", flat=True)[:batch_size]
    )
    if dry_run:
        return {
            "audit_connections_expired": len(stale_connection_ids),
            "audit_connections_purged": len(connection_ids),
            "legacy_file_audits_purged": len(legacy_file_ids),
            "legacy_alarm_audits_purged": len(legacy_alarm_ids),
        }
    return {
        "audit_connections_expired": sum(
            _expire_connection(identifier, lease_now) for identifier in stale_connection_ids
        ),
        "audit_connections_purged": sum(_purge_connection(identifier, cutoff) for identifier in connection_ids),
        "legacy_file_audits_purged": FileLog.objects.filter(pk__in=legacy_file_ids).delete()[0],
        "legacy_alarm_audits_purged": AlarmLog.objects.filter(pk__in=legacy_alarm_ids).delete()[0],
    }
