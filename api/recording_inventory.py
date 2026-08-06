import datetime
import hashlib
import json
import os
import re
import stat
import struct
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from api import recording_uploads
from api.models import (
    RecordingBackupControl,
    RecordingBackupEpoch,
    RecordingBackupObject,
    RecordingUpload,
)

BACKUP_FORMAT = "camellia-recording-backup-v1"
BACKUP_MAGIC = b"CAMELLIA-REMOTE-RECORDING-BACKUP\x00"
BACKUP_END = b"E"
BACKUP_OBJECT = b"O"
BACKUP_ID_RE = re.compile(r"^[0-9a-f]{32}$")
INVENTORY_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
NAMESPACE_RE = re.compile(r"^[0-9a-f]{64}$")
OBJECT_NAME_RE = re.compile(
    r"^(?P<object_id>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"
    r"(?P<suffix>\.recording|\.part|\.aborted|\.deleting)$"
)
MAX_HEADER_BYTES = 4096
MAX_OBJECT_METADATA_BYTES = 4096
COPY_CHUNK_BYTES = 1024 * 1024
SNAPSHOT_BATCH_SIZE = 250


class RecordingBackupInProgress(RuntimeError):
    pass


class RecordingInventoryError(RuntimeError):
    pass


def lock_recording_mutation():
    """Serialize a recording mutation with backup checkpoint creation.

    The caller must already be inside transaction.atomic(). Every file/row
    mutation takes this singleton row first; checkpoint creation therefore
    waits for earlier mutations and blocks later ones until the paired
    database and ciphertext artifacts are durable.
    """

    control = RecordingBackupControl.objects.select_for_update().filter(singleton=1).first()
    if control is None:
        raise RecordingInventoryError("Recording backup control is missing")
    if control.active_epoch_id is not None:
        raise RecordingBackupInProgress("A consistent recording backup is in progress")
    return control


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _timestamp(value):
    if value is None:
        return None
    if timezone.is_naive(value):
        raise RecordingInventoryError("Recording inventory timestamp is naive")
    return value.astimezone(datetime.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_requested_at(value):
    try:
        parsed = datetime.datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.UTC)
    except (TypeError, ValueError) as error:
        raise RecordingInventoryError("Recording backup timestamp is invalid") from error
    if parsed.strftime("%Y%m%dT%H%M%SZ") != value:
        raise RecordingInventoryError("Recording backup timestamp is invalid")
    return parsed


def _validate_backup_id(value):
    if not isinstance(value, str) or not BACKUP_ID_RE.fullmatch(value):
        raise RecordingInventoryError("Recording backup ID is invalid")
    return value


def _root():
    root = os.path.abspath(os.fspath(settings.RECORD_UPLOAD_ROOT))
    try:
        root_stat = os.lstat(root)
    except OSError as error:
        raise RecordingInventoryError("Recording root is unavailable") from error
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or os.path.realpath(root) != root:
        raise RecordingInventoryError("Recording root is not a canonical real directory")
    return root


def _relative_paths(upload):
    object_name = str(upload.storage_object_id)
    namespace = upload.storage_namespace
    stage = f"{namespace}/.uploads/{object_name}.part"
    aborted = f"{namespace}/.uploads/{object_name}.aborted"
    deleting = f"{namespace}/.uploads/{object_name}.deleting"
    published = f"{namespace}/{object_name}.recording"
    if upload.state == RecordingUpload.STATE_ACTIVE:
        return (stage, published)
    if upload.state == RecordingUpload.STATE_FINALIZED:
        return (published, deleting)
    if upload.state == RecordingUpload.STATE_ABORTED:
        return (aborted,)
    raise RecordingInventoryError("Recording row has an invalid state")


def _regular_file(path):
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RecordingInventoryError("Recording object cannot be inspected") from error
    if not stat.S_ISREG(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode):
        raise RecordingInventoryError("Recording object is not a regular file")
    return path_stat


def _locate_upload_object(root, upload):
    existing = []
    for relative_path in _relative_paths(upload):
        absolute_path = os.path.join(root, relative_path)
        path_stat = _regular_file(absolute_path)
        if path_stat is not None:
            existing.append((relative_path, absolute_path, path_stat))
    if len(existing) > 1:
        raise RecordingInventoryError("Recording upload has conflicting physical objects")
    if not existing:
        if upload.state == RecordingUpload.STATE_ABORTED:
            return None
        raise RecordingInventoryError("Recording inventory references a missing physical object")
    return existing[0]


def _snapshot_metadata(upload, relative_path, *, plaintext_size, plaintext_digest, ciphertext_size, ciphertext_digest):
    return {
        "aborted_at": _timestamp(upload.aborted_at),
        "ciphertext_digest": ciphertext_digest,
        "ciphertext_size": ciphertext_size,
        "created_at": _timestamp(upload.created_at),
        "data_key_kek_id": upload.data_key_kek_id,
        "deployment_generation": upload.deployment_generation,
        "device_id_at_create": upload.device_id_at_create,
        "device_rid_at_create": upload.device_rid_at_create,
        "device_uuid_at_create": upload.device_uuid_at_create,
        "encryption_version": upload.encryption_version,
        "finalized_at": _timestamp(upload.finalized_at),
        "object_present": bool(relative_path),
        "owner_id_at_create": upload.owner_id_at_create,
        "plaintext_digest": plaintext_digest,
        "plaintext_size": plaintext_size,
        "retention_hold": upload.retention_hold,
        "retention_hold_at": _timestamp(upload.retention_hold_at),
        "retention_hold_reason": upload.retention_hold_reason,
        "state": upload.state,
        "storage_object_id": str(upload.storage_object_id),
        "storage_relative_path": relative_path,
        "storage_version": upload.storage_version,
        "upload_id": str(upload.upload_id),
    }


def _model_values(epoch, metadata):
    values = dict(metadata)
    for field in ("created_at", "finalized_at", "aborted_at", "retention_hold_at"):
        value = values[field]
        values[field] = datetime.datetime.fromisoformat(value.replace("Z", "+00:00")) if value is not None else None
    return RecordingBackupObject(epoch=epoch, **values)


def _authenticate_upload(upload, absolute_path):
    try:
        data_key = recording_uploads._recording_data_key(upload)
        plaintext_size, plaintext_digest, ciphertext_digest = recording_uploads._verify_recording_file(
            upload,
            absolute_path,
            data_key,
            include_ciphertext_digest=True,
        )
    except (OSError, ValidationError) as error:
        raise RecordingInventoryError("Recording ciphertext failed inventory authentication") from error
    return plaintext_size, plaintext_digest, upload.storage_offset, ciphertext_digest


def _observed_relative_paths(root):
    for namespace_entry in os.scandir(root):
        if namespace_entry.name == ".quarantine" or namespace_entry.name.startswith(".capability-"):
            continue
        if not NAMESPACE_RE.fullmatch(namespace_entry.name):
            continue
        if not namespace_entry.is_dir(follow_symlinks=False):
            raise RecordingInventoryError("Recording namespace is not a real directory")
        with os.scandir(namespace_entry.path) as entries:
            for entry in entries:
                if entry.name in (".locks",):
                    if not entry.is_dir(follow_symlinks=False):
                        raise RecordingInventoryError("Recording lock path is not a real directory")
                    continue
                if entry.name == ".uploads":
                    if not entry.is_dir(follow_symlinks=False):
                        raise RecordingInventoryError("Recording staging path is not a real directory")
                    with os.scandir(entry.path) as staged_entries:
                        for staged in staged_entries:
                            match = OBJECT_NAME_RE.fullmatch(staged.name)
                            if match is None or match.group("suffix") == ".recording":
                                raise RecordingInventoryError("Recording staging directory contains an unknown object")
                            if not staged.is_file(follow_symlinks=False):
                                raise RecordingInventoryError("Recording staging object is not a regular file")
                            yield f"{namespace_entry.name}/.uploads/{staged.name}"
                    continue
                match = OBJECT_NAME_RE.fullmatch(entry.name)
                if match is None or match.group("suffix") != ".recording":
                    raise RecordingInventoryError("Recording namespace contains an unknown object")
                if not entry.is_file(follow_symlinks=False):
                    raise RecordingInventoryError("Published recording object is not a regular file")
                yield f"{namespace_entry.name}/{entry.name}"


def _validate_bidirectional_inventory(root, epoch):
    observed_count = 0
    for relative_path in _observed_relative_paths(root):
        observed_count += 1
        if not RecordingBackupObject.objects.filter(
            epoch=epoch,
            object_present=True,
            storage_relative_path=relative_path,
        ).exists():
            raise RecordingInventoryError("Recording volume contains an object outside the authoritative inventory")
    if observed_count != epoch.object_count:
        raise RecordingInventoryError("Recording inventory and volume object counts differ")


def begin_backup(backup_id, requested_at):
    backup_id = _validate_backup_id(backup_id)
    requested_at = _parse_requested_at(requested_at)
    root = _root()
    epoch = None
    try:
        with transaction.atomic():
            control = RecordingBackupControl.objects.select_for_update().filter(singleton=1).first()
            if control is None:
                raise RecordingInventoryError("Recording backup control is missing")
            if control.active_epoch_id is not None:
                raise RecordingBackupInProgress("A consistent recording backup is already in progress")
            RecordingBackupEpoch.objects.filter(
                state__in=(RecordingBackupEpoch.STATE_COMPLETE, RecordingBackupEpoch.STATE_RESTORED)
            ).delete()
            epoch = RecordingBackupEpoch.objects.create(backup_id=backup_id, requested_at=requested_at)
            control.active_epoch = epoch
            control.save(update_fields=("active_epoch", "updated_at"))

        digest = hashlib.sha256()
        batch = []
        inventory_count = 0
        object_count = 0
        last_upload_id = None
        while True:
            uploads = RecordingUpload.objects.order_by("upload_id")
            if last_upload_id is not None:
                uploads = uploads.filter(upload_id__gt=last_upload_id)
            page = list(uploads[:SNAPSHOT_BATCH_SIZE])
            if not page:
                break
            for upload in page:
                located = _locate_upload_object(root, upload)
                if located is None:
                    metadata = _snapshot_metadata(
                        upload,
                        "",
                        plaintext_size=upload.committed_offset,
                        plaintext_digest="",
                        ciphertext_size=0,
                        ciphertext_digest="",
                    )
                else:
                    relative_path, absolute_path, before = located
                    plaintext_size, plaintext_digest, ciphertext_size, ciphertext_digest = _authenticate_upload(
                        upload,
                        absolute_path,
                    )
                    if plaintext_size != upload.committed_offset:
                        raise RecordingInventoryError("Recording receipt inventory does not match committed bytes")
                    after = os.lstat(absolute_path)
                    if (
                        before.st_dev != after.st_dev
                        or before.st_ino != after.st_ino
                        or before.st_mtime_ns != after.st_mtime_ns
                        or before.st_size != after.st_size
                        or after.st_size != ciphertext_size
                    ):
                        raise RecordingInventoryError("Recording object changed while its backup snapshot was prepared")
                    if upload.state == RecordingUpload.STATE_FINALIZED and (
                        upload.ciphertext_size != ciphertext_size
                        or upload.ciphertext_digest != ciphertext_digest
                        or upload.expected_size != plaintext_size
                        or upload.expected_digest != plaintext_digest
                    ):
                        raise RecordingInventoryError("Finalized recording inventory does not match its ciphertext")
                    metadata = _snapshot_metadata(
                        upload,
                        relative_path,
                        plaintext_size=plaintext_size,
                        plaintext_digest=plaintext_digest,
                        ciphertext_size=ciphertext_size,
                        ciphertext_digest=ciphertext_digest,
                    )
                    object_count += 1
                digest.update(_canonical_json(metadata))
                digest.update(b"\n")
                batch.append(_model_values(epoch, metadata))
                inventory_count += 1
            RecordingBackupObject.objects.bulk_create(batch, batch_size=SNAPSHOT_BATCH_SIZE)
            batch.clear()
            last_upload_id = page[-1].upload_id

        with transaction.atomic():
            control = RecordingBackupControl.objects.select_for_update().get(singleton=1)
            if control.active_epoch_id != epoch.epoch_id:
                raise RecordingInventoryError("Recording backup authority changed during snapshot creation")
            epoch = RecordingBackupEpoch.objects.select_for_update().get(pk=epoch.pk)
            epoch.inventory_count = inventory_count
            epoch.object_count = object_count
            epoch.inventory_digest = digest.hexdigest()
            epoch.prepared_at = timezone.now()
            epoch.state = RecordingBackupEpoch.STATE_READY
            epoch.save(
                update_fields=(
                    "inventory_count",
                    "object_count",
                    "inventory_digest",
                    "prepared_at",
                    "state",
                )
            )
        _validate_bidirectional_inventory(root, epoch)
        return epoch
    except Exception:
        if epoch is not None:
            abort_backup(backup_id, ignore_mismatch=True)
        raise


def _epoch_header(epoch):
    return {
        "backup_id": epoch.backup_id,
        "epoch_id": str(epoch.epoch_id),
        "format": BACKUP_FORMAT,
        "inventory_count": epoch.inventory_count,
        "inventory_digest": epoch.inventory_digest,
        "manifest_version": epoch.manifest_version,
        "object_count": epoch.object_count,
        "requested_at": _timestamp(epoch.requested_at),
    }


def _snapshot_row_metadata(row):
    return {
        "aborted_at": _timestamp(row.aborted_at),
        "ciphertext_digest": row.ciphertext_digest,
        "ciphertext_size": row.ciphertext_size,
        "created_at": _timestamp(row.created_at),
        "data_key_kek_id": row.data_key_kek_id,
        "deployment_generation": row.deployment_generation,
        "device_id_at_create": row.device_id_at_create,
        "device_rid_at_create": row.device_rid_at_create,
        "device_uuid_at_create": row.device_uuid_at_create,
        "encryption_version": row.encryption_version,
        "finalized_at": _timestamp(row.finalized_at),
        "object_present": row.object_present,
        "owner_id_at_create": row.owner_id_at_create,
        "plaintext_digest": row.plaintext_digest,
        "plaintext_size": row.plaintext_size,
        "retention_hold": row.retention_hold,
        "retention_hold_at": _timestamp(row.retention_hold_at),
        "retention_hold_reason": row.retention_hold_reason,
        "state": row.state,
        "storage_object_id": str(row.storage_object_id),
        "storage_relative_path": row.storage_relative_path,
        "storage_version": row.storage_version,
        "upload_id": str(row.upload_id),
    }


def _write_all(stream, value):
    written = stream.write(value)
    if written is not None and written != len(value):
        raise RecordingInventoryError("Recording backup output was truncated")


def export_backup(backup_id, output_stream):
    backup_id = _validate_backup_id(backup_id)
    root = _root()
    control = RecordingBackupControl.objects.select_related("active_epoch").get(singleton=1)
    epoch = control.active_epoch
    if epoch is None or epoch.backup_id != backup_id or epoch.state != RecordingBackupEpoch.STATE_READY:
        raise RecordingInventoryError("Recording backup epoch is not ready for export")
    header = _canonical_json(_epoch_header(epoch))
    if len(header) > MAX_HEADER_BYTES:
        raise RecordingInventoryError("Recording backup header is too large")
    _write_all(output_stream, BACKUP_MAGIC)
    _write_all(output_stream, struct.pack(">I", len(header)))
    _write_all(output_stream, header)

    last_upload_id = None
    exported = 0
    while True:
        rows = epoch.inventory_objects.order_by("upload_id")
        if last_upload_id is not None:
            rows = rows.filter(upload_id__gt=last_upload_id)
        page = list(rows[:SNAPSHOT_BATCH_SIZE])
        if not page:
            break
        for row in page:
            metadata = _canonical_json(_snapshot_row_metadata(row))
            if len(metadata) > MAX_OBJECT_METADATA_BYTES:
                raise RecordingInventoryError("Recording object metadata is too large")
            _write_all(output_stream, BACKUP_OBJECT)
            _write_all(output_stream, struct.pack(">IQ", len(metadata), row.ciphertext_size))
            _write_all(output_stream, metadata)
            if row.object_present:
                absolute_path = os.path.join(root, row.storage_relative_path)
                before = _regular_file(absolute_path)
                if before is None or before.st_size != row.ciphertext_size:
                    raise RecordingInventoryError("Recording object changed before backup export")
                hasher = hashlib.sha256()
                remaining = row.ciphertext_size
                with open(absolute_path, "rb", buffering=0) as source:
                    while remaining:
                        chunk = source.read(min(COPY_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise RecordingInventoryError("Recording object was truncated during export")
                        _write_all(output_stream, chunk)
                        hasher.update(chunk)
                        remaining -= len(chunk)
                    if source.read(1):
                        raise RecordingInventoryError("Recording object grew during export")
                after = os.lstat(absolute_path)
                if (
                    before.st_dev != after.st_dev
                    or before.st_ino != after.st_ino
                    or before.st_mtime_ns != after.st_mtime_ns
                    or not stat.S_ISREG(after.st_mode)
                    or hasher.hexdigest() != row.ciphertext_digest
                ):
                    raise RecordingInventoryError("Recording object changed during backup export")
            elif row.ciphertext_size != 0 or row.ciphertext_digest:
                raise RecordingInventoryError("Absent recording object has invalid snapshot metadata")
            exported += 1
        last_upload_id = page[-1].upload_id
    if exported != epoch.inventory_count:
        raise RecordingInventoryError("Recording backup inventory count changed during export")
    _write_all(output_stream, BACKUP_END)


def finish_backup(backup_id):
    backup_id = _validate_backup_id(backup_id)
    with transaction.atomic():
        control = RecordingBackupControl.objects.select_for_update().get(singleton=1)
        epoch = (
            RecordingBackupEpoch.objects.select_for_update().filter(pk=control.active_epoch_id).first()
            if control.active_epoch_id is not None
            else None
        )
        if epoch is None or epoch.backup_id != backup_id or epoch.state != RecordingBackupEpoch.STATE_READY:
            raise RecordingInventoryError("Recording backup epoch cannot be completed")
        epoch.state = RecordingBackupEpoch.STATE_COMPLETE
        epoch.completed_at = timezone.now()
        epoch.save(update_fields=("state", "completed_at"))
        control.active_epoch = None
        control.save(update_fields=("active_epoch", "updated_at"))
    return epoch


def abort_backup(backup_id, *, ignore_mismatch=False):
    backup_id = _validate_backup_id(backup_id)
    with transaction.atomic():
        control = RecordingBackupControl.objects.select_for_update().get(singleton=1)
        epoch = (
            RecordingBackupEpoch.objects.select_for_update().filter(pk=control.active_epoch_id).first()
            if control.active_epoch_id is not None
            else None
        )
        if epoch is None or epoch.backup_id != backup_id:
            if ignore_mismatch:
                return False
            raise RecordingInventoryError("Recording backup epoch cannot be aborted")
        control.active_epoch = None
        control.save(update_fields=("active_epoch", "updated_at"))
        epoch.delete()
    return True


def backup_summary(epoch):
    return {
        "backup_id": epoch.backup_id,
        "epoch_id": str(epoch.epoch_id),
        "inventory_count": epoch.inventory_count,
        "inventory_digest": epoch.inventory_digest,
        "manifest_version": epoch.manifest_version,
        "object_count": epoch.object_count,
        "requested_at": _timestamp(epoch.requested_at),
        "state": epoch.state,
    }


def _read_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise RecordingInventoryError("Recording backup bundle is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_canonical_json(stream, size, maximum, name):
    if not 1 <= size <= maximum:
        raise RecordingInventoryError(f"{name} length is invalid")
    encoded = _read_exact(stream, size)
    try:
        value = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecordingInventoryError(f"{name} JSON is invalid") from error
    if _canonical_json(value) != encoded:
        raise RecordingInventoryError(f"{name} JSON is not canonical")
    return value


def _empty_restore_root(root):
    if any(True for _path in _observed_relative_paths(root)):
        raise RecordingInventoryError("Recording restore requires an empty authoritative object volume")


def restore_preflight():
    root = _root()
    _empty_restore_root(root)
    return root


def _secure_parent_for_restore(root, relative_path):
    components = relative_path.split("/")
    if len(components) not in (2, 3) or not NAMESPACE_RE.fullmatch(components[0]):
        raise RecordingInventoryError("Recording restore path is invalid")
    namespace = os.path.join(root, components[0])
    recording_uploads._secure_directory(namespace)
    if len(components) == 3:
        if components[1] != ".uploads":
            raise RecordingInventoryError("Recording restore staging path is invalid")
        recording_uploads._secure_directory(os.path.join(namespace, ".uploads"))
    return os.path.join(root, *components)


def restore_backup(backup_id, epoch_id, inventory_digest, input_stream):
    backup_id = _validate_backup_id(backup_id)
    raw_epoch_id = epoch_id
    try:
        epoch_id = uuid.UUID(raw_epoch_id)
    except (TypeError, ValueError) as error:
        raise RecordingInventoryError("Recording backup epoch ID is invalid") from error
    if str(epoch_id) != raw_epoch_id:
        raise RecordingInventoryError("Recording backup epoch ID is invalid")
    if not isinstance(inventory_digest, str) or not INVENTORY_DIGEST_RE.fullmatch(inventory_digest):
        raise RecordingInventoryError("Recording inventory digest is invalid")
    root = _root()
    _empty_restore_root(root)
    control = RecordingBackupControl.objects.select_related("active_epoch").get(singleton=1)
    epoch = control.active_epoch
    if (
        epoch is None
        or epoch.epoch_id != epoch_id
        or epoch.backup_id != backup_id
        or epoch.state != RecordingBackupEpoch.STATE_READY
        or epoch.inventory_digest != inventory_digest
    ):
        raise RecordingInventoryError("Restored database does not match the recording backup epoch")

    if _read_exact(input_stream, len(BACKUP_MAGIC)) != BACKUP_MAGIC:
        raise RecordingInventoryError("Recording backup magic is invalid")
    header_size = struct.unpack(">I", _read_exact(input_stream, 4))[0]
    header = _read_canonical_json(input_stream, header_size, MAX_HEADER_BYTES, "Recording backup header")
    if header != _epoch_header(epoch):
        raise RecordingInventoryError("Recording backup header does not match the restored database")

    last_upload_id = None
    restored = 0
    while restored < epoch.inventory_count:
        marker = _read_exact(input_stream, 1)
        if marker != BACKUP_OBJECT:
            raise RecordingInventoryError("Recording backup object marker is invalid")
        metadata_size, payload_size = struct.unpack(">IQ", _read_exact(input_stream, 12))
        metadata = _read_canonical_json(
            input_stream,
            metadata_size,
            MAX_OBJECT_METADATA_BYTES,
            "Recording object metadata",
        )
        try:
            upload_id = uuid.UUID(metadata.get("upload_id", ""))
        except (AttributeError, ValueError) as error:
            raise RecordingInventoryError("Recording backup upload ID is invalid") from error
        if str(upload_id) != metadata.get("upload_id") or (last_upload_id is not None and upload_id <= last_upload_id):
            raise RecordingInventoryError("Recording backup upload order is invalid")
        row = epoch.inventory_objects.filter(upload_id=upload_id).first()
        if row is None or metadata != _snapshot_row_metadata(row) or payload_size != row.ciphertext_size:
            raise RecordingInventoryError("Recording object metadata does not match the restored database")
        if row.object_present:
            destination = _secure_parent_for_restore(root, row.storage_relative_path)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(destination, flags, 0o600)
            hasher = hashlib.sha256()
            try:
                remaining = payload_size
                while remaining:
                    chunk = _read_exact(input_stream, min(COPY_CHUNK_BYTES, remaining))
                    recording_uploads._write_all(fd, chunk)
                    hasher.update(chunk)
                    remaining -= len(chunk)
                os.fsync(fd)
            finally:
                os.close(fd)
            if hasher.hexdigest() != row.ciphertext_digest:
                raise RecordingInventoryError("Restored recording ciphertext digest does not match inventory")
            recording_uploads._fsync_directory(os.path.dirname(destination))
        elif payload_size != 0 or row.ciphertext_digest:
            raise RecordingInventoryError("Absent recording object has an unexpected backup payload")
        restored += 1
        last_upload_id = upload_id
    if _read_exact(input_stream, 1) != BACKUP_END or input_stream.read(1):
        raise RecordingInventoryError("Recording backup bundle has trailing or missing data")
    _validate_bidirectional_inventory(root, epoch)

    with transaction.atomic():
        control = RecordingBackupControl.objects.select_for_update().get(singleton=1)
        locked_epoch = RecordingBackupEpoch.objects.select_for_update().get(pk=epoch.pk)
        if control.active_epoch_id != locked_epoch.epoch_id or locked_epoch.state != RecordingBackupEpoch.STATE_READY:
            raise RecordingInventoryError("Recording restore authority changed during object installation")
        locked_epoch.state = RecordingBackupEpoch.STATE_RESTORED
        locked_epoch.completed_at = timezone.now()
        locked_epoch.save(update_fields=("state", "completed_at"))
        control.active_epoch = None
        control.save(update_fields=("active_epoch", "updated_at"))
    return locked_epoch
