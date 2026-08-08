import contextlib
import fcntl
import hashlib
import logging
import os
import re
import stat
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, IntegrityError, transaction
from django.http import JsonResponse
from django.utils import timezone

from api import ingestion_governance, recording_crypto, recording_inventory
from api.models import RecordingUpload, RecordingUploadChunk

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = 2
DIGEST_LENGTH = 64
RECORD_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,255}$")


class UploadRequestError(Exception):
    def __init__(self, message, *, status=400, code="invalid_request", state=None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.state = state


def _error_response(error):
    payload = {"error": error.message, "code": error.code}
    if error.state is not None:
        payload["upload"] = error.state
    return JsonResponse(payload, status=error.status)


def _request_content_length(request):
    if "HTTP_TRANSFER_ENCODING" in request.META:
        raise UploadRequestError(
            "Transfer-Encoding is not supported",
            status=400,
            code="unsupported_transfer_encoding",
        )
    if "HTTP_CONTENT_LENGTH" in request.META:
        raise UploadRequestError(
            "Ambiguous Content-Length",
            status=400,
            code="invalid_content_length",
        )
    raw_length = request.META.get("CONTENT_LENGTH")
    if raw_length is None or raw_length == "":
        raise UploadRequestError(
            "Content-Length is required",
            status=411,
            code="content_length_required",
        )
    if not isinstance(raw_length, str) or not raw_length.isascii() or not raw_length.isdecimal():
        raise UploadRequestError(
            "Invalid Content-Length",
            status=400,
            code="invalid_content_length",
        )
    normalized_length = raw_length.lstrip("0") or "0"
    maximum_length = str(settings.RECORD_UPLOAD_MAX_CHUNK_BYTES)
    if len(normalized_length) > len(maximum_length) or (
        len(normalized_length) == len(maximum_length) and normalized_length > maximum_length
    ):
        raise UploadRequestError(
            "Upload chunk is too large",
            status=413,
            code="chunk_too_large",
        )
    return int(normalized_length)


def _parse_uuid(value, name):
    if not isinstance(value, str) or len(value) != 36:
        raise UploadRequestError(f"Invalid {name}")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise UploadRequestError(f"Invalid {name}") from None
    if parsed.version != 4 or str(parsed) != value:
        raise UploadRequestError(f"Invalid {name}")
    return parsed


def _parse_nonnegative_int(value, name):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise UploadRequestError(f"Invalid {name}") from None
    if parsed < 0 or str(parsed) != str(value):
        raise UploadRequestError(f"Invalid {name}")
    return parsed


def _parse_digest(value, name="digest"):
    if not isinstance(value, str) or len(value) != DIGEST_LENGTH:
        raise UploadRequestError(f"Invalid {name}")
    if any(character not in "0123456789abcdef" for character in value):
        raise UploadRequestError(f"Invalid {name}")
    return value


def _safe_record_name(name):
    if not isinstance(name, str) or name != os.path.basename(name):
        return ""
    return name if RECORD_NAME_RE.fullmatch(name) else ""


def _record_dir():
    return os.fspath(settings.RECORD_UPLOAD_ROOT)


def _record_upload_dir(upload):
    return os.path.join(_record_dir(), upload.storage_namespace)


def _secure_directory(path):
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    directory_stat = os.lstat(path)
    if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
        raise OSError("Recording directory is not a real directory")
    if directory_stat.st_mode & 0o077:
        os.chmod(path, 0o700)


def _ensure_record_upload_dir(upload):
    root = _record_dir()
    _secure_directory(root)
    upload_dir = _record_upload_dir(upload)
    _secure_directory(upload_dir)
    return upload_dir


def _stage_dir(base_dir):
    path = os.path.join(base_dir, ".uploads")
    _secure_directory(path)
    return path


def _stage_path(base_dir, upload_id):
    return os.path.join(_stage_dir(base_dir), f"{upload_id}.part")


def _aborted_path(base_dir, upload_id):
    return os.path.join(_stage_dir(base_dir), f"{upload_id}.aborted")


def _deleting_path(base_dir, upload_id):
    return os.path.join(_stage_dir(base_dir), f"{upload_id}.deleting")


def _final_path(base_dir, upload):
    return os.path.join(base_dir, f"{upload.storage_object_id}.recording")


def _fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path, flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextlib.contextmanager
def _record_file_lock(base_dir):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    lock_fd = os.open(base_dir, flags)
    try:
        descriptor_stat = os.fstat(lock_fd)
        path_stat = os.lstat(base_dir)
        if (
            not stat.S_ISDIR(descriptor_stat.st_mode)
            or stat.S_ISLNK(path_stat.st_mode)
            or descriptor_stat.st_dev != path_stat.st_dev
            or descriptor_stat.st_ino != path_stat.st_ino
            or descriptor_stat.st_uid != os.geteuid()
        ):
            raise OSError("Recording namespace is not an owned real directory")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BlockingIOError("Recording is busy") from None
        current_stat = os.lstat(base_dir)
        if (
            stat.S_ISLNK(current_stat.st_mode)
            or current_stat.st_dev != descriptor_stat.st_dev
            or current_stat.st_ino != descriptor_stat.st_ino
        ):
            raise OSError("Recording namespace changed during lock acquisition")
        yield
    finally:
        os.close(lock_fd)


def _open_record_file(filepath, flags):
    fd = os.open(
        filepath,
        flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    file_stat = os.fstat(fd)
    if not stat.S_ISREG(file_stat.st_mode):
        os.close(fd)
        raise OSError("Recording path is not a regular file")
    return fd


def _write_all(fd, data):
    written = 0
    while written < len(data):
        count = os.write(fd, data[written:])
        if count <= 0:
            raise OSError("Recording write did not make progress")
        written += count


def _state_payload(upload, *, queried_chunk_committed=None):
    return {
        "protocol": PROTOCOL_VERSION,
        "upload_id": str(upload.upload_id),
        "state": upload.state,
        "offset": upload.committed_offset,
        "revision": upload.revision,
        "finalized": upload.state == RecordingUpload.STATE_FINALIZED,
        "final_size": upload.expected_size,
        "final_digest": upload.expected_digest or None,
        "queried_chunk_committed": queried_chunk_committed,
    }


def _receipt_matches(receipt, *, chunk_id, offset, revision, length, digest):
    return (
        receipt.chunk_id == chunk_id
        and receipt.offset == offset
        and receipt.revision == revision + 1
        and receipt.length == length
        and receipt.digest == digest
    )


def _load_bound_upload(token, upload_id, *, for_update=False, include_data_key=True):
    query = RecordingUpload.objects.select_related("device")
    if not include_data_key:
        query = query.defer("encrypted_data_key")
    if for_update:
        query = query.select_for_update()
    try:
        upload = query.get(upload_id=upload_id, device_id=token.device_id)
    except RecordingUpload.DoesNotExist:
        raise UploadRequestError("Recording upload does not exist", status=404, code="upload_not_found") from None
    # select_for_update() also locks the joined device row on PostgreSQL. Use
    # that current authority snapshot rather than the token object's earlier
    # relation cache so owner/generation/disable races cannot pass on stale
    # in-request state.
    current_device = upload.device
    if (
        current_device is None
        or not current_device.is_active
        or not current_device.public_key_hash
        or upload.device_id_at_create != current_device.id
        or upload.owner_id_at_create != current_device.owner_id
        or upload.deployment_generation != current_device.deployment_generation
    ):
        raise UploadRequestError(
            "Recording upload authority changed",
            status=409,
            code="upload_authority_changed",
        )
    return upload


def _ensure_empty_body(content_length):
    if content_length != 0:
        raise UploadRequestError("Request body must be empty")


def _recording_data_key(upload):
    if upload.encryption_version != recording_crypto.FORMAT_VERSION:
        raise recording_crypto.RecordingFormatError("Recording ciphertext format is invalid")
    return recording_crypto.decode_data_key(upload.encrypted_data_key)


def _reconcile_staging_file(upload, stage_path, final_path, data_key):
    if os.path.lexists(final_path):
        raise UploadRequestError(
            "Recording publication is awaiting finalize recovery",
            status=409,
            code="finalize_recovery_required",
            state=_state_payload(upload),
        )
    if not os.path.lexists(stage_path):
        # A process can die after the upload row commits but before the
        # initial empty staging file is created. Re-create that file only for
        # the still-empty revision; a missing file after any committed bytes
        # is ambiguous and must fail closed.
        if (
            upload.committed_offset != 0
            or upload.revision != 0
            or upload.storage_offset != recording_crypto.HEADER_SIZE
        ):
            raise OSError("Recording staging file is missing")
        fd = _open_record_file(stage_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            _write_all(fd, recording_crypto.build_header(upload.upload_id, data_key))
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(os.path.dirname(stage_path))
    fd = _open_record_file(stage_path, os.O_RDWR)
    try:
        current_size = os.fstat(fd).st_size
        if current_size < upload.storage_offset:
            raise OSError("Recording staging file is shorter than the committed ciphertext")
        if current_size > upload.storage_offset:
            os.ftruncate(fd, upload.storage_offset)
            os.fsync(fd)
        recording_crypto.validate_header_fd(
            fd,
            upload_id=upload.upload_id,
            data_key=data_key,
        )
    finally:
        os.close(fd)


def _rollback_staging_file(stage_path, offset):
    try:
        fd = _open_record_file(stage_path, os.O_RDWR)
        try:
            os.ftruncate(fd, offset)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        logger.exception("event=recording_upload_rollback_failed")


def _verify_recording_file(upload, path, data_key, *, include_ciphertext_digest=False):
    fd = _open_record_file(path, os.O_RDONLY)
    try:
        return recording_crypto.verify_recording_fd(
            fd,
            upload_id=upload.upload_id,
            data_key=data_key,
            receipts=_recording_receipts(upload),
            expected_revision=upload.revision,
            expected_storage_offset=upload.storage_offset,
            max_chunk_bytes=settings.RECORD_UPLOAD_MAX_CHUNK_BYTES,
            include_ciphertext_digest=include_ciphertext_digest,
        )
    finally:
        os.close(fd)


def _recording_receipts(upload):
    """Yield bounded receipt pages without a transaction-spanning server cursor."""

    last_revision = 0
    while True:
        batch = list(
            upload.chunks.filter(revision__gt=last_revision)
            .only("revision", "offset", "length", "digest")
            .order_by("revision")[:1000]
        )
        if not batch:
            return
        yield from batch
        last_revision = batch[-1].revision


def _create_upload(request, token, content_length):
    _ensure_empty_body(content_length)
    filename = _safe_record_name(request.GET.get("file", ""))
    if not filename:
        raise UploadRequestError("Invalid file")
    create_id = _parse_uuid(request.GET.get("create_id", ""), "create_id")
    stage_created = None
    try:
        with transaction.atomic():
            recording_inventory.lock_recording_mutation()
            existing = (
                RecordingUpload.objects.select_for_update()
                .filter(device_id=token.device_id, create_id=create_id)
                .first()
            )
            if existing is not None:
                if existing.filename != filename:
                    raise UploadRequestError(
                        "Create identity conflicts with another recording",
                        status=409,
                        code="create_conflict",
                    )
                return JsonResponse(_state_payload(existing), status=200)
            if RecordingUpload.objects.filter(device_id=token.device_id, filename=filename).exists():
                raise UploadRequestError(
                    "Recording filename already exists",
                    status=409,
                    code="filename_conflict",
                )
            usage = ingestion_governance.lock_recording_create_usage(
                token.device.owner_id,
                token.device_id,
            )
            existing = RecordingUpload.objects.filter(device_id=token.device_id, create_id=create_id).first()
            if existing is not None:
                if existing.filename != filename:
                    raise UploadRequestError(
                        "Create identity conflicts with another recording",
                        status=409,
                        code="create_conflict",
                    )
                return JsonResponse(_state_payload(existing), status=200)
            ingestion_governance.reserve_locked_recording_create(usage)
            ingestion_governance.check_recording_storage_capability(
                recording_crypto.HEADER_SIZE,
                force=True,
            )
            data_key = recording_crypto.generate_data_key()
            storage_object_id = uuid.uuid4()
            upload = RecordingUpload.objects.create(
                create_id=create_id,
                device_id=token.device_id,
                device_id_at_create=token.device_id,
                owner_id_at_create=token.device.owner_id,
                deployment_generation=token.device.deployment_generation,
                device_rid_at_create=token.device.rid,
                device_uuid_at_create=token.device.uuid,
                storage_object_id=storage_object_id,
                storage_namespace=ingestion_governance.recording_namespace(storage_object_id),
                filename=filename,
                encryption_version=recording_crypto.FORMAT_VERSION,
                data_key_kek_id=settings.DATA_ENCRYPTION_PRIMARY_KEY_ID,
                encrypted_data_key=recording_crypto.encode_data_key(data_key),
                storage_offset=recording_crypto.HEADER_SIZE,
            )
            base_dir = _ensure_record_upload_dir(upload)
            stage_path = _stage_path(base_dir, upload.storage_object_id)
            fd = _open_record_file(stage_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            stage_created = stage_path
            try:
                _write_all(fd, recording_crypto.build_header(upload.upload_id, data_key))
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_directory(os.path.dirname(stage_created))
            payload = _state_payload(upload)
    except IntegrityError:
        if stage_created is not None:
            try:
                os.unlink(stage_created)
            except FileNotFoundError:
                pass
        existing = RecordingUpload.objects.filter(device_id=token.device_id, create_id=create_id).first()
        if existing is not None and existing.filename == filename:
            return JsonResponse(_state_payload(existing), status=200)
        raise UploadRequestError(
            "Recording create conflict",
            status=409,
            code="create_conflict",
        ) from None
    except Exception as error:
        # If PostgreSQL accepted COMMIT but the connection lost its response,
        # deleting the durable staging file would split an existing upload row
        # from its bytes. Leave the opaque staging orphan/row pair intact on a
        # database error so a retry can resolve the authoritative outcome.
        if stage_created is not None and not isinstance(error, DatabaseError):
            try:
                os.unlink(stage_created)
            except FileNotFoundError:
                pass
        raise
    return JsonResponse(payload, status=201)


def _status_upload(request, token, content_length):
    _ensure_empty_body(content_length)
    upload_id = _parse_uuid(request.GET.get("upload_id", ""), "upload_id")
    chunk_fields = ("chunk_id", "offset", "revision", "length", "digest")
    supplied_chunk_fields = [field for field in chunk_fields if request.GET.get(field) is not None]
    chunk_query = None
    if supplied_chunk_fields:
        if len(supplied_chunk_fields) != len(chunk_fields):
            raise UploadRequestError("Incomplete chunk status identity")
        chunk_query = {
            "chunk_id": _parse_uuid(request.GET.get("chunk_id", ""), "chunk_id"),
            "offset": _parse_nonnegative_int(request.GET.get("offset", ""), "offset"),
            "revision": _parse_nonnegative_int(request.GET.get("revision", ""), "revision"),
            "length": _parse_nonnegative_int(request.GET.get("length", ""), "length"),
            "digest": _parse_digest(request.GET.get("digest", "")),
        }
        if chunk_query["length"] <= 0 or chunk_query["length"] > settings.RECORD_UPLOAD_MAX_CHUNK_BYTES:
            raise UploadRequestError("Invalid chunk status length")
    with transaction.atomic():
        recording_inventory.lock_recording_mutation()
        upload = _load_bound_upload(token, upload_id, for_update=True)
        if upload.state == RecordingUpload.STATE_ACTIVE:
            data_key = _recording_data_key(upload)
            base_dir = _ensure_record_upload_dir(upload)
            with _record_file_lock(base_dir):
                stage_path = _stage_path(base_dir, upload.storage_object_id)
                final_path = _final_path(base_dir, upload)
                _reconcile_staging_file(upload, stage_path, final_path, data_key)
        queried_chunk_committed = None
        if chunk_query is not None:
            receipt = upload.chunks.filter(chunk_id=chunk_query["chunk_id"]).first()
            if receipt is not None and not _receipt_matches(receipt, **chunk_query):
                raise UploadRequestError(
                    "Chunk identity conflicts with committed content",
                    status=409,
                    code="chunk_identity_conflict",
                    state=_state_payload(upload),
                )
            queried_chunk_committed = receipt is not None
        return JsonResponse(_state_payload(upload, queried_chunk_committed=queried_chunk_committed))


def _commit_part(request, token, content_length):
    if content_length <= 0 or content_length > settings.RECORD_UPLOAD_MAX_CHUNK_BYTES:
        raise UploadRequestError("Upload chunk is too large", status=413, code="chunk_too_large")
    declared_length = _parse_nonnegative_int(request.GET.get("length", ""), "length")
    if declared_length != content_length:
        raise UploadRequestError("Invalid upload length")
    data = request.body or b""
    if len(data) != content_length:
        raise UploadRequestError("Incomplete upload body")
    digest = _parse_digest(request.GET.get("digest", ""))
    if hashlib.sha256(data).hexdigest() != digest:
        raise UploadRequestError("Upload digest mismatch", status=409, code="digest_mismatch")
    upload_id = _parse_uuid(request.GET.get("upload_id", ""), "upload_id")
    chunk_id = _parse_uuid(request.GET.get("chunk_id", ""), "chunk_id")
    offset = _parse_nonnegative_int(request.GET.get("offset", ""), "offset")
    revision = _parse_nonnegative_int(request.GET.get("revision", ""), "revision")
    rollback = None
    try:
        with transaction.atomic():
            recording_inventory.lock_recording_mutation()
            upload = _load_bound_upload(token, upload_id, for_update=True)
            receipt = upload.chunks.filter(chunk_id=chunk_id).first()
            if receipt is not None:
                if not _receipt_matches(
                    receipt,
                    chunk_id=chunk_id,
                    offset=offset,
                    revision=revision,
                    length=declared_length,
                    digest=digest,
                ):
                    raise UploadRequestError(
                        "Chunk identity conflicts with committed content",
                        status=409,
                        code="chunk_identity_conflict",
                        state=_state_payload(upload),
                    )
                return JsonResponse(_state_payload(upload))
            if upload.state != RecordingUpload.STATE_ACTIVE:
                raise UploadRequestError(
                    "Recording upload is immutable",
                    status=409,
                    code="upload_immutable",
                    state=_state_payload(upload),
                )
            if offset != upload.committed_offset or revision != upload.revision:
                raise UploadRequestError(
                    "Upload position conflict",
                    status=409,
                    code="position_conflict",
                    state=_state_payload(upload),
                )
            if offset + declared_length > settings.RECORD_UPLOAD_MAX_FILE_BYTES:
                raise UploadRequestError("Recording is too large", status=413, code="recording_too_large")
            ingestion_governance.reserve_recording_bytes(
                upload.owner_id_at_create,
                upload.device_id_at_create,
                declared_length,
            )
            # The authenticated view rejects an unavailable volume before body
            # materialization. Recheck while the global usage row is locked so
            # concurrent writers cannot all consume the same final reserve.
            physical_length = recording_crypto.chunk_record_size(declared_length)
            ingestion_governance.check_recording_storage_capability(
                physical_length,
                force=True,
            )
            data_key = _recording_data_key(upload)
            base_dir = _ensure_record_upload_dir(upload)
            with _record_file_lock(base_dir):
                stage_path = _stage_path(base_dir, upload.storage_object_id)
                final_path = _final_path(base_dir, upload)
                _reconcile_staging_file(upload, stage_path, final_path, data_key)
                rollback = (stage_path, upload.storage_offset)
                next_revision = upload.revision + 1
                record_frame, record_ciphertext = recording_crypto.encrypt_chunk_record(
                    upload_id=upload.upload_id,
                    data_key=data_key,
                    revision=next_revision,
                    offset=offset,
                    digest=digest,
                    data=data,
                )
                fd = _open_record_file(stage_path, os.O_RDWR)
                try:
                    os.lseek(fd, upload.storage_offset, os.SEEK_SET)
                    _write_all(fd, record_frame)
                    _write_all(fd, record_ciphertext)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                RecordingUploadChunk.objects.create(
                    upload=upload,
                    chunk_id=chunk_id,
                    offset=offset,
                    length=declared_length,
                    digest=digest,
                    revision=next_revision,
                )
                upload.committed_offset += declared_length
                upload.storage_offset += len(record_frame) + len(record_ciphertext)
                upload.revision = next_revision
                upload.heartbeat_at = timezone.now()
                upload.save(
                    update_fields=(
                        "committed_offset",
                        "storage_offset",
                        "revision",
                        "heartbeat_at",
                        "updated_at",
                    )
                )
                payload = _state_payload(upload)
        rollback = None
        return JsonResponse(payload)
    except Exception as error:
        # A DatabaseError at transaction exit can mean COMMIT succeeded but its
        # acknowledgement was lost. Keep the fsynced bytes in that case: if the
        # database stayed at the old revision, status/the next part truncates
        # them; if it advanced, truncating here would corrupt committed state.
        if rollback is not None and not isinstance(error, DatabaseError):
            _rollback_staging_file(*rollback)
        raise


def _finalize_upload(request, token, content_length):
    _ensure_empty_body(content_length)
    upload_id = _parse_uuid(request.GET.get("upload_id", ""), "upload_id")
    revision = _parse_nonnegative_int(request.GET.get("revision", ""), "revision")
    final_size = _parse_nonnegative_int(request.GET.get("final_size", ""), "final_size")
    final_digest = _parse_digest(request.GET.get("final_digest", ""), "final_digest")
    moved = None
    try:
        with transaction.atomic():
            recording_inventory.lock_recording_mutation()
            upload = _load_bound_upload(token, upload_id, for_update=True)
            if upload.state == RecordingUpload.STATE_FINALIZED:
                if (
                    upload.revision != revision
                    or upload.expected_size != final_size
                    or upload.expected_digest != final_digest
                ):
                    raise UploadRequestError(
                        "Finalize identity conflicts with committed recording",
                        status=409,
                        code="finalize_conflict",
                        state=_state_payload(upload),
                    )
            elif upload.state != RecordingUpload.STATE_ACTIVE:
                raise UploadRequestError(
                    "Recording upload is immutable",
                    status=409,
                    code="upload_immutable",
                    state=_state_payload(upload),
                )
            elif revision != upload.revision or final_size != upload.committed_offset:
                raise UploadRequestError(
                    "Finalize position conflict",
                    status=409,
                    code="position_conflict",
                    state=_state_payload(upload),
                )
            data_key = _recording_data_key(upload)
            base_dir = _ensure_record_upload_dir(upload)
            with _record_file_lock(base_dir):
                stage_path = _stage_path(base_dir, upload.storage_object_id)
                final_path = _final_path(base_dir, upload)
                stage_exists = os.path.lexists(stage_path)
                final_exists = os.path.lexists(final_path)
                if stage_exists and final_exists:
                    raise OSError("Recording has both staging and published files")
                if not stage_exists and not final_exists:
                    if upload.state == RecordingUpload.STATE_FINALIZED:
                        raise OSError("Published recording is missing")
                    if (
                        upload.committed_offset != 0
                        or upload.revision != 0
                        or upload.storage_offset != recording_crypto.HEADER_SIZE
                    ):
                        raise OSError("Recording staging file is missing")
                    _reconcile_staging_file(upload, stage_path, final_path, data_key)
                    stage_exists = True
                if upload.state == RecordingUpload.STATE_FINALIZED and stage_exists:
                    raise OSError("Finalized recording is not published")
                if stage_exists:
                    _reconcile_staging_file(upload, stage_path, final_path, data_key)
                source_path = stage_path if stage_exists else final_path
                actual_size, actual_digest, ciphertext_digest = _verify_recording_file(
                    upload,
                    source_path,
                    data_key,
                    include_ciphertext_digest=True,
                )
                if actual_size != final_size or actual_digest != final_digest:
                    raise UploadRequestError(
                        "Final recording digest mismatch",
                        status=409,
                        code="final_digest_mismatch",
                        state=_state_payload(upload),
                    )
                if upload.state == RecordingUpload.STATE_FINALIZED:
                    if upload.ciphertext_size != upload.storage_offset or upload.ciphertext_digest != ciphertext_digest:
                        raise OSError("Published recording inventory is inconsistent")
                    return JsonResponse(_state_payload(upload))
                if stage_exists:
                    os.rename(stage_path, final_path)
                    _fsync_directory(os.path.dirname(stage_path))
                    _fsync_directory(base_dir)
                    moved = (final_path, stage_path)
                upload.state = RecordingUpload.STATE_FINALIZED
                upload.expected_size = final_size
                upload.expected_digest = final_digest
                upload.ciphertext_size = upload.storage_offset
                upload.ciphertext_digest = ciphertext_digest
                upload.finalized_at = timezone.now()
                upload.heartbeat_at = upload.finalized_at
                ingestion_governance.finalize_recording_usage(
                    upload.owner_id_at_create,
                    upload.device_id_at_create,
                )
                upload.save(
                    update_fields=(
                        "state",
                        "expected_size",
                        "expected_digest",
                        "ciphertext_size",
                        "ciphertext_digest",
                        "finalized_at",
                        "heartbeat_at",
                        "updated_at",
                    )
                )
                payload = _state_payload(upload)
        moved = None
        return JsonResponse(payload)
    except Exception as error:
        # Preserve the forward rename when the database commit result is
        # uncertain. Both an active row and a finalized row can safely recover
        # from final_path; moving it back would break the latter outcome.
        if moved is not None and not isinstance(error, DatabaseError):
            final_path, stage_path = moved
            try:
                os.rename(final_path, stage_path)
                _fsync_directory(os.path.dirname(stage_path))
                _fsync_directory(os.path.dirname(final_path))
            except OSError:
                logger.exception("event=recording_finalize_rollback_failed")
        raise


def _abort_upload(request, token, content_length):
    _ensure_empty_body(content_length)
    upload_id = _parse_uuid(request.GET.get("upload_id", ""), "upload_id")
    moved = None
    tomb_path = None
    try:
        with transaction.atomic():
            recording_inventory.lock_recording_mutation()
            upload = _load_bound_upload(
                token,
                upload_id,
                for_update=True,
                include_data_key=False,
            )
            base_dir = _ensure_record_upload_dir(upload)
            tomb_path = _aborted_path(base_dir, upload.storage_object_id)
            if upload.state == RecordingUpload.STATE_ABORTED:
                payload = _state_payload(upload)
            elif upload.state == RecordingUpload.STATE_FINALIZED:
                raise UploadRequestError(
                    "Finalized recording cannot be aborted",
                    status=409,
                    code="upload_immutable",
                    state=_state_payload(upload),
                )
            else:
                with _record_file_lock(base_dir):
                    stage_path = _stage_path(base_dir, upload.storage_object_id)
                    final_path = _final_path(base_dir, upload)
                    if os.path.lexists(final_path):
                        raise UploadRequestError(
                            "Recording publication is awaiting finalize recovery",
                            status=409,
                            code="finalize_recovery_required",
                            state=_state_payload(upload),
                        )
                    if os.path.lexists(stage_path):
                        if os.path.lexists(tomb_path):
                            raise OSError("Recording abort tomb already exists")
                        os.rename(stage_path, tomb_path)
                        _fsync_directory(os.path.dirname(stage_path))
                        moved = (tomb_path, stage_path)
                    elif not os.path.lexists(tomb_path):
                        if upload.committed_offset != 0 or upload.revision != 0:
                            raise OSError("Recording staging file is missing")
                    upload.state = RecordingUpload.STATE_ABORTED
                    upload.aborted_at = timezone.now()
                    upload.heartbeat_at = upload.aborted_at
                    ingestion_governance.release_active_recording_usage(
                        upload.owner_id_at_create,
                        upload.device_id_at_create,
                        upload.committed_offset,
                    )
                    upload.save(update_fields=("state", "aborted_at", "heartbeat_at", "updated_at"))
                    payload = _state_payload(upload)
        moved = None
    except Exception as error:
        # Preserve the tomb on an uncertain database commit. A retry can either
        # finish the active abort or clean the tomb for an already-aborted row.
        if moved is not None and not isinstance(error, DatabaseError):
            tomb_path, stage_path = moved
            try:
                os.rename(tomb_path, stage_path)
                _fsync_directory(os.path.dirname(stage_path))
            except OSError:
                logger.exception("event=recording_abort_rollback_failed")
        raise
    if tomb_path is not None:
        try:
            os.unlink(tomb_path)
            _fsync_directory(os.path.dirname(tomb_path))
        except FileNotFoundError:
            pass
        except OSError:
            logger.exception("event=recording_abort_cleanup_failed")
    return JsonResponse(payload)


def handle_record_upload(request, token):
    try:
        content_length = _request_content_length(request)
        ingestion_governance.check_recording_storage_capability(content_length)
        if request.GET.get("version", "") != str(PROTOCOL_VERSION):
            return JsonResponse(
                {
                    "error": "Unsupported recording upload protocol",
                    "code": "unsupported_protocol",
                    "required_protocol": PROTOCOL_VERSION,
                },
                status=426,
            )
        operation = request.GET.get("type", "")
        handlers = {
            "new": _create_upload,
            "status": _status_upload,
            "part": _commit_part,
            "finalize": _finalize_upload,
            "abort": _abort_upload,
        }
        handler = handlers.get(operation)
        if handler is None:
            return JsonResponse({"error": "Invalid type", "code": "invalid_operation"}, status=400)
        return handler(request, token, content_length)
    except UploadRequestError as error:
        return _error_response(error)
    except ingestion_governance.IngestionQuotaExceeded as error:
        return ingestion_governance.quota_response(error)
    except ingestion_governance.RecordingStorageUnavailable as error:
        return ingestion_governance.storage_error_response(error)
    except recording_inventory.RecordingBackupInProgress:
        response = JsonResponse(
            {
                "error": "Recording backup checkpoint is in progress",
                "code": "recording_backup_in_progress",
                "retryable": True,
            },
            status=503,
        )
        response["Retry-After"] = "30"
        response["Cache-Control"] = "no-store"
        return response
    except BlockingIOError:
        return JsonResponse({"error": "Recording is busy", "code": "upload_busy"}, status=423)
    except (DatabaseError, OSError, ValidationError):
        logger.exception("event=recording_upload_storage_error")
        return JsonResponse(
            {"error": "Recording storage failed", "code": "storage_failed"},
            status=500,
        )
