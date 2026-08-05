import contextlib
import hashlib
import logging
import os
import re
import stat
import time
import uuid

from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from django.http import JsonResponse
from django.utils import timezone

from api.models import RecordingUpload, RecordingUploadChunk

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = 2
DIGEST_LENGTH = 64
LOCK_STALE_SECONDS = 300
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
    try:
        return int(request.META.get("CONTENT_LENGTH", "0") or 0)
    except (TypeError, ValueError):
        return -1


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


def _record_device_dir(token):
    namespace = hashlib.sha256(
        (f"{token.device.owner_id}\0{token.device.rid}\0{token.device.uuid}").encode()
    ).hexdigest()
    return os.path.join(_record_dir(), namespace)


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


def _ensure_record_device_dir(token):
    root = _record_dir()
    _secure_directory(root)
    device_dir = _record_device_dir(token)
    _secure_directory(device_dir)
    return device_dir


def _stage_dir(base_dir):
    path = os.path.join(base_dir, ".uploads")
    _secure_directory(path)
    return path


def _stage_path(base_dir, upload_id):
    return os.path.join(_stage_dir(base_dir), f"{upload_id}.part")


def _aborted_path(base_dir, upload_id):
    return os.path.join(_stage_dir(base_dir), f"{upload_id}.aborted")


def _final_path(base_dir, upload):
    return os.path.join(base_dir, upload.filename)


def _fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path, flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextlib.contextmanager
def _record_file_lock(base_dir, identity):
    lock_dir = os.path.join(base_dir, ".locks")
    _secure_directory(lock_dir)
    lock_name = hashlib.sha256(str(identity).encode()).hexdigest() + ".lock"
    lock_path = os.path.join(lock_dir, lock_name)
    lock_fd = None
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    for _attempt in range(2):
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
            break
        except FileExistsError:
            try:
                lock_stat = os.lstat(lock_path)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(lock_stat.st_mode) or time.time() - lock_stat.st_mtime <= LOCK_STALE_SECONDS:
                raise BlockingIOError("Recording is busy") from None
            try:
                os.unlink(lock_path)
            except FileNotFoundError:
                continue
    if lock_fd is None:
        raise BlockingIOError("Recording is busy")
    try:
        os.write(lock_fd, f"{os.getpid()} {time.time_ns()}\n".encode())
        os.fsync(lock_fd)
        yield
    finally:
        os.close(lock_fd)
        try:
            os.unlink(lock_path)
        except FileNotFoundError:
            pass


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


def _load_bound_upload(token, upload_id, *, for_update=False):
    query = RecordingUpload.objects.select_related("device")
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
        not current_device.is_active
        or not current_device.public_key_hash
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


def _reconcile_staging_file(upload, stage_path, final_path):
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
        if upload.committed_offset != 0 or upload.revision != 0:
            raise OSError("Recording staging file is missing")
        fd = _open_record_file(stage_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(os.path.dirname(stage_path))
    fd = _open_record_file(stage_path, os.O_RDWR)
    try:
        current_size = os.fstat(fd).st_size
        if current_size < upload.committed_offset:
            raise OSError("Recording staging file is shorter than the committed offset")
        if current_size > upload.committed_offset:
            os.ftruncate(fd, upload.committed_offset)
            os.fsync(fd)
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


def _hash_regular_file(path):
    digest = hashlib.sha256()
    fd = _open_record_file(path, os.O_RDONLY)
    try:
        file_size = os.fstat(fd).st_size
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(fd)
    return file_size, digest.hexdigest()


def _create_upload(request, token, content_length):
    _ensure_empty_body(content_length)
    filename = _safe_record_name(request.GET.get("file", ""))
    if not filename:
        raise UploadRequestError("Invalid file")
    create_id = _parse_uuid(request.GET.get("create_id", ""), "create_id")
    base_dir = _ensure_record_device_dir(token)
    stage_created = None
    try:
        with transaction.atomic():
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
            upload = RecordingUpload.objects.create(
                create_id=create_id,
                device_id=token.device_id,
                owner_id_at_create=token.device.owner_id,
                deployment_generation=token.device.deployment_generation,
                filename=filename,
            )
            stage_path = _stage_path(base_dir, upload.upload_id)
            fd = _open_record_file(stage_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            stage_created = stage_path
            try:
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
        upload = _load_bound_upload(token, upload_id, for_update=True)
        if upload.state == RecordingUpload.STATE_ACTIVE:
            base_dir = _ensure_record_device_dir(token)
            with _record_file_lock(base_dir, upload.upload_id):
                stage_path = _stage_path(base_dir, upload.upload_id)
                final_path = _final_path(base_dir, upload)
                _reconcile_staging_file(upload, stage_path, final_path)
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
            base_dir = _ensure_record_device_dir(token)
            with _record_file_lock(base_dir, upload.upload_id):
                stage_path = _stage_path(base_dir, upload.upload_id)
                final_path = _final_path(base_dir, upload)
                _reconcile_staging_file(upload, stage_path, final_path)
                rollback = (stage_path, upload.committed_offset)
                fd = _open_record_file(stage_path, os.O_RDWR)
                try:
                    os.lseek(fd, upload.committed_offset, os.SEEK_SET)
                    _write_all(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                next_revision = upload.revision + 1
                RecordingUploadChunk.objects.create(
                    upload=upload,
                    chunk_id=chunk_id,
                    offset=offset,
                    length=declared_length,
                    digest=digest,
                    revision=next_revision,
                )
                upload.committed_offset += declared_length
                upload.revision = next_revision
                upload.heartbeat_at = timezone.now()
                upload.save(update_fields=("committed_offset", "revision", "heartbeat_at", "updated_at"))
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
            upload = _load_bound_upload(token, upload_id, for_update=True)
            if upload.state == RecordingUpload.STATE_FINALIZED:
                if upload.expected_size != final_size or upload.expected_digest != final_digest:
                    raise UploadRequestError(
                        "Finalize identity conflicts with committed recording",
                        status=409,
                        code="finalize_conflict",
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
            if revision != upload.revision or final_size != upload.committed_offset:
                raise UploadRequestError(
                    "Finalize position conflict",
                    status=409,
                    code="position_conflict",
                    state=_state_payload(upload),
                )
            base_dir = _ensure_record_device_dir(token)
            with _record_file_lock(base_dir, upload.upload_id):
                stage_path = _stage_path(base_dir, upload.upload_id)
                final_path = _final_path(base_dir, upload)
                stage_exists = os.path.lexists(stage_path)
                final_exists = os.path.lexists(final_path)
                if stage_exists and final_exists:
                    raise OSError("Recording has both staging and published files")
                if not stage_exists and not final_exists:
                    if upload.committed_offset != 0 or upload.revision != 0:
                        raise OSError("Recording staging file is missing")
                    _reconcile_staging_file(upload, stage_path, final_path)
                    stage_exists = True
                source_path = stage_path if stage_exists else final_path
                actual_size, actual_digest = _hash_regular_file(source_path)
                if actual_size != final_size or actual_digest != final_digest:
                    raise UploadRequestError(
                        "Final recording digest mismatch",
                        status=409,
                        code="final_digest_mismatch",
                        state=_state_payload(upload),
                    )
                if stage_exists:
                    os.rename(stage_path, final_path)
                    _fsync_directory(os.path.dirname(stage_path))
                    _fsync_directory(base_dir)
                    moved = (final_path, stage_path)
                upload.state = RecordingUpload.STATE_FINALIZED
                upload.expected_size = final_size
                upload.expected_digest = final_digest
                upload.finalized_at = timezone.now()
                upload.heartbeat_at = upload.finalized_at
                upload.save(
                    update_fields=(
                        "state",
                        "expected_size",
                        "expected_digest",
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
            upload = _load_bound_upload(token, upload_id, for_update=True)
            base_dir = _ensure_record_device_dir(token)
            tomb_path = _aborted_path(base_dir, upload.upload_id)
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
                with _record_file_lock(base_dir, upload.upload_id):
                    stage_path = _stage_path(base_dir, upload.upload_id)
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
    content_length = _request_content_length(request)
    if content_length < 0 or content_length > settings.RECORD_UPLOAD_MAX_CHUNK_BYTES:
        return JsonResponse(
            {"error": "Upload chunk is too large", "code": "chunk_too_large"},
            status=413,
        )
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
    try:
        return handler(request, token, content_length)
    except UploadRequestError as error:
        return _error_response(error)
    except BlockingIOError:
        return JsonResponse({"error": "Recording is busy", "code": "upload_busy"}, status=423)
    except (DatabaseError, OSError):
        logger.exception("event=recording_upload_storage_error")
        return JsonResponse(
            {"error": "Recording storage failed", "code": "storage_failed"},
            status=500,
        )
