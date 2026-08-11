#!/usr/bin/env python3
"""Bind database and recording artifacts to one authenticated backup epoch."""

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import struct
import sys
import uuid

MAGIC = b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00"
FORMAT = "camellia-remote-consistent-backup-v2"
MAX_MANIFEST_BYTES = 4096
SET_FORMAT = "camellia-remote-backup-set-v1"
STATUS_FORMAT = "camellia-remote-backup-status-v1"
RESTORE_RECEIPT_FORMAT = "camellia-remote-restore-receipt-v1"
RUN_STATE_FORMAT = "camellia-remote-backup-run-v1"
MAX_SET_MANIFEST_BYTES = 16384
BACKUP_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CREATED_AT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
DEPLOYMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
POSTGRES_MAJOR_RE = re.compile(r"^[1-9][0-9]{0,2}$")
INVENTORY_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SCHEMA_GENERATION_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PHASE_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
COMPONENTS = frozenset(("database", "recordings"))
REQUIRED_FIELDS = frozenset(
    {
        "backup_id",
        "created_at",
        "database_name",
        "deployment_id",
        "format",
        "key_id",
        "postgres_major",
        "component",
        "recording_epoch_id",
        "recording_inventory_digest",
    }
)


class EnvelopeError(ValueError):
    pass


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _json_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EnvelopeError("backup manifest contains duplicate fields")
        result[key] = value
    return result


def _bounded_text(value, name, max_bytes):
    if not value or len(value.encode("utf-8")) > max_bytes or any(ord(character) < 32 for character in value):
        raise EnvelopeError(f"{name} is invalid")
    return value


def _validate_created_at(value):
    if not CREATED_AT_RE.fullmatch(value):
        raise EnvelopeError("created_at is invalid")
    try:
        parsed = dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ")
    except ValueError as exc:
        raise EnvelopeError("created_at is invalid") from exc
    if parsed.strftime("%Y%m%dT%H%M%SZ") != value:
        raise EnvelopeError("created_at is invalid")
    return value


def _parse_timestamp(value, field):
    if not isinstance(value, str):
        raise EnvelopeError(f"{field} is invalid")
    try:
        parsed = dt.datetime.strptime(_validate_created_at(value), "%Y%m%dT%H%M%SZ")
    except EnvelopeError as exc:
        raise EnvelopeError(f"{field} is invalid") from exc
    return parsed.replace(tzinfo=dt.UTC)


def _validate_image(value):
    if (
        not isinstance(value, str)
        or not 20 <= len(value) <= 512
        or any(character.isspace() or ord(character) < 33 for character in value)
        or not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", value)
    ):
        raise EnvelopeError("management_image is not pinned by SHA-256 digest")
    return value


def _expected_artifact_names(manifest):
    stem = f'{manifest["created_at"]}-{manifest["backup_id"]}'
    return {
        "database": f"postgres-{stem}.dump.age",
        "recordings": f"recordings-{stem}.bundle.age",
        "manifest": f"backup-set-{stem}.manifest.age",
    }


def _validate_artifact(value, component, expected_name):
    if not isinstance(value, dict) or set(value) != {"bytes", "filename", "sha256"}:
        raise EnvelopeError(f"{component} artifact metadata is invalid")
    if value["filename"] != expected_name:
        raise EnvelopeError(f"{component} artifact filename is invalid")
    if not isinstance(value["bytes"], int) or isinstance(value["bytes"], bool) or value["bytes"] <= 0:
        raise EnvelopeError(f"{component} artifact size is invalid")
    if not isinstance(value["sha256"], str) or not SHA256_RE.fullmatch(value["sha256"]):
        raise EnvelopeError(f"{component} artifact digest is invalid")
    return value


def validate_set_manifest(manifest):
    required = {
        "artifacts",
        "backup_id",
        "completed_at",
        "created_at",
        "data_encryption_key_id",
        "database_name",
        "deployment_id",
        "format",
        "key_id",
        "management_image",
        "migration_count",
        "postgres_major",
        "recording_epoch_id",
        "recording_inventory_digest",
        "schema_generation",
        "schema_manifest_version",
        "source_revision",
        "started_at",
        "verification",
        "verified_at",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise EnvelopeError("backup set manifest fields are invalid")
    if manifest["format"] != SET_FORMAT:
        raise EnvelopeError("backup set format is unsupported")
    if not isinstance(manifest["backup_id"], str) or not BACKUP_ID_RE.fullmatch(manifest["backup_id"]):
        raise EnvelopeError("backup_id is invalid")
    created = _parse_timestamp(manifest["created_at"], "created_at")
    started = _parse_timestamp(manifest["started_at"], "started_at")
    verified = _parse_timestamp(manifest["verified_at"], "verified_at")
    completed = _parse_timestamp(manifest["completed_at"], "completed_at")
    if created != started or not started <= verified <= completed:
        raise EnvelopeError("backup set timestamps are inconsistent")
    if not isinstance(manifest["deployment_id"], str) or not DEPLOYMENT_ID_RE.fullmatch(manifest["deployment_id"]):
        raise EnvelopeError("deployment_id is invalid")
    if not isinstance(manifest["database_name"], str):
        raise EnvelopeError("database_name is invalid")
    _bounded_text(manifest["database_name"], "database_name", 63)
    if not isinstance(manifest["postgres_major"], str) or not POSTGRES_MAJOR_RE.fullmatch(
        manifest["postgres_major"]
    ):
        raise EnvelopeError("postgres_major is invalid")
    if not isinstance(manifest["key_id"], str) or not KEY_ID_RE.fullmatch(manifest["key_id"]):
        raise EnvelopeError("key_id is invalid")
    if not isinstance(manifest["data_encryption_key_id"], str) or not KEY_ID_RE.fullmatch(
        manifest["data_encryption_key_id"]
    ):
        raise EnvelopeError("data_encryption_key_id is invalid")
    if not isinstance(manifest["source_revision"], str) or not SOURCE_REVISION_RE.fullmatch(
        manifest["source_revision"]
    ):
        raise EnvelopeError("source_revision is invalid")
    _validate_image(manifest["management_image"])
    if not isinstance(manifest["schema_generation"], str) or not SCHEMA_GENERATION_RE.fullmatch(
        manifest["schema_generation"]
    ):
        raise EnvelopeError("schema_generation is invalid")
    for field in ("schema_manifest_version", "migration_count"):
        if not isinstance(manifest[field], int) or isinstance(manifest[field], bool) or manifest[field] <= 0:
            raise EnvelopeError(f"{field} is invalid")
    try:
        epoch_id = uuid.UUID(manifest["recording_epoch_id"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnvelopeError("recording_epoch_id is invalid") from exc
    if epoch_id.version != 4 or str(epoch_id) != manifest["recording_epoch_id"]:
        raise EnvelopeError("recording_epoch_id is invalid")
    if not isinstance(manifest["recording_inventory_digest"], str) or not INVENTORY_DIGEST_RE.fullmatch(
        manifest["recording_inventory_digest"]
    ):
        raise EnvelopeError("recording_inventory_digest is invalid")
    verification = manifest["verification"]
    if verification != {
        "ciphertext_read_after_write": "verified",
        "database_archive": "fully-read",
        "recording_bundle": "fully-read",
    }:
        raise EnvelopeError("backup set verification state is invalid")
    if not isinstance(manifest["artifacts"], dict) or set(manifest["artifacts"]) != COMPONENTS:
        raise EnvelopeError("backup set artifacts are invalid")
    names = _expected_artifact_names(manifest)
    for component in COMPONENTS:
        _validate_artifact(manifest["artifacts"][component], component, names[component])
    return manifest


def read_set_manifest(input_stream):
    encoded = input_stream.read(MAX_SET_MANIFEST_BYTES + 1)
    if not encoded or len(encoded) > MAX_SET_MANIFEST_BYTES:
        raise EnvelopeError("backup set manifest size is invalid")
    try:
        manifest = json.loads(encoded.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("backup set manifest JSON is invalid") from exc
    validate_set_manifest(manifest)
    if _canonical_json(manifest) != encoded:
        raise EnvelopeError("backup set manifest encoding is not canonical")
    return manifest


def _regular_artifact_metadata(path):
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise EnvelopeError(f"backup artifact cannot be inspected: {os.path.basename(path)}") from exc
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise EnvelopeError(f"backup artifact is not a regular file: {os.path.basename(path)}")
    hasher = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb", buffering=0) as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
        after = os.lstat(path)
    except OSError as exc:
        raise EnvelopeError(f"backup artifact cannot be read: {os.path.basename(path)}") from exc
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or size != before.st_size
        or size <= 0
    ):
        raise EnvelopeError(f"backup artifact changed while it was verified: {os.path.basename(path)}")
    return {"bytes": size, "filename": os.path.basename(path), "sha256": hasher.hexdigest()}


def build_set_manifest(args):
    return validate_set_manifest(
        {
            "artifacts": {
                "database": _regular_artifact_metadata(args.database_artifact),
                "recordings": _regular_artifact_metadata(args.recordings_artifact),
            },
            "backup_id": args.backup_id,
            "completed_at": args.completed_at,
            "created_at": args.created_at,
            "data_encryption_key_id": args.data_encryption_key_id,
            "database_name": args.database_name,
            "deployment_id": args.deployment_id,
            "format": SET_FORMAT,
            "key_id": args.key_id,
            "management_image": args.management_image,
            "migration_count": args.migration_count,
            "postgres_major": args.postgres_major,
            "recording_epoch_id": args.recording_epoch_id,
            "recording_inventory_digest": args.recording_inventory_digest,
            "schema_generation": args.schema_generation,
            "schema_manifest_version": args.schema_manifest_version,
            "source_revision": args.source_revision,
            "started_at": args.created_at,
            "verification": {
                "ciphertext_read_after_write": "verified",
                "database_archive": "fully-read",
                "recording_bundle": "fully-read",
            },
            "verified_at": args.verified_at,
        }
    )


def verify_set_manifest(manifest, args, *, verify_digests=True):
    expected = {
        "backup_id": args.expect_backup_id,
        "created_at": args.expect_created_at,
        "database_name": args.expect_database_name,
        "data_encryption_key_id": args.expect_data_encryption_key_id,
        "deployment_id": args.expect_deployment_id,
        "key_id": args.expect_key_id,
        "management_image": args.expect_management_image,
        "postgres_major": args.expect_postgres_major,
        "source_revision": args.expect_source_revision,
    }
    for field, value in expected.items():
        if value is not None and manifest[field] != value:
            raise EnvelopeError(f"backup set {field} does not match the target")
    names = _expected_artifact_names(manifest)
    supplied = {"database": args.database_artifact, "recordings": args.recordings_artifact}
    for component, path in supplied.items():
        if os.path.basename(path) != names[component]:
            raise EnvelopeError(f"backup set {component} path does not match its manifest")
        if verify_digests and _regular_artifact_metadata(path) != manifest["artifacts"][component]:
            raise EnvelopeError(f"backup set {component} ciphertext digest does not match its manifest")
    return manifest


def _read_canonical_file(path, maximum, description):
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            encoded = stream.read(maximum + 1)
    except OSError as exc:
        raise EnvelopeError(f"{description} cannot be read") from exc
    if not encoded or len(encoded) > maximum:
        raise EnvelopeError(f"{description} size is invalid")
    try:
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"{description} JSON is invalid") from exc
    if _canonical_json(value) != encoded:
        raise EnvelopeError(f"{description} is not canonical")
    return value


def _atomic_write(path, encoded):
    parent = os.path.dirname(path)
    if not parent or not os.path.isdir(parent):
        raise EnvelopeError("state directory is unavailable")
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        current = None
    except OSError as exc:
        raise EnvelopeError("state path cannot be inspected") from exc
    if current is not None and not stat.S_ISREG(current.st_mode):
        raise EnvelopeError("state path is not a regular file")
    temporary = os.path.join(parent, f".{os.path.basename(path)}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(temporary, flags, 0o600)
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(fd, encoded[offset:])
                if written <= 0:
                    raise OSError("short state write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise EnvelopeError("state file cannot be committed") from exc


def _validate_run_state(value):
    required = {"format", "heartbeat_at", "phase", "pid", "run_id", "started_at"}
    if not isinstance(value, dict) or set(value) != required or value["format"] != RUN_STATE_FORMAT:
        raise EnvelopeError("backup run state fields are invalid")
    if not isinstance(value["run_id"], str) or not BACKUP_ID_RE.fullmatch(value["run_id"]):
        raise EnvelopeError("backup run ID is invalid")
    started = _parse_timestamp(value["started_at"], "started_at")
    heartbeat = _parse_timestamp(value["heartbeat_at"], "heartbeat_at")
    if heartbeat < started:
        raise EnvelopeError("backup run heartbeat precedes its start")
    if not isinstance(value["pid"], int) or isinstance(value["pid"], bool) or value["pid"] <= 0:
        raise EnvelopeError("backup run pid is invalid")
    if not isinstance(value["phase"], str) or not PHASE_RE.fullmatch(value["phase"]):
        raise EnvelopeError("backup run phase is invalid")
    return value


def _read_run_state(path):
    if not os.path.lexists(path):
        raise FileNotFoundError(path)
    return _validate_run_state(_read_canonical_file(path, 4096, "backup run state"))


@contextlib.contextmanager
def _run_state_lock(path):
    lock_path = f"{path}.update.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise EnvelopeError("backup run state lock is unavailable") from exc
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def write_run_state(path, run_id, started_at, pid, phase, *, create=False):
    with _run_state_lock(path):
        now = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        if create:
            value = {
                "format": RUN_STATE_FORMAT,
                "heartbeat_at": now,
                "phase": phase,
                "pid": pid,
                "run_id": run_id,
                "started_at": started_at,
            }
        else:
            value = _read_run_state(path)
            if value["run_id"] != run_id:
                raise EnvelopeError("backup run state belongs to another run")
            value["heartbeat_at"] = now
            if phase is not None:
                value["phase"] = phase
        _validate_run_state(value)
        _atomic_write(path, _canonical_json(value))
    return value


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest) != REQUIRED_FIELDS:
        raise EnvelopeError("backup manifest fields are invalid")
    if manifest["format"] != FORMAT:
        raise EnvelopeError("backup format is unsupported")
    if not isinstance(manifest["backup_id"], str) or not BACKUP_ID_RE.fullmatch(manifest["backup_id"]):
        raise EnvelopeError("backup_id is invalid")
    if not isinstance(manifest["created_at"], str):
        raise EnvelopeError("created_at is invalid")
    _validate_created_at(manifest["created_at"])
    if not isinstance(manifest["deployment_id"], str) or not DEPLOYMENT_ID_RE.fullmatch(manifest["deployment_id"]):
        raise EnvelopeError("deployment_id is invalid")
    if not isinstance(manifest["database_name"], str):
        raise EnvelopeError("database_name is invalid")
    _bounded_text(manifest["database_name"], "database_name", 63)
    if not isinstance(manifest["postgres_major"], str) or not POSTGRES_MAJOR_RE.fullmatch(manifest["postgres_major"]):
        raise EnvelopeError("postgres_major is invalid")
    if not isinstance(manifest["key_id"], str) or not KEY_ID_RE.fullmatch(manifest["key_id"]):
        raise EnvelopeError("key_id is invalid")
    if manifest["component"] not in COMPONENTS:
        raise EnvelopeError("component is invalid")
    try:
        epoch_id = uuid.UUID(manifest["recording_epoch_id"])
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnvelopeError("recording_epoch_id is invalid") from exc
    if epoch_id.version != 4 or str(epoch_id) != manifest["recording_epoch_id"]:
        raise EnvelopeError("recording_epoch_id is invalid")
    if not isinstance(manifest["recording_inventory_digest"], str) or not INVENTORY_DIGEST_RE.fullmatch(
        manifest["recording_inventory_digest"]
    ):
        raise EnvelopeError("recording_inventory_digest is invalid")
    return manifest


def build_manifest(args):
    return validate_manifest(
        {
            "backup_id": args.backup_id,
            "created_at": args.created_at,
            "database_name": args.database_name,
            "deployment_id": args.deployment_id,
            "format": FORMAT,
            "key_id": args.key_id,
            "postgres_major": args.postgres_major,
            "component": args.component,
            "recording_epoch_id": args.recording_epoch_id,
            "recording_inventory_digest": args.recording_inventory_digest,
        }
    )


def pack(input_stream, output_stream, manifest):
    encoded = json.dumps(
        validate_manifest(manifest), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise EnvelopeError("backup manifest is too large")
    output_stream.write(MAGIC)
    output_stream.write(struct.pack(">I", len(encoded)))
    output_stream.write(encoded)
    shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)


def read_manifest(input_stream):
    if input_stream.read(len(MAGIC)) != MAGIC:
        raise EnvelopeError("backup envelope magic is invalid")
    raw_length = input_stream.read(4)
    if len(raw_length) != 4:
        raise EnvelopeError("backup manifest length is truncated")
    manifest_length = struct.unpack(">I", raw_length)[0]
    if not 1 <= manifest_length <= MAX_MANIFEST_BYTES:
        raise EnvelopeError("backup manifest length is invalid")
    encoded = input_stream.read(manifest_length)
    if len(encoded) != manifest_length:
        raise EnvelopeError("backup manifest is truncated")
    try:
        manifest = json.loads(encoded.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("backup manifest JSON is invalid") from exc
    validate_manifest(manifest)
    canonical = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    if canonical != encoded:
        raise EnvelopeError("backup manifest encoding is not canonical")
    return manifest


def unpack(input_stream, output_stream, expectations):
    manifest = read_manifest(input_stream)
    for field, expected in expectations.items():
        if expected is not None and manifest[field] != expected:
            raise EnvelopeError(f"backup manifest {field} does not match the restore target")
    first_payload_byte = input_stream.read(1)
    if not first_payload_byte:
        raise EnvelopeError("PostgreSQL archive payload is empty")
    output_stream.write(first_payload_byte)
    shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    return manifest


def _add_manifest_arguments(parser):
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--database-name", required=True)
    parser.add_argument("--postgres-major", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--component", required=True, choices=sorted(COMPONENTS))
    parser.add_argument("--recording-epoch-id", required=True)
    parser.add_argument("--recording-inventory-digest", required=True)


def _add_set_context_arguments(parser):
    parser.add_argument("--backup-id", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--database-name", required=True)
    parser.add_argument("--postgres-major", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--data-encryption-key-id", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--management-image", required=True)
    parser.add_argument("--schema-generation", required=True)
    parser.add_argument("--schema-manifest-version", required=True, type=int)
    parser.add_argument("--migration-count", required=True, type=int)
    parser.add_argument("--recording-epoch-id", required=True)
    parser.add_argument("--recording-inventory-digest", required=True)
    parser.add_argument("--database-artifact", required=True)
    parser.add_argument("--recordings-artifact", required=True)


def _add_set_expectations(parser, *, required=True):
    parser.add_argument("--expect-backup-id", required=required)
    parser.add_argument("--expect-created-at", required=required)
    parser.add_argument("--expect-deployment-id", required=required)
    parser.add_argument("--expect-database-name", required=required)
    parser.add_argument("--expect-postgres-major", required=required)
    parser.add_argument("--expect-key-id", required=required)
    parser.add_argument("--expect-data-encryption-key-id", required=required)
    parser.add_argument("--expect-source-revision", required=required)
    parser.add_argument("--expect-management-image", required=required)
    parser.add_argument("--database-artifact", required=True)
    parser.add_argument("--recordings-artifact", required=True)


def _parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("new-id")
    pack_parser = subparsers.add_parser("pack")
    _add_manifest_arguments(pack_parser)
    unpack_parser = subparsers.add_parser("unpack")
    unpack_parser.add_argument("--expect-backup-id", required=True)
    unpack_parser.add_argument("--expect-created-at", required=True)
    unpack_parser.add_argument("--expect-deployment-id", required=True)
    unpack_parser.add_argument("--expect-database-name", required=True)
    unpack_parser.add_argument("--expect-postgres-major", required=True)
    unpack_parser.add_argument("--expect-key-id", required=True)
    unpack_parser.add_argument("--expect-component", required=True, choices=sorted(COMPONENTS))
    unpack_parser.add_argument("--expect-recording-epoch-id", required=True)
    unpack_parser.add_argument("--expect-recording-inventory-digest", required=True)
    pair_parser = subparsers.add_parser("pair")
    pair_parser.add_argument("database_envelope")
    pair_parser.add_argument("recordings_envelope")
    set_create = subparsers.add_parser("set-create")
    _add_set_context_arguments(set_create)
    set_create.add_argument("--verified-at", required=True)
    set_create.add_argument("--completed-at", required=True)
    set_verify = subparsers.add_parser("set-verify")
    _add_set_expectations(set_verify)
    set_entry = subparsers.add_parser("set-entry")
    set_entry.add_argument("--manifest-filename", required=True)
    set_entry.add_argument("--database-artifact", required=True)
    set_entry.add_argument("--recordings-artifact", required=True)
    status = subparsers.add_parser("status")
    status.add_argument("--manifest-filename", required=True)
    status.add_argument("--recorded-at", required=True)
    receipt = subparsers.add_parser("restore-receipt")
    receipt.add_argument("--manifest-filename", required=True)
    receipt.add_argument("--manifest-artifact", required=True)
    receipt.add_argument("--restore-run-id", required=True)
    receipt.add_argument("--target-id", required=True)
    receipt.add_argument("--restore-started-at", required=True)
    receipt.add_argument("--completed-at", required=True)
    receipt.add_argument("--rto-seconds", required=True, type=int)
    run_create = subparsers.add_parser("run-create")
    run_create.add_argument("--path", required=True)
    run_create.add_argument("--run-id", required=True)
    run_create.add_argument("--started-at", required=True)
    run_create.add_argument("--pid", required=True, type=int)
    run_create.add_argument("--phase", required=True)
    run_update = subparsers.add_parser("run-update")
    run_update.add_argument("--path", required=True)
    run_update.add_argument("--run-id", required=True)
    run_update.add_argument("--phase")
    run_inspect = subparsers.add_parser("run-inspect")
    run_inspect.add_argument("--path", required=True)
    run_inspect.add_argument("--stale-seconds", required=True, type=int)
    run_clear = subparsers.add_parser("run-clear")
    run_clear.add_argument("--path", required=True)
    run_clear.add_argument("--run-id", required=True)
    return parser


def paired_manifest(database_path, recordings_path):
    try:
        with open(database_path, "rb") as database_stream:
            database = read_manifest(database_stream)
        with open(recordings_path, "rb") as recordings_stream:
            recordings = read_manifest(recordings_stream)
    except OSError as exc:
        raise EnvelopeError("backup pair cannot be read") from exc
    if database["component"] != "database" or recordings["component"] != "recordings":
        raise EnvelopeError("backup pair components are invalid")
    common_fields = REQUIRED_FIELDS - {"component"}
    if any(database[field] != recordings[field] for field in common_fields):
        raise EnvelopeError("database and recording backup manifests do not describe the same epoch")
    return {field: database[field] for field in sorted(common_fields)}


def _set_status(manifest, manifest_filename, recorded_at):
    if manifest_filename != _expected_artifact_names(manifest)["manifest"]:
        raise EnvelopeError("backup set manifest filename is invalid")
    _parse_timestamp(recorded_at, "recorded_at")
    if recorded_at < manifest["completed_at"]:
        raise EnvelopeError("backup status predates backup completion")
    return {
        "backup_id": manifest["backup_id"],
        "completed_at": manifest["completed_at"],
        "format": STATUS_FORMAT,
        "manifest_filename": manifest_filename,
        "recorded_at": recorded_at,
        "status": "verified",
    }


def _restore_receipt(manifest, args):
    if not TARGET_ID_RE.fullmatch(args.target_id):
        raise EnvelopeError("restore target ID is invalid")
    if args.manifest_filename != _expected_artifact_names(manifest)["manifest"]:
        raise EnvelopeError("backup set manifest filename is invalid")
    if not BACKUP_ID_RE.fullmatch(args.restore_run_id):
        raise EnvelopeError("restore run ID is invalid")
    if os.path.basename(args.manifest_artifact) != args.manifest_filename:
        raise EnvelopeError("backup set manifest artifact path is invalid")
    started = _parse_timestamp(args.restore_started_at, "restore_started_at")
    completed = _parse_timestamp(args.completed_at, "completed_at")
    if completed < started or args.rto_seconds < 0 or int((completed - started).total_seconds()) < args.rto_seconds - 1:
        raise EnvelopeError("restore timing evidence is invalid")
    manifest_artifact = _regular_artifact_metadata(args.manifest_artifact)
    return {
        "backup_id": manifest["backup_id"],
        "backup_set_manifest": manifest_artifact,
        "completed_at": args.completed_at,
        "database": "fully-restored",
        "format": RESTORE_RECEIPT_FORMAT,
        "recordings": "fully-restored",
        "restore_started_at": args.restore_started_at,
        "restore_run_id": args.restore_run_id,
        "rto_seconds": args.rto_seconds,
        "schema_generation": manifest["schema_generation"],
        "source_revision": manifest["source_revision"],
        "status": "verified",
        "target_id": args.target_id,
    }


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.command == "new-id":
        print(secrets.token_hex(16))
        return 0
    if args.command == "pack":
        pack(sys.stdin.buffer, sys.stdout.buffer, build_manifest(args))
        return 0
    if args.command == "pair":
        print(json.dumps(paired_manifest(args.database_envelope, args.recordings_envelope), sort_keys=True))
        return 0
    if args.command == "set-create":
        sys.stdout.buffer.write(_canonical_json(build_set_manifest(args)))
        return 0
    if args.command == "set-verify":
        manifest = verify_set_manifest(read_set_manifest(sys.stdin.buffer), args)
        print(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
        return 0
    if args.command == "set-entry":
        manifest = read_set_manifest(sys.stdin.buffer)
        if args.manifest_filename != _expected_artifact_names(manifest)["manifest"]:
            raise EnvelopeError("backup set manifest filename is invalid")
        names = _expected_artifact_names(manifest)
        supplied = {"database": args.database_artifact, "recordings": args.recordings_artifact}
        for component, path in supplied.items():
            if os.path.basename(path) != names[component]:
                raise EnvelopeError(f"backup set {component} path does not match its manifest")
            try:
                observed = os.lstat(path)
            except OSError as exc:
                raise EnvelopeError(f"backup set {component} artifact is missing") from exc
            if (
                not stat.S_ISREG(observed.st_mode)
                or stat.S_ISLNK(observed.st_mode)
                or observed.st_size != manifest["artifacts"][component]["bytes"]
            ):
                raise EnvelopeError(f"backup set {component} artifact size is invalid")
        completed_epoch = int(_parse_timestamp(manifest["completed_at"], "completed_at").timestamp())
        print(
            completed_epoch,
            manifest["backup_id"],
            names["database"],
            names["recordings"],
            names["manifest"],
        )
        return 0
    if args.command == "status":
        manifest = read_set_manifest(sys.stdin.buffer)
        sys.stdout.buffer.write(_canonical_json(_set_status(manifest, args.manifest_filename, args.recorded_at)))
        return 0
    if args.command == "restore-receipt":
        manifest = read_set_manifest(sys.stdin.buffer)
        sys.stdout.buffer.write(_canonical_json(_restore_receipt(manifest, args)))
        return 0
    if args.command == "run-create":
        _parse_timestamp(args.started_at, "started_at")
        if not BACKUP_ID_RE.fullmatch(args.run_id) or not PHASE_RE.fullmatch(args.phase):
            raise EnvelopeError("backup run arguments are invalid")
        write_run_state(args.path, args.run_id, args.started_at, args.pid, args.phase, create=True)
        return 0
    if args.command == "run-update":
        if not BACKUP_ID_RE.fullmatch(args.run_id) or (args.phase is not None and not PHASE_RE.fullmatch(args.phase)):
            raise EnvelopeError("backup run arguments are invalid")
        write_run_state(args.path, args.run_id, "", 0, args.phase)
        return 0
    if args.command == "run-inspect":
        if not 30 <= args.stale_seconds <= 3600:
            raise EnvelopeError("backup run stale threshold is invalid")
        try:
            value = _read_run_state(args.path)
        except FileNotFoundError:
            print(json.dumps({"holder": "unknown", "status": "skipped:active-run"}, sort_keys=True))
            return 0
        heartbeat = _parse_timestamp(value["heartbeat_at"], "heartbeat_at")
        age = max(0, int((dt.datetime.now(dt.UTC) - heartbeat).total_seconds()))
        status = "failed:stale-holder" if age > args.stale_seconds else "skipped:active-run"
        print(
            json.dumps(
                {
                    "heartbeat_age_seconds": age,
                    "holder_phase": value["phase"],
                    "holder_run_id": value["run_id"],
                    "holder_started_at": value["started_at"],
                    "status": status,
                },
                sort_keys=True,
            )
        )
        return 3 if status == "failed:stale-holder" else 0
    if args.command == "run-clear":
        try:
            value = _read_run_state(args.path)
        except FileNotFoundError:
            return 0
        if value["run_id"] != args.run_id:
            raise EnvelopeError("backup run state belongs to another run")
        try:
            os.unlink(args.path)
        except OSError as exc:
            raise EnvelopeError("backup run state cannot be removed") from exc
        return 0
    expectations = {
        "backup_id": args.expect_backup_id,
        "created_at": args.expect_created_at,
        "database_name": args.expect_database_name,
        "deployment_id": args.expect_deployment_id,
        "key_id": args.expect_key_id,
        "postgres_major": args.expect_postgres_major,
        "component": args.expect_component,
        "recording_epoch_id": args.expect_recording_epoch_id,
        "recording_inventory_digest": args.expect_recording_inventory_digest,
    }
    unpack(sys.stdin.buffer, sys.stdout.buffer, expectations)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EnvelopeError as exc:
        print(f"backup envelope error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
