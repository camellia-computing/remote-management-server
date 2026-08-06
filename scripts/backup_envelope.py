#!/usr/bin/env python3
"""Bind database and recording artifacts to one authenticated backup epoch."""

import argparse
import datetime as dt
import json
import re
import secrets
import shutil
import struct
import sys
import uuid

MAGIC = b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00"
FORMAT = "camellia-remote-consistent-backup-v2"
MAX_MANIFEST_BYTES = 4096
BACKUP_ID_RE = re.compile(r"^[0-9a-f]{32}$")
CREATED_AT_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
DEPLOYMENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
POSTGRES_MAJOR_RE = re.compile(r"^[1-9][0-9]{0,2}$")
INVENTORY_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
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
