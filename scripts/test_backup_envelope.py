#!/usr/bin/env python3
"""Deterministic tests for paired database/recording backup envelopes."""

import json
import pathlib
import subprocess
import sys
import unittest

HELPER = pathlib.Path(__file__).with_name("backup_envelope.py")
BACKUP_ID = "0123456789abcdef0123456789abcdef"
CREATED_AT = "20260805T120000Z"
EPOCH_ID = "11111111-1111-4111-8111-111111111111"
INVENTORY_DIGEST = "a" * 64
MANIFEST_ARGS = [
    "--backup-id",
    BACKUP_ID,
    "--created-at",
    CREATED_AT,
    "--deployment-id",
    "production-a",
    "--database-name",
    "camellia_remote",
    "--postgres-major",
    "18",
    "--key-id",
    "backup-v1",
    "--component",
    "database",
    "--recording-epoch-id",
    EPOCH_ID,
    "--recording-inventory-digest",
    INVENTORY_DIGEST,
]
EXPECT_ARGS = [
    "--expect-backup-id",
    BACKUP_ID,
    "--expect-created-at",
    CREATED_AT,
    "--expect-deployment-id",
    "production-a",
    "--expect-database-name",
    "camellia_remote",
    "--expect-postgres-major",
    "18",
    "--expect-key-id",
    "backup-v1",
    "--expect-component",
    "database",
    "--expect-recording-epoch-id",
    EPOCH_ID,
    "--expect-recording-inventory-digest",
    INVENTORY_DIGEST,
]


def invoke(command, payload=b""):
    return subprocess.run(
        [sys.executable, str(HELPER), *command],
        input=payload,
        capture_output=True,
        check=False,
    )


class BackupEnvelopeTests(unittest.TestCase):
    def test_new_id_is_128_bit_hex(self):
        result = invoke(["new-id"])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertRegex(result.stdout.decode().strip(), r"^[0-9a-f]{32}$")

    def test_pack_and_unpack_round_trip(self):
        payload = b"PGDUMP-CANARY\x00" + bytes(range(256))
        packed = invoke(["pack", *MANIFEST_ARGS], payload)
        self.assertEqual(packed.returncode, 0, packed.stderr.decode())
        self.assertTrue(packed.stdout.startswith(b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00"))

        restored = invoke(["unpack", *EXPECT_ARGS], packed.stdout)
        self.assertEqual(restored.returncode, 0, restored.stderr.decode())
        self.assertEqual(restored.stdout, payload)

    def test_manifest_mismatch_is_rejected_before_payload(self):
        packed = invoke(["pack", *MANIFEST_ARGS], b"payload")
        mismatch = [*EXPECT_ARGS]
        mismatch[mismatch.index("production-a") + 0] = "other-deployment"
        result = invoke(["unpack", *mismatch], packed.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"deployment_id", result.stderr)

    def test_magic_length_json_and_payload_truncation_fail(self):
        packed = invoke(["pack", *MANIFEST_ARGS], b"payload").stdout
        cases = [
            b"wrong" + packed[5:],
            packed[: len(b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00") + 3],
            packed[: len(b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00") + 4] + b"\xff\xff\xff\xff",
            packed[: len(b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00") + 4 + 1],
        ]
        for case in cases:
            with self.subTest(length=len(case)):
                result = invoke(["unpack", *EXPECT_ARGS], case)
                self.assertNotEqual(result.returncode, 0)

    def test_manifest_with_extra_or_missing_fields_is_rejected(self):
        packed = invoke(["pack", *MANIFEST_ARGS], b"payload").stdout
        magic_length = len(b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00")
        manifest_length = int.from_bytes(packed[magic_length : magic_length + 4], "big")
        manifest_start = magic_length + 4
        manifest = json.loads(packed[manifest_start : manifest_start + manifest_length])
        manifest["unexpected"] = True
        encoded = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
        modified = (
            packed[:magic_length]
            + len(encoded).to_bytes(4, "big")
            + encoded
            + packed[manifest_start + manifest_length :]
        )
        result = invoke(["unpack", *EXPECT_ARGS], modified)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_noncanonical_manifest_encoding_is_rejected(self):
        packed = invoke(["pack", *MANIFEST_ARGS], b"payload").stdout
        magic_length = len(b"CAMELLIA-REMOTE-CONSISTENT-BACKUP\x00")
        manifest_length = int.from_bytes(packed[magic_length : magic_length + 4], "big")
        manifest_start = magic_length + 4
        encoded = packed[manifest_start : manifest_start + manifest_length]
        noncanonical = json.dumps(json.loads(encoded), ensure_ascii=False).encode()
        modified = (
            packed[:magic_length]
            + len(noncanonical).to_bytes(4, "big")
            + noncanonical
            + packed[manifest_start + manifest_length :]
        )
        result = invoke(["unpack", *EXPECT_ARGS], modified)
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_manifest_arguments_fail(self):
        bad = [*MANIFEST_ARGS]
        bad[bad.index(BACKUP_ID)] = "not-a-backup-id"
        result = invoke(["pack", *bad], b"payload")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
