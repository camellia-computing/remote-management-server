#!/usr/bin/env python3
"""Deterministic tests for paired database/recording backup envelopes."""

import json
import pathlib
import subprocess
import sys
import tempfile
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


def catalog_entry(generation, backup_id, previous_backup_id, completed_at):
    stem = f"{completed_at}-{backup_id}"
    return {
        "backup_id": backup_id,
        "completed_at": completed_at,
        "created_at": completed_at,
        "database": f"postgres-{stem}.dump.age",
        "generation": generation,
        "manifest": f"backup-set-{stem}.manifest.age",
        "previous_backup_id": previous_backup_id,
        "recordings": f"recordings-{stem}.bundle.age",
    }


def catalog_payload(entries):
    return b"".join(json.dumps(entry, separators=(",", ":"), sort_keys=True).encode() + b"\n" for entry in entries)


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

    def test_backup_set_manifest_binds_final_ciphertext_and_release(self):
        with tempfile.TemporaryDirectory(prefix="camellia-set-manifest-") as temporary:
            root = pathlib.Path(temporary)
            database = root / f"postgres-{CREATED_AT}-{BACKUP_ID}.dump.age"
            recordings = root / f"recordings-{CREATED_AT}-{BACKUP_ID}.bundle.age"
            database.write_bytes(b"database ciphertext")
            recordings.write_bytes(b"recording ciphertext")
            context = [
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
                "--generation",
                "1",
                "--data-encryption-key-id",
                "data-v3",
                "--source-revision",
                "b" * 40,
                "--management-image",
                "ghcr.io/example/management@sha256:" + ("c" * 64),
                "--schema-generation",
                "management-schema-0032-v1",
                "--schema-manifest-version",
                "1",
                "--migration-count",
                "50",
                "--recording-epoch-id",
                EPOCH_ID,
                "--recording-inventory-digest",
                INVENTORY_DIGEST,
                "--database-artifact",
                str(database),
                "--recordings-artifact",
                str(recordings),
            ]
            created = invoke(["set-create", *context, "--verified-at", CREATED_AT, "--completed-at", CREATED_AT])
            self.assertEqual(created.returncode, 0, created.stderr.decode())
            manifest = json.loads(created.stdout)
            self.assertEqual(manifest["format"], "camellia-remote-backup-set-v2")
            self.assertEqual(manifest["artifacts"]["database"]["bytes"], len(b"database ciphertext"))

            verified = invoke(
                [
                    "set-verify",
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
                    "--expect-generation",
                    "1",
                    "--expect-data-encryption-key-id",
                    "data-v3",
                    "--expect-source-revision",
                    "b" * 40,
                    "--expect-management-image",
                    "ghcr.io/example/management@sha256:" + ("c" * 64),
                    "--database-artifact",
                    str(database),
                    "--recordings-artifact",
                    str(recordings),
                ],
                created.stdout,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr.decode())

            database.write_bytes(b"database ciphertexu")
            corrupted = invoke(
                [
                    "set-verify",
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
                    "--expect-generation",
                    "1",
                    "--expect-data-encryption-key-id",
                    "data-v3",
                    "--expect-source-revision",
                    "b" * 40,
                    "--expect-management-image",
                    "ghcr.io/example/management@sha256:" + ("c" * 64),
                    "--database-artifact",
                    str(database),
                    "--recordings-artifact",
                    str(recordings),
                ],
                created.stdout,
            )
            self.assertNotEqual(corrupted.returncode, 0)
            self.assertIn(b"digest", corrupted.stderr)

    def test_generation_catalog_and_clock_aware_retention_are_fail_closed(self):
        first_id = "1" * 32
        second_id = "2" * 32
        third_id = "3" * 32
        first = catalog_entry(1, first_id, None, "20260810T000000Z")
        second = catalog_entry(2, second_id, first_id, "20260811T000000Z")
        stable_third = catalog_entry(3, third_id, second_id, "20260811T010000Z")

        next_generation = invoke(
            ["catalog-next", "--observed-manifests", "2", "--candidate-backup-id", third_id],
            catalog_payload((second, first)),
        )
        self.assertEqual(next_generation.returncode, 0, next_generation.stderr.decode())
        self.assertEqual(
            json.loads(next_generation.stdout),
            {"generation": 3, "previous_backup_id": second_id},
        )

        common = [
            "retention-plan",
            "--observed-manifests",
            "3",
            "--now",
            "20260812T120000Z",
            "--retention-hours",
            "24",
            "--minimum-count",
            "2",
            "--maximum-clock-step-seconds",
            "7200",
            "--maximum-deletions",
            "10",
            "--expect-latest-backup-id",
            third_id,
        ]
        stable = invoke(common, catalog_payload((first, second, stable_third)))
        self.assertEqual(stable.returncode, 0, stable.stderr.decode())
        stable_plan = json.loads(stable.stdout)
        self.assertEqual(stable_plan["status"], "retention-planned")
        self.assertEqual([entry["generation"] for entry in stable_plan["delete"]], [1])

        rollback_third = catalog_entry(3, third_id, second_id, "20260810T120000Z")
        rollback = invoke(common, catalog_payload((first, second, rollback_third)))
        self.assertEqual(rollback.returncode, 0, rollback.stderr.decode())
        rollback_plan = json.loads(rollback.stdout)
        self.assertEqual(rollback_plan["status"], "retention-skipped:clock-rollback")
        self.assertEqual(rollback_plan["delete"], [])

        broken = catalog_entry(4, third_id, first_id, "20260811T020000Z")
        invalid_chain = invoke(
            ["catalog-next", "--observed-manifests", "3", "--candidate-backup-id", "4" * 32],
            catalog_payload((first, second, broken)),
        )
        self.assertNotEqual(invalid_chain.returncode, 0)

        reused_id = invoke(
            ["catalog-next", "--observed-manifests", "2", "--candidate-backup-id", first_id],
            catalog_payload((first, second)),
        )
        self.assertNotEqual(reused_id.returncode, 0)

        reused_retained_anchor = invoke(
            ["catalog-next", "--observed-manifests", "2", "--candidate-backup-id", first_id],
            catalog_payload((second, stable_third)),
        )
        self.assertNotEqual(reused_retained_anchor.returncode, 0)

    def test_run_state_is_canonical_and_stale_holder_is_monitorable(self):
        with tempfile.TemporaryDirectory(prefix="camellia-run-state-") as temporary:
            state = pathlib.Path(temporary) / ".backup-run.json"
            created = invoke(
                [
                    "run-create",
                    "--path",
                    str(state),
                    "--run-id",
                    BACKUP_ID,
                    "--started-at",
                    "20200101T000000Z",
                    "--pid",
                    "123",
                    "--phase",
                    "exporting-database",
                ]
            )
            self.assertEqual(created.returncode, 0, created.stderr.decode())
            self.assertEqual(
                json.dumps(json.loads(state.read_bytes()), separators=(",", ":"), sort_keys=True).encode(),
                state.read_bytes(),
            )
            stale_state = json.loads(state.read_bytes())
            stale_state["heartbeat_at"] = "20200101T000000Z"
            state.write_text(json.dumps(stale_state, separators=(",", ":"), sort_keys=True))
            inspected = invoke(["run-inspect", "--path", str(state), "--stale-seconds", "180"])
            self.assertEqual(inspected.returncode, 3)
            self.assertEqual(json.loads(inspected.stdout)["status"], "failed:stale-holder")
            cleared = invoke(["run-clear", "--path", str(state), "--run-id", BACKUP_ID])
            self.assertEqual(cleared.returncode, 0, cleared.stderr.decode())
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
