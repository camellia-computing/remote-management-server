#!/usr/bin/env python3
"""Integration tests for encrypted backup/restore shell entry points.

The tests use a real age binary and a deliberately small fake docker-compose
adapter.  PostgreSQL itself is not mocked in the artifact: the adapter emits a
custom-format-shaped canary and verifies the exact stream sent to pg_restore.
"""

import fcntl
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKUP = ROOT / "deploy" / "backup-postgres.sh"
RESTORE = ROOT / "deploy" / "restore-postgres.sh"
HELPER = ROOT / "scripts" / "backup_envelope.py"


def find_age():
    configured = os.environ.get("CAMELLIA_REMOTE_BACKUP_AGE_BINARY")
    if configured and pathlib.Path(configured).is_file():
        return pathlib.Path(configured), pathlib.Path(configured).with_name("age-keygen")
    age = shutil.which("age")
    keygen = shutil.which("age-keygen")
    if age and keygen:
        return pathlib.Path(age), pathlib.Path(keygen)
    return None, None


class BackupScriptsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.age, cls.age_keygen = find_age()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="camellia-backup-test-")
        self.root = pathlib.Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "docker-compose.yaml").write_text("services: {}\n")
        deploy = self.project / "deploy"
        deploy.mkdir()
        (deploy / "bootstrap-postgres-roles.sh").write_text("#!/bin/sh\nexit 0\n")
        self.env_file = self.root / "management.env"
        self.env_file.write_text("CAMELLIA_REMOTE_DATABASE_NAME=camellia_remote\n")
        self.env_file.chmod(0o600)
        self.backups = self.root / "backups"
        self.tmpdir = self.root / "tmp"
        self.tmpdir.mkdir()
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        if self.age is None:
            self.age = self.fake_bin / "age"
            self.age_keygen = self.fake_bin / "age-keygen"
            self.age.write_text(
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import hashlib, hmac, pathlib, sys
                    args = sys.argv[1:]
                    key = hashlib.sha256(b"camellia-backup-shell-test-adapter").digest()
                    if "--encrypt" in args:
                        output = pathlib.Path(args[args.index("--output") + 1])
                        plaintext = sys.stdin.buffer.read()
                        ciphertext = bytes(value ^ key[index % len(key)] for index, value in enumerate(plaintext))
                        output.write_bytes(b"FAKE-AGE-V1\\x00" + ciphertext + hmac.digest(key, ciphertext, "sha256"))
                        raise SystemExit(0)
                    if "--decrypt" in args:
                        artifact = pathlib.Path(args[-1]).read_bytes()
                        if not artifact.startswith(b"FAKE-AGE-V1\\x00") or len(artifact) < 44:
                            raise SystemExit(1)
                        ciphertext, tag = artifact[12:-32], artifact[-32:]
                        if not hmac.compare_digest(tag, hmac.digest(key, ciphertext, "sha256")):
                            raise SystemExit(1)
                        sys.stdout.buffer.write(
                            bytes(value ^ key[index % len(key)] for index, value in enumerate(ciphertext))
                        )
                        raise SystemExit(0)
                    raise SystemExit(2)
                    """
                ).lstrip()
            )
            self.age.chmod(0o755)
            self.age_keygen.write_text(
                "#!/bin/sh\nprintf '%s\\n' '# public key: age1testtesttesttesttesttesttesttest' "
                "'AGE-SECRET-KEY-TEST-ONLY'\n"
            )
            self.age_keygen.chmod(0o755)
        self.restore_capture = self.root / "restored.dump"
        self.recording_restore_capture = self.root / "restored.recordings"
        self.fake_docker = self.fake_bin / "docker"
        self.fake_docker.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import json, os, pathlib, sys
                args = sys.argv[1:]
                mode = os.environ.get("FAKE_DOCKER_MODE", "ok")
                epoch_id = "11111111-1111-4111-8111-111111111111"
                inventory_digest = "a" * 64
                if "recording_backup" in args:
                    operation = args[args.index("recording_backup") + 1]
                    if operation == "begin":
                        backup_id = args[args.index("--backup-id") + 1]
                        requested_at = args[args.index("--requested-at") + 1]
                        print(json.dumps({
                            "backup_id": backup_id,
                            "epoch_id": epoch_id,
                            "inventory_count": 1,
                            "inventory_digest": inventory_digest,
                            "manifest_version": 1,
                            "object_count": 1,
                            "requested_at": requested_at,
                            "state": "ready",
                        }))
                        raise SystemExit(0)
                    if operation == "export":
                        sys.stdout.buffer.write(b"RECORDING-BUNDLE-CANARY\\x00ciphertext\\n")
                        raise SystemExit(0)
                    if operation == "restore":
                        pathlib.Path(os.environ["FAKE_RECORDING_RESTORE_CAPTURE"]).write_bytes(
                            sys.stdin.buffer.read()
                        )
                        raise SystemExit(0)
                    if operation in {"finish", "abort", "restore-preflight"}:
                        print("{}")
                        raise SystemExit(0)
                if "database-bootstrap" in args:
                    raise SystemExit(0)
                if "database-probe" in args:
                    print("1")
                    raise SystemExit(0)
                if "psql" in args and "SHOW server_version_num" in args:
                    print("180000")
                    raise SystemExit(0)
                if "pg_dump" in args:
                    if mode == "pg_dump-fail":
                        print("pg_dump failed", file=sys.stderr)
                        raise SystemExit(42)
                    sys.stdout.buffer.write(b"PGDUMP-CANARY\\x00custom-format\\n")
                    raise SystemExit(0)
                if "pg_restore" in args:
                    payload = sys.stdin.buffer.read()
                    pathlib.Path(os.environ["FAKE_RESTORE_CAPTURE"]).write_bytes(payload)
                    if mode == "pg_restore-fail":
                        raise SystemExit(43)
                    raise SystemExit(0)
                print("unexpected fake docker command", args, file=sys.stderr)
                raise SystemExit(44)
                """
            ).lstrip()
        )
        self.fake_docker.chmod(0o755)
        keygen = subprocess.run([str(self.age_keygen)], check=True, text=True, capture_output=True)
        key = keygen.stdout
        self.identity = self.root / "identity.txt"
        self.identity.write_text(key)
        self.identity.chmod(stat.S_IRUSR | stat.S_IWUSR)
        self.recipient = re.search(r"^# public key: (age1\S+)$", key, re.MULTILINE).group(1)

    def tearDown(self):
        self.temp.cleanup()

    def env(self, **extra):
        result = os.environ.copy()
        result.update(
            {
                "PATH": f"{self.fake_bin}:{result['PATH']}",
                "CAMELLIA_REMOTE_PROJECT_DIR": str(self.project),
                "CAMELLIA_REMOTE_ENV_FILE": str(self.env_file),
                "CAMELLIA_REMOTE_BACKUP_DIR": str(self.backups),
                "CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER": str(HELPER),
                "CAMELLIA_REMOTE_BACKUP_AGE_BINARY": str(self.age),
                "CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT": self.recipient,
                "CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID": "backup-v1",
                "CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID": "production-a",
                "CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR": "18",
                "CAMELLIA_REMOTE_DATABASE_NAME": "camellia_remote",
                "FAKE_RESTORE_CAPTURE": str(self.restore_capture),
                "FAKE_RECORDING_RESTORE_CAPTURE": str(self.recording_restore_capture),
                "TMPDIR": str(self.tmpdir),
            }
        )
        result.update({key: value for key, value in extra.items() if value is not None})
        return result

    def run_backup(self, **extra):
        return subprocess.run([str(BACKUP)], env=self.env(**extra), text=True, capture_output=True)

    def run_restore(self, path, **extra):
        return subprocess.run(
            [str(RESTORE), str(path)],
            env=self.env(CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE=str(self.identity), **extra),
            text=True,
            capture_output=True,
        )

    def test_encrypted_backup_restores_canary_without_plaintext_artifact(self):
        backup = self.run_backup()
        self.assertEqual(backup.returncode, 0, backup.stderr)
        artifacts = list(self.backups.glob("postgres-*.dump.age"))
        self.assertEqual(len(artifacts), 1)
        artifact = artifacts[0]
        recording_artifacts = list(self.backups.glob("recordings-*.bundle.age"))
        self.assertEqual(len(recording_artifacts), 1)
        self.assertNotIn(b"PGDUMP-CANARY", artifact.read_bytes())
        self.assertNotIn(b"RECORDING-BUNDLE-CANARY", recording_artifacts[0].read_bytes())
        self.assertRegex(artifact.name, r"^postgres-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.dump\.age$")

        restored = self.run_restore(artifact)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(self.restore_capture.read_bytes(), b"PGDUMP-CANARY\x00custom-format\n")
        self.assertEqual(
            self.recording_restore_capture.read_bytes(),
            b"RECORDING-BUNDLE-CANARY\x00ciphertext\n",
        )
        self.assertEqual(list(self.tmpdir.glob("camellia-restore-*")), [])

        self.identity.chmod(0o644)
        insecure = self.run_restore(artifact)
        self.assertNotEqual(insecure.returncode, 0)
        self.assertIn("inaccessible", insecure.stderr)
        self.identity.chmod(0o600)

    def test_manifest_expectations_and_ciphertext_tampering_fail(self):
        self.assertEqual(self.run_backup().returncode, 0)
        artifact = next(self.backups.glob("postgres-*.dump.age"))
        recording_artifact = next(self.backups.glob("recordings-*.bundle.age"))
        hidden_recording_artifact = recording_artifact.with_suffix(".missing")
        recording_artifact.rename(hidden_recording_artifact)
        missing_pair = self.run_restore(artifact)
        self.assertNotEqual(missing_pair.returncode, 0)
        self.assertFalse(self.restore_capture.exists())
        hidden_recording_artifact.rename(recording_artifact)
        for variable, value in (
            ("CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID", "other"),
            ("CAMELLIA_REMOTE_DATABASE_NAME", "other_db"),
            ("CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR", "17"),
            ("CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID", "old-key"),
        ):
            with self.subTest(variable=variable):
                result = self.run_restore(artifact, **{variable: value})
                self.assertNotEqual(result.returncode, 0)

        original_recording = recording_artifact.read_bytes()
        self.assertEqual(self.run_backup().returncode, 0)
        other_recording = next(
            path for path in self.backups.glob("recordings-*.bundle.age") if path != recording_artifact
        )
        recording_artifact.write_bytes(other_recording.read_bytes())
        mismatched_pair = self.run_restore(artifact)
        self.assertNotEqual(mismatched_pair.returncode, 0)
        self.assertFalse(self.restore_capture.exists())
        recording_artifact.write_bytes(original_recording)

        data = bytearray(artifact.read_bytes())
        data[-1] ^= 1
        artifact.write_bytes(data)
        self.restore_capture.unlink(missing_ok=True)
        result = self.run_restore(artifact)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.restore_capture.exists())
        self.assertEqual(list(self.tmpdir.glob("camellia-restore-*")), [])

    def test_pg_dump_or_age_failure_leaves_no_artifact_and_lock_is_monitorable(self):
        self.env_file.chmod(0o644)
        insecure_env = self.run_backup()
        self.assertNotEqual(insecure_env.returncode, 0)
        self.env_file.chmod(0o600)

        failed_dump = self.run_backup(FAKE_DOCKER_MODE="pg_dump-fail")
        self.assertNotEqual(failed_dump.returncode, 0)
        self.assertEqual(list(self.backups.glob("*.dump.age")), [])
        self.assertEqual(list(self.backups.glob("*.bundle.age")), [])
        self.assertEqual(list(self.backups.glob("*.tmp")), [])

        failing_age = self.fake_bin / "age-fail"
        failing_age.write_text("#!/bin/sh\nexit 46\n")
        failing_age.chmod(0o755)
        failed_age = self.run_backup(CAMELLIA_REMOTE_BACKUP_AGE_BINARY=str(failing_age))
        self.assertNotEqual(failed_age.returncode, 0)
        self.assertEqual(list(self.backups.glob("*.dump.age")), [])
        self.assertEqual(list(self.backups.glob("*.bundle.age")), [])
        self.assertEqual(list(self.backups.glob("*.tmp")), [])

        self.backups.mkdir(exist_ok=True)
        lock_path = self.backups / ".backup.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            collision = self.run_backup()
        self.assertEqual(collision.returncode, 75, collision.stderr)

    def test_retention_removes_only_complete_expired_backup_pairs(self):
        self.backups.mkdir()
        expired_timestamp = "20260801T000000Z"
        expired_id = "1" * 32
        expired_database = self.backups / f"postgres-{expired_timestamp}-{expired_id}.dump.age"
        expired_recordings = self.backups / f"recordings-{expired_timestamp}-{expired_id}.bundle.age"
        expired_database.write_bytes(b"old database")
        expired_recordings.write_bytes(b"old recordings")

        mixed_timestamp = "20260801T010000Z"
        mixed_id = "2" * 32
        mixed_database = self.backups / f"postgres-{mixed_timestamp}-{mixed_id}.dump.age"
        mixed_recordings = self.backups / f"recordings-{mixed_timestamp}-{mixed_id}.bundle.age"
        mixed_database.write_bytes(b"old database")
        mixed_recordings.write_bytes(b"current recordings")

        unpaired_database = self.backups / f"postgres-20260801T020000Z-{'3' * 32}.dump.age"
        unpaired_recordings = self.backups / f"recordings-20260801T030000Z-{'4' * 32}.bundle.age"
        unpaired_database.write_bytes(b"unpaired database")
        unpaired_recordings.write_bytes(b"unpaired recordings")

        old = time.time() - (25 * 60 * 60)
        for path in (expired_database, expired_recordings, mixed_database, unpaired_database, unpaired_recordings):
            os.utime(path, (old, old))

        result = self.run_backup(CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS="24")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(expired_database.exists())
        self.assertFalse(expired_recordings.exists())
        self.assertTrue(mixed_database.exists())
        self.assertTrue(mixed_recordings.exists())
        self.assertTrue(unpaired_database.exists())
        self.assertTrue(unpaired_recordings.exists())


if __name__ == "__main__":
    unittest.main()
