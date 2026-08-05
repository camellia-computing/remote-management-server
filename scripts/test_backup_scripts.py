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
        if cls.age is None:
            raise unittest.SkipTest("age and age-keygen are required for shell integration")

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
        self.restore_capture = self.root / "restored.dump"
        self.fake_docker = self.fake_bin / "docker"
        self.fake_docker.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import os, pathlib, sys
                args = sys.argv[1:]
                mode = os.environ.get("FAKE_DOCKER_MODE", "ok")
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
        self.assertNotIn(b"PGDUMP-CANARY", artifact.read_bytes())
        self.assertRegex(artifact.name, r"^postgres-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.dump\.age$")

        restored = self.run_restore(artifact)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(self.restore_capture.read_bytes(), b"PGDUMP-CANARY\x00custom-format\n")
        self.assertEqual(list(self.tmpdir.glob("camellia-restore.*")), [])

        self.identity.chmod(0o644)
        insecure = self.run_restore(artifact)
        self.assertNotEqual(insecure.returncode, 0)
        self.assertIn("inaccessible", insecure.stderr)
        self.identity.chmod(0o600)

    def test_manifest_expectations_and_ciphertext_tampering_fail(self):
        self.assertEqual(self.run_backup().returncode, 0)
        artifact = next(self.backups.glob("postgres-*.dump.age"))
        for variable, value in (
            ("CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID", "other"),
            ("CAMELLIA_REMOTE_DATABASE_NAME", "other_db"),
            ("CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR", "17"),
            ("CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID", "old-key"),
        ):
            with self.subTest(variable=variable):
                result = self.run_restore(artifact, **{variable: value})
                self.assertNotEqual(result.returncode, 0)

        data = bytearray(artifact.read_bytes())
        data[-1] ^= 1
        artifact.write_bytes(data)
        self.restore_capture.unlink(missing_ok=True)
        result = self.run_restore(artifact)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.restore_capture.exists())
        self.assertEqual(list(self.tmpdir.glob("camellia-restore.*")), [])

    def test_pg_dump_or_age_failure_leaves_no_artifact_and_lock_is_monitorable(self):
        self.env_file.chmod(0o644)
        insecure_env = self.run_backup()
        self.assertNotEqual(insecure_env.returncode, 0)
        self.env_file.chmod(0o600)

        failed_dump = self.run_backup(FAKE_DOCKER_MODE="pg_dump-fail")
        self.assertNotEqual(failed_dump.returncode, 0)
        self.assertEqual(list(self.backups.glob("*.dump.age")), [])
        self.assertEqual(list(self.backups.glob("*.tmp")), [])

        failing_age = self.fake_bin / "age-fail"
        failing_age.write_text("#!/bin/sh\nexit 46\n")
        failing_age.chmod(0o755)
        failed_age = self.run_backup(CAMELLIA_REMOTE_BACKUP_AGE_BINARY=str(failing_age))
        self.assertNotEqual(failed_age.returncode, 0)
        self.assertEqual(list(self.backups.glob("*.dump.age")), [])
        self.assertEqual(list(self.backups.glob("*.tmp")), [])

        self.backups.mkdir(exist_ok=True)
        lock_path = self.backups / ".backup.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            collision = self.run_backup()
        self.assertEqual(collision.returncode, 75, collision.stderr)


if __name__ == "__main__":
    unittest.main()
