#!/usr/bin/env python3
"""Integration tests for encrypted backup/restore shell entry points.

The tests use a real age binary and a deliberately small fake docker-compose
adapter.  PostgreSQL itself is not mocked in the artifact: the adapter emits a
custom-format-shaped canary and verifies the exact stream sent to pg_restore.
"""

import fcntl
import json
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
        self.restore_evidence = self.root / "restore-evidence"
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
                if args[:2] == ["container", "ls"]:
                    raise SystemExit(0)
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
                    if operation == "verify":
                        if mode == "recording-verify-fail":
                            raise SystemExit(53)
                        payload = sys.stdin.buffer.read()
                        if not payload.startswith(b"RECORDING-BUNDLE-CANARY"):
                            raise SystemExit(48)
                        print("{}")
                        raise SystemExit(0)
                    if operation in {"finish", "abort", "restore-preflight"}:
                        print("{}")
                        raise SystemExit(0)
                if "check_username_identity" in args:
                    if mode == "username-identity-fail":
                        raise SystemExit(45)
                    print("username identity contract is valid")
                    raise SystemExit(0)
                if "check_release_schema" in args:
                    if mode == "release-schema-fail":
                        raise SystemExit(46)
                    print(json.dumps({
                        "migration_count": 50,
                        "schema_generation": "management-schema-0032-v1",
                        "schema_manifest_version": 1,
                    }))
                    raise SystemExit(0)
                if "rotate_data_encryption" in args:
                    if mode == "data-key-fail":
                        raise SystemExit(51)
                    print("{}")
                    raise SystemExit(0)
                if args and args[-1] == "migrate":
                    if mode == "migration-fail":
                        raise SystemExit(47)
                    raise SystemExit(0)
                if "database-bootstrap" in args:
                    raise SystemExit(0)
                if "database-probe" in args:
                    print("1")
                    raise SystemExit(0)
                if "psql" in args and "SHOW server_version_num" in args:
                    print("180000")
                    raise SystemExit(0)
                if "psql" in args and any("pg_catalog.pg_class" in argument for argument in args):
                    print("1" if mode == "nonempty-restore-target" else "0")
                    raise SystemExit(0)
                if "pg_dump" in args:
                    if "--lock-wait-timeout=30s" not in args:
                        print("pg_dump lock deadline is missing", file=sys.stderr)
                        raise SystemExit(52)
                    compression = os.environ.get("CAMELLIA_REMOTE_BACKUP_COMPRESSION", "zstd:3")
                    if f"--compress={compression}" not in args:
                        print("pg_dump compression contract is missing", file=sys.stderr)
                        raise SystemExit(54)
                    if mode == "pg_dump-fail":
                        print("pg_dump failed", file=sys.stderr)
                        raise SystemExit(42)
                    sys.stdout.buffer.write(b"PGDUMP-CANARY\\x00custom-format\\n")
                    raise SystemExit(0)
                if "pg_restore" in args:
                    payload = sys.stdin.buffer.read()
                    if "--file=/dev/null" in args:
                        if mode == "pg_restore-verify-fail":
                            raise SystemExit(49)
                        if not payload.startswith(b"PGDUMP-CANARY"):
                            raise SystemExit(50)
                        raise SystemExit(0)
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
                "CAMELLIA_REMOTE_OPERATION_RUNNER": str(ROOT / "deploy" / "run-compose-operation.sh"),
                "CAMELLIA_REMOTE_DOCKER_BINARY": str(self.fake_docker),
                "CAMELLIA_REMOTE_BACKUP_AGE_BINARY": str(self.age),
                "CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT": self.recipient,
                "CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID": "backup-v1",
                "CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID": "data-v3",
                "CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID": "production-a",
                "CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR": "18",
                "CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE": str(self.identity),
                "CAMELLIA_REMOTE_BACKUP_RETENTION_MINIMUM_COUNT": "2",
                "CAMELLIA_REMOTE_DATABASE_NAME": "camellia_remote",
                "CAMELLIA_REMOTE_MANAGEMENT_IMAGE": "ghcr.io/example/management@sha256:" + ("b" * 64),
                "CAMELLIA_REMOTE_RELEASE_REVISION": "c" * 40,
                "CAMELLIA_REMOTE_RESTORE_TARGET_ID": "isolated-ci",
                "CAMELLIA_REMOTE_RESTORE_EVIDENCE_DIR": str(self.restore_evidence),
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
        match = re.fullmatch(r"postgres-[0-9]{8}T[0-9]{6}Z-([0-9a-f]{32})\.dump\.age", path.name)
        self.assertIsNotNone(match)
        restore_environment = {
            "CAMELLIA_REMOTE_RESTORE_CONFIRM": f"restore:{match.group(1)}:isolated-ci",
            **extra,
        }
        return subprocess.run(
            [str(RESTORE), str(path)],
            env=self.env(**restore_environment),
            text=True,
            capture_output=True,
        )

    def fixed_backup_identity(self, timestamp, backup_id):
        helper = self.root / "fixed-backup-envelope.py"
        helper.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import os, sys
                if sys.argv[1:] == ["new-id"]:
                    print(os.environ["FAKE_BACKUP_ID"])
                    raise SystemExit(0)
                os.execv(
                    sys.executable,
                    [sys.executable, os.environ["REAL_BACKUP_ENVELOPE_HELPER"], *sys.argv[1:]],
                )
                """
            ).lstrip()
        )
        clock = self.fake_bin / "date"
        clock.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import os, sys
                if sys.argv[1:] == ["-u", "+%Y%m%dT%H%M%SZ"] and "FAKE_BACKUP_TIMESTAMP" in os.environ:
                    print(os.environ["FAKE_BACKUP_TIMESTAMP"])
                    raise SystemExit(0)
                os.execv("/usr/bin/date", ["/usr/bin/date", *sys.argv[1:]])
                """
            ).lstrip()
        )
        clock.chmod(0o755)
        return {
            "CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER": str(helper),
            "FAKE_BACKUP_ID": backup_id,
            "FAKE_BACKUP_TIMESTAMP": timestamp,
            "REAL_BACKUP_ENVELOPE_HELPER": str(HELPER),
        }

    def test_encrypted_backup_restores_canary_without_plaintext_artifact(self):
        backup = self.run_backup()
        self.assertEqual(backup.returncode, 0, backup.stderr)
        artifacts = list(self.backups.glob("postgres-*.dump.age"))
        self.assertEqual(len(artifacts), 1)
        artifact = artifacts[0]
        recording_artifacts = list(self.backups.glob("recordings-*.bundle.age"))
        self.assertEqual(len(recording_artifacts), 1)
        set_artifacts = list(self.backups.glob("backup-set-*.manifest.age"))
        self.assertEqual(len(set_artifacts), 1)
        self.assertNotIn(b"PGDUMP-CANARY", artifact.read_bytes())
        self.assertNotIn(b"RECORDING-BUNDLE-CANARY", recording_artifacts[0].read_bytes())
        self.assertNotIn(b"camellia-remote-backup-set-v2", set_artifacts[0].read_bytes())
        self.assertRegex(artifact.name, r"^postgres-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\.dump\.age$")

        restored = self.run_restore(artifact)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(self.restore_capture.read_bytes(), b"PGDUMP-CANARY\x00custom-format\n")
        self.assertEqual(
            self.recording_restore_capture.read_bytes(),
            b"RECORDING-BUNDLE-CANARY\x00ciphertext\n",
        )
        self.assertEqual(list(self.tmpdir.glob("camellia-restore-*")), [])
        receipts = list(self.restore_evidence.glob("restore-receipt-*.json.age"))
        self.assertEqual(len(receipts), 1)
        receipt = subprocess.run(
            [str(self.age), "--decrypt", "--identity", str(self.identity), str(receipts[0])],
            check=True,
            capture_output=True,
        )
        receipt_payload = json.loads(receipt.stdout)
        self.assertEqual(receipt_payload["format"], "camellia-remote-restore-receipt-v2")
        self.assertEqual(receipt_payload["generation"], 1)
        self.assertEqual(receipt_payload["backup_id"], artifact.name.split("-")[-1].removesuffix(".dump.age"))
        self.assertTrue((self.restore_evidence / "latest-restore-verified.json").is_file())

        self.identity.chmod(0o644)
        insecure = self.run_restore(artifact)
        self.assertNotEqual(insecure.returncode, 0)
        self.assertIn("inaccessible", insecure.stderr)
        self.identity.chmod(0o600)

    def test_manifest_expectations_and_ciphertext_tampering_fail(self):
        self.assertEqual(self.run_backup().returncode, 0)
        artifact = next(self.backups.glob("postgres-*.dump.age"))
        recording_artifact = next(self.backups.glob("recordings-*.bundle.age"))
        set_artifact = next(self.backups.glob("backup-set-*.manifest.age"))
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
            ("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID", "old-data-key"),
            ("CAMELLIA_REMOTE_RELEASE_REVISION", "d" * 40),
            ("CAMELLIA_REMOTE_MANAGEMENT_IMAGE", "ghcr.io/example/management@sha256:" + ("d" * 64)),
        ):
            with self.subTest(variable=variable):
                result = self.run_restore(artifact, **{variable: value})
                self.assertNotEqual(result.returncode, 0)

        original_recording = recording_artifact.read_bytes()
        original_set = set_artifact.read_bytes()
        self.assertEqual(self.run_backup().returncode, 0)
        other_recording = next(
            path for path in self.backups.glob("recordings-*.bundle.age") if path != recording_artifact
        )
        recording_artifact.write_bytes(other_recording.read_bytes())
        mismatched_pair = self.run_restore(artifact)
        self.assertNotEqual(mismatched_pair.returncode, 0)
        self.assertFalse(self.restore_capture.exists())
        recording_artifact.write_bytes(original_recording)

        other_set = next(path for path in self.backups.glob("backup-set-*.manifest.age") if path != set_artifact)
        set_artifact.write_bytes(other_set.read_bytes())
        replayed_set = self.run_restore(artifact)
        self.assertNotEqual(replayed_set.returncode, 0)
        self.assertFalse(self.restore_capture.exists())
        set_artifact.write_bytes(original_set)

        set_data = bytearray(set_artifact.read_bytes())
        set_data[-1] ^= 1
        set_artifact.write_bytes(set_data)
        invalid_set = self.run_restore(artifact)
        self.assertNotEqual(invalid_set.returncode, 0)
        set_data[-1] ^= 1
        set_artifact.write_bytes(set_data)

        data = bytearray(artifact.read_bytes())
        data[-1] ^= 1
        artifact.write_bytes(data)
        self.restore_capture.unlink(missing_ok=True)
        result = self.run_restore(artifact)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.restore_capture.exists())
        self.assertEqual(list(self.tmpdir.glob("camellia-restore-*")), [])

    def test_pg_dump_or_age_failure_leaves_no_artifact_and_lock_is_monitorable(self):
        invalid_id = self.run_backup(**self.fixed_backup_identity("20260811T120000Z", "not-a-backup-id"))
        self.assertNotEqual(invalid_id.returncode, 0)
        self.assertIn("invalid ID", invalid_id.stderr)

        for invalid_compression in ("", "gzip", "gzip:0", "gzip:9", "zstd:0", "zstd:10", "lz4", "zstd:3 --no-acl"):
            with self.subTest(invalid_compression=invalid_compression):
                invalid = self.run_backup(CAMELLIA_REMOTE_BACKUP_COMPRESSION=invalid_compression)
                self.assertNotEqual(invalid.returncode, 0)
                self.assertIn("COMPRESSION", invalid.stderr)
        for variable, value in (
            ("CAMELLIA_REMOTE_BACKUP_RETENTION_MAXIMUM_DELETIONS", "0"),
            ("CAMELLIA_REMOTE_BACKUP_RETENTION_MAXIMUM_DELETIONS", "101"),
            ("CAMELLIA_REMOTE_BACKUP_MAX_CLOCK_STEP_SECONDS", "59"),
            ("CAMELLIA_REMOTE_BACKUP_MAX_CLOCK_STEP_SECONDS", "604801"),
        ):
            with self.subTest(variable=variable, value=value):
                invalid = self.run_backup(**{variable: value})
                self.assertNotEqual(invalid.returncode, 0)
                self.assertIn(variable, invalid.stderr)

        self.env_file.chmod(0o644)
        insecure_env = self.run_backup()
        self.assertNotEqual(insecure_env.returncode, 0)
        self.env_file.chmod(0o600)

        failed_dump = self.run_backup(FAKE_DOCKER_MODE="pg_dump-fail")
        self.assertNotEqual(failed_dump.returncode, 0)
        self.assertEqual(list(self.backups.glob("*.dump.age")), [])
        self.assertEqual(list(self.backups.glob("*.bundle.age")), [])
        self.assertEqual(list(self.backups.glob("*.manifest.age")), [])
        self.assertEqual(list(self.backups.glob("*.tmp")), [])

        failing_age = self.fake_bin / "age-fail"
        failing_age.write_text("#!/bin/sh\nexit 46\n")
        failing_age.chmod(0o755)
        failed_age = self.run_backup(CAMELLIA_REMOTE_BACKUP_AGE_BINARY=str(failing_age))
        self.assertNotEqual(failed_age.returncode, 0)
        self.assertEqual(list(self.backups.glob("*.dump.age")), [])
        self.assertEqual(list(self.backups.glob("*.bundle.age")), [])
        self.assertEqual(list(self.backups.glob("*.manifest.age")), [])
        self.assertEqual(list(self.backups.glob("*.tmp")), [])

        for mode in ("pg_restore-verify-fail", "recording-verify-fail"):
            with self.subTest(mode=mode):
                failed_verify = self.run_backup(FAKE_DOCKER_MODE=mode)
                self.assertNotEqual(failed_verify.returncode, 0)
                self.assertEqual(list(self.backups.glob("*.dump.age")), [])
                self.assertEqual(list(self.backups.glob("*.bundle.age")), [])
                self.assertEqual(list(self.backups.glob("*.manifest.age")), [])
                self.assertFalse((self.backups / "latest-verified.json").exists())

        self.backups.mkdir(exist_ok=True)
        lock_path = self.backups / ".backup.lock"
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            collision = self.run_backup()
        self.assertEqual(collision.returncode, 75, collision.stderr)
        self.assertIn("skipped:active-run", collision.stderr)

        state = self.backups / ".backup-run.json"
        subprocess.run(
            [
                str(HELPER),
                "run-create",
                "--path",
                str(state),
                "--run-id",
                "f" * 32,
                "--started-at",
                "20200101T000000Z",
                "--pid",
                "123",
                "--phase",
                "exporting-database",
            ],
            check=True,
        )
        state_text = state.read_text()
        heartbeat = re.search(r'"heartbeat_at":"[0-9TZ]+"', state_text)
        self.assertIsNotNone(heartbeat)
        state.write_text(state_text.replace(heartbeat.group(0), '"heartbeat_at":"20200101T000000Z"'))
        with lock_path.open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            stale_collision = self.run_backup()
        self.assertNotEqual(stale_collision.returncode, 0)
        self.assertIn("failed:stale-holder", stale_collision.stderr)

    def test_final_path_collision_never_removes_the_existing_recovery_point(self):
        timestamp = "20260811T120000Z"
        backup_id = "d" * 32
        identity = self.fixed_backup_identity(timestamp, backup_id)
        names = {
            "database": f"postgres-{timestamp}-{backup_id}.dump.age",
            "recordings": f"recordings-{timestamp}-{backup_id}.bundle.age",
            "manifest": f"backup-set-{timestamp}-{backup_id}.manifest.age",
        }
        for component, collision_name in names.items():
            with self.subTest(component=component):
                shutil.rmtree(self.backups, ignore_errors=True)
                self.backups.mkdir()
                collision = self.backups / collision_name
                sentinel = f"existing-{component}-recovery-point".encode()
                collision.write_bytes(sentinel)

                result = self.run_backup(**identity)

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(collision.read_bytes(), sentinel)
                for other_component, other_name in names.items():
                    if other_component != component:
                        self.assertFalse((self.backups / other_name).exists())

    def test_same_second_and_clock_rollback_keep_monotonic_generations(self):
        first_id = "a" * 32
        second_id = "b" * 32
        third_id = "c" * 32
        first = self.run_backup(**self.fixed_backup_identity("20260810T100000Z", first_id))
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_backup(**self.fixed_backup_identity("20260810T100000Z", second_id))
        self.assertEqual(second.returncode, 0, second.stderr)
        rollback = self.run_backup(**self.fixed_backup_identity("20260809T100000Z", third_id))
        self.assertEqual(rollback.returncode, 0, rollback.stderr)
        self.assertIn('"status":"retention-skipped:clock-rollback"', rollback.stderr)

        self.assertEqual(len(list(self.backups.glob("postgres-*.dump.age"))), 3)
        self.assertEqual(len(list(self.backups.glob("recordings-*.bundle.age"))), 3)
        self.assertEqual(len(list(self.backups.glob("backup-set-*.manifest.age"))), 3)
        status = json.loads((self.backups / "latest-verified.json").read_text())
        self.assertEqual(status["format"], "camellia-remote-backup-status-v2")
        self.assertEqual(status["backup_id"], third_id)
        self.assertEqual(status["generation"], 3)
        self.assertEqual(status["previous_backup_id"], second_id)

        reused = self.run_backup(**self.fixed_backup_identity("20260811T100000Z", first_id))
        self.assertNotEqual(reused.returncode, 0)
        self.assertIn("already used", reused.stderr)
        self.assertEqual(len(list(self.backups.glob("backup-set-*.manifest.age"))), 3)
        self.assertEqual(json.loads((self.backups / "latest-verified.json").read_text()), status)

    def test_backup_and_restore_reject_invalid_username_identity(self):
        failed_backup = self.run_backup(FAKE_DOCKER_MODE="username-identity-fail")
        self.assertNotEqual(failed_backup.returncode, 0)
        self.assertEqual(list(self.backups.glob("*.dump.age")), [])
        self.assertEqual(list(self.backups.glob("*.bundle.age")), [])

        self.assertEqual(self.run_backup().returncode, 0)
        artifact = next(self.backups.glob("postgres-*.dump.age"))
        self.restore_capture.unlink(missing_ok=True)
        failed_restore = self.run_restore(artifact, FAKE_DOCKER_MODE="username-identity-fail")
        self.assertNotEqual(failed_restore.returncode, 0)
        self.assertTrue(self.restore_capture.exists())
        self.assertFalse(self.recording_restore_capture.exists())

    def test_restore_rejects_migration_or_release_schema_failure_before_recordings(self):
        self.assertEqual(self.run_backup().returncode, 0)
        artifact = next(self.backups.glob("postgres-*.dump.age"))
        for mode in ("migration-fail", "release-schema-fail", "data-key-fail"):
            with self.subTest(mode=mode):
                self.restore_capture.unlink(missing_ok=True)
                self.recording_restore_capture.unlink(missing_ok=True)
                failed = self.run_restore(artifact, FAKE_DOCKER_MODE=mode)
                self.assertNotEqual(failed.returncode, 0)
                self.assertTrue(self.restore_capture.exists())
                self.assertFalse(self.recording_restore_capture.exists())

    def test_restore_requires_per_run_confirmation_and_empty_database(self):
        self.assertEqual(self.run_backup().returncode, 0)
        artifact = next(self.backups.glob("postgres-*.dump.age"))
        unconfirmed = self.run_restore(artifact, CAMELLIA_REMOTE_RESTORE_CONFIRM="reusable-yes")
        self.assertNotEqual(unconfirmed.returncode, 0)
        self.assertFalse(self.restore_capture.exists())

        nonempty = self.run_restore(artifact, FAKE_DOCKER_MODE="nonempty-restore-target")
        self.assertNotEqual(nonempty.returncode, 0)
        self.assertIn("not empty", nonempty.stderr)
        self.assertFalse(self.restore_capture.exists())
        self.assertFalse((self.restore_evidence / "latest-restore-verified.json").exists())

    def test_retention_uses_verified_manifest_generations_and_protects_minimum(self):
        self.backups.mkdir()
        old_sets = []
        for hour, digit in enumerate(("1", "2", "3")):
            timestamp = f"20260810T0{hour}0000Z"
            backup_id = digit * 32
            database = self.backups / f"postgres-{timestamp}-{backup_id}.dump.age"
            recordings = self.backups / f"recordings-{timestamp}-{backup_id}.bundle.age"
            manifest = self.backups / f"backup-set-{timestamp}-{backup_id}.manifest.age"
            database.write_bytes(f"old database {digit}".encode())
            recordings.write_bytes(f"old recordings {digit}".encode())
            generation_arguments = ["--generation", str(hour + 1)]
            if hour:
                generation_arguments.extend(("--previous-backup-id", str(hour) * 32))
            created = subprocess.run(
                [
                    str(HELPER),
                    "set-create",
                    "--backup-id",
                    backup_id,
                    "--created-at",
                    timestamp,
                    "--deployment-id",
                    "production-a",
                    "--database-name",
                    "camellia_remote",
                    "--postgres-major",
                    "18",
                    "--key-id",
                    "backup-v1",
                    *generation_arguments,
                    "--data-encryption-key-id",
                    "data-v3",
                    "--source-revision",
                    "c" * 40,
                    "--management-image",
                    "ghcr.io/example/management@sha256:" + ("b" * 64),
                    "--schema-generation",
                    "management-schema-0032-v1",
                    "--schema-manifest-version",
                    "1",
                    "--migration-count",
                    "50",
                    "--recording-epoch-id",
                    "11111111-1111-4111-8111-111111111111",
                    "--recording-inventory-digest",
                    "a" * 64,
                    "--database-artifact",
                    str(database),
                    "--recordings-artifact",
                    str(recordings),
                    "--verified-at",
                    timestamp,
                    "--completed-at",
                    timestamp,
                ],
                check=True,
                capture_output=True,
            )
            encrypted = subprocess.run(
                [str(self.age), "--encrypt", "--recipient", self.recipient, "--output", str(manifest)],
                input=created.stdout,
                check=True,
            )
            self.assertEqual(encrypted.returncode, 0)
            old_sets.append((database, recordings, manifest))

        unpaired_database = self.backups / f"postgres-20260810T030000Z-{'4' * 32}.dump.age"
        unpaired_database.write_bytes(b"unpaired legacy database")

        identity = self.fixed_backup_identity("20260811T100000Z", "e" * 32)
        result = self.run_backup(
            CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS="24",
            CAMELLIA_REMOTE_BACKUP_MAX_CLOCK_STEP_SECONDS="172800",
            CAMELLIA_REMOTE_BACKUP_RETENTION_MAXIMUM_DELETIONS="2",
            **identity,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for generation in old_sets[:2]:
            self.assertTrue(all(not path.exists() for path in generation))
        self.assertTrue(all(path.exists() for path in old_sets[2]))
        self.assertTrue(unpaired_database.exists())


if __name__ == "__main__":
    unittest.main()
