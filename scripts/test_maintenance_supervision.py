#!/usr/bin/env python3
"""Integration tests for the maintenance wrappers, notifier, and freshness command."""

import json
import os
import pathlib
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LEDGER = ROOT / "scripts" / "maintenance_ledger.py"
BACKUP_WRAPPER = ROOT / "deploy" / "run-maintenance-backup.sh"
CLEANUP_WRAPPER = ROOT / "deploy" / "run-maintenance-cleanup.sh"
FRESHNESS = ROOT / "deploy" / "check-maintenance-freshness.sh"
NOTIFIER = ROOT / "deploy" / "maintenance-ledger-notify.sh"


class MaintenanceSupervisionTests(unittest.TestCase):
    def write_executable(self, path, content):
        path.write_text(content)
        path.chmod(0o755)
        return path

    def base_environment(self, root):
        state = root / "state"
        state.mkdir(mode=0o700)
        env_file = root / "management.env"
        env_file.write_text("CAMELLIA_REMOTE_TEST=true\n")
        guard = self.write_executable(root / "guard.sh", "#!/usr/bin/env bash\nexit 0\n")
        return state, env_file, guard

    def run_wrapper(self, wrapper, root, state, env_file, guard, **extra):
        environment = os.environ | {
            "CAMELLIA_REMOTE_PROJECT_DIR": str(root),
            "CAMELLIA_REMOTE_ENV_FILE": str(env_file),
            "CAMELLIA_REMOTE_MAINTENANCE_STATE_DIR": str(state),
            "CAMELLIA_REMOTE_MAINTENANCE_LEDGER_HELPER": str(LEDGER),
            "CAMELLIA_REMOTE_MAINTENANCE_GUARD_SCRIPT": str(guard),
            **{key: str(value) for key, value in extra.items()},
        }
        return subprocess.run(  # noqa: S603 - fixed repository wrapper and controlled fixture paths
            [str(wrapper)], env=environment, text=True, capture_output=True, timeout=10
        )

    def summary(self, state, kind):
        return json.loads((state / f"latest-{kind}.json").read_text())

    def test_cleanup_success_streams_output_and_records_counts(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-cleanup-") as temporary:
            root = pathlib.Path(temporary)
            state, env_file, guard = self.base_environment(root)
            cleanup = self.write_executable(
                root / "cleanup.sh",
                '#!/usr/bin/env bash\necho cleanup-started\necho cleanup-warning >&2\nprintf \'%s\\n\' \'{"capacity_status":"warning","format":"camellia-remote-cleanup-result-v1","input_count":5,"output_count":2}\'\n',
            )
            result = self.run_wrapper(
                CLEANUP_WRAPPER,
                root,
                state,
                env_file,
                guard,
                CAMELLIA_REMOTE_CLEANUP_SCRIPT=cleanup,
                CAMELLIA_REMOTE_CLEANUP_OPERATION_TIMEOUT_SECONDS="60",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("cleanup-started", result.stdout)
            self.assertIn("cleanup-warning", result.stderr)
            recorded = self.summary(state, "cleanup")
            self.assertEqual(recorded["status"], "completed")
            self.assertEqual(recorded["input_count"], 5)
            self.assertEqual(recorded["output_count"], 2)

    def test_cleanup_guard_skip_is_durable_and_non_business(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-skip-") as temporary:
            root = pathlib.Path(temporary)
            state, env_file, guard = self.base_environment(root)
            guard.write_text("#!/usr/bin/env bash\necho skipped:maintenance\nexit 1\n")
            business = root / "business-called"
            cleanup = self.write_executable(root / "cleanup.sh", f"#!/usr/bin/env bash\ntouch {business}\nexit 0\n")
            result = self.run_wrapper(
                CLEANUP_WRAPPER,
                root,
                state,
                env_file,
                guard,
                CAMELLIA_REMOTE_CLEANUP_SCRIPT=cleanup,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.summary(state, "cleanup")["status"], "skipped")
            self.assertFalse(business.exists())

    def test_cleanup_child_failure_records_failed(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-failure-") as temporary:
            root = pathlib.Path(temporary)
            state, env_file, guard = self.base_environment(root)
            cleanup = self.write_executable(root / "cleanup.sh", "#!/usr/bin/env bash\necho child-failed >&2\nexit 7\n")
            result = self.run_wrapper(
                CLEANUP_WRAPPER,
                root,
                state,
                env_file,
                guard,
                CAMELLIA_REMOTE_CLEANUP_SCRIPT=cleanup,
            )
            self.assertEqual(result.returncode, 7)
            self.assertEqual(self.summary(state, "cleanup")["status"], "failed")
            self.assertIn("child-failed", result.stderr)

    def test_sigterm_records_unknown_and_terminates_child(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-signal-") as temporary:
            root = pathlib.Path(temporary)
            state, env_file, guard = self.base_environment(root)
            marker = root / "terminated"
            cleanup = self.write_executable(
                root / "cleanup.sh",
                f"#!/usr/bin/env bash\ntrap 'touch {marker}; exit 143' TERM INT HUP\nsleep 30\n",
            )
            environment = os.environ | {
                "CAMELLIA_REMOTE_PROJECT_DIR": str(root),
                "CAMELLIA_REMOTE_ENV_FILE": str(env_file),
                "CAMELLIA_REMOTE_MAINTENANCE_STATE_DIR": str(state),
                "CAMELLIA_REMOTE_MAINTENANCE_LEDGER_HELPER": str(LEDGER),
                "CAMELLIA_REMOTE_MAINTENANCE_GUARD_SCRIPT": str(guard),
                "CAMELLIA_REMOTE_CLEANUP_SCRIPT": str(cleanup),
            }
            process = subprocess.Popen(  # noqa: S603 - fixed repository wrapper and controlled fixture paths
                [str(CLEANUP_WRAPPER)], env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(0.3)
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130, stderr)
            self.assertEqual(self.summary(state, "cleanup")["status"], "unknown")
            self.assertTrue(marker.exists(), stdout)
            self.assertFalse(list(state.glob(".cleanup-wrapper-*")))

    def test_backup_success_validates_generation_and_artifact_paths(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-backup-wrapper-") as temporary:
            root = pathlib.Path(temporary)
            state, env_file, guard = self.base_environment(root)
            backup_dir = root / "backups"
            backup_dir.mkdir(mode=0o700)
            backup = self.write_executable(
                root / "backup.sh",
                """#!/usr/bin/env bash
set -euo pipefail
id="$CAMELLIA_REMOTE_BACKUP_OPERATION_ID"
stamp=20260817T000000Z
printf '%s' db > "$CAMELLIA_REMOTE_BACKUP_DIR/postgres-$stamp-$id.dump.age"
printf '%s' rec > "$CAMELLIA_REMOTE_BACKUP_DIR/recordings-$stamp-$id.bundle.age"
manifest="$CAMELLIA_REMOTE_BACKUP_DIR/backup-set-$stamp-$id.manifest.age"
printf '%s' manifest > "$manifest"
printf '%s' '{"backup_id":"'"$id"'","completed_at":"20260817T000000Z","format":"camellia-remote-backup-status-v2","generation":4,"manifest_filename":"backup-set-'"$stamp-$id"'.manifest.age","previous_backup_id":null,"recorded_at":"20260817T000001Z","status":"verified"}' > "$CAMELLIA_REMOTE_BACKUP_DIR/latest-verified.json"
echo backup-live
echo backup-diagnostic >&2
printf '%s\n' '{"backup_id":"'"$id"'","manifest":"'"$manifest"'","status":"created:verified"}'
""",
            )
            result = self.run_wrapper(
                BACKUP_WRAPPER,
                root,
                state,
                env_file,
                guard,
                CAMELLIA_REMOTE_BACKUP_SCRIPT=backup,
                CAMELLIA_REMOTE_BACKUP_DIR=backup_dir,
                CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER=ROOT / "scripts" / "backup_envelope.py",
                INVOCATION_ID="e" * 32,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("backup-live", result.stdout)
            self.assertIn("backup-diagnostic", result.stderr)
            recorded = self.summary(state, "backup")
            self.assertEqual(recorded["status"], "completed")
            self.assertEqual(recorded["artifact_generation"], 4)
            self.assertEqual(recorded["output_bytes"], len(b"db") + len(b"rec") + len(b"manifest"))

    def test_backup_active_lock_is_skipped_and_alerts(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-active-") as temporary:
            root = pathlib.Path(temporary)
            state, env_file, guard = self.base_environment(root)
            backup = self.write_executable(
                root / "backup.sh",
                "#!/usr/bin/env bash\necho skipped:active-run >&2\nexit 75\n",
            )
            result = self.run_wrapper(
                BACKUP_WRAPPER,
                root,
                state,
                env_file,
                guard,
                CAMELLIA_REMOTE_BACKUP_SCRIPT=backup,
                CAMELLIA_REMOTE_BACKUP_DIR=root / "backups",
                CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER=ROOT / "scripts" / "backup_envelope.py",
                INVOCATION_ID="f" * 32,
            )
            self.assertEqual(result.returncode, 75)
            self.assertEqual(self.summary(state, "backup")["status"], "skipped")
            freshness = subprocess.run(  # noqa: S603 - fixed repository wrapper and controlled fixture paths
                [str(FRESHNESS), "backup"],
                env=os.environ
                | {
                    "CAMELLIA_REMOTE_PROJECT_DIR": str(root),
                    "CAMELLIA_REMOTE_MAINTENANCE_STATE_DIR": str(state),
                    "CAMELLIA_REMOTE_MAINTENANCE_LEDGER_HELPER": str(LEDGER),
                },
                text=True,
                capture_output=True,
            )
            self.assertEqual(freshness.returncode, 30)
            self.assertIn('"state":"skipped"', freshness.stdout)

    def test_ledger_backend_failure_prevents_business_child(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-ledger-failure-") as temporary:
            root = pathlib.Path(temporary)
            state, env_file, guard = self.base_environment(root)
            state.chmod(0o755)
            marker = root / "called"
            cleanup = self.write_executable(root / "cleanup.sh", f"#!/usr/bin/env bash\ntouch {marker}\nexit 0\n")
            result = self.run_wrapper(
                CLEANUP_WRAPPER,
                root,
                state,
                env_file,
                guard,
                CAMELLIA_REMOTE_CLEANUP_SCRIPT=cleanup,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_failure_notifier_is_repeatable(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-notifier-") as temporary:
            root = pathlib.Path(temporary)
            state, _env_file, _guard = self.base_environment(root)
            systemctl = self.write_executable(
                root / "systemctl",
                "#!/usr/bin/env bash\nprintf '%s\\n' 0123456789abcdef0123456789abcdef\n",
            )
            environment = os.environ | {
                "CAMELLIA_REMOTE_PROJECT_DIR": str(root),
                "CAMELLIA_REMOTE_MAINTENANCE_STATE_DIR": str(state),
                "CAMELLIA_REMOTE_MAINTENANCE_LEDGER_HELPER": str(LEDGER),
                "CAMELLIA_REMOTE_SYSTEMCTL_BINARY": str(systemctl),
            }
            for _ in range(2):
                result = subprocess.run(  # noqa: S603 - fixed notifier and controlled fixture paths
                    [str(NOTIFIER), "camellia-remote-management-cleanup.service"],
                    env=environment,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.summary(state, "cleanup")["status"], "failed")
            self.assertEqual(len((state / "maintenance-events.jsonl").read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
