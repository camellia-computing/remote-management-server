#!/usr/bin/env python3
"""Regression tests for the durable maintenance ledger and freshness query."""

import datetime as dt
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "maintenance_ledger.py"
SPEC = importlib.util.spec_from_file_location("maintenance_ledger", HELPER)
LEDGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER)


def timestamp(value=None):
    value = value or dt.datetime.now(dt.UTC)
    return value.strftime("%Y%m%dT%H%M%SZ")


class MaintenanceLedgerTests(unittest.TestCase):
    def invoke(self, *arguments, check=False):
        result = subprocess.run(  # noqa: S603 - fixed local repository helper
            [str(HELPER), *map(str, arguments)],
            text=True,
            capture_output=True,
        )
        if check and result.returncode != 0:
            self.fail(f"ledger command failed: {result.stderr}")
        return result

    def record(self, state, operation, kind, status, started_at, *extra, check=True):
        return self.invoke(
            "record",
            "--state-dir",
            state,
            "--operation-id",
            operation,
            "--kind",
            kind,
            "--status",
            status,
            "--reason",
            {
                "scheduled": "timer-triggered",
                "started": "execution-started",
                "heartbeat": f"{kind}-running",
                "completed": "verified",
                "failed": f"{kind}-exit",
                "skipped": "active-run",
                "unknown": "interrupted",
            }[status],
            "--started-at",
            started_at,
            "--deadline-seconds",
            "600",
            *extra,
            check=check,
        )

    def test_lifecycle_is_append_only_and_failure_does_not_advance_success(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-ledger-") as temporary:
            state = pathlib.Path(temporary) / "state"
            started = timestamp()
            first = "1" * 32
            self.record(state, first, "cleanup", "scheduled", started)
            self.record(state, first, "cleanup", "started", started)
            self.record(state, first, "cleanup", "heartbeat", started, "--duration-seconds", "1")
            completed = self.record(
                state,
                first,
                "cleanup",
                "completed",
                started,
                "--duration-seconds",
                "2",
                "--input-count",
                "8",
                "--output-count",
                "7",
            )
            success = json.loads(completed.stdout)
            self.assertEqual(success["status"], "completed")
            self.assertEqual(success["last_success_operation_id"], first)
            self.assertEqual(success["heartbeat_at"], None)

            skipped_id = "2" * 32
            self.record(state, skipped_id, "cleanup", "scheduled", started)
            skipped = self.record(
                state,
                skipped_id,
                "cleanup",
                "skipped",
                started,
                "--duration-seconds",
                "0",
            )
            skipped_summary = json.loads(skipped.stdout)
            self.assertEqual(skipped_summary["last_success_at"], success["last_success_at"])
            self.assertEqual(skipped_summary["last_success_operation_id"], first)
            self.assertEqual(skipped_summary["consecutive_skips"], 1)

            failed_id = "3" * 32
            self.record(state, failed_id, "cleanup", "scheduled", started)
            failed = self.record(
                state,
                failed_id,
                "cleanup",
                "failed",
                started,
                "--duration-seconds",
                "1",
            )
            failed_summary = json.loads(failed.stdout)
            self.assertEqual(failed_summary["last_success_at"], success["last_success_at"])
            self.assertEqual(failed_summary["consecutive_failures"], 1)
            events = (state / "maintenance-events.jsonl").read_text().splitlines()
            self.assertEqual(len(events), 8)
            decoded = [json.loads(line) for line in events]
            self.assertEqual([item["sequence"] for item in decoded], list(range(1, 9)))
            self.assertIsNone(decoded[0]["previous_digest"])
            for previous, current in zip(decoded, decoded[1:], strict=False):
                self.assertEqual(current["previous_digest"], previous["digest"])

    def test_completed_backup_requires_generation_and_ciphertext_bytes(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-backup-") as temporary:
            state = pathlib.Path(temporary) / "state"
            started = timestamp()
            operation = "4" * 32
            self.record(state, operation, "backup", "scheduled", started)
            self.record(state, operation, "backup", "started", started)
            incomplete = self.record(
                state,
                operation,
                "backup",
                "completed",
                started,
                "--duration-seconds",
                "2",
                check=False,
            )
            self.assertNotEqual(incomplete.returncode, 0)
            complete = self.record(
                state,
                operation,
                "backup",
                "completed",
                started,
                "--duration-seconds",
                "2",
                "--artifact-generation",
                "9",
                "--output-bytes",
                "4096",
            )
            summary = json.loads(complete.stdout)
            self.assertEqual(summary["artifact_generation"], 9)
            self.assertEqual(summary["output_bytes"], 4096)

    def test_terminal_state_is_idempotent_but_cannot_change(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-terminal-") as temporary:
            state = pathlib.Path(temporary) / "state"
            started = timestamp()
            operation = "5" * 32
            self.record(state, operation, "cleanup", "scheduled", started)
            self.record(state, operation, "cleanup", "started", started)
            arguments = (
                "--duration-seconds",
                "1",
                "--input-count",
                "0",
                "--output-count",
                "0",
            )
            self.record(state, operation, "cleanup", "completed", started, *arguments)
            self.record(state, operation, "cleanup", "completed", started, *arguments)
            self.assertEqual(len((state / "maintenance-events.jsonl").read_text().splitlines()), 3)
            conflict = self.record(
                state,
                operation,
                "cleanup",
                "failed",
                started,
                "--duration-seconds",
                "2",
                check=False,
            )
            self.assertNotEqual(conflict.returncode, 0)
            self.assertIn("terminal state", conflict.stderr)

    def test_global_append_lock_preserves_concurrent_events(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-concurrent-") as temporary:
            state = pathlib.Path(temporary) / "state"
            state.mkdir(mode=0o700)
            started = timestamp()
            commands = []
            for kind, operation in (("backup", "6" * 32), ("cleanup", "7" * 32)):
                commands.append(
                    subprocess.Popen(  # noqa: S603 - fixed local repository helper
                        [
                            str(HELPER),
                            "record",
                            "--state-dir",
                            str(state),
                            "--operation-id",
                            operation,
                            "--kind",
                            kind,
                            "--status",
                            "scheduled",
                            "--reason",
                            "timer-triggered",
                            "--started-at",
                            started,
                            "--deadline-seconds",
                            "600",
                        ],
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                )
            for process in commands:
                _, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
            events = [json.loads(line) for line in (state / "maintenance-events.jsonl").read_text().splitlines()]
            self.assertEqual({item["kind"] for item in events}, {"backup", "cleanup"})
            self.assertEqual({item["sequence"] for item in events}, {1, 2})

    def test_unsafe_or_corrupt_state_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-safety-") as temporary:
            root = pathlib.Path(temporary)
            started = timestamp()
            wide = root / "wide"
            wide.mkdir(mode=0o700)
            wide.chmod(0o755)
            rejected = self.record(wide, "8" * 32, "cleanup", "scheduled", started, check=False)
            self.assertNotEqual(rejected.returncode, 0)

            state = root / "state"
            self.record(state, "9" * 32, "cleanup", "scheduled", started)
            summary = state / "latest-cleanup.json"
            summary.unlink()
            summary.symlink_to(root / "outside")
            rejected = self.record(state, "9" * 32, "cleanup", "started", started, check=False)
            self.assertNotEqual(rejected.returncode, 0)

            summary.unlink()
            (state / "maintenance-events.jsonl").write_text("not-json\n")
            rejected = self.record(state, "a" * 32, "backup", "scheduled", started, check=False)
            self.assertNotEqual(rejected.returncode, 0)

    def test_failure_notification_closes_running_operation_and_is_idempotent(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-notify-") as temporary:
            state = pathlib.Path(temporary) / "state"
            started = timestamp()
            operation = "b" * 32
            self.record(state, operation, "cleanup", "scheduled", started)
            self.record(state, operation, "cleanup", "started", started)
            for _ in range(2):
                result = self.invoke(
                    "notify-failure",
                    "--state-dir",
                    state,
                    "--kind",
                    "cleanup",
                    "--notification-id",
                    operation,
                    check=True,
                )
                self.assertEqual(json.loads(result.stdout)["status"], "failed")
            self.assertEqual(len((state / "maintenance-events.jsonl").read_text().splitlines()), 3)

    def test_freshness_distinguishes_never_running_failed_current_stale_and_clock_anomaly(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-freshness-") as temporary:
            state = pathlib.Path(temporary) / "state"
            missing = self.invoke(
                "check",
                "--state-dir",
                state,
                "--kind",
                "cleanup",
                "--maximum-age-seconds",
                "60",
            )
            self.assertEqual(missing.returncode, 20)
            self.assertEqual(json.loads(missing.stdout)["state"], "never-run")

            started_time = dt.datetime.now(dt.UTC).replace(microsecond=0)
            started = timestamp(started_time)
            operation = "c" * 32
            self.record(state, operation, "cleanup", "scheduled", started)
            running = self.invoke(
                "check",
                "--state-dir",
                state,
                "--kind",
                "cleanup",
                "--maximum-age-seconds",
                "60",
                "--now",
                timestamp(started_time + dt.timedelta(seconds=5)),
            )
            self.assertEqual(running.returncode, 0)
            self.assertEqual(json.loads(running.stdout)["state"], "running")

            self.record(state, operation, "cleanup", "started", started)
            self.record(
                state,
                operation,
                "cleanup",
                "completed",
                started,
                "--duration-seconds",
                "1",
                "--input-count",
                "0",
                "--output-count",
                "0",
            )
            current = self.invoke(
                "check",
                "--state-dir",
                state,
                "--kind",
                "cleanup",
                "--maximum-age-seconds",
                "60",
                "--now",
                timestamp(started_time + dt.timedelta(seconds=30)),
            )
            self.assertEqual(current.returncode, 0)
            self.assertEqual(json.loads(current.stdout)["state"], "healthy")
            stale = self.invoke(
                "check",
                "--state-dir",
                state,
                "--kind",
                "cleanup",
                "--maximum-age-seconds",
                "60",
                "--now",
                timestamp(started_time + dt.timedelta(seconds=120)),
            )
            self.assertEqual(stale.returncode, 40)
            self.assertEqual(json.loads(stale.stdout)["state"], "stale")
            backwards = self.invoke(
                "check",
                "--state-dir",
                state,
                "--kind",
                "cleanup",
                "--maximum-age-seconds",
                "60",
                "--clock-skew-seconds",
                "0",
                "--now",
                timestamp(started_time - dt.timedelta(seconds=1)),
            )
            self.assertEqual(backwards.returncode, 50)
            self.assertEqual(json.loads(backwards.stdout)["state"], "clock-anomaly")

            failed_id = "d" * 32
            failed_started = timestamp()
            self.record(state, failed_id, "cleanup", "scheduled", failed_started)
            self.record(
                state,
                failed_id,
                "cleanup",
                "failed",
                failed_started,
                "--duration-seconds",
                "0",
            )
            failed = self.invoke(
                "check",
                "--state-dir",
                state,
                "--kind",
                "cleanup",
                "--maximum-age-seconds",
                "60",
            )
            self.assertEqual(failed.returncode, 30)
            self.assertEqual(json.loads(failed.stdout)["state"], "failed")

    def test_atomic_writer_retries_short_writes(self):
        writes = []

        def short_write(_fd, value):
            writes.append(bytes(value))
            return min(2, len(value))

        with mock.patch.object(LEDGER.os, "write", side_effect=short_write):
            LEDGER._write_all(99, b"abcdefg")
        self.assertEqual([len(value) for value in writes], [7, 5, 3, 1])


if __name__ == "__main__":
    unittest.main()
