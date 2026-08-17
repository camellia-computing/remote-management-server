#!/usr/bin/env python3
"""Regression tests for the single-source shutdown budget contract."""

import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUDGET = ROOT / "deploy" / "shutdown-budget.sh"
COMPOSE = ROOT / "docker-compose.yaml"
RUN = ROOT / "run.sh"
STACK_UNIT = ROOT / "deploy" / "systemd" / "camellia-remote-management-stack.service"
START = ROOT / "deploy" / "start-management-stack.sh"
STOP = ROOT / "deploy" / "stop-management-stack.sh"


class ShutdownBudgetTests(unittest.TestCase):
    def run_budget(self, **values):
        environment = {"PATH": "/usr/bin:/bin"}
        environment.update(values)
        return subprocess.run(
            [str(BUDGET), "--values"],
            env=environment,
            text=True,
            capture_output=True,
        )

    def test_default_and_maximum_chain_are_accepted(self):
        default = self.run_budget()
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertEqual(default.stdout, "30 45 660\n")

        maximum = self.run_budget(
            CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS="600",
            CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS="615",
        )
        self.assertEqual(maximum.returncode, 0, maximum.stderr)
        self.assertEqual(maximum.stdout, "600 615 660\n")

    def test_budget_drift_fails_closed(self):
        result = self.run_budget(
            CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS="600",
            CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS="45",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must equal Gunicorn graceful timeout", result.stderr)

        result = self.run_budget(
            CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS="0",
            CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS="15",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("between 1 and 600", result.stderr)

    def test_env_file_is_used_without_executing_shell(self):
        with tempfile.TemporaryDirectory(prefix="camellia-shutdown-budget-") as temporary:
            env_file = pathlib.Path(temporary) / "management.env"
            env_file.write_text(
                "CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS=60\n"
                "CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS=75\n"
            )
            result = subprocess.run(
                [str(BUDGET), "--env-file", str(env_file), "--values"],
                env={"PATH": "/usr/bin:/bin"},
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "60 75 660\n")

    def test_all_lifecycle_layers_reference_the_same_contract(self):
        compose = COMPOSE.read_text()
        self.assertIn("stop_grace_period: ${CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS:-45}s", compose)
        self.assertIn("CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS", compose)

        run = RUN.read_text()
        self.assertIn("deploy/shutdown-budget.sh", run)
        self.assertLess(run.index("shutdown-budget.sh"), run.index("exec gunicorn"))

        unit = STACK_UNIT.read_text()
        self.assertIn("ExecStop=/bin/kill -TERM $MAINPID", unit)
        self.assertIn("ExecStopPost=/opt/camellia-remote-management/deploy/stop-management-stack.sh", unit)
        self.assertIn("TimeoutStopSec=11min", unit)
        self.assertIn("KillMode=control-group", unit)
        self.assertNotIn("TimeoutStopSec=2min", unit)

        self.assertIn("shutdown-budget.sh", START.read_text())
        self.assertIn('stop --timeout "$docker_stop" management', START.read_text())
        self.assertIn('down --timeout "$docker_stop"', STOP.read_text())


if __name__ == "__main__":
    unittest.main()
