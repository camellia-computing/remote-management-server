#!/usr/bin/env python3
"""Deterministic regression tests for Management health supervision."""

import os
import pathlib
import stat
import subprocess
import tempfile
import textwrap
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUPERVISOR = ROOT / "deploy" / "supervise-management-stack.sh"
HEALTH = ROOT / "deploy" / "check-management-health.sh"
STACK_UNIT = ROOT / "deploy" / "systemd" / "camellia-remote-management-stack.service"


def executable(path: pathlib.Path, content: str) -> pathlib.Path:
    path.write_text(textwrap.dedent(content).lstrip())
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


def supervisor_fixture(root: pathlib.Path):
    project = root / "project"
    project.mkdir()
    (project / "docker-compose.yaml").write_text("services: {}\n")
    env_file = root / "management.env"
    env_file.write_text("TEST=true\n")
    env_file.chmod(0o600)
    runtime = root / "run"
    calls = root / "calls"
    docker = executable(root / "docker", "#!/bin/sh\nexit 0\n")
    controller = executable(
        root / "controller",
        """
        #!/usr/bin/env python3
        import os
        import time
        from pathlib import Path
        calls = Path(os.environ["FAKE_CONTROLLER_CALLS"])
        with calls.open("a") as output:
            output.write("controller\\n")
        time.sleep(float(os.environ.get("FAKE_CONTROLLER_SLEEP", "0")))
        raise SystemExit(int(os.environ.get("FAKE_CONTROLLER_EXIT", "0")))
        """,
    )
    probe = executable(
        root / "probe",
        """
        #!/usr/bin/env python3
        import os
        from pathlib import Path
        sequence = os.environ["FAKE_PROBE_SEQUENCE"].split(",")
        cursor = Path(os.environ["FAKE_PROBE_CURSOR"])
        try:
            index = int(cursor.read_text())
        except FileNotFoundError:
            index = 0
        cursor.write_text(str(index + 1))
        value = sequence[min(index, len(sequence) - 1)]
        if value == "healthy":
            print("healthy running healthy")
            raise SystemExit(0)
        if value == "starting":
            print("starting running starting")
            raise SystemExit(10)
        if value == "dependency":
            print("dependency_unhealthy running unhealthy")
            raise SystemExit(20)
        if value == "process":
            print("process_failure exited missing")
            raise SystemExit(30)
        print("control_failure unknown unknown")
        raise SystemExit(40)
        """,
    )
    notify = executable(
        root / "notify",
        """
        #!/usr/bin/env python3
        import os
        from pathlib import Path
        with Path(os.environ["FAKE_NOTIFY_CALLS"]).open("a") as output:
            output.write(" ".join(os.sys.argv[1:]) + "\\n")
        raise SystemExit(int(os.environ.get("FAKE_NOTIFY_EXIT", "0")))
        """,
    )
    base_environment = os.environ | {
        "CAMELLIA_REMOTE_SUPERVISION_INTERVAL_SECONDS": "1",
        "CAMELLIA_REMOTE_SUPERVISION_STABLE_SUCCESSES": "3",
        "CAMELLIA_REMOTE_SUPERVISION_RECOVERY_ATTEMPTS": "3",
        "CAMELLIA_REMOTE_SUPERVISION_RECOVERY_WINDOW_SECONDS": "600",
        "CAMELLIA_REMOTE_SUPERVISION_HEALTH_TIMEOUT_SECONDS": "5",
        "FAKE_CONTROLLER_CALLS": str(calls),
        "FAKE_PROBE_CURSOR": str(root / "probe.cursor"),
        "FAKE_NOTIFY_CALLS": str(root / "notify.calls"),
    }
    command = [
        str(SUPERVISOR),
        "--project-dir",
        str(project),
        "--env-file",
        str(env_file),
        "--runtime-dir",
        str(runtime),
        "--docker-binary",
        str(docker),
        "--controller",
        str(controller),
        "--health-probe",
        str(probe),
        "--notify-binary",
        str(notify),
        "--timeout-binary",
        "/usr/bin/timeout",
    ]
    return command, base_environment, runtime, calls


class ManagementSupervisorTests(unittest.TestCase):
    def run_supervisor(self, sequence, cycles, root, **environment):
        command, base_environment, runtime, calls = supervisor_fixture(root)
        result = subprocess.run(
            [*command, "--max-cycles", str(cycles)],
            env=base_environment | {"FAKE_PROBE_SEQUENCE": sequence, **environment},
            text=True,
            capture_output=True,
            timeout=max(15, cycles + 8),
        )
        return result, runtime, calls, root / "notify.calls"

    def test_healthy_requires_stable_window_before_ready(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-healthy-") as temporary:
            result, runtime, calls, notifications = self.run_supervisor(
                "healthy,healthy,healthy", 3, pathlib.Path(temporary)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text(), "controller\n")
            state = (runtime / "admission.state").read_text()
            self.assertIn("state=ready", state)
            self.assertIn("--ready", notifications.read_text())
            self.assertEqual(stat.S_IMODE((runtime / "admission.state").stat().st_mode), 0o600)

    def test_dependency_failure_isolation_does_not_restart_container(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-dependency-") as temporary:
            result, runtime, calls, _notifications = self.run_supervisor(
                "dependency,healthy,healthy,healthy", 4, pathlib.Path(temporary)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text(), "controller\n")
            self.assertIn("state=ready", (runtime / "admission.state").read_text())

    def test_process_failure_runs_one_complete_recovery(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-process-") as temporary:
            result, runtime, calls, _notifications = self.run_supervisor(
                "process,healthy,healthy,healthy", 4, pathlib.Path(temporary)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls.read_text().splitlines(), ["controller", "controller"])
            self.assertIn("state=ready", (runtime / "admission.state").read_text())

    def test_process_recovery_has_a_hard_cap(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-cap-") as temporary:
            result, runtime, calls, notifications = self.run_supervisor(
                "process,process,process,process,process", 5, pathlib.Path(temporary)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls.read_text().splitlines()), 4)  # initial + three retries
            state = (runtime / "admission.state").read_text()
            self.assertIn("state=isolated", state)
            self.assertIn("recovery_exhausted", notifications.read_text())

    def test_flapping_never_reenters_before_a_new_stable_window(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-flapping-") as temporary:
            result, _runtime, _calls, notifications = self.run_supervisor(
                "healthy,healthy,dependency,healthy,healthy,healthy", 6, pathlib.Path(temporary)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            ready_lines = [line for line in notifications.read_text().splitlines() if "--ready" in line]
            self.assertEqual(len(ready_lines), 1)
            lines = notifications.read_text().splitlines()
            self.assertEqual(lines[-1], ready_lines[0])

    def test_control_failure_is_a_unit_failure(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-control-") as temporary:
            result, runtime, _calls, _notifications = self.run_supervisor("control", 1, pathlib.Path(temporary))
            self.assertEqual(result.returncode, 125)
            self.assertIn("state=isolated", (runtime / "admission.state").read_text())
            self.assertIn("reason=control_failure", (runtime / "admission.state").read_text())

    def test_existing_state_symlink_is_rejected_before_controller(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-state-") as temporary:
            root = pathlib.Path(temporary)
            command, env, runtime, calls = supervisor_fixture(root)
            runtime.mkdir(mode=0o700)
            target = root / "outside.state"
            target.write_text("state=ready\n")
            (runtime / "admission.state").symlink_to(target)
            result = subprocess.run(
                [*command, "--max-cycles", "1"],
                env=env | {"FAKE_PROBE_SEQUENCE": "healthy"},
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 125)
            self.assertFalse(calls.exists())
            self.assertEqual(target.read_text(), "state=ready\n")

    def test_health_probe_timeout_is_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-timeout-") as temporary:
            root = pathlib.Path(temporary)
            command, env, runtime, _calls = supervisor_fixture(root)
            slow_probe = executable(
                root / "slow-probe",
                "#!/bin/sh\nsleep 3\n",
            )
            command[command.index("--health-probe") + 1] = str(slow_probe)
            env = env | {
                "FAKE_PROBE_SEQUENCE": "healthy",
                "CAMELLIA_REMOTE_SUPERVISION_HEALTH_TIMEOUT_SECONDS": "1",
            }
            result = subprocess.run(
                [*command, "--max-cycles", "1"],
                env=env,
                text=True,
                capture_output=True,
                timeout=8,
            )
            self.assertEqual(result.returncode, 125)
            self.assertIn("reason=health_probe_timeout", (runtime / "admission.state").read_text())

    def test_term_stops_controller_before_stack_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="camellia-supervisor-stop-") as temporary:
            root = pathlib.Path(temporary)
            command, env, runtime, calls = supervisor_fixture(root)
            process = subprocess.Popen(
                [*command, "--max-cycles", "100"],
                env=env
                | {
                    "FAKE_PROBE_SEQUENCE": "healthy",
                    "FAKE_CONTROLLER_SLEEP": "20",
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                for _ in range(20):
                    if calls.exists():
                        break
                    process.poll()
                    if process.returncode is not None:
                        self.fail("supervisor exited before controller started")
                    time.sleep(0.05)
                process.terminate()
                stdout, stderr = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            self.assertEqual(process.returncode, 0, (stdout, stderr))
            self.assertEqual(calls.read_text().splitlines(), ["controller"])
            self.assertIn("reason=supervisor_stopping", (runtime / "admission.state").read_text())


class HealthInspectorTests(unittest.TestCase):
    def fixture(self, root):
        project = root / "project"
        project.mkdir()
        (project / "docker-compose.yaml").write_text("services: {}\n")
        env_file = root / "management.env"
        env_file.write_text("TEST=true\n")
        env_file.chmod(0o600)
        docker = executable(
            root / "docker",
            """
            #!/usr/bin/env python3
            import os
            import sys
            args = sys.argv[1:]
            if "ps" in args:
                if os.environ.get("FAKE_DOCKER_FAIL") == "1":
                    raise SystemExit(42)
                print(os.environ.get("FAKE_IDS", "container-1"), end="\\n")
                raise SystemExit(0)
            if args[:2] == ["container", "inspect"]:
                if os.environ.get("FAKE_DOCKER_FAIL") == "1":
                    raise SystemExit(42)
                print(os.environ.get("FAKE_INSPECTION", "running healthy"))
                raise SystemExit(0)
            raise SystemExit(42)
            """,
        )
        return project, env_file, docker

    def test_health_states_are_classified_without_restarting(self):
        expected = {
            "running healthy": (0, "healthy running healthy"),
            "running starting": (10, "starting running starting"),
            "running unhealthy": (20, "dependency_unhealthy running unhealthy"),
            "exited missing": (30, "process_failure exited missing"),
        }
        for inspection, (status, output) in expected.items():
            with (
                self.subTest(inspection=inspection),
                tempfile.TemporaryDirectory(prefix="camellia-health-inspector-") as temporary,
            ):
                project, env_file, docker = self.fixture(pathlib.Path(temporary))
                result = subprocess.run(
                    [
                        str(HEALTH),
                        "--project-dir",
                        str(project),
                        "--env-file",
                        str(env_file),
                        "--docker-binary",
                        str(docker),
                    ],
                    env=os.environ | {"FAKE_INSPECTION": inspection},
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(result.stdout.strip(), output)

    def test_control_or_ambiguous_state_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="camellia-health-control-") as temporary:
            root = pathlib.Path(temporary)
            project, env_file, docker = self.fixture(root)
            result = subprocess.run(
                [
                    str(HEALTH),
                    "--project-dir",
                    str(project),
                    "--env-file",
                    str(env_file),
                    "--docker-binary",
                    str(docker),
                ],
                env=os.environ | {"FAKE_DOCKER_FAIL": "1"},
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 40)
            self.assertTrue(result.stdout.startswith("control_failure"))


class SystemdSupervisorContractTests(unittest.TestCase):
    def test_unit_uses_long_lived_notify_supervisor_and_bounded_restart(self):
        unit = STACK_UNIT.read_text()
        self.assertIn("Type=notify", unit)
        self.assertIn("NotifyAccess=main", unit)
        self.assertIn("ExecStart=/opt/camellia-remote-management/deploy/supervise-management-stack.sh", unit)
        self.assertIn("ExecStop=/bin/kill -TERM $MAINPID", unit)
        self.assertIn("ExecStopPost=/opt/camellia-remote-management/deploy/stop-management-stack.sh", unit)
        self.assertIn("Restart=on-failure", unit)
        self.assertIn("RestartSec=30s", unit)
        self.assertIn("WatchdogSec=45s", unit)
        self.assertIn("StartLimitIntervalSec=10min", unit)
        self.assertIn("StartLimitBurst=4", unit)


if __name__ == "__main__":
    unittest.main()
