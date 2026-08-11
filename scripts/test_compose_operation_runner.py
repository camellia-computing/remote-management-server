#!/usr/bin/env python3
"""Regression tests for supervised one-shot Compose operations."""

import os
import pathlib
import subprocess
import tempfile
import textwrap
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNNER = ROOT / "deploy" / "run-compose-operation.sh"


class ComposeOperationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="camellia-compose-operation-")
        self.root = pathlib.Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "docker-compose.yaml").write_text("services: {}\n")
        self.env_file = self.root / "management.env"
        self.env_file.write_text("TEST=true\n")
        self.env_file.chmod(0o600)
        self.state = self.root / "container-state"
        self.calls = self.root / "calls"
        self.fake_docker = self.root / "docker"
        self.fake_docker.write_text(
            textwrap.dedent(
                """
                #!/usr/bin/env python3
                import os, pathlib, signal, sys, time

                args = sys.argv[1:]
                state = pathlib.Path(os.environ["FAKE_CONTAINER_STATE"])
                calls = pathlib.Path(os.environ["FAKE_DOCKER_CALLS"])
                with calls.open("a") as output:
                    output.write(" ".join(args) + "\\n")

                if args[:2] == ["container", "inspect"]:
                    if not state.exists():
                        raise SystemExit(1)
                    print(state.read_text().strip())
                    raise SystemExit(0)
                if args[:2] == ["container", "ls"]:
                    if os.environ.get("FAKE_DOCKER_MODE") == "state-query-fail":
                        raise SystemExit(71)
                    if state.exists():
                        print("camellia-remote-cleanup-0123456789abcdef-cle")
                    raise SystemExit(0)
                if args[:2] in (["container", "stop"], ["container", "kill"], ["container", "rm"]):
                    state.unlink(missing_ok=True)
                    raise SystemExit(0)
                if "run" in args:
                    label = next(value for value in args if value.startswith("io.camellia.remote.operation-id="))
                    state.write_text(label.split("=", 1)[1])
                    if os.environ.get("FAKE_DOCKER_MODE") == "hang":
                        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
                        time.sleep(30)
                    payload = sys.stdin.buffer.read()
                    if payload:
                        sys.stdout.buffer.write(payload)
                    state.unlink(missing_ok=True)
                    raise SystemExit(int(os.environ.get("FAKE_DOCKER_EXIT", "0")))
                raise SystemExit(90)
                """
            ).lstrip()
        )
        self.fake_docker.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def environment(self, **extra):
        return os.environ | {
            "FAKE_CONTAINER_STATE": str(self.state),
            "FAKE_DOCKER_CALLS": str(self.calls),
            **extra,
        }

    def command(self, *, timeout=5):
        return [
            str(RUNNER),
            "--project-dir",
            str(self.project),
            "--env-file",
            str(self.env_file),
            "--docker-binary",
            str(self.fake_docker),
            "--operation-id",
            "0123456789abcdef-cleanup",
            "--operation-kind",
            "cleanup",
            "--service",
            "management",
            "--timeout-seconds",
            str(timeout),
            "--stop-seconds",
            "1",
            "--",
            "python",
            "manage.py",
            "purge_expired_state",
        ]

    def test_success_preserves_stream_and_removes_named_container(self):
        result = subprocess.run(  # noqa: S603 - fixed repository runner and controlled fixture arguments
            self.command(),
            input=b"stream-canary\x00payload",
            env=self.environment(),
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"stream-canary\x00payload")
        self.assertFalse(self.state.exists())
        calls = self.calls.read_text()
        self.assertIn("--name camellia-remote-cleanup-0123456789abcdef-cle", calls)
        self.assertIn("--label io.camellia.remote.operation-id=0123456789abcdef-cleanup", calls)

    def test_internal_timeout_stops_and_confirms_remote_container_exit(self):
        started = time.monotonic()
        result = subprocess.run(  # noqa: S603 - fixed repository runner and controlled fixture arguments
            self.command(timeout=1),
            env=self.environment(FAKE_DOCKER_MODE="hang"),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("operation_timeout", result.stderr)
        self.assertFalse(self.state.exists())
        self.assertIn("container stop --time 1", self.calls.read_text())

    def test_host_termination_is_propagated_and_remote_exit_is_confirmed(self):
        process = subprocess.Popen(  # noqa: S603 - fixed repository runner and controlled fixture arguments
            self.command(timeout=20),
            env=self.environment(FAKE_DOCKER_MODE="hang"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 3
        while not self.state.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.state.exists(), "fake remote container was not created")
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(stdout, "")
        self.assertEqual(process.returncode, 130, stderr)
        self.assertIn("operation_cancelled", stderr)
        self.assertFalse(self.state.exists())
        self.assertIn("container stop --time 1", self.calls.read_text())

    def test_unconfirmed_remote_state_fails_closed(self):
        result = subprocess.run(  # noqa: S603 - fixed repository runner and controlled fixture arguments
            self.command(),
            env=self.environment(FAKE_DOCKER_MODE="state-query-fail"),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn("cannot confirm remote container state", result.stderr)


if __name__ == "__main__":
    unittest.main()
