#!/usr/bin/env python3
"""Regression tests for the migration-before-application deployment gate."""

import fcntl
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
STACK_UNIT = ROOT / "deploy" / "systemd" / "camellia-remote-management-stack.service"
CONTROLLER = ROOT / "deploy" / "start-management-stack.sh"
MAINTENANCE = ROOT / "deploy" / "management-maintenance.sh"


def compose_service(name):
    lines = (ROOT / "docker-compose.yaml").read_text().splitlines()
    start = lines.index(f"  {name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("  ") and not lines[index].startswith("    ") and lines[index].endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def deployment_fixture(root):
    project = root / "project"
    project.mkdir()
    (project / "docker-compose.yaml").write_text("services: {}\n")
    env_file = root / "management.env"
    env_file.write_text("TEST=true\n")
    env_file.chmod(0o600)
    runtime = root / "run"
    calls = root / "calls"
    fake_docker = root / "docker"
    fake_docker.write_text(
        textwrap.dedent(
            """
            #!/usr/bin/env python3
            import os, pathlib, sys
            calls = pathlib.Path(os.environ["FAKE_DOCKER_CALLS"])
            with calls.open("a") as output:
                output.write(" ".join(sys.argv[1:]) + "\\n")
            args = sys.argv[1:]
            if "ps" in args:
                if os.environ.get("FAKE_PS_FAIL") == "1":
                    raise SystemExit(42)
                if os.environ.get("FAKE_MANAGEMENT_RUNNING") == "1":
                    print("management")
            if "run" in args and os.environ.get("FAKE_MIGRATION_FAIL") == "1":
                raise SystemExit(41)
            raise SystemExit(0)
            """
        ).lstrip()
    )
    fake_docker.chmod(0o755)
    command = [
        str(CONTROLLER),
        "--docker-binary",
        str(fake_docker),
        "--project-dir",
        str(project),
        "--env-file",
        str(env_file),
        "--runtime-dir",
        str(runtime),
        "--lease-file",
        str(runtime / "maintenance.lease"),
    ]
    env = os.environ | {"FAKE_DOCKER_CALLS": str(calls)}
    return command, env, calls, runtime, env_file


class DeploymentGateTests(unittest.TestCase):
    def test_official_lifecycle_has_no_online_reload_or_engine_app_restart(self):
        unit = STACK_UNIT.read_text()
        self.assertNotIn("ExecReload=", unit)
        self.assertNotIn("ExecStartPre=/usr/bin/docker", unit)
        self.assertIn("ExecStart=/opt/camellia-remote-management/start-management-stack.sh", unit)

        management = compose_service("management")
        self.assertIn('restart: "no"', management)
        self.assertNotIn("depends_on:", management)

        run_script = (ROOT / "run.sh").read_text()
        migration_check = run_script.index("python manage.py migrate --check")
        gunicorn = run_script.index("exec gunicorn")
        self.assertLess(migration_check, gunicorn)

        maintenance = MAINTENANCE.read_text()
        self.assertIn('deployment_lock="$lease_dir/deployment.lock"', maintenance)
        enter = maintenance.index('if [[ "$command" == "enter" ]]')
        lock = maintenance.index("    acquire_deployment_lock", enter)
        lease_create = maintenance.index("    if ! (set -o noclobber", enter)
        self.assertLess(lock, lease_create)

    def test_controller_stops_old_app_before_migration_and_starts_after_success(self):
        with tempfile.TemporaryDirectory(prefix="camellia-deployment-gate-") as temporary:
            root = pathlib.Path(temporary)
            command, env, calls, _runtime, _env_file = deployment_fixture(root)
            result = subprocess.run(command, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            log = calls.read_text().splitlines()
            stop_index = next(
                index for index, line in enumerate(log) if " stop " in f" {line} " and line.endswith("management")
            )
            migration_index = next(
                index for index, line in enumerate(log) if " run " in f" {line} " and line.endswith("migrate")
            )
            app_start_index = next(
                index for index, line in enumerate(log) if " up " in f" {line} " and line.endswith("management")
            )
            self.assertLess(stop_index, migration_index)
            self.assertLess(migration_index, app_start_index)

            calls.write_text("")
            failed = subprocess.run(
                command,
                env=env | {"FAKE_MIGRATION_FAIL": "1"},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(failed.returncode, 0)
            failed_log = calls.read_text().splitlines()
            self.assertTrue(any(" run " in f" {line} " and line.endswith("migrate") for line in failed_log))
            self.assertFalse(any(" up " in f" {line} " and line.endswith("management") for line in failed_log))

    def test_controller_fails_closed_on_state_query_and_running_old_app(self):
        with tempfile.TemporaryDirectory(prefix="camellia-deployment-inspection-") as temporary:
            root = pathlib.Path(temporary)
            command, env, calls, _runtime, _env_file = deployment_fixture(root)
            failed_query = subprocess.run(
                command,
                env=env | {"FAKE_PS_FAIL": "1"},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(failed_query.returncode, 0)
            self.assertIn("cannot inspect running services", failed_query.stderr)
            query_log = calls.read_text().splitlines()
            self.assertFalse(any(" run " in f" {line} " and line.endswith("migrate") for line in query_log))
            self.assertFalse(any(" up " in f" {line} " and line.endswith("management") for line in query_log))

            calls.write_text("")
            still_running = subprocess.run(
                command,
                env=env | {"FAKE_MANAGEMENT_RUNNING": "1"},
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(still_running.returncode, 0)
            self.assertIn("remained online", still_running.stderr)
            running_log = calls.read_text().splitlines()
            self.assertFalse(any(" run " in f" {line} " and line.endswith("migrate") for line in running_log))

    def test_controller_rejects_lock_collision_and_symlinked_inputs_before_docker(self):
        with tempfile.TemporaryDirectory(prefix="camellia-deployment-boundary-") as temporary:
            root = pathlib.Path(temporary)
            command, env, calls, runtime, env_file = deployment_fixture(root)
            runtime.mkdir(mode=0o700)
            lock_path = runtime / "deployment.lock"
            with lock_path.open("a") as lock:
                lock_path.chmod(0o600)
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                collision = subprocess.run(command, env=env, text=True, capture_output=True)
            self.assertEqual(collision.returncode, 75, collision.stderr)
            self.assertFalse(calls.exists(), "a lock collision must be detected before Docker")

            env_link = root / "linked-management.env"
            env_link.symlink_to(env_file)
            linked_command = list(command)
            env_index = linked_command.index("--env-file") + 1
            linked_command[env_index] = str(env_link)
            linked = subprocess.run(linked_command, env=env, text=True, capture_output=True)
            self.assertNotEqual(linked.returncode, 0)
            self.assertIn("symlinked", linked.stderr)
            self.assertFalse(calls.exists(), "unsafe deployment paths must be rejected before Docker")

    def test_controller_refuses_maintenance_lease_before_docker(self):
        with tempfile.TemporaryDirectory(prefix="camellia-deployment-lease-") as temporary:
            root = pathlib.Path(temporary)
            lease = root / "maintenance.lease"
            lease.write_text("maintenance\n")
            lease.chmod(0o600)
            result = subprocess.run(
                [
                    str(CONTROLLER),
                    "--docker-binary",
                    "/bin/true",
                    "--project-dir",
                    str(root),
                    "--env-file",
                    str(lease),
                    "--runtime-dir",
                    str(root),
                    "--lease-file",
                    str(lease),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("maintenance lease", result.stderr)

    @unittest.skipUnless(importlib.util.find_spec("django"), "Django is not installed in the automation-only Python")
    def test_django_migrate_check_rejects_pending_schema_and_accepts_current_schema(self):
        with tempfile.TemporaryDirectory(prefix="camellia-migrate-check-") as temporary:
            database = pathlib.Path(temporary) / "migration-check.sqlite3"
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("CAMELLIA_REMOTE_DATABASE_") and key != "CAMELLIA_REMOTE_SQLITE_DB_PATH"
            }
            env |= {
                "CAMELLIA_REMOTE_DEBUG": "true",
                "CAMELLIA_REMOTE_SECRET_KEY": "deployment-gate-test-secret",
                "CAMELLIA_REMOTE_ALLOWED_HOSTS": "127.0.0.1,localhost",
                "CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS": "http://127.0.0.1:21114",
                "CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN": "deployment-gate-device-token-00000000",
                "CAMELLIA_REMOTE_SQLITE_DB_PATH": str(database),
            }
            command = [sys.executable, "manage.py", "migrate"]
            pending = subprocess.run(command + ["--check"], cwd=ROOT, env=env, text=True, capture_output=True)
            self.assertNotEqual(pending.returncode, 0, "an empty database must not pass the runtime migration gate")

            migrated = subprocess.run(command + ["--noinput"], cwd=ROOT, env=env, text=True, capture_output=True)
            self.assertEqual(migrated.returncode, 0, migrated.stderr)
            current = subprocess.run(command + ["--check"], cwd=ROOT, env=env, text=True, capture_output=True)
            self.assertEqual(current.returncode, 0, current.stderr)


if __name__ == "__main__":
    unittest.main()
