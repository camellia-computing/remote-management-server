#!/usr/bin/env python3
"""Regression tests for timer/maintenance systemd authority boundaries."""

import os
import pathlib
import stat
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deploy" / "systemd"
GUARD = ROOT / "deploy" / "management-maintenance-guard.sh"
MAINTENANCE = ROOT / "deploy" / "management-maintenance.sh"
STACK_UNIT = "camellia-remote-management-stack.service"
OPERATIONS = (
    SYSTEMD / "camellia-remote-management-backup.service",
    SYSTEMD / "camellia-remote-management-cleanup.service",
)


def directives(path, section):
    current = None
    result = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
        elif current == section and line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result.append((key, value))
    return result


class SystemdMaintenanceTests(unittest.TestCase):
    def test_timer_services_cannot_start_the_stack(self):
        start_authority = {"Requires", "Wants", "BindsTo", "Upholds"}
        for path in OPERATIONS:
            with self.subTest(path=path.name):
                unit = directives(path, "Unit")
                for key, value in unit:
                    if key in start_authority:
                        self.assertNotIn(STACK_UNIT, value.split())
                after = [value for key, value in unit if key == "After"]
                self.assertTrue(any(STACK_UNIT in value.split() for value in after))
                conditions = [value for key, value in directives(path, "Service") if key == "ExecCondition"]
                self.assertEqual(conditions, ["/opt/camellia-remote-management/management-maintenance-guard.sh"])

    def test_guard_skips_inactive_stack_and_maintenance_without_starting_any_unit(self):
        with tempfile.TemporaryDirectory(prefix="camellia-maintenance-guard-") as temporary:
            root = pathlib.Path(temporary)
            state = root / "state"
            state.write_text("inactive\n")
            calls = root / "calls"
            fake_systemctl = root / "systemctl"
            fake_systemctl.write_text(
                textwrap.dedent(
                    """
                    #!/usr/bin/env python3
                    import os, pathlib, sys
                    pathlib.Path(os.environ["FAKE_SYSTEMCTL_CALLS"]).write_text(" ".join(sys.argv[1:]))
                    if sys.argv[1:4] == ["show", "--property=ActiveState", "--value"]:
                        print(pathlib.Path(os.environ["FAKE_SYSTEMCTL_STATE"]).read_text().strip())
                        raise SystemExit(0)
                    raise SystemExit(90)
                    """
                ).lstrip()
            )
            fake_systemctl.chmod(0o755)
            lease = root / "maintenance.lease"
            env = os.environ | {
                "FAKE_SYSTEMCTL_CALLS": str(calls),
                "FAKE_SYSTEMCTL_STATE": str(state),
            }

            inactive = subprocess.run(
                [
                    str(GUARD),
                    "--lease-file",
                    str(lease),
                    "--stack-unit",
                    "camellia-test-stack.service",
                    "--systemctl-binary",
                    str(fake_systemctl),
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(inactive.returncode, 1, inactive.stderr)
            self.assertIn("skipped:not-running", inactive.stdout)
            self.assertEqual(calls.read_text(), "show --property=ActiveState --value camellia-test-stack.service")

            state.write_text("active\n")
            active = subprocess.run(
                [
                    str(GUARD),
                    "--lease-file",
                    str(lease),
                    "--stack-unit",
                    "camellia-test-stack.service",
                    "--systemctl-binary",
                    str(fake_systemctl),
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(active.returncode, 0, active.stderr)

            lease.write_text("maintenance\n")
            lease.chmod(stat.S_IRUSR | stat.S_IWUSR)
            calls.unlink(missing_ok=True)
            maintenance = subprocess.run(
                [
                    str(GUARD),
                    "--lease-file",
                    str(lease),
                    "--stack-unit",
                    "camellia-test-stack.service",
                    "--systemctl-binary",
                    str(fake_systemctl),
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(maintenance.returncode, 1, maintenance.stderr)
            self.assertIn("skipped:maintenance", maintenance.stdout)
            self.assertFalse(calls.exists(), "lease must be checked before systemd state")

            lease.chmod(0o644)
            unsafe = subprocess.run(
                [
                    str(GUARD),
                    "--lease-file",
                    str(lease),
                    "--systemctl-binary",
                    str(fake_systemctl),
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(unsafe.returncode, 255)
            self.assertIn("unsafe maintenance lease", unsafe.stderr)

    def test_maintenance_tool_requires_explicit_validated_exit(self):
        result = subprocess.run([str(MAINTENANCE), "leave"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--confirm-validated", result.stderr)


if __name__ == "__main__":
    unittest.main()
