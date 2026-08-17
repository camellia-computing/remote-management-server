#!/usr/bin/env python3
"""Required production-Compose lifecycle and systemd contract integration gate."""

from __future__ import annotations

import argparse
import copy
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yaml"
CONTROLLER = ROOT / "deploy" / "start-management-stack.sh"
SYSTEMD = ROOT / "deploy" / "systemd"
PROJECT_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
DATABASE_SERVICES = ("postgres", "database-bootstrap", "database-probe", "migrate", "management")
INTEGRATION_ERRORS = (KeyError, OSError, RuntimeError, subprocess.SubprocessError, ValueError)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def service_block(name: str) -> str:
    lines = COMPOSE.read_text().splitlines()
    start = lines.index(f"  {name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("  ") and not lines[index].startswith("    ") and lines[index].endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - executable and all arguments are controlled by this gate
        command,
        check=False,
        **kwargs,
    )


def output(command: list[str], **kwargs: object) -> str:
    result = run(command, text=True, capture_output=True, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def compose_command(docker: str, project_name: str, env_file: pathlib.Path, *arguments: str) -> list[str]:
    return [
        docker,
        "compose",
        "--project-name",
        project_name,
        "--env-file",
        str(env_file),
        "-f",
        str(COMPOSE),
        *arguments,
    ]


def prepare_environment(path: pathlib.Path, image: str, revision: str) -> None:
    require(
        REVISION_PATTERN.fullmatch(revision) is not None, "release revision must be 40 or 64 lowercase hex characters"
    )
    require("\n" not in image and image, "management image reference is invalid")
    values = {
        "CAMELLIA_REMOTE_MANAGEMENT_IMAGE": image,
        "CAMELLIA_REMOTE_MANAGEMENT_PULL_POLICY": "never",
        "CAMELLIA_REMOTE_RELEASE_REVISION": revision,
        "CAMELLIA_REMOTE_SECRET_KEY": "ci-only-production-secret-key-with-sufficient-length-000",
        "CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID": "ci-primary-v1",
        "CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID": "ci-primary-v1",
        "CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN": "ci-device-verification-token-with-sufficient-length",
        "CAMELLIA_REMOTE_DATABASE_HOST": "postgres",
        "CAMELLIA_REMOTE_DATABASE_PORT": "5432",
        "CAMELLIA_REMOTE_DATABASE_NAME": "camellia_remote",
        "CAMELLIA_REMOTE_DATABASE_BOOTSTRAP_USER": "ci_bootstrap",
        "CAMELLIA_REMOTE_DATABASE_BOOTSTRAP_PASSWORD": "ci-bootstrap-password-01",
        "CAMELLIA_REMOTE_DATABASE_MIGRATION_USER": "ci_migration",
        "CAMELLIA_REMOTE_DATABASE_MIGRATION_PASSWORD": "ci-migration-password-02",
        "CAMELLIA_REMOTE_DATABASE_RUNTIME_USER": "ci_runtime",
        "CAMELLIA_REMOTE_DATABASE_RUNTIME_PASSWORD": "ci-runtime-password-03",
        "CAMELLIA_REMOTE_DATABASE_BACKUP_USER": "ci_backup",
        "CAMELLIA_REMOTE_DATABASE_BACKUP_PASSWORD": "ci-backup-password-04",
        "CAMELLIA_REMOTE_DATABASE_PROBE_USER": "ci_probe",
        "CAMELLIA_REMOTE_DATABASE_PROBE_PASSWORD": "ci-probe-password-05",
        "CAMELLIA_REMOTE_DATABASE_SSLMODE": "disable",
        "CAMELLIA_REMOTE_ALLOWED_HOSTS": "127.0.0.1,localhost",
        "CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS": "https://api.example.test",
        "CAMELLIA_REMOTE_API_SERVER": "https://api.example.test",
        "CAMELLIA_REMOTE_ID_SERVER": "wss://remote.example.test:443",
        "CAMELLIA_REMOTE_RS_PUB_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "CAMELLIA_REMOTE_SECURE_TLS": "true",
        "CAMELLIA_REMOTE_RATE_LIMIT_ENABLED": "true",
        "CAMELLIA_REMOTE_REQUIRE_CGROUP_BUDGET": "true",
        "CAMELLIA_REMOTE_API_BIND_PORT": "21114",
        "CAMELLIA_REMOTE_GUNICORN_WORKERS": "1",
        "CAMELLIA_REMOTE_GUNICORN_THREADS": "2",
        "CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS": "30",
        "CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS": "45",
        "CAMELLIA_REMOTE_RECORD_REQUIRE_MOUNT": "true",
        "CAMELLIA_REMOTE_RUN_MIGRATIONS": "false",
    }
    path.write_text("".join(f"{key}={values[key]}\n" for key in sorted(values)))
    path.chmod(0o600)


def project_resource_ids(docker: str, resource: str, project_name: str) -> list[str]:
    result = run(
        [
            docker,
            resource,
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project_name}",
        ],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cannot enumerate project {resource}s for cleanup")
    return result.stdout.split()


def cleanup_project(docker: str, project_name: str) -> None:
    containers = project_resource_ids(docker, "container", project_name)
    if containers:
        result = run([docker, "container", "rm", "--force", *containers], text=True, capture_output=True)
        require(result.returncode == 0, "project containers could not be removed")
    for resource in ("network", "volume"):
        identifiers = project_resource_ids(docker, resource, project_name)
        if identifiers:
            result = run([docker, resource, "rm", *identifiers], text=True, capture_output=True)
            require(result.returncode == 0, f"project {resource}s could not be removed")
    for resource in ("container", "network", "volume"):
        require(not project_resource_ids(docker, resource, project_name), f"project {resource} cleanup left residue")


def inspect_service(docker: str, project_name: str, env_file: pathlib.Path, service: str) -> dict:
    container = output(compose_command(docker, project_name, env_file, "ps", "--all", "-q", service))
    require(re.fullmatch(r"[0-9a-f]+", container) is not None, f"Compose did not return one {service} container")
    payload = json.loads(output([docker, "container", "inspect", container]))
    require(len(payload) == 1, f"Docker inspect returned an ambiguous {service} container")
    inspected = payload[0]
    require(
        inspected["Config"]["Labels"].get("com.docker.compose.project") == project_name,
        f"{service} escaped project scope",
    )
    require(
        inspected["Config"]["Labels"].get("com.docker.compose.service") == service,
        f"service label drifted for {service}",
    )
    return inspected


def wait_healthy(
    docker: str, project_name: str, env_file: pathlib.Path, service: str, timeout_seconds: int = 120
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last = None
    while time.monotonic() < deadline:
        last = inspect_service(docker, project_name, env_file, service)
        state = last["State"]
        health = state.get("Health", {}).get("Status")
        if state.get("Running") and health == "healthy":
            return last
        time.sleep(2)
    raise RuntimeError(f"{service} did not become healthy (last={last and last['State']})")


def validate_effective_config(document: dict) -> None:
    services = document["services"]
    require(set(DATABASE_SERVICES).issubset(services), "production Compose service set is incomplete")
    require(
        services.get("migrate", {}).get("depends_on", {}).get("postgres", {}).get("condition") == "service_healthy",
        "migration health gate drifted",
    )
    require(services["management"]["restart"] == "no", "Management restart policy bypasses controller")
    require(services["management"]["pull_policy"] == "never", "CI local image pull policy was not explicit")
    require("depends_on" not in services["management"], "Management has an online dependency shortcut")
    require(services["postgres"]["user"] == "70:70", "effective PostgreSQL identity drifted")
    require(services["postgres"]["read_only"] is True, "effective PostgreSQL rootfs is writable")
    require(services["postgres"]["cap_drop"] == ["ALL"], "effective PostgreSQL caps are not dropped")
    require(services["postgres"].get("cap_add", []) == [], "effective PostgreSQL gained a capability")
    require(services["postgres"]["security_opt"] == ["no-new-privileges:true"], "effective PostgreSQL NNP drifted")
    require(services["postgres"]["healthcheck"]["retries"] >= 3, "PostgreSQL healthcheck is not bounded")
    for name in ("postgres", "migrate", "management"):
        for key in ("cpus", "mem_limit", "mem_reservation", "pids_limit"):
            require(services[name].get(key) not in (None, "", 0), f"{name} resource contract missing {key}")
    require(document["networks"]["backend"]["internal"] is True, "backend network is externally routable")
    management_ports = services["management"].get("ports", [])
    require(
        len(management_ports) == 1
        and management_ports[0]["host_ip"] == "127.0.0.1"
        and management_ports[0]["target"] == 21114,
        "Management host port is not loopback-only",
    )
    require(not services["postgres"].get("ports"), "PostgreSQL publishes a host port")


def assert_effective_config(docker: str, project_name: str, env_file: pathlib.Path) -> dict:
    result = run(
        compose_command(
            docker, project_name, env_file, "--profile", "database-operations", "config", "--format", "json"
        ),
        text=True,
        capture_output=True,
    )
    require(result.returncode == 0, "production Compose effective config failed")
    document = json.loads(result.stdout)
    validate_effective_config(document)
    return document


def check_ready() -> None:
    request = urllib.request.Request(
        "http://127.0.0.1:21114/health/ready",
        headers={"X-Forwarded-Proto": "https"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - fixed loopback readiness endpoint
        payload = json.loads(response.read())
        require(response.status == 200 and payload.get("status") == "ready", "host readiness contract failed")


def run_integration(
    *,
    project_dir: pathlib.Path,
    env_file: pathlib.Path,
    project_name: str,
    runtime_dir: pathlib.Path,
    docker: str,
    evidence_path: pathlib.Path,
) -> None:
    require(PROJECT_NAME_PATTERN.fullmatch(project_name) is not None, "Compose project name is invalid")
    require(project_dir.is_dir() and not project_dir.is_symlink(), "project directory is unsafe")
    require(env_file.is_file() and not env_file.is_symlink(), "Compose environment file is unsafe")
    require(
        env_file.stat().st_mode & 0o077 == 0 and env_file.stat().st_mode & 0o400,
        "Compose environment permissions are unsafe",
    )
    require(not runtime_dir.is_symlink(), "runtime directory is unsafe")
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime_dir.chmod(0o700)
    compose_env = os.environ | {"COMPOSE_PROJECT_NAME": project_name}
    evidence: dict[str, object] = {
        "format": "camellia-remote-deployment-integration-v1",
        "project": project_name,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "services": {},
    }
    error: Exception | None = None
    try:
        effective = assert_effective_config(docker, project_name, env_file)
        evidence["effective_services"] = sorted(effective["services"])
        started = time.monotonic()
        controller = run(
            [
                str(CONTROLLER),
                "--project-dir",
                str(project_dir),
                "--env-file",
                str(env_file),
                "--runtime-dir",
                str(runtime_dir),
                "--lease-file",
                str(runtime_dir / "maintenance.lease"),
                "--docker-binary",
                docker,
            ],
            env=compose_env,
            text=True,
            capture_output=True,
            timeout=2400,
        )
        require(controller.returncode == 0, "production start controller failed")
        management = wait_healthy(docker, project_name, env_file, "management")
        postgres = wait_healthy(docker, project_name, env_file, "postgres")
        check_ready()
        evidence["ready_seconds"] = round(time.monotonic() - started, 3)
        evidence["services"] = {
            "management": {
                "container": management["Id"][:12],
                "restart_count": management["RestartCount"],
                "health": management["State"]["Health"]["Status"],
            },
            "postgres": {
                "container": postgres["Id"][:12],
                "restart_count": postgres["RestartCount"],
                "health": postgres["State"]["Health"]["Status"],
                "uid": postgres["Config"]["User"],
            },
        }

        restart = run(
            compose_command(docker, project_name, env_file, "restart", "--timeout", "60", "postgres"),
            env=compose_env,
            text=True,
            capture_output=True,
            timeout=90,
        )
        require(restart.returncode == 0, "PostgreSQL restart recovery failed")
        wait_healthy(docker, project_name, env_file, "postgres", timeout_seconds=120)
        check_ready()

        stop_started = time.monotonic()
        stop = run(
            compose_command(docker, project_name, env_file, "stop", "--timeout", "45", "management"),
            env=compose_env,
            text=True,
            capture_output=True,
            timeout=75,
        )
        require(stop.returncode == 0, "Management TERM drain failed")
        stop_seconds = time.monotonic() - stop_started
        time.sleep(3)
        stopped = inspect_service(docker, project_name, env_file, "management")
        require(not stopped["State"].get("Running"), "Management restarted without the supervisor")
        evidence["term_stop_seconds"] = round(stop_seconds, 3)
        require(stop_seconds <= 60, "Management TERM drain exceeded its bounded budget")
    except INTEGRATION_ERRORS as exc:
        error = exc
        evidence["failure"] = type(exc).__name__
    finally:
        cleanup_error: Exception | None = None
        try:
            down = run(
                compose_command(
                    docker,
                    project_name,
                    env_file,
                    "down",
                    "--timeout",
                    "60",
                    "--volumes",
                    "--remove-orphans",
                ),
                env=compose_env,
                text=True,
                capture_output=True,
                timeout=90,
            )
        except INTEGRATION_ERRORS as exc:
            down = None
            cleanup_error = exc
        try:
            cleanup_project(docker, project_name)
        except INTEGRATION_ERRORS as exc:
            cleanup_error = cleanup_error or exc
        evidence_path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        evidence_path.chmod(0o600)
        if cleanup_error is None:
            require(down is not None and down.returncode == 0, "Compose down failed during integration cleanup")
        else:
            raise RuntimeError("Compose cleanup failed") from cleanup_error
    if error is not None:
        raise RuntimeError("production Compose integration failed") from error


class ProductionComposeContractTests(unittest.TestCase):
    def test_container_job_runs_controller_and_has_always_cleanup(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        container = workflow.split("\n  container:\n", 1)[1].split("\n  performance_smoke:", 1)[0]
        self.assertNotIn("\n    services:\n", container)
        self.assertIn("scripts/test_production_compose.py", container)
        self.assertIn("--run", container)
        self.assertIn("if: always()", container)
        self.assertIn("--cleanup", container)
        self.assertIn("start-management-stack.sh", (ROOT / "scripts/test_production_compose.py").read_text())
        self.assertIn("CAMELLIA_REMOTE_MANAGEMENT_PULL_POLICY:-always", COMPOSE.read_text())
        self.assertIn("CAMELLIA_REMOTE_MANAGEMENT_PULL_POLICY=always", (ROOT / ".env.example").read_text())

    def test_required_gate_requires_container_for_runtime_and_never_accepts_unknown(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        required = workflow.split("\n  required:\n", 1)[1]
        self.assertIn('if [[ "$RUNTIME_REQUIRED" == "true" ]]', required)
        self.assertIn('require_success "container smoke test" "$CONTAINER_RESULT"', required)
        self.assertIn('require_success "Management performance contract smoke" "$PERFORMANCE_SMOKE_RESULT"', required)
        self.assertIn('if [[ "$result" != "success" ]]', required)

    def test_systemd_units_keep_machine_readable_lifecycle_and_failure_boundaries(self):
        stack = (SYSTEMD / "camellia-remote-management-stack.service").read_text()
        self.assertIn("Type=notify", stack)
        self.assertIn("WatchdogSec=45s", stack)
        self.assertIn("KillMode=control-group", stack)
        self.assertIn("ExecStopPost=/opt/camellia-remote-management/deploy/stop-management-stack.sh", stack)
        for name in ("camellia-remote-management-backup.service", "camellia-remote-management-cleanup.service"):
            unit = (SYSTEMD / name).read_text()
            self.assertIn("OnFailure=camellia-remote-management-maintenance-failure@%n.service", unit)
            self.assertIn("KillMode=control-group", unit)
            self.assertIn("StateDirectoryMode=0700", unit)

    def test_effective_contract_rejects_removed_runtime_guards(self):
        valid = {
            "services": {
                "postgres": {
                    "user": "70:70",
                    "read_only": True,
                    "cap_drop": ["ALL"],
                    "cap_add": [],
                    "security_opt": ["no-new-privileges:true"],
                    "healthcheck": {"retries": 3},
                    "cpus": 2,
                    "mem_limit": 1,
                    "mem_reservation": 1,
                    "pids_limit": 64,
                    "ports": [],
                },
                "migrate": {"depends_on": {"postgres": {"condition": "service_healthy"}}},
                "management": {
                    "restart": "no",
                    "pull_policy": "never",
                    "cpus": 2,
                    "mem_limit": 1,
                    "mem_reservation": 1,
                    "pids_limit": 64,
                    "ports": [{"host_ip": "127.0.0.1", "target": 21114}],
                },
                "database-bootstrap": {},
                "database-probe": {},
            },
            "networks": {"backend": {"internal": True}},
        }
        for mutation in (
            lambda value: value["services"]["management"].__setitem__("restart", "unless-stopped"),
            lambda value: value["services"]["migrate"]["depends_on"].__delitem__("postgres"),
            lambda value: value["services"]["postgres"].__setitem__("read_only", False),
            lambda value: value["services"]["postgres"]["healthcheck"].__setitem__("retries", 0),
            lambda value: value["networks"]["backend"].__setitem__("internal", False),
        ):
            candidate = copy.deepcopy(valid)
            mutation(candidate)
            with self.assertRaises(RuntimeError):
                validate_effective_config(candidate)


def verify_systemd_units() -> None:
    analyzer = shutil.which("systemd-analyze")
    if analyzer is None:
        raise SystemExit("systemd-analyze is required for the systemd contract gate")
    with tempfile.TemporaryDirectory(prefix="camellia-systemd-verify-") as temporary:
        root = pathlib.Path(temporary)
        unit_dir = root / "etc/systemd/system"
        unit_dir.mkdir(parents=True)
        for unit in SYSTEMD.glob("*"):
            shutil.copy2(unit, unit_dir / unit.name)
        for target in ("network-online.target", "multi-user.target", "timers.target", "sysinit.target"):
            (unit_dir / target).write_text("[Unit]\nDescription=isolated verification stub\n")
        (unit_dir / "docker.service").write_text(
            "[Unit]\nDescription=isolated Docker verification stub\n"
            "[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n"
        )
        for path in (
            "/bin/kill",
            "/usr/bin/test",
            "/usr/bin/age",
            "/usr/bin/docker",
            "/usr/bin/systemd-notify",
            "/usr/bin/timeout",
        ):
            destination = root / path.lstrip("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2("/bin/true", destination)
        install_root = root / "opt/camellia-remote-management"
        for directory in ("deploy", "scripts"):
            (install_root / directory).mkdir(parents=True)
        for path in list((ROOT / "deploy").glob("*.sh")) + list((ROOT / "scripts").glob("*.py")):
            destination = install_root / path.parent.name / path.name
            shutil.copy2(path, destination)
            destination.chmod(0o755)
        env_file = root / "etc/camellia-remote-management/management.env"
        env_file.parent.mkdir(parents=True)
        env_file.write_text("CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS=30\n")
        result = run(
            [
                analyzer,
                "verify",
                "--root",
                str(root),
                *[path.name for path in SYSTEMD.glob("*.service")],
                *[path.name for path in SYSTEMD.glob("*.timer")],
            ],
            text=True,
            capture_output=True,
        )
        require(result.returncode == 0, "isolated systemd-analyze verify failed")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare-env", action="store_true")
    parser.add_argument("--systemd-contract", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--project-dir", type=pathlib.Path, default=ROOT)
    parser.add_argument("--env-file", type=pathlib.Path)
    parser.add_argument("--image")
    parser.add_argument("--revision")
    parser.add_argument("--project-name")
    parser.add_argument("--runtime-dir", type=pathlib.Path)
    parser.add_argument("--docker", default=shutil.which("docker") or "")
    parser.add_argument("--evidence", type=pathlib.Path)
    args = parser.parse_args(argv)
    if not any((args.prepare_env, args.systemd_contract, args.run, args.cleanup)):
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(ProductionComposeContractTests)
        )
        return 0 if result.wasSuccessful() else 1
    if args.prepare_env:
        require(
            args.env_file is not None and args.image and args.revision,
            "prepare-env requires --env-file, --image, and --revision",
        )
        prepare_environment(args.env_file, args.image, args.revision)
    if args.systemd_contract:
        verify_systemd_units()
    if args.run:
        require(
            all((args.env_file, args.project_name, args.runtime_dir, args.evidence, args.docker)),
            "run requires env, project, runtime, evidence, and docker",
        )
        run_integration(
            project_dir=args.project_dir,
            env_file=args.env_file,
            project_name=args.project_name,
            runtime_dir=args.runtime_dir,
            docker=args.docker,
            evidence_path=args.evidence,
        )
    if args.cleanup:
        require(args.project_name and args.docker, "cleanup requires project name and docker")
        cleanup_project(args.docker, args.project_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
