#!/usr/bin/env python3
"""Verify the PostgreSQL bootstrap/runtime least-privilege boundary."""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yaml"
CONTROLLER = ROOT / "deploy" / "start-management-stack.sh"
IMAGE_DIGEST = "sha256:" + "0" * 64
PROJECT_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
RUNTIME_TMPFS_TARGETS = {"/tmp", "/var/run/postgresql"}  # noqa: S108 - container mount targets, not host paths


def service_block(name):
    lines = COMPOSE.read_text().splitlines()
    start = lines.index(f"  {name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("  ") and not lines[index].startswith("    ") and lines[index].endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class PostgresContainerContractTests(unittest.TestCase):
    def test_runtime_postgres_is_non_root_read_only_and_capability_empty(self):
        postgres = service_block("postgres")
        for required in (
            'user: "70:70"',
            "pull_policy: always",
            "read_only: true",
            "cap_drop:\n      - ALL",
            "security_opt:\n      - no-new-privileges:true",
            "- /tmp:size=64m,mode=1777",
            "- /var/run/postgresql:size=16m,uid=70,gid=70,mode=775",
            "PGDATA: /var/lib/postgresql/18/docker",
            "postgres-data:/var/lib/postgresql",
            "pids_limit:",
            "mem_limit:",
            "cpus:",
        ):
            self.assertIn(required, postgres)
        for forbidden in ("cap_add:", "privileged:", "ports:", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, postgres)

    def test_short_lived_volume_bootstrap_has_only_required_root_capabilities(self):
        bootstrap = service_block("postgres-data-bootstrap")
        for required in (
            'user: "0:0"',
            "pull_policy: always",
            "read_only: true",
            "cap_drop:\n      - ALL",
            "cap_add:\n      - CHOWN\n      - DAC_OVERRIDE\n      - FOWNER",
            "security_opt:\n      - no-new-privileges:true",
            "network_mode: none",
            "postgres-data:/var/lib/postgresql",
            "PGDATA: /var/lib/postgresql/18/docker",
            "profiles:\n      - database-operations",
            'cpus: "0.25"',
            "mem_limit: 64m",
            "pids_limit: 32",
        ):
            self.assertIn(required, bootstrap)
        for forbidden in ("privileged:", "networks:", "ports:", "/var/run/docker.sock"):
            self.assertNotIn(forbidden, bootstrap)

    def test_bootstrap_rejects_symlinks_before_mkdir_or_chown(self):
        bootstrap = service_block("postgres-data-bootstrap")
        symlink_check = bootstrap.index('test -z "$(find /var/lib/postgresql -xdev -type l -print -quit)"')
        mkdir = bootstrap.index('mkdir -p "$${PGDATA}"')
        chown = bootstrap.index("find /var/lib/postgresql -xdev \\( ! -user 70 -o ! -group 70 \\)")
        chmod = bootstrap.index('( test "$(stat -c %a "$${PGDATA}")" = 700 || chmod 700 "$${PGDATA}" )')
        self.assertLess(symlink_check, mkdir)
        self.assertLess(mkdir, chown)
        self.assertLess(chown, chmod)

    def test_controller_never_chowns_a_serving_database_and_bootstraps_before_start(self):
        controller = CONTROLLER.read_text()
        running_check = controller.index(
            "ps --status running --services", controller.index("rm --force --stop migrate")
        )
        bootstrap = controller.index("run_operation pgdata-bootstrap 120 postgres-data-bootstrap", running_check)
        postgres_start = controller.index("up --detach postgres", bootstrap)
        self.assertLess(running_check, bootstrap)
        self.assertLess(bootstrap, postgres_start)
        self.assertIn("Never mount", controller)
        self.assertIn("while the database is serving it", controller)


def required_environment():
    content = COMPOSE.read_text()
    names = sorted(set(re.findall(r"\$\{([A-Z][A-Z0-9_]+):\?", content)))
    values = {}
    for name in names:
        if name.endswith("_IMAGE"):
            values[name] = f"camellia-remote-management:ci@{IMAGE_DIGEST}"
        elif name.endswith("_RELEASE_REVISION"):
            values[name] = "a" * 40
        elif name.endswith("_RS_PUB_KEY"):
            values[name] = "A" * 44
        elif name.endswith("_API_SERVER"):
            values[name] = "https://api.example.test"
        elif name.endswith("_ID_SERVER"):
            values[name] = "wss://remote.example.test:443"
        elif name.endswith("_ALLOWED_HOSTS"):
            values[name] = "api.example.test"
        elif name.endswith("_CSRF_TRUSTED_ORIGINS"):
            values[name] = "https://api.example.test"
        elif name.endswith("_PORT"):
            values[name] = "5432"
        elif name.endswith("_KEY"):
            values[name] = "A" * 44
        elif name.endswith(("_PASSWORD", "_TOKEN", "_SECRET")):
            values[name] = f"ci-{name.lower()}-with-sufficient-length-000"
        else:
            values[name] = "ci-value"
    return values


def compose_command(compose_binary, env_file, project_name, *arguments):
    return [
        compose_binary,
        "compose",
        "--project-name",
        project_name,
        "--env-file",
        str(env_file),
        "-f",
        str(COMPOSE),
        *arguments,
    ]


def run(command, **kwargs):
    return subprocess.run(  # noqa: S603 - executable is resolved once and all arguments are controlled
        command,
        check=False,
        **kwargs,
    )


def output(command):
    result = run(command, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def project_resource_ids(compose_binary, resource, project_name):
    result = run(
        [
            compose_binary,
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
        raise RuntimeError(f"cannot enumerate {resource} resources for cleanup: {result.stderr.strip()}")
    return result.stdout.split()


def cleanup_project(compose_binary, project_name):
    containers = project_resource_ids(compose_binary, "container", project_name)
    if containers:
        result = run([compose_binary, "container", "rm", "--force", *containers], text=True, capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(f"cannot remove PostgreSQL test containers: {result.stderr.strip()}")
    for resource in ("network", "volume"):
        identifiers = project_resource_ids(compose_binary, resource, project_name)
        if identifiers:
            result = run([compose_binary, resource, "rm", *identifiers], text=True, capture_output=True)
            if result.returncode != 0:
                raise RuntimeError(f"cannot remove PostgreSQL test {resource}s: {result.stderr.strip()}")


def volume_targets(service):
    return {
        (volume["type"], volume["source"], volume["target"], volume.get("read_only", False))
        for volume in service["volumes"]
    }


def assert_effective_config(compose_binary, env_file, project_name):
    result = run(
        compose_command(
            compose_binary,
            env_file,
            project_name,
            "--profile",
            "database-operations",
            "config",
            "--format",
            "json",
        ),
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker compose config failed: {result.stderr}")
    document = json.loads(result.stdout)
    services = document["services"]
    postgres = services["postgres"]
    require(postgres["user"] == "70:70", "effective PostgreSQL UID/GID drifted")
    require(postgres["read_only"] is True, "effective PostgreSQL rootfs is writable")
    require(postgres["cap_drop"] == ["ALL"], "effective PostgreSQL capability drop is incomplete")
    require(postgres.get("cap_add", []) == [], "effective PostgreSQL runtime gained capabilities")
    require("no-new-privileges:true" in postgres["security_opt"], "effective PostgreSQL NNP is disabled")
    require(postgres["environment"]["PGDATA"] == "/var/lib/postgresql/18/docker", "effective PGDATA drifted")
    require(
        {item.split(":", 1)[0] for item in postgres["tmpfs"]} == RUNTIME_TMPFS_TARGETS,
        "effective PostgreSQL tmpfs allowlist drifted",
    )
    require(
        volume_targets(postgres) == {("volume", "postgres-data", "/var/lib/postgresql", False)},
        "effective PostgreSQL persistent mounts drifted",
    )
    require(not postgres.get("ports"), "effective PostgreSQL unexpectedly publishes a host port")

    bootstrap = services["postgres-data-bootstrap"]
    require(bootstrap["user"] == "0:0", "effective volume bootstrap is not root")
    require(bootstrap["read_only"] is True, "effective volume bootstrap rootfs is writable")
    require(bootstrap["network_mode"] == "none", "effective volume bootstrap has network access")
    require(bootstrap["cap_drop"] == ["ALL"], "effective volume bootstrap does not drop defaults")
    require(
        set(bootstrap["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER"},
        "effective volume bootstrap capability allowlist drifted",
    )
    require(
        volume_targets(bootstrap) == {("volume", "postgres-data", "/var/lib/postgresql", False)},
        "effective volume bootstrap mount allowlist drifted",
    )
    require(not bootstrap.get("networks"), "effective volume bootstrap joined a network")
    require(not bootstrap.get("ports"), "effective volume bootstrap publishes a host port")


def compose_run(compose_binary, env_file, project_name, *arguments):
    return run(
        compose_command(compose_binary, env_file, project_name, *arguments),
        text=True,
        capture_output=True,
    )


def inspect_container(compose_binary, container):
    payload = json.loads(output([compose_binary, "container", "inspect", container]))
    require(len(payload) == 1, "Docker inspect returned an ambiguous PostgreSQL container")
    return payload[0]


def exec_output(compose_binary, container, *arguments):
    return output([compose_binary, "container", "exec", container, *arguments])


def assert_runtime(compose_binary, env_file, project_name):
    create_canary = compose_run(
        compose_binary,
        env_file,
        project_name,
        "--profile",
        "database-operations",
        "run",
        "--rm",
        "--no-deps",
        "postgres-data-bootstrap",
        "/bin/sh",
        "-ec",
        "touch /var/lib/postgresql/ownership-canary",
    )
    if create_canary.returncode != 0:
        raise RuntimeError(f"cannot create wrong-owner volume fixture: {create_canary.stderr}")

    for attempt in range(2):
        bootstrap = compose_run(
            compose_binary,
            env_file,
            project_name,
            "--profile",
            "database-operations",
            "run",
            "--rm",
            "--no-deps",
            "postgres-data-bootstrap",
        )
        if bootstrap.returncode != 0:
            raise RuntimeError(f"postgres volume bootstrap attempt {attempt + 1} failed: {bootstrap.stderr}")

    start = compose_run(compose_binary, env_file, project_name, "up", "--detach", "postgres")
    if start.returncode != 0:
        raise RuntimeError(f"postgres runtime start failed: {start.stderr}")
    container = output(compose_command(compose_binary, env_file, project_name, "ps", "-q", "postgres"))
    require(re.fullmatch(r"[0-9a-f]+", container) is not None, "Compose did not return a PostgreSQL container ID")

    payload = None
    for _ in range(30):
        payload = inspect_container(compose_binary, container)
        if payload["State"]["Running"]:
            readiness = run(
                [compose_binary, "container", "exec", container, "pg_isready", "--quiet"],
                text=True,
                capture_output=True,
            )
            if readiness.returncode == 0:
                break
        time.sleep(1)
    else:
        logs = compose_run(compose_binary, env_file, project_name, "logs", "--no-color", "postgres")
        raise RuntimeError(f"PostgreSQL did not become ready: {logs.stdout}\n{logs.stderr}")

    time.sleep(1)
    payload = inspect_container(compose_binary, container)
    require(payload["State"]["Running"], "PostgreSQL did not remain running after readiness")
    require(payload["RestartCount"] == 0, "PostgreSQL required a restart during hardened initialization")
    config = payload["Config"]
    host = payload["HostConfig"]
    require(config["User"] == "70:70", "runtime container UID/GID drifted")
    require(host["ReadonlyRootfs"] is True, "runtime rootfs is writable")
    require(host["CapDrop"] == ["ALL"], "runtime default capabilities were not dropped")
    require(not host.get("CapAdd"), "runtime container gained a capability")
    require("no-new-privileges:true" in host["SecurityOpt"], "runtime NNP is disabled")
    require(set(host["Tmpfs"]) == RUNTIME_TMPFS_TARGETS, "runtime tmpfs allowlist drifted")
    require(
        {(mount["Type"], mount["Destination"], mount["RW"]) for mount in payload["Mounts"]}
        == {("volume", "/var/lib/postgresql", True)},
        "runtime persistent mount allowlist drifted",
    )

    require(exec_output(compose_binary, container, "id", "-u") == "70", "runtime process UID is not 70")
    require(exec_output(compose_binary, container, "id", "-g") == "70", "runtime process GID is not 70")
    status = exec_output(
        compose_binary,
        container,
        "sh",
        "-ec",
        "awk '/^(CapEff|NoNewPrivs):/{print $1 $2}' /proc/1/status",
    ).splitlines()
    require("CapEff:0000000000000000" in status, "runtime process retains an effective capability")
    require("NoNewPrivs:1" in status, "runtime process NNP flag is not set")
    require(
        exec_output(compose_binary, container, "stat", "-c", "%u:%g", "/var/lib/postgresql/ownership-canary")
        == "70:70",
        "volume bootstrap did not converge existing ownership",
    )
    writable = run(
        [
            compose_binary,
            "container",
            "exec",
            container,
            "sh",
            "-ec",
            'touch "$PGDATA/runtime-write-probe" && rm -f "$PGDATA/runtime-write-probe" /var/lib/postgresql/ownership-canary',
        ],
        text=True,
        capture_output=True,
    )
    require(writable.returncode == 0, f"declared PGDATA mount is not writable: {writable.stderr}")
    forbidden_write = run(
        [compose_binary, "container", "exec", container, "sh", "-ec", "touch /etc/camellia-must-not-write"],
        text=True,
        capture_output=True,
    )
    require(forbidden_write.returncode != 0, "runtime process wrote outside declared writable mounts")


def run_static_tests():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PostgresContainerContractTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--effective", action="store_true")
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--project-name")
    args = parser.parse_args(argv)
    if not args.effective and not args.runtime and not args.cleanup:
        return run_static_tests()

    compose_binary = shutil.which("docker")
    if compose_binary is None:
        raise SystemExit("docker is required for effective/runtime PostgreSQL checks")
    project_name = args.project_name or f"camellia-remote-pg-{os.getpid()}"
    if PROJECT_NAME_PATTERN.fullmatch(project_name) is None:
        raise SystemExit("project name must contain only lowercase ASCII letters, digits, underscores, and hyphens")
    if args.cleanup:
        if args.effective or args.runtime:
            raise SystemExit("--cleanup cannot be combined with effective/runtime checks")
        cleanup_project(compose_binary, project_name)
        return 0

    with tempfile.TemporaryDirectory(prefix="camellia-postgres-hardening-") as temporary:
        env_file = pathlib.Path(temporary) / "compose.env"
        env_file.write_text("\n".join(f"{key}={value}" for key, value in required_environment().items()) + "\n")
        env_file.chmod(0o600)
        try:
            assert_effective_config(compose_binary, env_file, project_name)
            if args.runtime:
                assert_runtime(compose_binary, env_file, project_name)
        finally:
            cleanup_project(compose_binary, project_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
