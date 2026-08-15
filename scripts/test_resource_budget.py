#!/usr/bin/env python3
"""Static contract tests for the production Compose cgroup envelope."""

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yaml"
ENV_EXAMPLE = ROOT / ".env.example"
RUN = ROOT / "run.sh"


def service_block(name):
    lines = COMPOSE.read_text().splitlines()
    start = lines.index(f"  {name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("  ") and not lines[index].startswith("    ") and lines[index].endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


class ResourceBudgetContractTests(unittest.TestCase):
    def test_runtime_services_have_independent_finite_resource_contracts(self):
        for service in ("postgres", "migrate", "management", "database-backup"):
            block = service_block(service)
            with self.subTest(service=service):
                for key in ("cpus:", "cpu_shares:", "mem_limit:", "mem_reservation:", "pids_limit:"):
                    self.assertIn(key, block)
                if service != "database-backup":
                    self.assertIn("ulimits:", block)
        self.assertIn("ulimits:", COMPOSE.read_text().split("x-database-client:", 1)[1].split("services:", 1)[0])
        self.assertIn('CAMELLIA_REMOTE_REQUIRE_CGROUP_BUDGET: "true"', service_block("management"))
        self.assertIn('CAMELLIA_REMOTE_REQUIRE_CGROUP_BUDGET: "true"', service_block("migrate"))

    def test_default_capacity_envelope_is_consistent_and_not_unbounded(self):
        compose = COMPOSE.read_text()
        expected_defaults = {
            "CAMELLIA_REMOTE_MANAGEMENT_CPUS": "2.0",
            "CAMELLIA_REMOTE_MANAGEMENT_MEMORY_LIMIT": "1g",
            "CAMELLIA_REMOTE_MANAGEMENT_PIDS_LIMIT": "256",
            "CAMELLIA_REMOTE_MIGRATION_CPUS": "2.0",
            "CAMELLIA_REMOTE_MIGRATION_MEMORY_LIMIT": "1g",
            "CAMELLIA_REMOTE_POSTGRES_CPUS": "2.0",
            "CAMELLIA_REMOTE_POSTGRES_MEMORY_LIMIT": "2g",
            "CAMELLIA_REMOTE_POSTGRES_PIDS_LIMIT": "256",
            "CAMELLIA_REMOTE_DATABASE_CLIENT_MEMORY_LIMIT": "256m",
        }
        for variable, default in expected_defaults.items():
            with self.subTest(variable=variable):
                self.assertRegex(compose, rf"\$\{{{re.escape(variable)}:-{re.escape(default)}\}}")
        self.assertIn("controller stops management before migration", compose)
        self.assertIn("never runs concurrently with migration", compose)
        for setting in ("max_connections=", "shared_buffers=", "work_mem=", "maintenance_work_mem="):
            self.assertIn(setting, service_block("postgres"))

    def test_env_documents_every_operator_tunable_budget(self):
        env = ENV_EXAMPLE.read_text()
        for variable in (
            "CAMELLIA_REMOTE_MANAGEMENT_MEMORY_LIMIT",
            "CAMELLIA_REMOTE_MIGRATION_MEMORY_LIMIT",
            "CAMELLIA_REMOTE_POSTGRES_MEMORY_LIMIT",
            "CAMELLIA_REMOTE_MANAGEMENT_NOFILE_SOFT",
            "CAMELLIA_REMOTE_POSTGRES_NOFILE_HARD",
            "CAMELLIA_REMOTE_POSTGRES_MAX_CONNECTIONS",
            "CAMELLIA_REMOTE_POSTGRES_SHARED_BUFFERS",
            "CAMELLIA_REMOTE_REQUIRE_CGROUP_BUDGET",
        ):
            with self.subTest(variable=variable):
                self.assertIn(variable, env)

    def test_entrypoint_requires_finite_cgroup_v2_when_production_requests_it(self):
        run = RUN.read_text()
        for required in (
            "CAMELLIA_REMOTE_REQUIRE_CGROUP_BUDGET",
            "memory.max",
            "pids.max",
            "cpu.max",
            "cgroup memory.max must be finite",
            "cgroup pids.max must be finite",
            "cgroup cpu.max must be finite",
        ):
            self.assertIn(required, run)


if __name__ == "__main__":
    unittest.main()
