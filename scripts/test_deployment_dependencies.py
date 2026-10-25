"""Regression tests for immutable production database dependency evidence."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
import unittest
from pathlib import Path

import deployment_dependencies as dependencies

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
CLIENT_COMMIT = "b" * 40
GENERATED_AT = "2026-08-20T12:00:00Z"


class DeploymentDependencyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        policy_text = (ROOT / "deployment-dependencies.json").read_text(encoding="utf-8")
        (self.root / "deployment-dependencies.json").write_text(policy_text, encoding="utf-8")
        self.policy = json.loads(policy_text)
        reference = self.policy["database"]["reference"]
        for relative, count in dependencies.ROOT_REFERENCES.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("".join(f"    image: {reference}\n" for _ in range(count)), encoding="utf-8")

        self.scan_amd64 = self.write_json(
            "POSTGRESQL-amd64-VULNERABILITY-SCAN.json",
            {
                "SchemaVersion": 2,
                "Results": [{"Target": "alpine", "Vulnerabilities": []}],
            },
        )
        self.scan_arm64 = self.write_json(
            "POSTGRESQL-arm64-VULNERABILITY-SCAN.json",
            {
                "SchemaVersion": 2,
                "Results": [{"Target": "alpine", "Vulnerabilities": None}],
            },
        )
        self.sbom_amd64 = self.write_json(
            "POSTGRESQL-amd64-SBOM.spdx.json",
            {"spdxVersion": "SPDX-2.3", "packages": [{"name": "postgresql"}]},
        )
        self.sbom_arm64 = self.write_json(
            "POSTGRESQL-arm64-SBOM.spdx.json",
            {"spdxVersion": "SPDX-2.3", "packages": [{"name": "postgresql"}]},
        )
        self.scanner = self.write_json(
            "POSTGRESQL-SCANNER-DATABASE.json",
            {
                "scanner": "trivy",
                "version": "0.72.0",
                "updated_at": "2026-08-20T06:00:00Z",
            },
        )
        self.compatibility = self.write_json(
            "production-compose-evidence.json",
            {
                "format": "camellia-remote-deployment-integration-v1",
                "source_revision": COMMIT,
                "database_image": reference,
                "status": "passed",
                "services": {
                    "management": {"health": "healthy"},
                    "postgres": {"health": "healthy"},
                },
            },
        )

    def tearDown(self):
        self.temporary.cleanup()

    def write_json(self, name: str, value: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        return path

    def args(self, *, platforms=None):
        return argparse.Namespace(
            root=self.root,
            version="1.2.3",
            commit=COMMIT,
            client_commit=CLIENT_COMMIT,
            validation_run_id=42,
            generated_at=GENERATED_AT,
            scanner_database=self.scanner,
            compatibility=self.compatibility,
            platform=platforms
            or [
                ("amd64", f"sha256:{'c' * 64}", self.scan_amd64, self.sbom_amd64),
                ("arm64", f"sha256:{'d' * 64}", self.scan_arm64, self.sbom_arm64),
            ],
            output=self.root / "deployment-bom.json",
        )

    def test_builds_complete_two_platform_bom(self):
        bom = dependencies.build_bom(self.args())
        dependencies.validate_bom(bom)

        self.assertEqual(bom["release"]["commit"], COMMIT)
        self.assertEqual(bom["client_web"]["commit"], CLIENT_COMMIT)
        self.assertEqual(
            [item["architecture"] for item in bom["components"][0]["platforms"]],
            ["amd64", "arm64"],
        )
        self.assertEqual(bom["scanner_database"]["updated_at"], "2026-08-20T06:00:00Z")

    def test_rejects_digest_drift_in_every_repository_consumer(self):
        for relative in dependencies.ROOT_REFERENCES:
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_text(encoding="utf-8")
                digest = self.policy["database"]["digest"]
                self.assertIn(digest, original)
                replacement = "sha256:" + ("f" if digest[-1] != "f" else "e") * 64
                path.write_text(original.replace(digest, replacement, 1), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "reference drifted"):
                    dependencies.load_policy(self.root)
                path.write_text(original, encoding="utf-8")

    def test_rejects_blocked_vulnerability_even_without_a_fixed_version(self):
        self.scan_amd64.write_text(
            json.dumps(
                {
                    "SchemaVersion": 2,
                    "Results": [
                        {
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-0001",
                                    "Severity": "HIGH",
                                    "FixedVersion": "",
                                }
                            ]
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "CVE-2026-0001"):
            dependencies.build_bom(self.args())

    def test_rejects_stale_or_future_scanner_database(self):
        for updated_at in ("2026-08-19T11:59:59Z", "2026-08-20T12:05:01Z"):
            with self.subTest(updated_at=updated_at):
                self.scanner.write_text(
                    json.dumps({"scanner": "trivy", "version": "0.72.0", "updated_at": updated_at}),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "stale or from the future"):
                    dependencies.build_bom(self.args())

    def test_rejects_missing_platform_or_incomplete_sbom(self):
        with self.assertRaisesRegex(ValueError, "amd64 and arm64"):
            dependencies.build_bom(self.args(platforms=self.args().platform[:1]))

        self.sbom_arm64.write_text('{"spdxVersion":"SPDX-2.3","packages":[]}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "SBOM is incomplete"):
            dependencies.build_bom(self.args())

    def test_rejects_compatibility_evidence_for_another_database_or_commit(self):
        for field, value in (
            ("source_revision", "e" * 40),
            ("database_image", "postgres:18-alpine@sha256:" + "f" * 64),
            ("status", "failed"),
        ):
            with self.subTest(field=field):
                document = json.loads(self.compatibility.read_text(encoding="utf-8"))
                document[field] = value
                self.compatibility.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "does not bind|did not pass"):
                    dependencies.build_bom(self.args())
                document[field] = (
                    COMMIT
                    if field == "source_revision"
                    else self.policy["database"]["reference"]
                    if field == "database_image"
                    else "passed"
                )
                self.compatibility.write_text(json.dumps(document), encoding="utf-8")

    def test_bom_validator_rejects_unknown_fields_and_duplicate_platform_digests(self):
        bom = dependencies.build_bom(self.args())
        changed = copy.deepcopy(bom)
        changed["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            dependencies.validate_bom(changed)

        changed = copy.deepcopy(bom)
        changed["components"][0]["platforms"][1]["digest"] = changed["components"][0]["platforms"][0]["digest"]
        with self.assertRaisesRegex(ValueError, "must be unique"):
            dependencies.validate_bom(changed)

    def test_bom_evidence_root_binds_all_referenced_files(self):
        bom = dependencies.build_bom(self.args())
        dependencies.validate_bom_evidence(bom, self.root)
        self.scan_arm64.write_text('{"SchemaVersion":2,"Results":[]}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            dependencies.validate_bom_evidence(bom, self.root)

    def test_normalizes_trivy_database_metadata(self):
        output = self.root / "scanner-normalized.json"
        value = dependencies.normalize_scanner_database(
            argparse.Namespace(
                metadata=self.write_json(
                    "trivy-metadata.json",
                    {"Version": 2, "UpdatedAt": 1_755_660_000},
                ),
                version="0.72.0",
                output=output,
            )
        )
        self.assertEqual(value["scanner"], "trivy")
        self.assertEqual(value["version"], "0.72.0")
        self.assertTrue(value["updated_at"].endswith("Z"))

    def test_inventory_deduplicates_releases_by_parent_digest(self):
        release_root = self.root / "releases"
        release_root.mkdir()
        bom = dependencies.build_bom(self.args())
        for version in ("1.2.3", "1.2.4"):
            directory = release_root / f"v{version}"
            directory.mkdir()
            bom_copy = copy.deepcopy(bom)
            bom_copy["release"]["version"] = version
            bom_path = directory / "deployment-bom.json"
            bom_path.write_text(json.dumps(bom_copy), encoding="utf-8")
            attestation = directory / dependencies.DEPLOYMENT_ATTESTATION_NAME
            attestation.write_text("attestation\n", encoding="utf-8")
            release = {
                "schema_version": 2,
                "repository": "remote-management",
                "version": version,
                "source": {"commit": COMMIT},
                "release_kind": "formal",
                "deployment": {
                    "bom": dependencies.evidence_file(bom_path),
                    "attestation": dependencies.evidence_file(attestation),
                },
            }
            (directory / "release-evidence.json").write_text(json.dumps(release), encoding="utf-8")
        github_output = self.root / "github-output"
        result = dependencies.build_inventory(
            argparse.Namespace(
                release_root=release_root,
                generated_at=GENERATED_AT,
                github_output=github_output,
                output=self.root / "inventory.json",
            )
        )
        self.assertEqual(len(result["images"]), 1)
        self.assertEqual(result["images"][0]["releases"], ["1.2.3", "1.2.4"])
        self.assertEqual(result["images"][0]["platforms"][0]["architecture"], "amd64")
        matrix = json.loads(github_output.read_text().removeprefix("matrix="))
        self.assertEqual(len(matrix["include"]), 1)
        self.assertEqual(matrix["include"][0]["releases"], "1.2.3,1.2.4")
        self.assertNotIn(":", matrix["include"][0]["id"])

    def test_inventory_rejects_bom_hash_mismatch(self):
        release_root = self.root / "releases"
        release_root.mkdir()
        bom = dependencies.build_bom(self.args())
        directory = release_root / "v1.2.3"
        directory.mkdir()
        bom_path = directory / "deployment-bom.json"
        bom_path.write_text(json.dumps(bom), encoding="utf-8")
        attestation = directory / dependencies.DEPLOYMENT_ATTESTATION_NAME
        attestation.write_text("attestation\n", encoding="utf-8")
        release = {
            "schema_version": 2,
            "repository": "remote-management",
            "version": "1.2.3",
            "source": {"commit": COMMIT},
            "release_kind": "formal",
            "deployment": {
                "bom": {"name": "deployment-bom.json", "sha256": "0" * 64},
                "attestation": dependencies.evidence_file(attestation),
            },
        }
        (directory / "release-evidence.json").write_text(json.dumps(release), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not bind"):
            dependencies.build_inventory(
                argparse.Namespace(
                    release_root=release_root,
                    generated_at=GENERATED_AT,
                    github_output=None,
                    output=self.root / "inventory.json",
                )
            )


if __name__ == "__main__":
    unittest.main()
