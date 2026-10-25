#!/usr/bin/env python3
"""Regression tests for generic container release evidence."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("build-container-release-evidence.py")
SPEC = importlib.util.spec_from_file_location("container_evidence", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load container evidence builder")
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class ContainerEvidenceTests(unittest.TestCase):
    def fixture_args(self, root: Path, *, repository: str = "remote-management") -> argparse.Namespace:
        sbom = root / "SBOM.spdx.json"
        provenance = root / "PROVENANCE.intoto.jsonl"
        dependencies = root / "dependencies.json"
        deployment_bom = root / "deployment-bom.json"
        deployment_attestation = root / "DEPLOYMENT-BOM-ATTESTATION.intoto.jsonl"
        for path, contents in (
            (sbom, '{"spdxVersion":"SPDX-2.3"}\n'),
            (provenance, '{"mediaType":"fixture"}\n'),
            (dependencies, "[]\n"),
            (deployment_bom, '{"schema_version":1}\n'),
            (deployment_attestation, '{"mediaType":"fixture"}\n'),
        ):
            path.write_text(contents)
        return argparse.Namespace(
            repository=repository,
            image="remote-management-service",
            version="1.0.0",
            commit="a" * 40,
            validation_run_id=42,
            digest=f"sha256:{'b' * 64}",
            platform=[f"linux/amd64=sha256:{'c' * 64}", f"linux/arm64=sha256:{'d' * 64}"],
            sbom=sbom,
            provenance=provenance,
            dependencies=dependencies,
            deployment_bom=deployment_bom,
            deployment_attestation=deployment_attestation,
            generated_at="2026-07-31T00:00:00Z",
            output=root / "frozen.json",
        )

    def test_two_platform_formal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sbom = root / "SBOM.spdx.json"
            provenance = root / "PROVENANCE.intoto.jsonl"
            dependencies = root / "dependencies.json"
            deployment_bom = root / "deployment-bom.json"
            deployment_attestation = root / "DEPLOYMENT-BOM-ATTESTATION.intoto.jsonl"
            sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n')
            provenance.write_text('{"mediaType":"fixture"}\n')
            dependencies.write_text("[]\n")
            deployment_bom.write_text('{"schema_version":1}\n')
            deployment_attestation.write_text('{"mediaType":"fixture"}\n')
            frozen = evidence.freeze(
                argparse.Namespace(
                    repository="remote-management",
                    image="remote-management-service",
                    version="1.0.0",
                    commit="a" * 40,
                    validation_run_id=42,
                    digest=f"sha256:{'b' * 64}",
                    platform=[
                        f"linux/amd64=sha256:{'c' * 64}",
                        f"linux/arm64=sha256:{'d' * 64}",
                    ],
                    sbom=sbom,
                    provenance=provenance,
                    dependencies=dependencies,
                    deployment_bom=deployment_bom,
                    deployment_attestation=deployment_attestation,
                    generated_at="2026-07-31T00:00:00Z",
                    output=root / "frozen.json",
                )
            )
            frozen_path = root / "frozen.json"
            frozen_path.write_text(json.dumps(frozen))
            registries = root / "registries.json"
            registries.write_text(
                json.dumps(
                    [
                        {
                            "name": "dockerhub",
                            "status": "skipped",
                            "reason": "not-configured",
                        },
                        {
                            "name": "ghcr",
                            "status": "published",
                            "repository": "ghcr.io/example/server",
                            "digest": frozen["digest"],
                            "aliases": ["1.0.0", f"sha-{'a' * 40}"],
                            "signature": {
                                "mechanism": "keyless-cosign",
                                "verification": "verified",
                                "identity": "workflow-identity",
                                "issuer": "https://token.actions.githubusercontent.com",
                                "evidence": ["ghcr-cosign-verification.json"],
                            },
                            "readback": "verified",
                        },
                    ]
                )
            )
            formal = evidence.finalize(
                argparse.Namespace(
                    frozen=frozen_path,
                    registries=registries,
                    output=root / "release-evidence.json",
                )
            )
            self.assertEqual(len(formal["images"][0]["platforms"]), 2)
            self.assertEqual(formal["schema_version"], 2)
            self.assertEqual(formal["deployment"]["bom"]["name"], "deployment-bom.json")
            self.assertEqual(formal["policy"]["exceptions"], [])

            invalid = copy.deepcopy(formal)
            invalid["deployment"]["bom"]["name"] = "other.json"
            with self.assertRaisesRegex(ValueError, "unexpected name"):
                evidence.load_validator().validate_release_evidence(invalid)

            legacy = copy.deepcopy(formal)
            legacy["schema_version"] = 1
            legacy.pop("deployment")
            with self.assertRaisesRegex(ValueError, "not valid for Management"):
                evidence.load_validator().validate_release_evidence(legacy)

    def test_management_requires_bom_and_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.fixture_args(Path(temporary))
            args.deployment_bom = None
            with self.assertRaisesRegex(ValueError, "requires deployment BOM"):
                evidence.freeze(args)

    def test_non_management_schema_v1_rejects_deployment_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.fixture_args(Path(temporary), repository="remote-client")
            with self.assertRaisesRegex(ValueError, "valid only for remote-management"):
                evidence.freeze(args)

    def test_schema_v2_is_reserved_for_management(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.fixture_args(Path(temporary), repository="remote-client")
            args.deployment_bom = None
            args.deployment_attestation = None
            frozen = evidence.freeze(args)
            frozen["schema_version"] = 2
            with self.assertRaisesRegex(ValueError, "reserved for Management"):
                evidence.validate_frozen(frozen)


if __name__ == "__main__":
    unittest.main()
