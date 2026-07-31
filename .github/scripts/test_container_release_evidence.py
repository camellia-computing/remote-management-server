#!/usr/bin/env python3
"""Regression tests for generic container release evidence."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

import importlib.util


SCRIPT = Path(__file__).with_name("build-container-release-evidence.py")
SPEC = importlib.util.spec_from_file_location("container_evidence", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load container evidence builder")
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class ContainerEvidenceTests(unittest.TestCase):
    def test_two_platform_formal_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sbom = root / "SBOM.spdx.json"
            provenance = root / "PROVENANCE.intoto.jsonl"
            dependencies = root / "dependencies.json"
            sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n')
            provenance.write_text('{"mediaType":"fixture"}\n')
            dependencies.write_text("[]\n")
            frozen = evidence.freeze(
                argparse.Namespace(
                    repository="remote-server",
                    image="remote-server-service",
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
            self.assertEqual(formal["policy"]["exceptions"], [])


if __name__ == "__main__":
    unittest.main()
