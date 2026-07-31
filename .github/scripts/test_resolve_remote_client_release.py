#!/usr/bin/env python3
"""Regression tests for exact Remote Client release dependency resolution."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("resolve-remote-client-release.py")
SPEC = importlib.util.spec_from_file_location(
    "resolve_remote_client_release", SCRIPT
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load resolver")
resolver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resolver)

COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40


def release_evidence(
    version: str = "1.2.3", commit: str = COMMIT, *, web: bool = True
) -> dict:
    platform = "web" if web else "linux"
    architecture = "universal" if web else "x64"
    name = "client-web.zip" if web else "client-linux.tar.gz"
    return {
        "schema_version": 1,
        "repository": "remote-client",
        "version": version,
        "source": {
            "commit": commit,
            "ref": f"refs/tags/v{version}",
            "validation_run_id": 42,
        },
        "release_kind": "formal",
        "generated_at": "2026-07-31T00:00:00Z",
        "policy": {
            "repository_policy_revision": "2026-07-31.1",
            "signing_registry_revision": "2026-07-31.1",
            "exceptions": [],
        },
        "dependencies": [],
        "files": [
            {
                "name": name,
                "sha256": "c" * 64,
                "size_bytes": 1,
                "platform": platform,
                "architecture": architecture,
                "signing": {
                    "category": (
                        "not-applicable" if web else "platform-key"
                    ),
                    "verification": (
                        "not-applicable" if web else "verified"
                    ),
                    "verifier": "none" if web else "openpgp",
                    "timestamp": "not-applicable",
                    "distribution": (
                        "not-applicable" if web else "installable"
                    ),
                    "evidence": [] if web else ["client-linux.tar.gz.asc"],
                },
                "sbom": {"name": "SBOM.spdx.json", "sha256": "d" * 64},
                "provenance": {
                    "name": "PROVENANCE.intoto.jsonl",
                    "sha256": "e" * 64,
                },
            }
        ],
        "images": [],
    }


def managed_release(
    *,
    version: str = "1.2.3",
    commit: str = COMMIT,
    complete: bool = True,
) -> dict:
    body = f"<!-- release-complete:{commit} -->" if complete else ""
    return {
        "id": 17,
        "tag_name": f"v{version}",
        "target_commitish": commit,
        "body": body,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "author": {"login": "release-app[bot]"},
        "assets": [{"id": 23, "name": "release-evidence.json"}],
    }


class ResolveRemoteClientReleaseTests(unittest.TestCase):
    def args(self, root: Path):
        return resolver.parser().parse_args(
            [
                "--repository-map",
                json.dumps(
                    {
                        "remote-client": "desktop",
                        "remote-management": "service",
                        "remote-protocol": "protocol",
                        "remote-server": "relay",
                    }
                ),
                "--owner",
                "example",
                "--current-repository",
                "example/service",
                "--release-app-login",
                "release-app[bot]",
                "--commit",
                COMMIT,
                "--output-directory",
                str(root),
            ]
        )

    def test_selects_exact_locked_release_and_writes_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = [[
                managed_release(),
                managed_release(version="1.3.0", commit=OTHER_COMMIT),
            ]]

            def gh_json(*arguments: str):
                endpoint = arguments[-1]
                if endpoint == "repos/example/desktop":
                    return {
                        "private": False,
                        "full_name": "example/desktop",
                    }
                if endpoint.endswith("releases?per_page=100"):
                    return releases
                if endpoint.endswith("git/ref/tags/v1.2.3"):
                    return {
                        "ref": "refs/tags/v1.2.3",
                        "object": {"type": "commit", "sha": COMMIT},
                    }
                raise AssertionError(arguments)

            payload = (json.dumps(release_evidence()) + "\n").encode()
            with (
                patch.object(resolver, "run_gh_json", side_effect=gh_json),
                patch.object(resolver, "run_gh_bytes", return_value=payload),
            ):
                resolved = resolver.resolve(self.args(root))
                resolver.write_outputs(self.args(root), resolved)

            dependency = json.loads(
                (root / "dependencies.json").read_text()
            )[0]
            metadata = json.loads(
                (root / "remote-client-release.json").read_text()
            )
            self.assertEqual(dependency["commit"], COMMIT)
            self.assertEqual(dependency["relation"], "bundles")
            self.assertEqual(metadata["version"], "1.2.3")
            self.assertNotIn("example/desktop", json.dumps(metadata))

    def test_rejects_incomplete_locked_release(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one"):
            resolver.completed_release(
                [[managed_release(complete=False)]],
                "release-app[bot]",
                COMMIT,
            )

    def test_rejects_release_without_web_artifact(self) -> None:
        with self.assertRaisesRegex(ValueError, "Web-capable"):
            resolver.validate_client_evidence(
                release_evidence(web=False),
                version="1.2.3",
                commit=COMMIT,
            )

    def test_rejects_repository_map_identity_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "current repository"):
            resolver.repository_names(
                json.dumps(
                    {
                        "remote-client": "desktop",
                        "remote-management": "other",
                        "remote-protocol": "protocol",
                        "remote-server": "relay",
                    }
                ),
                "example/service",
            )


if __name__ == "__main__":
    unittest.main()
