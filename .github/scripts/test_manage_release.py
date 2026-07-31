#!/usr/bin/env python3
"""Pure regression tests for the managed stable release controller."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Self
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("manage-release.py")
SPEC = importlib.util.spec_from_file_location("managed_release", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load managed release controller")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ManagedReleaseTests(unittest.TestCase):
    def test_first_formal_version_is_one(self) -> None:
        with patch.object(release, "completed_releases", return_value=[]):
            self.assertEqual(release.automatic_version("a" * 40), "1.0.0")

    def test_release_history_preserves_an_empty_commit_body(self) -> None:
        sha = "a" * 40
        history = f"{sha}\x1ffix: close release gap\x1f\x1e\n"
        process = release.subprocess.CompletedProcess([], 0, history, "")
        with patch.object(release, "run", return_value=process) as command:
            commits = release.release_commits(sha, None)
        self.assertEqual(
            commits,
            [{"sha": sha, "subject": "fix: close release gap", "body": ""}],
        )
        self.assertEqual(command.call_count, 1)

    def test_working_tree_status_preserves_the_first_status_column(self) -> None:
        status = " M pyproject.toml\n M uv.lock\n?? CHANGELOG.md\n"
        process = release.subprocess.CompletedProcess([], 0, status, "")
        with patch.object(release, "run", return_value=process) as command:
            paths = release.working_tree_paths()
        self.assertEqual(paths, ["CHANGELOG.md", "pyproject.toml", "uv.lock"])
        command.assert_called_once_with(["git", "status", "--short"])

    def test_semver_and_client_build_number_are_canonical(self) -> None:
        self.assertEqual(release.parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(release.client_build_number("1.2.3"), 1_002_003)
        with self.assertRaises(release.ReleaseError):
            release.parse_version("01.2.3")

    def test_commit_sha_canonicalization_is_fail_closed(self) -> None:
        self.assertEqual(release.canonical_sha("a" * 40), "a" * 40)
        for value in ("A" * 40, "../" + "a" * 37, "-" + "a" * 39):
            with self.subTest(value=value), self.assertRaises(release.ReleaseError):
                release.canonical_sha(value)

    def test_app_git_identity_uses_rest_bot_and_process_environment(self) -> None:
        login = "release-manager[bot]"
        response = {"id": 1234, "login": login, "type": "Bot"}
        with (
            patch.dict(
                release.os.environ,
                {"GH_TOKEN": "token", "RELEASE_APP_LOGIN": login},
                clear=True,
            ),
            patch.object(release, "release_app_user", return_value=response) as github,
        ):
            release.configure_app_git()
            self.assertEqual(release.os.environ["GIT_AUTHOR_NAME"], login)
            self.assertEqual(
                release.os.environ["GIT_AUTHOR_EMAIL"],
                f"1234+{login}@users.noreply.github.com",
            )
        github.assert_called_once_with(login)

    def test_app_bot_lookup_uses_fixed_encoded_rest_endpoint(self) -> None:
        class Response:
            requested_bound = 0

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self, bound: int) -> bytes:
                self.requested_bound = bound
                return b'{"id":1234,"login":"release-manager[bot]","type":"Bot"}'

        response = Response()
        with (
            patch.dict(release.os.environ, {"GH_TOKEN": "token"}, clear=True),
            patch.object(release, "urlopen", return_value=response) as opener,
        ):
            user = release.release_app_user("release-manager[bot]")
        self.assertEqual(user["id"], 1234)
        self.assertEqual(response.requested_bound, 1_000_001)
        request = opener.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://api.github.com/users/release-manager%5Bbot%5D",
        )
        self.assertEqual(request.get_header("Authorization"), "Bearer token")
        self.assertEqual(opener.call_args.kwargs, {"timeout": 30})

    def test_app_git_identity_rejects_non_bot_actor(self) -> None:
        login = "release-manager[bot]"
        with (
            patch.dict(release.os.environ, {"RELEASE_APP_LOGIN": login}, clear=True),
            patch.object(
                release,
                "release_app_user",
                return_value={"id": 1234, "login": login, "type": "User"},
            ),
            self.assertRaisesRegex(release.ReleaseError, "differs from policy"),
        ):
            release.configure_app_git()

    def test_runner_output_rejects_paths_outside_runner_commands(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(
                release.os.environ,
                {"GITHUB_OUTPUT": str(Path(temporary) / "output")},
                clear=True,
            ),
            self.assertRaisesRegex(release.ReleaseError, "outside"),
        ):
            release.append_output("release-id", 1)

    def test_cargo_version_rewrite_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "fixture"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                'version = 4\n\n[[package]]\nname = "fixture"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            release.rewrite_cargo_version(root, {"package_name": "fixture"}, "1.0.0")
            self.assertIn(
                'version = "1.0.0"',
                (root / "Cargo.toml").read_text(encoding="utf-8"),
            )
            self.assertIn(
                'version = "1.0.0"',
                (root / "Cargo.lock").read_text(encoding="utf-8"),
            )

    def test_release_record_requires_digest_for_container(self) -> None:
        sha = "a" * 40
        record = {
            "id": 1,
            "tag_name": "v1.0.0",
            "target_commitish": sha,
            "name": "Fixture 1.0.0",
            "author": {"login": "release-app[bot]"},
            "draft": False,
            "immutable": True,
            "body": (f"<!-- release-pr:7 -->\n<!-- release-commit:{sha} -->\n<!-- release-complete:{sha} -->\n"),
        }
        with (
            patch.dict(
                release.os.environ,
                {"RELEASE_APP_LOGIN": "release-app[bot]"},
            ),
            self.assertRaises(release.ReleaseError),
        ):
            release.validate_release_record(
                {"title": "Fixture", "container": True},
                record,
                version="1.0.0",
                sha=sha,
                number=7,
            )

    def test_release_configuration_is_portable(self) -> None:
        config = json.loads((Path(__file__).parents[1] / "release-config.json").read_text())
        self.assertTrue(config["logical_id"].startswith("remote-"))
        self.assertNotIn("/", config["logical_id"])


if __name__ == "__main__":
    unittest.main()
