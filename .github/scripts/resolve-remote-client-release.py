#!/usr/bin/env python3
"""Resolve the exact completed Remote Client release selected by web-client.lock."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any


COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SEMVER = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
LOGICAL_IDS = (
    "remote-client",
    "remote-management",
    "remote-protocol",
    "remote-server",
)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_json(value: str | bytes, label: str) -> Any:
    try:
        return json.loads(value, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error


def load_validator() -> ModuleType:
    path = Path(__file__).with_name("validate-release-evidence.py")
    spec = importlib.util.spec_from_file_location(
        "release_evidence_validator", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load release evidence validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_gh_json(*arguments: str) -> Any:
    process = subprocess.run(
        ["gh", "api", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_json(process.stdout, "GitHub API response")


def run_gh_bytes(*arguments: str) -> bytes:
    process = subprocess.run(
        ["gh", "api", *arguments],
        check=True,
        capture_output=True,
    )
    return process.stdout


def repository_names(value: str, current_repository: str) -> tuple[str, str]:
    parsed = parse_json(value, "REMOTE_REPOSITORY_MAP")
    if (
        not isinstance(parsed, dict)
        or tuple(sorted(parsed)) != LOGICAL_IDS
        or any(
            not isinstance(parsed[item], str)
            or not NAME.fullmatch(parsed[item])
            or parsed[item] in {".", ".."}
            for item in LOGICAL_IDS
        )
    ):
        raise ValueError(
            "REMOTE_REPOSITORY_MAP must be the complete reviewed logical map"
        )
    current_name = current_repository.split("/", 1)[-1]
    if parsed["remote-management"].casefold() != current_name.casefold():
        raise ValueError(
            "logical repository map does not match the current repository"
        )
    if parsed["remote-client"].casefold() == current_name.casefold():
        raise ValueError(
            "Remote Client and Management repository names must differ"
        )
    return parsed["remote-client"], parsed["remote-management"]


def flatten_pages(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("GitHub release response must be an array")
    if value and all(isinstance(page, list) for page in value):
        value = [item for page in value for item in page]
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("GitHub release response contains an invalid item")
    return value


def completed_release(
    releases: Any, release_app_login: str, commit: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    stable_tags: set[str] = set()
    for release in flatten_pages(releases):
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not SEMVER.fullmatch(tag):
            continue
        if tag in stable_tags:
            raise ValueError(f"multiple releases use stable tag {tag}")
        stable_tags.add(tag)
        assets = release.get("assets")
        body = release.get("body")
        if (
            release.get("target_commitish") != commit
            or release.get("draft") is not False
            or release.get("prerelease") is not False
            or release.get("immutable") is not True
            or release.get("author", {}).get("login") != release_app_login
            or not isinstance(release.get("id"), int)
            or isinstance(release.get("id"), bool)
            or release["id"] < 1
            or not isinstance(body, str)
            or not isinstance(assets, list)
        ):
            continue
        if body.splitlines().count(f"<!-- release-complete:{commit} -->") != 1:
            continue
        evidence_assets = [
            asset
            for asset in assets
            if isinstance(asset, dict)
            and asset.get("name") == "release-evidence.json"
            and isinstance(asset.get("id"), int)
            and not isinstance(asset.get("id"), bool)
            and asset["id"] > 0
        ]
        if len(evidence_assets) == 1:
            matches.append((release, evidence_assets[0]))
    if len(matches) != 1:
        raise ValueError(
            "locked Remote Client commit must have exactly one completed "
            "immutable stable release"
        )
    return matches[0]


def validate_client_evidence(
    value: Any, *, version: str, commit: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Remote Client release evidence must be an object")
    load_validator().validate_release_evidence(value)
    web_files = [
        item
        for item in value.get("files", [])
        if item.get("platform") == "web"
        and item.get("architecture") == "universal"
        and item.get("name", "").endswith(".zip")
        and item.get("signing", {}).get("category") == "not-applicable"
        and item.get("signing", {}).get("distribution") == "not-applicable"
    ]
    if (
        value.get("repository") != "remote-client"
        or value.get("version") != version
        or value.get("release_kind") != "formal"
        or value.get("source", {}).get("commit") != commit
        or value.get("source", {}).get("ref") != f"refs/tags/v{version}"
        or value.get("images") != []
        or len(web_files) != 1
    ):
        raise ValueError(
            "Remote Client evidence does not identify one Web-capable "
            "formal release"
        )
    return value


def resolve(args: argparse.Namespace) -> dict[str, Any]:
    if not COMMIT.fullmatch(args.commit):
        raise ValueError("locked commit must be one full lowercase Git SHA")
    client_name, _ = repository_names(
        args.repository_map, args.current_repository
    )
    target_repository = f"{args.owner}/{client_name}"
    repository = run_gh_json(f"repos/{target_repository}")
    if (
        not isinstance(repository, dict)
        or str(repository.get("full_name", "")).casefold()
        != target_repository.casefold()
    ):
        raise ValueError("Remote Client repository identity is invalid")
    releases = run_gh_json(
        "--paginate",
        "--slurp",
        f"repos/{target_repository}/releases?per_page=100",
    )
    release, evidence_asset = completed_release(
        releases, args.release_app_login, args.commit
    )
    tag = release["tag_name"]
    version = tag.removeprefix("v")
    tag_ref = run_gh_json(f"repos/{target_repository}/git/ref/tags/{tag}")
    if (
        not isinstance(tag_ref, dict)
        or tag_ref.get("ref") != f"refs/tags/{tag}"
        or tag_ref.get("object", {}).get("type") != "commit"
        or tag_ref.get("object", {}).get("sha") != args.commit
    ):
        raise ValueError(
            "selected Remote Client tag is not a lightweight exact commit ref"
        )
    evidence_bytes = run_gh_bytes(
        "-H",
        "Accept: application/octet-stream",
        f"repos/{target_repository}/releases/assets/{evidence_asset['id']}",
    )
    evidence = validate_client_evidence(
        parse_json(evidence_bytes, "Remote Client release evidence"),
        version=version,
        commit=args.commit,
    )
    return {
        "target_repository": target_repository,
        "release": release,
        "evidence": evidence,
        "evidence_bytes": evidence_bytes,
        "version": version,
        "tag": tag,
        "commit": args.commit,
    }


def write_outputs(args: argparse.Namespace, resolved: dict[str, Any]) -> None:
    output = args.output_directory
    if not output.is_dir() or output.is_symlink():
        raise ValueError("output directory must be an existing real directory")
    evidence_path = output / "remote-client-release-evidence.json"
    metadata_path = output / "remote-client-release.json"
    dependencies_path = output / "dependencies.json"
    evidence_path.write_bytes(resolved["evidence_bytes"])
    evidence_sha = hashlib.sha256(resolved["evidence_bytes"]).hexdigest()
    metadata = {
        "schema_version": 1,
        "repository": "remote-client",
        "version": resolved["version"],
        "tag": resolved["tag"],
        "commit": resolved["commit"],
        "release_id": resolved["release"]["id"],
        "immutable": True,
        "complete": True,
        "release_evidence": {
            "name": evidence_path.name,
            "sha256": evidence_sha,
        },
    }
    dependency = {
        "repository": "remote-client",
        "commit": resolved["commit"],
        "version": resolved["version"],
        "relation": "bundles",
        "evidence": metadata_path.name,
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    dependencies_path.write_text(
        json.dumps([dependency], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"commit={resolved['commit']}\n")
            stream.write(f"repository={resolved['target_repository']}\n")
            stream.write(f"tag={resolved['tag']}\n")
            stream.write(f"version={resolved['version']}\n")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--repository-map", required=True)
    result.add_argument("--owner", required=True)
    result.add_argument("--current-repository", required=True)
    result.add_argument("--release-app-login", required=True)
    result.add_argument("--commit", required=True)
    result.add_argument("--output-directory", required=True, type=Path)
    result.add_argument("--github-output", type=Path)
    return result


def main() -> None:
    if not os.environ.get("GH_TOKEN"):
        raise ValueError("GH_TOKEN is required")
    args = parser().parse_args()
    write_outputs(args, resolve(args))


if __name__ == "__main__":
    main()
