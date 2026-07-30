#!/usr/bin/env python3
"""Validate and expose the API server's canonical release metadata."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class MetadataError(ValueError):
    """Raised when release metadata is missing, ambiguous, or inconsistent."""


@dataclass(frozen=True)
class ReleaseMetadata:
    version: str
    tag: str
    major: str
    minor: str
    patch: str


def _read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as file:
            return tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise MetadataError(f"cannot read {path}: {error}") from error


def _project_metadata(root: Path) -> tuple[str, str]:
    project = _read_toml(root / "pyproject.toml").get("project")
    if not isinstance(project, dict):
        raise MetadataError("pyproject.toml must contain a project table")
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not name.strip():
        raise MetadataError("pyproject.toml project.name must be a non-empty string")
    if not isinstance(version, str) or not version.strip():
        raise MetadataError("pyproject.toml project.version must be a non-empty string")
    return name, version


def _lock_version(root: Path, project_name: str) -> str:
    packages = _read_toml(root / "uv.lock").get("package")
    if not isinstance(packages, list):
        raise MetadataError("uv.lock does not contain a package list")
    matches = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == project_name
        and package.get("source") == {"virtual": "."}
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("version"), str):
        raise MetadataError(f"uv.lock must contain exactly one virtual {project_name} package")
    return matches[0]["version"]


def load_metadata(root: Path) -> ReleaseMetadata:
    root = root.resolve()
    project_name, project_version = _project_metadata(root)
    match = SEMVER_RE.fullmatch(project_version)
    if match is None:
        raise MetadataError("project version must be stable SemVer MAJOR.MINOR.PATCH")

    lock_version = _lock_version(root, project_name)
    if lock_version != project_version:
        raise MetadataError(f"version mismatch: pyproject.toml={project_version}, uv.lock={lock_version}")

    major, minor, patch = match.groups()
    return ReleaseMetadata(
        version=project_version,
        tag=f"v{project_version}",
        major=major,
        minor=minor,
        patch=patch,
    )


def _write_github_output(path: Path, metadata: ReleaseMetadata) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in asdict(metadata).items():
            output.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    parser.add_argument("--expect-tag", help="require this exact canonical v-prefixed tag")
    parser.add_argument(
        "--github-output",
        action="store_true",
        help="append fields to the path in GITHUB_OUTPUT",
    )
    args = parser.parse_args(argv)

    try:
        metadata = load_metadata(args.root)
        if args.expect_tag is not None and args.expect_tag != metadata.tag:
            raise MetadataError(f"expected tag {metadata.tag}, got {args.expect_tag}")
        if args.github_output:
            output_path = os.environ.get("GITHUB_OUTPUT")
            if not output_path:
                raise MetadataError("GITHUB_OUTPUT is required with --github-output")
            _write_github_output(Path(output_path), metadata)
    except MetadataError as error:
        print(f"release metadata error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(asdict(metadata), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
