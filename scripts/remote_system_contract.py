#!/usr/bin/env python3
"""Validate the Management-side inputs consumed by the Remote system harness."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
LOGICAL_IDS = (
    "remote-client",
    "remote-management",
    "remote-protocol",
    "remote-server",
)


class ContractError(ValueError):
    """Raised when a cross-repository input is not safe to consume."""


def parse_map(value: str) -> dict[str, str]:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("REMOTE_REPOSITORY_MAP must be valid JSON") from error
    if not isinstance(parsed, dict) or tuple(sorted(parsed)) != LOGICAL_IDS:
        raise ContractError("REMOTE_REPOSITORY_MAP must contain all four logical IDs")
    result: dict[str, str] = {}
    for logical_id in LOGICAL_IDS:
        item = parsed[logical_id]
        if not isinstance(item, str) or not NAME.fullmatch(item):
            raise ContractError(f"repository name for {logical_id} is invalid")
        result[logical_id] = item
    if len({item.casefold() for item in result.values()}) != len(result):
        raise ContractError("REMOTE_REPOSITORY_MAP contains duplicate physical names")
    return result


def read_web_lock(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ContractError("web-client.lock must be a regular file")
    lines = path.read_text(encoding="ascii").splitlines()
    if len(lines) != 1 or not COMMIT.fullmatch(lines[0]):
        raise ContractError("web-client.lock must contain one full lowercase commit")
    return lines[0]


def validate_compose_images(path: Path) -> dict[str, str]:
    """Check image references without evaluating environment or starting Docker."""
    text = path.read_text(encoding="utf-8")
    required = {
        "CAMELLIA_REMOTE_MANAGEMENT_IMAGE": re.compile(
            r"\s*image:\s*\$\{CAMELLIA_REMOTE_MANAGEMENT_IMAGE:\?[^}]+\}\s*$",
            re.MULTILINE,
        ),
        "POSTGRES_IMAGE": re.compile(
            r"\s*image:\s*postgres:18-alpine@sha256:[0-9a-f]{64}\s*$",
            re.MULTILINE,
        ),
    }
    for name, pattern in required.items():
        if pattern.search(text) is None:
            raise ContractError(f"Compose does not pin the required {name} boundary")
    return {
        "management": "CAMELLIA_REMOTE_MANAGEMENT_IMAGE",
        "postgres": "postgres:18-alpine@sha256:<reviewed-digest>",
    }


def validate(
    *,
    repository_map: str,
    current_repository: str,
    web_lock: Path,
    compose: Path,
) -> dict[str, Any]:
    names = parse_map(repository_map)
    current_name = current_repository.split("/", 1)[-1]
    if names["remote-management"].casefold() != current_name.casefold():
        raise ContractError("repository map does not identify the current Management repository")
    locked_client = read_web_lock(web_lock)
    validate_compose_images(compose)
    return {
        "logical_repository": "remote-management",
        "physical_repository": names["remote-management"],
        "client_web_commit": locked_client,
        "required_runtime": [
            "remote-client",
            "remote-management",
            "remote-protocol",
            "remote-server",
        ],
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-map", required=True)
    parser.add_argument("--current-repository", required=True)
    parser.add_argument("--web-lock", type=Path, default=Path("web-client.lock"))
    parser.add_argument("--compose", type=Path, default=Path("docker-compose.yaml"))
    args = parser.parse_args(arguments)
    try:
        result = validate(
            repository_map=args.repository_map,
            current_repository=args.current_repository,
            web_lock=args.web_lock,
            compose=args.compose,
        )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, UnicodeError, ContractError) as error:
        print(f"Remote system contract rejected: {error}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
