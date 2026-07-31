#!/usr/bin/env python3
"""Validate complete, immutable file and OCI release evidence."""

from __future__ import annotations

import argparse
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

CATEGORIES = {
    "public-trust",
    "private-trust",
    "platform-key",
    "ad-hoc",
    "unsigned",
    "not-applicable",
}
PLATFORMS = {"android", "ios", "linux", "macos", "source", "web", "windows"}
DISTRIBUTIONS = {
    "installable",
    "restricted",
    "re-signing-input",
    "source-only",
    "not-applicable",
}
REGISTRIES = {"dockerhub", "ghcr"}
ROOT_KEYS = {
    "schema_version",
    "repository",
    "version",
    "source",
    "release_kind",
    "generated_at",
    "policy",
    "dependencies",
    "files",
    "images",
}
SOURCE_KEYS = {"commit", "ref", "validation_run_id"}
POLICY_KEYS = {
    "repository_policy_revision",
    "signing_registry_revision",
    "exceptions",
}
EXCEPTION_KEYS = {
    "id",
    "owner",
    "expires_on",
    "reason",
    "compensating_control",
    "evidence",
}
DEPENDENCY_KEYS = {"repository", "commit", "version", "relation", "evidence"}
FILE_KEYS = {
    "name",
    "sha256",
    "size_bytes",
    "platform",
    "architecture",
    "sbom",
    "provenance",
    "signing",
}
EVIDENCE_FILE_KEYS = {"name", "sha256"}
SIGNING_KEYS = {
    "category",
    "verification",
    "verifier",
    "timestamp",
    "distribution",
    "evidence",
}
IMAGE_KEYS = {"name", "digest", "platforms", "sbom", "provenance", "registries"}
IMAGE_PLATFORM_KEYS = {"platform", "architecture", "digest"}
PUBLISHED_REGISTRY_KEYS = {
    "name",
    "status",
    "repository",
    "digest",
    "aliases",
    "signature",
    "readback",
}
SKIPPED_REGISTRY_KEYS = {"name", "status", "reason"}
IMAGE_SIGNATURE_KEYS = {
    "mechanism",
    "verification",
    "identity",
    "issuer",
    "evidence",
}
LOGICAL_ID_PATTERN = r"[a-z0-9]+(?:-[a-z0-9]+)*"
SEMVER_PATTERN = (
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?"
)
REVISION_PATTERN = r"20[0-9]{2}-[0-9]{2}-[0-9]{2}\.[1-9][0-9]*"
DIGEST_PATTERN = r"sha256:[0-9a-f]{64}"


def require_string(mapping: dict[str, Any], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def require_sorted_unique_strings(
    value: Any,
    location: str,
    *,
    allow_empty: bool = True,
) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        qualifier = "" if allow_empty else "non-empty "
        raise ValueError(f"{location} must be a sorted unique {qualifier}string array")
    return value


def validate_logical_id(value: Any, location: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(LOGICAL_ID_PATTERN, value):
        raise ValueError(f"{location} must be a logical id")
    return value


def validate_semver(value: Any, location: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(SEMVER_PATTERN, value):
        raise ValueError(f"{location} must be SemVer without v prefix or build metadata")
    return value


def validate_revision(value: Any, location: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(REVISION_PATTERN, value):
        raise ValueError(f"{location} must use YYYY-MM-DD.N")
    return value


def validate_sha256(value: Any, location: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{location} must be lowercase SHA-256")
    return value


def validate_digest(value: Any, location: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(DIGEST_PATTERN, value):
        raise ValueError(f"{location} must be a canonical sha256 OCI digest")
    return value


def validate_evidence_file(value: Any, location: str) -> None:
    if not isinstance(value, dict) or set(value) != EVIDENCE_FILE_KEYS:
        raise ValueError(f"{location} has unexpected fields")
    require_string(value, "name")
    validate_sha256(value.get("sha256"), f"{location}.sha256")


def validate_signing(
    value: Any,
    location: str,
    *,
    platform: str,
) -> None:
    if not isinstance(value, dict) or set(value) != SIGNING_KEYS:
        raise ValueError(f"{location} has unexpected fields")
    category = require_string(value, "category")
    verification = require_string(value, "verification")
    verifier = require_string(value, "verifier")
    timestamp = require_string(value, "timestamp")
    distribution = require_string(value, "distribution")
    evidence = require_sorted_unique_strings(value.get("evidence"), f"{location}.evidence")
    if category not in CATEGORIES:
        raise ValueError(f"{location}.category is invalid")
    if verification not in {"verified", "not-present", "not-applicable"}:
        raise ValueError(f"{location}.verification is invalid")
    if timestamp not in {"verified", "missing", "not-applicable"}:
        raise ValueError(f"{location}.timestamp is invalid")
    if distribution not in DISTRIBUTIONS:
        raise ValueError(f"{location}.distribution is invalid")

    if category == "not-applicable":
        if (
            verification != "not-applicable"
            or verifier != "none"
            or timestamp != "not-applicable"
            or evidence
        ):
            raise ValueError(f"{location} contradicts its not-applicable category")
        if platform not in {"source", "web"}:
            raise ValueError(f"{location} is not applicable only to source or Web files")
    elif category == "unsigned":
        if verification != "not-present" or verifier != "none":
            raise ValueError(f"{location} contradicts its unsigned category")
        if timestamp != "not-applicable" or evidence:
            raise ValueError(f"{location} unsigned evidence must be empty")
    elif verification != "verified" or verifier == "none" or not evidence:
        raise ValueError(f"{location} signed evidence must be verified")

    if platform in {"source", "web"} and category != "not-applicable":
        raise ValueError(f"{location} source and Web files use not-applicable signing")
    if distribution == "source-only" and platform != "source":
        raise ValueError(f"{location} source-only distribution requires source platform")
    if distribution == "not-applicable" and platform not in {"source", "web"}:
        raise ValueError(
            f"{location} not-applicable distribution requires source or Web platform"
        )
    if distribution == "re-signing-input" and platform not in {"android", "ios"}:
        raise ValueError(
            f"{location} re-signing inputs are limited to Android and iOS"
        )
    if category == "unsigned" and platform in {"android", "ios"}:
        if distribution != "re-signing-input":
            raise ValueError(
                f"{location} unsigned mobile output must be a re-signing input"
            )
    if category == "ad-hoc" and distribution == "installable":
        raise ValueError(
            f"{location} ad-hoc artifacts cannot claim installable distribution"
        )


def validate_policy(
    value: Any,
    *,
    generated_on: date,
) -> None:
    if not isinstance(value, dict) or set(value) != POLICY_KEYS:
        raise ValueError("policy has unexpected fields")
    validate_revision(
        value.get("repository_policy_revision"),
        "policy.repository_policy_revision",
    )
    validate_revision(
        value.get("signing_registry_revision"),
        "policy.signing_registry_revision",
    )
    exceptions = value.get("exceptions")
    if not isinstance(exceptions, list):
        raise ValueError("policy.exceptions must be an array")
    exception_ids: list[str] = []
    for index, exception in enumerate(exceptions):
        location = f"policy.exceptions[{index}]"
        if not isinstance(exception, dict) or set(exception) != EXCEPTION_KEYS:
            raise ValueError(f"{location} has unexpected fields")
        exception_id = validate_logical_id(exception.get("id"), f"{location}.id")
        exception_ids.append(exception_id)
        validate_logical_id(exception.get("owner"), f"{location}.owner")
        try:
            expires_on = date.fromisoformat(require_string(exception, "expires_on"))
        except ValueError as error:
            raise ValueError(f"{location}.expires_on must be an ISO date") from error
        if expires_on < generated_on:
            raise ValueError(f"{location} was expired when evidence was generated")
        require_string(exception, "reason")
        require_string(exception, "compensating_control")
        require_sorted_unique_strings(
            exception.get("evidence"),
            f"{location}.evidence",
            allow_empty=False,
        )
    if exception_ids != sorted(set(exception_ids)):
        raise ValueError("policy.exceptions must be sorted and unique by id")


def validate_dependencies(value: Any) -> None:
    if not isinstance(value, list):
        raise ValueError("dependencies must be an array")
    identities: list[tuple[str, str, str]] = []
    for index, dependency in enumerate(value):
        location = f"dependencies[{index}]"
        if not isinstance(dependency, dict) or set(dependency) != DEPENDENCY_KEYS:
            raise ValueError(f"{location} has unexpected fields")
        repository = validate_logical_id(
            dependency.get("repository"),
            f"{location}.repository",
        )
        commit = require_string(dependency, "commit")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError(f"{location}.commit must be a full lowercase commit SHA")
        version = dependency.get("version")
        if version is not None:
            validate_semver(version, f"{location}.version")
        relation = require_string(dependency, "relation")
        if relation not in {"builds-from", "bundles", "compatible-with"}:
            raise ValueError(f"{location}.relation is invalid")
        require_string(dependency, "evidence")
        identities.append((repository, relation, commit))
    if identities != sorted(set(identities)):
        raise ValueError(
            "dependencies must be sorted and unique by repository, relation, commit"
        )


def validate_files(value: Any) -> None:
    if not isinstance(value, list):
        raise ValueError("files must be an array")
    names: list[str] = []
    for index, artifact in enumerate(value):
        location = f"files[{index}]"
        if not isinstance(artifact, dict) or set(artifact) != FILE_KEYS:
            raise ValueError(f"{location} has unexpected fields")
        name = require_string(artifact, "name")
        names.append(name)
        validate_sha256(artifact.get("sha256"), f"{location}.sha256")
        size = artifact.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise ValueError(f"{location}.size_bytes must be positive")
        platform = artifact.get("platform")
        if platform not in PLATFORMS:
            raise ValueError(f"{location}.platform is invalid")
        validate_logical_id(artifact.get("architecture"), f"{location}.architecture")
        validate_evidence_file(artifact.get("sbom"), f"{location}.sbom")
        validate_evidence_file(artifact.get("provenance"), f"{location}.provenance")
        validate_signing(
            artifact.get("signing"),
            f"{location}.signing",
            platform=platform,
        )
    if names != sorted(set(names)):
        raise ValueError("files must be sorted and unique by name")


def validate_image_signature(value: Any, location: str) -> None:
    if not isinstance(value, dict) or set(value) != IMAGE_SIGNATURE_KEYS:
        raise ValueError(f"{location} has unexpected fields")
    if value.get("mechanism") != "keyless-cosign":
        raise ValueError(f"{location}.mechanism must be keyless-cosign")
    if value.get("verification") != "verified":
        raise ValueError(f"{location}.verification must be verified")
    require_string(value, "identity")
    require_string(value, "issuer")
    require_sorted_unique_strings(
        value.get("evidence"),
        f"{location}.evidence",
        allow_empty=False,
    )


def validate_registry(
    value: Any,
    location: str,
    *,
    image_digest: str,
    release_kind: str,
    version: str,
    commit: str,
) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be an object")
    name = require_string(value, "name")
    if name not in REGISTRIES:
        raise ValueError(f"{location}.name is invalid")
    status = require_string(value, "status")
    if status == "skipped":
        if set(value) != SKIPPED_REGISTRY_KEYS:
            raise ValueError(f"{location} skipped result has unexpected fields")
        reason = require_string(value, "reason")
        expected_reason = "candidate-only" if release_kind == "candidate" else "not-configured"
        if reason != expected_reason:
            raise ValueError(
                f"{location} skipped {release_kind} result must use {expected_reason}"
            )
        return name, status
    if status != "published" or set(value) != PUBLISHED_REGISTRY_KEYS:
        raise ValueError(f"{location} has an invalid publication result")
    if release_kind != "formal":
        raise ValueError(f"{location} candidates cannot publish registry images")
    repository = require_string(value, "repository")
    if not re.fullmatch(
        r"[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*",
        repository,
    ):
        raise ValueError(f"{location}.repository is invalid")
    if validate_digest(value.get("digest"), f"{location}.digest") != image_digest:
        raise ValueError(f"{location}.digest differs from the canonical image digest")
    aliases = require_sorted_unique_strings(
        value.get("aliases"),
        f"{location}.aliases",
        allow_empty=False,
    )
    required_aliases = {version, f"sha-{commit}"}
    if not required_aliases.issubset(aliases):
        raise ValueError(
            f"{location}.aliases must include the stable version and full source SHA"
        )
    validate_image_signature(value.get("signature"), f"{location}.signature")
    if value.get("readback") != "verified":
        raise ValueError(f"{location}.readback must be verified")
    return name, status


def validate_images(
    value: Any,
    *,
    release_kind: str,
    version: str,
    commit: str,
) -> None:
    if not isinstance(value, list):
        raise ValueError("images must be an array")
    names: list[str] = []
    for index, image in enumerate(value):
        location = f"images[{index}]"
        if not isinstance(image, dict) or set(image) != IMAGE_KEYS:
            raise ValueError(f"{location} has unexpected fields")
        name = validate_logical_id(image.get("name"), f"{location}.name")
        names.append(name)
        image_digest = validate_digest(image.get("digest"), f"{location}.digest")
        platforms = image.get("platforms")
        if not isinstance(platforms, list) or not platforms:
            raise ValueError(f"{location}.platforms must be a non-empty array")
        platform_ids: list[tuple[str, str]] = []
        platform_digests: list[str] = []
        for platform_index, platform in enumerate(platforms):
            platform_location = f"{location}.platforms[{platform_index}]"
            if (
                not isinstance(platform, dict)
                or set(platform) != IMAGE_PLATFORM_KEYS
            ):
                raise ValueError(f"{platform_location} has unexpected fields")
            if platform.get("platform") != "linux":
                raise ValueError(f"{platform_location}.platform must be linux")
            architecture = require_string(platform, "architecture")
            if architecture not in {"amd64", "arm64"}:
                raise ValueError(f"{platform_location}.architecture is invalid")
            platform_ids.append(("linux", architecture))
            platform_digests.append(
                validate_digest(platform.get("digest"), f"{platform_location}.digest")
            )
        if platform_ids != sorted(set(platform_ids)):
            raise ValueError(f"{location}.platforms must be sorted and unique")
        if len(platform_digests) != len(set(platform_digests)):
            raise ValueError(f"{location}.platform digests must be unique")
        validate_evidence_file(image.get("sbom"), f"{location}.sbom")
        validate_evidence_file(image.get("provenance"), f"{location}.provenance")

        registries = image.get("registries")
        if not isinstance(registries, list) or len(registries) != len(REGISTRIES):
            raise ValueError(
                f"{location}.registries must explicitly cover Docker Hub and GHCR"
            )
        registry_results = [
            validate_registry(
                registry,
                f"{location}.registries[{registry_index}]",
                image_digest=image_digest,
                release_kind=release_kind,
                version=version,
                commit=commit,
            )
            for registry_index, registry in enumerate(registries)
        ]
        if [item[0] for item in registry_results] != sorted(REGISTRIES):
            raise ValueError(f"{location}.registries must be sorted and unique by name")
        if release_kind == "formal" and not any(
            status == "published" for _, status in registry_results
        ):
            raise ValueError(f"{location} formal image has no configured registry")
    if names != sorted(set(names)):
        raise ValueError("images must be sorted and unique by name")


def validate_release_evidence(value: dict[str, Any]) -> None:
    if set(value) != ROOT_KEYS:
        raise ValueError("release evidence has unexpected fields")
    if value.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    validate_logical_id(value.get("repository"), "repository")
    version = validate_semver(value.get("version"), "version")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
        raise ValueError("source has unexpected fields")
    commit = require_string(source, "commit")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source.commit must be a full lowercase commit SHA")
    source_ref = require_string(source, "ref")
    validation_run_id = source.get("validation_run_id")
    if (
        not isinstance(validation_run_id, int)
        or isinstance(validation_run_id, bool)
        or validation_run_id < 1
    ):
        raise ValueError("source.validation_run_id must be a positive integer")
    release_kind = value.get("release_kind")
    if release_kind not in {"candidate", "formal"}:
        raise ValueError("release_kind must be candidate or formal")
    if release_kind == "formal" and source_ref != f"refs/tags/v{version}":
        raise ValueError("formal source.ref must be the exact stable version tag")
    generated_at = require_string(value, "generated_at")
    if not generated_at.endswith("Z"):
        raise ValueError("generated_at must use UTC")
    try:
        generated_timestamp = datetime.fromisoformat(
            generated_at.removesuffix("Z") + "+00:00"
        )
    except ValueError as error:
        raise ValueError("generated_at must be RFC 3339") from error
    if generated_timestamp.tzinfo != timezone.utc:
        raise ValueError("generated_at must use UTC")

    validate_policy(value.get("policy"), generated_on=generated_timestamp.date())
    validate_dependencies(value.get("dependencies"))
    validate_files(value.get("files"))
    validate_images(
        value.get("images"),
        release_kind=release_kind,
        version=version,
        commit=commit,
    )
    if not value["files"] and not value["images"]:
        raise ValueError("release evidence requires at least one file or image")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    value = json.loads(args.evidence.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("release evidence root must be an object")
    validate_release_evidence(value)
    print(
        "Validated release evidence for "
        f"{len(value['files'])} files and {len(value['images'])} images"
    )


if __name__ == "__main__":
    main()
