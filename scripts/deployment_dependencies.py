#!/usr/bin/env python3
"""Build and validate immutable deployment dependency evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
ARCHITECTURES = ("amd64", "arm64")
POLICY_KEYS = {
    "schema_version",
    "compose_contract",
    "systemd_contract",
    "database",
    "scan_policy",
}
DATABASE_KEYS = {"name", "image", "tag", "reference", "digest", "platforms"}
SCAN_POLICY_KEYS = {
    "scanner",
    "scanner_version",
    "database_max_age_hours",
    "rescan_interval_hours",
    "severities",
    "ignore_unfixed",
    "response_sla_hours",
}
ROOT_REFERENCES = {
    "docker-compose.yaml": 3,
    ".github/workflows/ci.yml": 2,
    ".github/workflows/performance.yml": 1,
}
BOM_KEYS = {
    "schema_version",
    "release",
    "contracts",
    "client_web",
    "scan_policy",
    "scanner_database",
    "components",
    "compatibility",
}
RELEASE_KEYS = {"repository", "version", "commit", "validation_run_id", "generated_at"}
CONTRACT_KEYS = {"compose", "systemd"}
CLIENT_KEYS = {"commit"}
SCANNER_DATABASE_KEYS = {"scanner", "version", "updated_at", "evidence"}
COMPONENT_KEYS = {"name", "role", "image", "tag", "reference", "digest", "platforms"}
PLATFORM_KEYS = {"os", "architecture", "digest", "scan", "sbom"}
EVIDENCE_KEYS = {"name", "sha256"}
DEPLOYMENT_ATTESTATION_NAME = "DEPLOYMENT-BOM-ATTESTATION.intoto.jsonl"


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path: Path, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular file")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        result = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError(f"{label} must be an RFC 3339 UTC timestamp") from error
    if result.tzinfo != UTC:
        raise ValueError(f"{label} must use UTC")
    return result


def require_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_file(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size < 1:
        raise ValueError(f"evidence must be a non-empty regular file: {path}")
    return {"name": path.name, "sha256": sha256(path)}


def validate_evidence(value: Any, label: str) -> None:
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        raise ValueError(f"{label} has unexpected fields")
    if not isinstance(value.get("name"), str) or not value["name"] or "/" in value["name"] or "\\" in value["name"]:
        raise ValueError(f"{label}.name is invalid")
    if not isinstance(value.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None:
        raise ValueError(f"{label}.sha256 is invalid")


def validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != POLICY_KEYS or value.get("schema_version") != 1:
        raise ValueError("deployment dependency policy has unexpected fields or version")
    for name in ("compose_contract", "systemd_contract"):
        if (
            not isinstance(value.get(name), str)
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*-v[1-9][0-9]*", value[name]) is None
        ):
            raise ValueError(f"{name} is invalid")

    database = value.get("database")
    if not isinstance(database, dict) or set(database) != DATABASE_KEYS:
        raise ValueError("database policy has unexpected fields")
    if database.get("name") != "postgresql" or database.get("image") != "docker.io/library/postgres":
        raise ValueError("database image identity is invalid")
    if not isinstance(database.get("tag"), str) or re.fullmatch(r"[1-9][0-9]*-alpine", database["tag"]) is None:
        raise ValueError("database tag must identify the reviewed Alpine major")
    if not isinstance(database.get("digest"), str) or DIGEST.fullmatch(database["digest"]) is None:
        raise ValueError("database digest is invalid")
    expected_reference = f"postgres:{database['tag']}@{database['digest']}"
    if database.get("reference") != expected_reference:
        raise ValueError("database reference does not match its tag and digest")
    if database.get("platforms") != [f"linux/{architecture}" for architecture in ARCHITECTURES]:
        raise ValueError("database platforms must cover sorted linux/amd64 and linux/arm64")

    scan = value.get("scan_policy")
    if not isinstance(scan, dict) or set(scan) != SCAN_POLICY_KEYS:
        raise ValueError("scan policy has unexpected fields")
    if (
        scan.get("scanner") != "trivy"
        or re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.[0-9]+\.[0-9]+",
            str(scan.get("scanner_version", "")),
        )
        is None
    ):
        raise ValueError("scan policy must pin Trivy")
    require_int(scan.get("database_max_age_hours"), "database_max_age_hours", minimum=1, maximum=48)
    require_int(scan.get("rescan_interval_hours"), "rescan_interval_hours", minimum=1, maximum=24)
    if scan.get("severities") != ["CRITICAL", "HIGH"] or scan.get("ignore_unfixed") is not False:
        raise ValueError("scan policy must fail on every HIGH and CRITICAL finding")
    if scan.get("response_sla_hours") != {"CRITICAL": 24, "HIGH": 72}:
        raise ValueError("database vulnerability response SLA drifted")
    return value


def validate_repository_references(root: Path, policy: dict[str, Any]) -> None:
    expected = policy["database"]["reference"]
    pattern = re.compile(r"(?m)^\s*image:\s*(postgres:[^\s]+)\s*$")
    for relative, minimum in ROOT_REFERENCES.items():
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required database consumer is missing: {relative}")
        references = pattern.findall(path.read_text(encoding="utf-8"))
        if len(references) < minimum or any(reference != expected for reference in references):
            raise ValueError(f"database image reference drifted in {relative}")


def load_policy(root: Path) -> dict[str, Any]:
    policy = validate_policy(load_json(root / "deployment-dependencies.json", "deployment dependency policy"))
    validate_repository_references(root, policy)
    return policy


def validate_scan(path: Path, policy: dict[str, Any]) -> None:
    value = load_json(path, "Trivy report")
    if not isinstance(value, dict) or value.get("SchemaVersion") != 2:
        raise ValueError("Trivy report schema is invalid")
    results = value.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy report has no scanned results")
    blocked = []
    severities = set(policy["scan_policy"]["severities"])
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("Trivy result is invalid")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy vulnerabilities must be an array")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Trivy vulnerability is invalid")
            if vulnerability.get("Severity") in severities:
                blocked.append(str(vulnerability.get("VulnerabilityID", "unknown"))[:128])
    if blocked:
        raise ValueError(f"database image has blocked vulnerabilities: {', '.join(blocked[:10])}")


def validate_sbom(path: Path) -> None:
    value = load_json(path, "database SPDX SBOM")
    if (
        not isinstance(value, dict)
        or value.get("spdxVersion") != "SPDX-2.3"
        or not isinstance(value.get("packages"), list)
        or not value["packages"]
    ):
        raise ValueError("database SPDX SBOM is incomplete")


def scanner_database(path: Path, policy: dict[str, Any], generated_at: datetime) -> dict[str, Any]:
    value = load_json(path, "scanner database metadata")
    if not isinstance(value, dict) or set(value) != {"scanner", "version", "updated_at"}:
        raise ValueError("scanner database metadata has unexpected fields")
    if (
        value.get("scanner") != policy["scan_policy"]["scanner"]
        or value.get("version") != policy["scan_policy"]["scanner_version"]
    ):
        raise ValueError("scanner version does not match deployment policy")
    updated_at = parse_utc(value.get("updated_at"), "scanner database updated_at")
    maximum_age = timedelta(hours=policy["scan_policy"]["database_max_age_hours"])
    if updated_at > generated_at + timedelta(minutes=5) or generated_at - updated_at > maximum_age:
        raise ValueError("scanner vulnerability database is stale or from the future")
    return {
        "scanner": value["scanner"],
        "version": value["version"],
        "updated_at": value["updated_at"],
        "evidence": evidence_file(path),
    }


def normalize_scanner_database(args: argparse.Namespace) -> dict[str, str]:
    """Normalize Trivy's runner-local metadata into the immutable BOM shape."""

    value = load_json(args.metadata, "Trivy database metadata")
    if not isinstance(value, dict):
        raise ValueError("Trivy database metadata must be an object")
    updated_at = value.get("UpdatedAt")
    if isinstance(updated_at, (int, float)) and not isinstance(updated_at, bool):
        if updated_at <= 0:
            raise ValueError("Trivy database UpdatedAt is invalid")
        updated = datetime.fromtimestamp(updated_at, UTC)
    elif isinstance(updated_at, str):
        updated = parse_utc(updated_at, "Trivy database UpdatedAt")
    else:
        raise ValueError("Trivy database metadata has no UpdatedAt")
    version = args.version
    if not isinstance(version, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError("Trivy version is invalid")
    return {
        "scanner": "trivy",
        "version": version,
        "updated_at": updated.isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def validate_compatibility(path: Path, *, commit: str, database_reference: str) -> None:
    value = load_json(path, "Compose compatibility evidence")
    if not isinstance(value, dict) or value.get("format") != "camellia-remote-deployment-integration-v1":
        raise ValueError("Compose compatibility evidence format is invalid")
    if value.get("source_revision") != commit or value.get("database_image") != database_reference:
        raise ValueError("Compose compatibility evidence does not bind the release inputs")
    if value.get("status") != "passed" or "failure" in value:
        raise ValueError("Compose compatibility evidence did not pass")
    services = value.get("services")
    if not isinstance(services, dict) or sorted(services) != ["management", "postgres"]:
        raise ValueError("Compose compatibility evidence has an incomplete service set")


def platform_argument(value: str) -> tuple[str, str, Path, Path]:
    parts = value.split("=", 1)
    if len(parts) != 2 or parts[0] not in ARCHITECTURES:
        raise argparse.ArgumentTypeError("platform must use architecture=digest,scan,sbom")
    fields = parts[1].split(",")
    if len(fields) != 3 or DIGEST.fullmatch(fields[0]) is None:
        raise argparse.ArgumentTypeError("platform must contain a digest, scan and SBOM")
    return parts[0], fields[0], Path(fields[1]), Path(fields[2])


def build_bom(args: argparse.Namespace) -> dict[str, Any]:
    root = args.root.resolve()
    policy = load_policy(root)
    if COMMIT.fullmatch(args.commit) is None or COMMIT.fullmatch(args.client_commit) is None:
        raise ValueError("release and client commits must be full lowercase SHAs")
    if SEMVER.fullmatch(args.version) is None:
        raise ValueError("release version must be stable SemVer")
    require_int(args.validation_run_id, "validation_run_id", minimum=1, maximum=2**63 - 1)
    generated_at = parse_utc(args.generated_at, "generated_at")
    scanner = scanner_database(args.scanner_database, policy, generated_at)
    validate_compatibility(
        args.compatibility,
        commit=args.commit,
        database_reference=policy["database"]["reference"],
    )

    platforms = []
    seen = []
    for architecture, digest, scan, sbom in args.platform:
        seen.append(architecture)
        validate_scan(scan, policy)
        validate_sbom(sbom)
        platforms.append(
            {
                "os": "linux",
                "architecture": architecture,
                "digest": digest,
                "scan": evidence_file(scan),
                "sbom": evidence_file(sbom),
            }
        )
    if seen != list(ARCHITECTURES) or len({item["digest"] for item in platforms}) != len(ARCHITECTURES):
        raise ValueError("database platform evidence must cover unique amd64 and arm64 manifests in order")

    value = {
        "schema_version": 1,
        "release": {
            "repository": "remote-management",
            "version": args.version,
            "commit": args.commit,
            "validation_run_id": args.validation_run_id,
            "generated_at": args.generated_at,
        },
        "contracts": {
            "compose": policy["compose_contract"],
            "systemd": policy["systemd_contract"],
        },
        "client_web": {"commit": args.client_commit},
        "scan_policy": policy["scan_policy"],
        "scanner_database": scanner,
        "components": [
            {
                "name": policy["database"]["name"],
                "role": "production-database",
                "image": policy["database"]["image"],
                "tag": policy["database"]["tag"],
                "reference": policy["database"]["reference"],
                "digest": policy["database"]["digest"],
                "platforms": platforms,
            }
        ],
        "compatibility": evidence_file(args.compatibility),
    }
    validate_bom(value)
    return value


def validate_bom(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != BOM_KEYS or value.get("schema_version") != 1:
        raise ValueError("deployment BOM has unexpected fields or version")
    release = value.get("release")
    if not isinstance(release, dict) or set(release) != RELEASE_KEYS:
        raise ValueError("deployment BOM release has unexpected fields")
    if release.get("repository") != "remote-management" or SEMVER.fullmatch(str(release.get("version", ""))) is None:
        raise ValueError("deployment BOM release identity is invalid")
    if COMMIT.fullmatch(str(release.get("commit", ""))) is None:
        raise ValueError("deployment BOM release commit is invalid")
    require_int(release.get("validation_run_id"), "validation_run_id", minimum=1, maximum=2**63 - 1)
    parse_utc(release.get("generated_at"), "generated_at")
    contracts = value.get("contracts")
    if not isinstance(contracts, dict) or set(contracts) != CONTRACT_KEYS:
        raise ValueError("deployment BOM contracts are invalid")
    client = value.get("client_web")
    if (
        not isinstance(client, dict)
        or set(client) != CLIENT_KEYS
        or COMMIT.fullmatch(str(client.get("commit", ""))) is None
    ):
        raise ValueError("deployment BOM client Web dependency is invalid")
    components = value.get("components")
    if not isinstance(components, list) or len(components) != 1 or not isinstance(components[0], dict):
        raise ValueError("deployment BOM must contain one production database")
    component = components[0]
    if set(component) != COMPONENT_KEYS or component.get("role") != "production-database":
        raise ValueError("deployment BOM database component is invalid")
    validate_policy(
        {
            "schema_version": 1,
            "compose_contract": contracts.get("compose"),
            "systemd_contract": contracts.get("systemd"),
            "database": {key: component.get(key) for key in DATABASE_KEYS if key != "platforms"}
            | {"platforms": ["linux/amd64", "linux/arm64"]},
            "scan_policy": value.get("scan_policy"),
        }
    )
    scanner = value.get("scanner_database")
    if not isinstance(scanner, dict) or set(scanner) != SCANNER_DATABASE_KEYS:
        raise ValueError("deployment BOM scanner database is invalid")
    if (
        scanner.get("scanner") != value["scan_policy"]["scanner"]
        or scanner.get("version") != value["scan_policy"]["scanner_version"]
    ):
        raise ValueError("deployment BOM scanner database does not match policy")
    parse_utc(scanner.get("updated_at"), "scanner database updated_at")
    validate_evidence(scanner.get("evidence"), "scanner_database.evidence")
    platforms = component.get("platforms")
    if not isinstance(platforms, list) or [
        item.get("architecture") for item in platforms if isinstance(item, dict)
    ] != list(ARCHITECTURES):
        raise ValueError("deployment BOM database platforms are incomplete")
    digests = []
    for index, platform in enumerate(platforms):
        if not isinstance(platform, dict) or set(platform) != PLATFORM_KEYS or platform.get("os") != "linux":
            raise ValueError(f"deployment BOM platform {index} is invalid")
        if DIGEST.fullmatch(str(platform.get("digest", ""))) is None:
            raise ValueError(f"deployment BOM platform {index} digest is invalid")
        digests.append(platform["digest"])
        validate_evidence(platform.get("scan"), f"platforms[{index}].scan")
        validate_evidence(platform.get("sbom"), f"platforms[{index}].sbom")
    if len(digests) != len(set(digests)):
        raise ValueError("deployment BOM platform digests must be unique")
    validate_evidence(value.get("compatibility"), "compatibility")
    return value


def validate_bom_evidence(value: dict[str, Any], root: Path) -> None:
    """Bind every BOM evidence reference to a regular file in its asset directory."""

    if not root.is_dir() or root.is_symlink():
        raise ValueError("deployment evidence root must be a regular directory")
    references = [
        value["scanner_database"]["evidence"],
        value["compatibility"],
        *(
            evidence
            for platform in value["components"][0]["platforms"]
            for evidence in (platform["scan"], platform["sbom"])
        ),
    ]
    for reference in references:
        path = root / reference["name"]
        if evidence_file(path) != reference:
            raise ValueError(f"deployment BOM evidence hash mismatch: {reference['name']}")


def write_json(path: Path, value: Any) -> None:
    if path.exists() and (not path.is_file() or path.is_symlink()):
        raise ValueError("output must be a regular file path")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_inventory(args: argparse.Namespace) -> dict[str, Any]:
    if not args.release_root.is_dir() or args.release_root.is_symlink():
        raise ValueError("release root must be a regular directory")
    releases = []
    for directory in sorted(args.release_root.iterdir()):
        if not directory.is_dir() or directory.is_symlink():
            continue
        release_path = directory / "release-evidence.json"
        bom_path = directory / "deployment-bom.json"
        release = load_json(release_path, "release evidence")
        bom = validate_bom(load_json(bom_path, "deployment BOM"))
        deployment = release.get("deployment") if isinstance(release, dict) else None
        source = release.get("source") if isinstance(release, dict) else None
        source_commit = source.get("commit") if isinstance(source, dict) else None
        if (
            not isinstance(release, dict)
            or release.get("schema_version") != 2
            or release.get("repository") != "remote-management"
            or release.get("release_kind") != "formal"
            or not isinstance(deployment, dict)
            or set(deployment) != {"bom", "attestation"}
            or deployment.get("bom") != evidence_file(bom_path)
            or deployment.get("attestation") != evidence_file(directory / DEPLOYMENT_ATTESTATION_NAME)
            or release.get("version") != bom["release"]["version"]
            or source_commit != bom["release"]["commit"]
            or directory.name != f"v{bom['release']['version']}"
        ):
            raise ValueError(f"release {directory.name} does not bind its deployment BOM")
        platforms = bom["components"][0]["platforms"]
        releases.append(
            (
                bom["components"][0]["digest"],
                release["version"],
                {item["architecture"]: item["digest"] for item in platforms},
            )
        )
    if not releases and not getattr(args, "allow_empty", False):
        raise ValueError("no immutable deployment releases were found")
    grouped: dict[str, dict[str, Any]] = {}
    for digest, version, platforms in releases:
        item = grouped.setdefault(digest, {"releases": set(), "platforms": {}})
        item["releases"].add(version)
        for architecture, child_digest in platforms.items():
            existing = item["platforms"].get(architecture)
            if existing is not None and existing != child_digest:
                raise ValueError(f"release inventory has conflicting {architecture} digest for {digest}")
            item["platforms"][architecture] = child_digest
    images = []
    for digest, item in sorted(grouped.items()):
        if set(item["platforms"]) != set(ARCHITECTURES):
            raise ValueError(f"release inventory is missing a platform for {digest}")
        images.append(
            {
                "digest": digest,
                "releases": sorted(item["releases"]),
                "platforms": [
                    {"architecture": architecture, "digest": item["platforms"][architecture]}
                    for architecture in ARCHITECTURES
                ],
            }
        )
    value = {
        "schema_version": 1,
        "generated_at": args.generated_at,
        "images": images,
    }
    parse_utc(args.generated_at, "generated_at")
    if args.github_output is not None:
        matrix = {
            "include": [
                {
                    "digest": item["digest"],
                    "id": item["digest"].removeprefix("sha256:"),
                    "releases": ",".join(item["releases"]),
                    "amd64": item["platforms"][0]["digest"],
                    "arm64": item["platforms"][1]["digest"],
                }
                for item in images
            ]
        }
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"matrix={json.dumps(matrix, separators=(',', ':'))}\n")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    policy = commands.add_parser("validate-policy")
    policy.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    policy.set_defaults(handler=lambda args: load_policy(args.root.resolve()))
    build = commands.add_parser("build-bom")
    build.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    build.add_argument("--version", required=True)
    build.add_argument("--commit", required=True)
    build.add_argument("--client-commit", required=True)
    build.add_argument("--validation-run-id", required=True, type=int)
    build.add_argument("--generated-at", required=True)
    build.add_argument("--scanner-database", required=True, type=Path)
    build.add_argument("--compatibility", required=True, type=Path)
    build.add_argument("--platform", required=True, action="append", type=platform_argument)
    build.add_argument("--output", required=True, type=Path)
    build.set_defaults(handler=build_bom)
    validate = commands.add_parser("validate-bom")
    validate.add_argument("bom", type=Path)
    validate.add_argument("--evidence-root", type=Path)
    validate.set_defaults(
        handler=lambda args: validate_bom_command(args),
    )
    scan = commands.add_parser("validate-scan")
    scan.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    scan.add_argument("scan", type=Path, nargs="+")
    scan.set_defaults(
        handler=lambda args: [validate_scan(path, load_policy(args.root.resolve())) for path in args.scan]
    )
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--release-root", required=True, type=Path)
    inventory.add_argument("--generated-at", required=True)
    inventory.add_argument("--github-output", type=Path)
    inventory.add_argument("--allow-empty", action="store_true")
    inventory.add_argument("--output", required=True, type=Path)
    inventory.set_defaults(handler=build_inventory)
    scanner = commands.add_parser("normalize-scanner-database")
    scanner.add_argument("--metadata", required=True, type=Path)
    scanner.add_argument("--version", required=True)
    scanner.add_argument("--output", required=True, type=Path)
    scanner.set_defaults(handler=normalize_scanner_database)
    return result


def validate_bom_command(args: argparse.Namespace) -> dict[str, Any]:
    value = validate_bom(load_json(args.bom, "deployment BOM"))
    if args.evidence_root is not None:
        validate_bom_evidence(value, args.evidence_root)
    return value


def main() -> None:
    args = parser().parse_args()
    value = args.handler(args)
    output = getattr(args, "output", None)
    if output is not None:
        write_json(output, value)
    else:
        print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
