"""Base-branch CI trust policy.

This module is executed by the base-owned ``pull_request_target`` verifier,
never by candidate workflow code.  It treats workflow and required-gate shape
as a security boundary: a candidate may add tests, but cannot silently remove
the jobs that the repository ruleset expects to protect the production path.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections.abc import Iterable


class TrustPolicyError(RuntimeError):
    """Raised when a candidate crosses the CI trust boundary."""


REQUIRED_JOB_IDS = (
    "classify",
    "metadata",
    "dependency_review",
    "release_dependency",
    "automation",
    "web_client",
    "quality",
    "quality_python313",
    "quality_sqlite",
    "container",
    "performance_smoke",
)
JOB_NEEDS = {
    "automation": {"classify"},
    "dependency_review": {"classify"},
    "web_client": {"classify", "metadata"},
    "quality": {"classify", "web_client"},
    "quality_python313": {"classify", "web_client"},
    "quality_sqlite": {"classify", "web_client"},
    "container": {"classify", "metadata", "web_client", "quality", "quality_python313", "quality_sqlite"},
    "performance_smoke": {"classify"},
}
JOB_GUARDS = {
    "automation": "needs.classify.outputs.automation == 'true'",
    "dependency_review": "needs.classify.outputs.dependencies == 'true'",
    "web_client": "needs.classify.outputs.runtime == 'true'",
    "quality": "needs.classify.outputs.runtime == 'true'",
    "quality_python313": "needs.classify.outputs.runtime == 'true'",
    "quality_sqlite": "needs.classify.outputs.runtime == 'true'",
    "container": "needs.classify.outputs.runtime == 'true'",
}
TRUST_WORKFLOW = pathlib.PurePosixPath(".github/workflows/ci-trust.yml")
CI_WORKFLOW = pathlib.PurePosixPath(".github/workflows/ci.yml")
TRUSTED_POLICY_FILES = (
    pathlib.PurePosixPath(".github/scripts/classify-changes.sh"),
    pathlib.PurePosixPath(".github/scripts/ci_trust_policy.py"),
    pathlib.PurePosixPath(".github/scripts/ci_coverage_contract.py"),
)
RESERVED_TRUST_NAMES = ("CI Trust Boundary", "CI Trust / Required")


def classify_paths(paths: Iterable[str]) -> dict[str, bool]:
    """Return the immutable policy classification for changed repository paths."""

    runtime = False
    automation = False
    dependencies = False
    for raw_path in paths:
        path = raw_path.replace("\\", "/")
        if path in {
            "README.md",
            "README_EN.md",
            "LICENSE",
            ".github/dependabot.yml",
            "scripts/release_metadata.py",
            "scripts/test_release_metadata.py",
        } or path.startswith(("docs/", "LICENSE.", ".github/ISSUE_TEMPLATE/")):
            pass
        else:
            runtime = True
        if path.startswith((".github/", "scripts/", "deploy/", "docker-compose")) or path in {
            "run.sh",
            "sync_web_client.sh",
        }:
            automation = True
        if path in {"pyproject.toml", "uv.lock", "Dockerfile", ".github/dependabot.yml"} or path.startswith(
            ("docker-compose", ".github/actions/", ".github/workflows/")
        ):
            dependencies = True
    return {"runtime": runtime, "automation": automation, "dependencies": dependencies}


def _block(text: str, key: str) -> str:
    """Extract a two-space top-level job block without interpreting YAML."""

    match = re.search(rf"^  {re.escape(key)}:\s*$", text, re.MULTILINE)
    if not match:
        raise TrustPolicyError(f"missing job: {key}")
    rest = text[match.end() :]
    next_job = re.search(r"^  [A-Za-z0-9_-]+:\s*$", rest, re.MULTILINE)
    return rest[: next_job.start() if next_job else len(rest)]


def _needs(block: str) -> set[str]:
    match = re.search(r"^    needs:\s*(.*?)(?=^    [A-Za-z]|\Z)", block, re.MULTILINE | re.DOTALL)
    if not match:
        return set()
    value = match.group(1)
    return set(re.findall(r"[A-Za-z0-9_]+", value))


_PERMISSION_NAMES = (
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "security-events",
    "statuses",
)


def _permission_writes(text: str) -> set[str]:
    names = "|".join(re.escape(name) for name in _PERMISSION_NAMES)
    return {match.group(0).strip() for match in re.finditer(rf"(?im)^\s+(?:{names}):\s*(?:write|read-write)\s*$", text)}


def _forbidden_permission(text: str, allowed: set[str] | None = None) -> str | None:
    forbidden = _permission_writes(text) - (allowed or set())
    if forbidden:
        return sorted(forbidden)[0]
    if re.search(r"(?im)^\s*permissions:\s*write-all\s*$", text):
        return "permissions: write-all"
    return None


def validate_ci_workflow(text: str) -> None:
    """Validate the candidate's required CI contract using a strict text ABI."""

    if "jobs:" not in text or "name: CI" not in text:
        raise TrustPolicyError("candidate CI workflow has no expected identity")
    for job_id in REQUIRED_JOB_IDS:
        _block(text, job_id)
    required = _block(text, "required")
    if "if: always()" not in required:
        raise TrustPolicyError("required aggregator must be unconditional")
    expected_needs = set(REQUIRED_JOB_IDS)
    actual_needs = _needs(required)
    if actual_needs != expected_needs:
        raise TrustPolicyError(f"required needs drifted: expected {sorted(expected_needs)}, got {sorted(actual_needs)}")
    for result_name in (
        "CLASSIFY_RESULT",
        "METADATA_RESULT",
        "AUTOMATION_RESULT",
        "WEB_CLIENT_RESULT",
        "QUALITY_RESULT",
        "QUALITY_PYTHON313_RESULT",
        "QUALITY_SQLITE_RESULT",
        "CONTAINER_RESULT",
        "PERFORMANCE_SMOKE_RESULT",
    ):
        if not re.search(rf"\b{re.escape(result_name)}\b", required):
            raise TrustPolicyError(f"required gate does not observe {result_name}")
    for job_id, guard in JOB_GUARDS.items():
        block = _block(text, job_id)
        if guard not in block:
            raise TrustPolicyError(f"job {job_id} is not guarded by classifier")
    for job_id, expected in JOB_NEEDS.items():
        actual = _needs(_block(text, job_id))
        if not expected.issubset(actual):
            raise TrustPolicyError(
                f"job {job_id} lost required dependencies: expected {sorted(expected)}, got {sorted(actual)}"
            )
    automation = _block(text, "automation")
    for marker in (
        "zizmorcore/zizmor-action@",
        "github.com/rhysd/actionlint/cmd/actionlint@v1.7.12",
        "shellcheck",
    ):
        if marker not in automation:
            raise TrustPolicyError(f"automation gate lost {marker}")
    if ".github/scripts/classify-changes.sh" not in text:
        raise TrustPolicyError("CI must call the reviewed classifier script")
    if 'require_success "container smoke test" "$CONTAINER_RESULT"' not in required:
        raise TrustPolicyError("required gate does not require the container suite")
    if 'require_success "Python and Django quality" "$QUALITY_RESULT"' not in required:
        raise TrustPolicyError("required gate does not require quality")
    if 'require_success "Python 3.13 lower-bound quality" "$QUALITY_PYTHON313_RESULT"' not in required:
        raise TrustPolicyError("required gate does not require the Python 3.13 lower bound")
    if 'require_success "SQLite debug equivalence" "$QUALITY_SQLITE_RESULT"' not in required:
        raise TrustPolicyError("required gate does not require SQLite equivalence")
    if 'if [[ "$result" != "success" ]]' not in required:
        raise TrustPolicyError("required gate must fail closed for failure, cancelled, or skipped jobs")
    quality = _block(text, "quality")
    for marker in (
        "fetch-depth: 0",
        'python-version: "3.14"',
        "uv run coverage run --branch -m pytest --create-db",
        "uv run coverage report",
        'uv run coverage xml -o "$RUNNER_TEMP/coverage.xml"',
        'COVERAGE_BASE_SHA="$(git rev-parse',
        "uv run python .github/scripts/ci_coverage_contract.py",
        '--base "$COVERAGE_BASE_SHA"',
        '--head "$COVERAGE_HEAD_SHA"',
    ):
        if marker not in quality:
            raise TrustPolicyError(f"quality gate lost coverage contract marker: {marker}")
    lower_bound = _block(text, "quality_python313")
    for marker in (
        'python-version: "3.13"',
        "actions/download-artifact@",
        "uv run python -m compileall api webui2 camellia_remote_management scripts",
        "uv run pytest --create-db",
    ):
        if marker not in lower_bound:
            raise TrustPolicyError(f"Python 3.13 gate lost matrix marker: {marker}")
    sqlite = _block(text, "quality_sqlite")
    for marker in (
        'CAMELLIA_REMOTE_DEBUG: "true"',
        'python-version: "3.14"',
        "actions/download-artifact@",
        "uv run pytest --create-db",
    ):
        if marker not in sqlite:
            raise TrustPolicyError(f"SQLite gate lost matrix marker: {marker}")


def validate_workflow_safety(
    path: pathlib.PurePosixPath,
    text: str,
    *,
    allowed_permission_writes: set[str] | None = None,
) -> None:
    """Reject candidate workflow constructs that bypass the trusted boundary."""

    forbidden = _forbidden_permission(text, allowed_permission_writes)
    if forbidden:
        raise TrustPolicyError(f"workflow {path} expands GITHUB_TOKEN permissions: {forbidden}")
    if "pull_request_target:" in text and path != TRUST_WORKFLOW:
        raise TrustPolicyError(f"untrusted workflow may not add pull_request_target: {path}")
    if path != TRUST_WORKFLOW and re.search(r"(?m)^\s*name:\s*(?:CI Trust Boundary|CI Trust / Required)\s*$", text):
        raise TrustPolicyError(f"reserved trust workflow identity used by {path}")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("uses:") or "./" in stripped:
            continue
        if not re.search(r"@[0-9a-f]{40}(?:\s|$)", stripped):
            raise TrustPolicyError(f"un-pinned action in {path}: {stripped}")


def verify_candidate(base_dir: pathlib.Path, candidate_dir: pathlib.Path, changed_paths: Iterable[str]) -> None:
    """Verify a PR checkout using only policy code from ``base_dir``."""

    changed = tuple(path.replace("\\", "/") for path in changed_paths)
    classification = classify_paths(changed)
    workflow_changed = any(
        path.startswith((".github/workflows/", ".github/actions/", ".github/scripts/ci_")) for path in changed
    )
    candidate_trust = candidate_dir / TRUST_WORKFLOW
    base_trust = base_dir / TRUST_WORKFLOW
    if not base_trust.is_file() or not candidate_trust.is_file():
        raise TrustPolicyError("base-owned CI trust workflow is missing")
    if candidate_trust.read_bytes() != base_trust.read_bytes():
        raise TrustPolicyError("CI trust workflow is immutable from ordinary pull requests")
    for relative in TRUSTED_POLICY_FILES:
        base_policy = base_dir / relative
        candidate_policy = candidate_dir / relative
        if base_policy.is_file() and (
            not candidate_policy.is_file() or candidate_policy.read_bytes() != base_policy.read_bytes()
        ):
            raise TrustPolicyError(f"base-owned CI policy is immutable from ordinary pull requests: {relative}")
    workflows = sorted((candidate_dir / ".github/workflows").glob("*.y*ml"))
    for workflow in workflows:
        relative = pathlib.PurePosixPath(workflow.relative_to(candidate_dir).as_posix())
        base_workflow = base_dir / relative
        allowed_writes = (
            _permission_writes(base_workflow.read_text(encoding="utf-8")) if base_workflow.is_file() else set()
        )
        validate_workflow_safety(
            relative,
            workflow.read_text(encoding="utf-8"),
            allowed_permission_writes=allowed_writes,
        )
    ci_path = candidate_dir / CI_WORKFLOW
    if not ci_path.is_file():
        raise TrustPolicyError("candidate CI workflow is missing")
    validate_ci_workflow(ci_path.read_text(encoding="utf-8"))
    base_ci_path = base_dir / CI_WORKFLOW
    base_ci = base_ci_path.read_text(encoding="utf-8")
    candidate_ci = ci_path.read_text(encoding="utf-8")
    for job_id in ("classify", "required"):
        if _block(candidate_ci, job_id) != _block(base_ci, job_id):
            raise TrustPolicyError(f"base-owned CI {job_id} contract is immutable from ordinary pull requests")
    if workflow_changed and not classification["runtime"]:
        raise TrustPolicyError("workflow/action change was classified outside runtime validation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-dir", type=pathlib.Path, required=True)
    parser.add_argument("--candidate-dir", type=pathlib.Path, required=True)
    parser.add_argument("--changed-path", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        verify_candidate(args.base_dir, args.candidate_dir, args.changed_path)
    except (OSError, TrustPolicyError) as exc:
        print(f"CI trust verification failed: {exc}", file=sys.stderr)
        return 1
    print("CI trust verification passed: base policy observed and runtime suite required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
