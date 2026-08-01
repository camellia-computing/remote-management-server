#!/usr/bin/env python3
"""Manage an App-authored, review-gated, immutable stable release state machine."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path.cwd().resolve()
CONFIG_PATH = ROOT / ".github" / "release-config.json"
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$")
RELEASE_APP_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,99})\[bot\]$")
GITHUB_API_ROOT = "https://api.github.com/"
REPOSITORY_ENDPOINT = "repos/{owner}/{repo}"
RUNNER_OUTPUT_ROOT = "/home/runner/work/_temp/_runner_file_commands"
TRUSTED_EXECUTABLES = {
    "bash": "/usr/bin/bash",
    "gh": "/usr/bin/gh",
    "git": "/usr/bin/git",
    sys.executable: sys.executable,
}
RELEASE_BRANCH = "release/next"
VALIDATION_BASE_REF = "refs/camellia-release/validation-base"
PENDING_LABEL = "release:pending"
LOCK_LABEL = "release:version-locked"
CI_WORKFLOW = ".github/workflows/ci.yml"


class ReleaseError(RuntimeError):
    """Fail-closed release policy error."""


def fail(message: str) -> NoReturn:
    raise ReleaseError(message)


def run(
    arguments: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    if not arguments or arguments[0] not in TRUSTED_EXECUTABLES:
        fail("release automation requested an untrusted executable")
    command = [TRUSTED_EXECUTABLES[arguments[0]], *arguments[1:]]
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    process = subprocess.run(  # noqa: S603 -- executable is selected above from a closed allowlist.
        command,
        cwd=cwd,
        env=merged_env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and process.returncode != 0:
        detail = process.stderr.strip() or process.stdout.strip()
        fail(f"command failed ({' '.join(arguments)}): {detail}")
    return process


def git(*arguments: str, cwd: Path = ROOT, authenticated: bool = False) -> str:
    environment: dict[str, str] = {}
    if authenticated:
        token = require_env("GH_TOKEN")
        encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        environment = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": f"http.{github_server_url()}/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {encoded}",
        }
    return run(["git", *arguments], cwd=cwd, env=environment).stdout.strip()


def gh_api(
    endpoint: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    token: str | None = None,
    paginate: bool = False,
    fields: dict[str, str | int] | None = None,
) -> Any:
    command = ["gh", "api", "-X", method]
    if paginate:
        command.extend(["--paginate", "--slurp"])
    for key, value in (fields or {}).items():
        option = "-F" if isinstance(value, int) else "-f"
        command.extend([option, f"{key}={value}"])
    input_text = None
    if payload is not None:
        command.extend(["--input", "-"])
        input_text = json.dumps(payload, separators=(",", ":"))
    command.extend(["--", endpoint])
    environment = {"GH_TOKEN": token or require_env("GH_TOKEN")}
    output = run(command, env=environment, input_text=input_text).stdout
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        fail(f"GitHub API returned invalid JSON for {endpoint}: {error}")


def gh_cli(*arguments: str, token: str | None = None) -> str:
    return run(
        ["gh", *arguments],
        env={"GH_TOKEN": token or require_env("GH_TOKEN")},
    ).stdout.strip()


def require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        fail(f"{name} is required")
    return value


def github_repository() -> str:
    value = require_env("GITHUB_REPOSITORY")
    components = value.split("/")
    if len(components) != 2 or any(
        component in {".", ".."} or REPOSITORY_COMPONENT.fullmatch(component) is None for component in components
    ):
        fail("GITHUB_REPOSITORY must identify owner/repository")
    return f"{components[0]}/{components[1]}"


def release_app_login() -> str:
    value = require_env("RELEASE_APP_LOGIN")
    if RELEASE_APP_LOGIN.fullmatch(value) is None:
        fail("RELEASE_APP_LOGIN must identify a GitHub App bot")
    return value


def github_server_url() -> str:
    value = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    if value != "https://github.com":
        fail("GITHUB_SERVER_URL must identify the reviewed GitHub.com host")
    return "https://github.com"


def release_app_user(login: str) -> dict[str, Any]:
    request = Request(  # noqa: S310 -- URL uses the fixed HTTPS API origin below.
        GITHUB_API_ROOT + "users/" + quote(login, safe=""),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {require_env('GH_TOKEN')}",
            "User-Agent": "managed-release-controller",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310 -- fixed HTTPS.
            encoded = response.read(1_000_001)
    except HTTPError as error:
        fail(f"GitHub bot identity lookup returned HTTP {error.code}")
    except (OSError, URLError) as error:
        fail(f"GitHub bot identity lookup failed: {error}")
    if len(encoded) > 1_000_000:
        fail("GitHub bot identity response exceeds the supported bound")
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"GitHub bot identity response is invalid JSON: {error}")
    if not isinstance(value, dict):
        fail("GitHub bot identity response must be an object")
    return value


def append_output(name: str, value: str | int | bool) -> None:
    output = os.path.realpath(require_env("GITHUB_OUTPUT"))
    if not output.startswith(RUNNER_OUTPUT_ROOT + os.sep):
        fail("GITHUB_OUTPUT is outside the hosted runner command directory")
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    # The runner supplies this canonical path inside its fixed command directory.
    # codeql[py/path-injection]
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(f"{name}={rendered}\n")


def load_config() -> dict[str, Any]:
    try:
        value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read release configuration: {error}")
    expected = {
        "schema_version",
        "logical_id",
        "title",
        "version_kind",
        "package_name",
        "metadata_script",
        "allowed_files",
        "container",
    }
    if not isinstance(value, dict) or set(value) != expected:
        fail("release configuration has unexpected fields")
    if value["schema_version"] != 1:
        fail("release configuration schema_version must be 1")
    if value["version_kind"] not in {"cargo", "python", "remote-client"}:
        fail("release configuration version_kind is unsupported")
    if not isinstance(value["container"], bool):
        fail("release configuration container must be boolean")
    for name in ("logical_id", "title", "package_name", "metadata_script"):
        if not isinstance(value[name], str) or not value[name]:
            fail(f"release configuration {name} must be a non-empty string")
    allowed = value["allowed_files"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or allowed != sorted(set(allowed))
        or any(
            not isinstance(path, str) or not path or path.startswith("/") or ".." in Path(path).parts
            for path in allowed
        )
    ):
        fail("release configuration allowed_files must be sorted, unique paths")
    return value


def parse_version(value: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(value)
    if not match:
        fail(f"invalid stable SemVer: {value}")
    parts = tuple(int(item) for item in match.groups())
    if any(item > 2_147_000_000 for item in parts):
        fail(f"version component exceeds the supported release bound: {value}")
    return parts


def canonical_sha(value: str, label: str = "commit") -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        fail(f"{label} must be a full lowercase commit SHA")
    canonical = f"{int(value, 16):040x}"
    if canonical != value:
        fail(f"{label} is not canonical")
    return canonical


def version_text(value: tuple[int, int, int]) -> str:
    return ".".join(str(item) for item in value)


def current_metadata(config: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    script = root / config["metadata_script"]
    process = run(
        [sys.executable, str(script), "--root", str(root)],
        cwd=root,
        env={"ACTIONS_TOKEN": "", "GH_TOKEN": ""},
    )
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        fail(f"release metadata script returned invalid JSON: {error}")
    version = value.get("version")
    if not isinstance(version, str):
        fail("release metadata contains no version")
    parse_version(version)
    if value.get("tag") != f"v{version}":
        fail("release metadata tag does not match its version")
    return value


def replace_exact(path: Path, pattern: re.Pattern[str], replacement: str, label: str) -> None:
    contents = path.read_text(encoding="utf-8")
    updated, count = pattern.subn(replacement, contents)
    if count != 1:
        fail(f"{label} must contain exactly one generated version field")
    path.write_text(updated, encoding="utf-8")


def rewrite_cargo_version(root: Path, config: dict[str, Any], version: str) -> None:
    manifest = root / "Cargo.toml"
    package = re.escape(config["package_name"])
    replace_exact(
        manifest,
        re.compile(
            rf'(\[package\]\n(?:(?!\n\[)[\s\S])*?name = "{package}"'
            rf'\n(?:(?!\n\[)[\s\S])*?version = ")[^"]+(")'
        ),
        rf"\g<1>{version}\g<2>",
        "Cargo.toml",
    )
    lock = root / "Cargo.lock"
    replace_exact(
        lock,
        re.compile(rf'(\[\[package\]\]\nname = "{package}"\nversion = ")[^"]+(")'),
        rf"\g<1>{version}\g<2>",
        "Cargo.lock",
    )


def rewrite_python_version(root: Path, config: dict[str, Any], version: str) -> None:
    package = re.escape(config["package_name"])
    replace_exact(
        root / "pyproject.toml",
        re.compile(
            rf'(\[project\]\n(?:(?!\n\[)[\s\S])*?name = "{package}"'
            rf'\n(?:(?!\n\[)[\s\S])*?version = ")[^"]+(")'
        ),
        rf"\g<1>{version}\g<2>",
        "pyproject.toml",
    )
    replace_exact(
        root / "uv.lock",
        re.compile(
            rf'(\[\[package\]\]\nname = "{package}"\nversion = ")[^"]+("'
            rf'\nsource = \{{ virtual = "\." \}})'
        ),
        rf"\g<1>{version}\g<2>",
        "uv.lock",
    )


def client_build_number(version: str) -> int:
    major, minor, patch = parse_version(version)
    if major > 2_000 or minor > 999 or patch > 999:
        fail("client version exceeds deterministic mobile build-number bounds")
    value = major * 1_000_000 + minor * 1_000 + patch
    if value < 1 or value > 2_100_000_000:
        fail("client version cannot produce a valid mobile build number")
    return value


def rewrite_version(root: Path, config: dict[str, Any], version: str, base_sha: str) -> None:
    kind = config["version_kind"]
    if kind == "cargo":
        rewrite_cargo_version(root, config, version)
    elif kind == "python":
        rewrite_python_version(root, config, version)
    else:
        timestamp = git("show", "-s", "--format=%ct", base_sha)
        run(
            [
                "bash",
                str(root / ".github" / "scripts" / "sync-version.sh"),
                version,
                str(client_build_number(version)),
                timestamp,
            ],
            cwd=root,
            env={"ACTIONS_TOKEN": "", "GH_TOKEN": ""},
        )
    metadata = current_metadata(config, root)
    if metadata["version"] != version:
        fail("generated version metadata differs from the requested version")


def changelog_baseline(contents: str) -> str | None:
    matches = re.findall(
        r"^## \[((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\]"
        r" - [0-9]{4}-[0-9]{2}-[0-9]{2}$",
        contents,
        re.MULTILINE,
    )
    if len(matches) != len(set(matches)):
        fail("CHANGELOG.md contains duplicate stable release sections")
    return matches[0] if matches else None


def release_commits(base_sha: str, baseline: str | None) -> list[dict[str, str]]:
    revision = f"v{baseline}..{base_sha}" if baseline else base_sha
    output = run(
        [
            "git",
            "log",
            "--reverse",
            "--format=%H%x1f%s%x1f%b%x1e",
            revision,
            "--",
            ".",
        ]
    ).stdout
    commits: list[dict[str, str]] = []
    for record in output.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        fields = record.split("\x1f", 2)
        if len(fields) != 3 or not SHA.fullmatch(fields[0]):
            fail("git returned malformed release history")
        if fields[1].startswith("chore(release): v"):
            continue
        commits.append({"sha": fields[0], "subject": fields[1], "body": fields[2]})
    return commits


def working_tree_paths() -> list[str]:
    status = run(["git", "status", "--short"]).stdout
    records = [record for record in status.splitlines() if record]
    if any(len(record) < 4 or record[2] != " " for record in records):
        fail("git returned malformed working tree status")
    return sorted(record[3:] for record in records)


def render_changelog(root: Path, version: str, base_sha: str) -> None:
    path = root / "CHANGELOG.md"
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Changelog\n"
    if not existing.startswith("# Changelog\n"):
        fail("CHANGELOG.md must start with one Changelog heading")
    if re.search(rf"^## \[{re.escape(version)}\] -", existing, re.MULTILINE):
        fail(f"CHANGELOG.md already records v{version}")
    baseline = changelog_baseline(existing)
    commits = release_commits(base_sha, baseline)
    if not commits:
        fail("release history contains no unreleased commits")
    categories: dict[str, list[str]] = {
        "Breaking changes": [],
        "Features": [],
        "Fixes": [],
        "Other changes": [],
    }
    for commit in commits:
        subject = commit["subject"].strip()
        body = commit["body"]
        if re.match(r"^[a-zA-Z0-9_-]+(?:\([^)]*\))?!:", subject) or re.search(
            r"^BREAKING[ -]CHANGE:", body, re.MULTILINE
        ):
            category = "Breaking changes"
        elif re.match(r"^feat(?:\([^)]*\))?:", subject):
            category = "Features"
        elif re.match(r"^(?:fix|security)(?:\([^)]*\))?:", subject):
            category = "Fixes"
        else:
            category = "Other changes"
        categories[category].append(f"- {subject} (`{commit['sha'][:12]}`)")
    release_date = dt.datetime.fromtimestamp(
        int(git("show", "-s", "--format=%ct", base_sha)),
        dt.UTC,
    ).date()
    section = [f"## [{version}] - {release_date.isoformat()}"]
    for heading, entries in categories.items():
        if entries:
            section.extend(["", f"### {heading}", "", *entries])
    section_text = "\n".join(section) + "\n"
    remainder = existing.removeprefix("# Changelog\n").lstrip("\n")
    updated = "# Changelog\n\n" + section_text
    if remainder:
        updated += "\n" + remainder
    path.write_text(updated, encoding="utf-8")


def generate_release_tree(root: Path, config: dict[str, Any], version: str, base_sha: str) -> None:
    rewrite_version(root, config, version, base_sha)
    render_changelog(root, version, base_sha)


def validate_generated_tree(config: dict[str, Any], version: str, base_sha: str, candidate: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="release-validate.") as temporary:
        expected = Path(temporary)
        run(
            ["git", "update-ref", "--stdin"],
            input_text=f"update {VALIDATION_BASE_REF} {base_sha}\n",
        )
        try:
            archive = subprocess.Popen(  # noqa: S603 -- every argument is a literal policy constant.
                ["/usr/bin/git", "archive", VALIDATION_BASE_REF],
                cwd=ROOT,
                stdout=subprocess.PIPE,
            )
            extract = subprocess.run(  # noqa: S603 -- destination is a fresh tempfile directory.
                ["/usr/bin/tar", "-x", "-C", str(expected)],
                stdin=archive.stdout,
                capture_output=True,
                text=False,
                check=False,
            )
            if archive.stdout:
                archive.stdout.close()
            archive_status = archive.wait()
        finally:
            run(["git", "update-ref", "-d", VALIDATION_BASE_REF], check=False)
        if archive_status != 0 or extract.returncode != 0:
            fail("unable to construct exact release proposal baseline")
        generate_release_tree(expected, config, version, base_sha)
        for relative in config["allowed_files"]:
            left = expected / relative
            right = candidate / relative
            if not left.is_file() or not right.is_file():
                fail(f"generated release file is unavailable: {relative}")
            if left.read_bytes() != right.read_bytes():
                fail(f"release proposal is not the exact generated {relative}")


def flatten_pages(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        fail("GitHub pagination response must be an array")
    if value and all(isinstance(page, list) for page in value):
        value = [item for page in value for item in page]
    if not all(isinstance(item, dict) for item in value):
        fail("GitHub pagination response contains an invalid item")
    return value


def releases() -> list[dict[str, Any]]:
    return flatten_pages(
        gh_api(
            f"{REPOSITORY_ENDPOINT}/releases?per_page=100",
            paginate=True,
        )
    )


def completion_marker(release: dict[str, Any]) -> bool:
    commit = release.get("target_commitish")
    body = release.get("body")
    return (
        isinstance(commit, str)
        and SHA.fullmatch(commit) is not None
        and isinstance(body, str)
        and body.splitlines().count(f"<!-- release-complete:{commit} -->") == 1
    )


def completed_releases() -> list[tuple[tuple[int, int, int], dict[str, Any]]]:
    result: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    seen: set[str] = set()
    for release in releases():
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not (match := TAG.fullmatch(tag)):
            continue
        if tag in seen:
            fail(f"multiple Releases use stable tag {tag}")
        seen.add(tag)
        if (
            release.get("draft") is False
            and release.get("prerelease") is False
            and release.get("immutable") is True
            and completion_marker(release)
        ):
            result.append((tuple(int(match.group(index)) for index in range(1, 4)), release))
    return sorted(result, key=lambda item: item[0])


def automatic_version(base_sha: str) -> str | None:
    completed = completed_releases()
    if not completed:
        return "1.0.0"
    previous, release = completed[-1]
    baseline = release.get("target_commitish")
    if not isinstance(baseline, str) or not SHA.fullmatch(baseline):
        fail("latest completed release has an invalid target commit")
    log = release_commits(base_sha, version_text(previous))
    if not log:
        return None
    breaking = any(
        re.match(r"^[a-zA-Z0-9_-]+(?:\([^)]*\))?!:", item["subject"])
        or re.search(r"^BREAKING[ -]CHANGE:", item["body"], re.MULTILINE)
        for item in log
    )
    feature = any(re.match(r"^feat(?:\([^)]*\))?:", item["subject"]) for item in log)
    major, minor, patch = previous
    if breaking:
        return version_text((major + 1, 0, 0))
    if feature:
        return version_text((major, minor + 1, 0))
    return version_text((major, minor, patch + 1))


def validation_run(run_id: int, expected_sha: str, *, event: str) -> dict[str, Any]:
    value = gh_api(
        f"{REPOSITORY_ENDPOINT}/actions/runs/{run_id}",
        token=require_env("ACTIONS_TOKEN"),
    )
    if (
        not isinstance(value, dict)
        or value.get("id") != run_id
        or value.get("head_sha") != expected_sha
        or value.get("event") != event
        or value.get("path") != CI_WORKFLOW
        or value.get("status") != "completed"
        or value.get("conclusion") != "success"
    ):
        fail("Actions run does not prove successful exact-source CI")
    if event == "push" and value.get("head_branch") != "main":
        fail("validated push CI did not run on main")
    return value


def repository_main_sha() -> str:
    value = gh_api(f"{REPOSITORY_ENDPOINT}/git/ref/heads/main")
    sha = value.get("object", {}).get("sha") if isinstance(value, dict) else None
    if not isinstance(sha, str):
        fail("unable to resolve the exact main SHA")
    return canonical_sha(sha, "hosted main SHA")


def label_names(pr: dict[str, Any]) -> set[str]:
    labels = pr.get("labels")
    if not isinstance(labels, list):
        fail("pull request labels are unavailable")
    return {item["name"] for item in labels if isinstance(item, dict) and isinstance(item.get("name"), str)}


def remove_pending_release_label(number: int) -> None:
    issue_endpoint = f"{REPOSITORY_ENDPOINT}/issues/{number}"
    issue = gh_api(issue_endpoint)
    if not isinstance(issue, dict):
        fail("merged Release PR labels are unavailable during completion")
    if PENDING_LABEL not in label_names(issue):
        return
    process = run(
        [
            "gh",
            "api",
            "-X",
            "DELETE",
            f"{issue_endpoint}/labels/{PENDING_LABEL}",
        ],
        env={"GH_TOKEN": require_env("GH_TOKEN")},
        check=False,
    )
    reread = gh_api(issue_endpoint)
    if not isinstance(reread, dict):
        fail("merged Release PR labels are unavailable after completion")
    if PENDING_LABEL in label_names(reread):
        fail(
            "unable to remove the pending release label "
            f"(GitHub CLI exit {process.returncode})"
        )


def parse_provenance(body: str) -> tuple[str, int]:
    base_matches = re.findall(r"^<!-- release-base:([0-9a-f]{40}) -->$", body, re.MULTILINE)
    run_matches = re.findall(r"^<!-- release-validation-run:([1-9][0-9]*) -->$", body, re.MULTILINE)
    if len(base_matches) != 1 or len(run_matches) != 1:
        fail("Release PR must contain one exact base and validation-run marker")
    if body.count("<!-- release-base:") != 1 or body.count("<!-- release-validation-run:") != 1:
        fail("Release PR contains malformed release provenance")
    return canonical_sha(base_matches[0], "release base"), int(run_matches[0])


def release_prs(state: str = "open") -> list[dict[str, Any]]:
    pages = gh_api(
        f"{REPOSITORY_ENDPOINT}/pulls",
        paginate=True,
        fields={
            "state": state,
            "base": "main",
            "per_page": 100,
        },
    )
    repository = github_repository()
    return [
        pull
        for pull in flatten_pages(pages)
        if pull.get("head", {}).get("ref") == RELEASE_BRANCH
        and pull.get("head", {}).get("repo", {}).get("full_name") == repository
    ]


def ensure_labels() -> None:
    existing = flatten_pages(
        gh_api(
            f"{REPOSITORY_ENDPOINT}/labels?per_page=100",
            paginate=True,
        )
    )
    names = {item.get("name") for item in existing}
    for name, color, description in (
        (
            PENDING_LABEL,
            "FBCA04",
            "Managed release has not completed immutable publication",
        ),
        (
            LOCK_LABEL,
            "BFD4F2",
            "Managed release uses an explicit version above the automatic minimum",
        ),
    ):
        if name not in names:
            gh_api(
                f"{REPOSITORY_ENDPOINT}/labels",
                method="POST",
                payload={"name": name, "color": color, "description": description},
            )


def configure_app_git() -> None:
    login = release_app_login()
    user = release_app_user(login)
    identifier = user.get("id")
    if not isinstance(identifier, int) or isinstance(identifier, bool) or identifier < 1:
        fail("unable to resolve the Release App bot identity")
    if user.get("login") != login or user.get("type") != "Bot":
        fail("resolved Release App bot identity differs from policy")
    email = f"{identifier}+{login}@users.noreply.github.com"
    os.environ.update(
        {
            "GIT_AUTHOR_EMAIL": email,
            "GIT_AUTHOR_NAME": login,
            "GIT_COMMITTER_EMAIL": email,
            "GIT_COMMITTER_NAME": login,
        }
    )


def prepare_candidate_tree(config: dict[str, Any], base_sha: str, version: str) -> None:
    git("checkout", "-B", RELEASE_BRANCH, base_sha)
    generate_release_tree(ROOT, config, version, base_sha)
    changed_paths = working_tree_paths()
    if changed_paths != config["allowed_files"]:
        fail("generated release changed an unexpected file set: " + ", ".join(changed_paths))
    git("add", "--", *config["allowed_files"])
    git("commit", "--no-gpg-sign", "-m", f"chore(release): v{version}")


def close_stale_pr(pr: dict[str, Any]) -> None:
    number = pr.get("number")
    if not isinstance(number, int):
        fail("open Release PR has no number")
    if pr.get("user", {}).get("login") != release_app_login():
        fail("release/next is occupied by a pull request outside the Release App")
    gh_api(
        f"{REPOSITORY_ENDPOINT}/pulls/{number}",
        method="PATCH",
        payload={"state": "closed"},
    )
    process = run(
        [
            "gh",
            "api",
            "-X",
            "DELETE",
            f"{REPOSITORY_ENDPOINT}/git/refs/heads/{RELEASE_BRANCH}",
        ],
        env={"GH_TOKEN": require_env("GH_TOKEN")},
        check=False,
    )
    if process.returncode != 0 and not (
        process.returncode == 1 and ("HTTP 404" in process.stderr or "Not Found" in process.stderr)
    ):
        fail("unable to delete the stale managed release branch: " + (process.stderr.strip() or process.stdout.strip()))


def propose(args: argparse.Namespace, config: dict[str, Any]) -> None:
    sha = canonical_sha(args.validated_sha, "validated SHA")
    validation_run(args.validation_run_id, sha, event="push")
    if repository_main_sha() != sha:
        print("Validated main was superseded; no release mutation")
        return
    git("fetch", "--force", "origin", "main", "--tags", authenticated=True)
    if git("rev-parse", "origin/main") != sha:
        fail("local origin/main does not match hosted main")
    title = git("show", "-s", "--format=%s", sha)
    if re.fullmatch(r"chore\(release\): v[0-9]+\.[0-9]+\.[0-9]+", title):
        prepare_merged_release(config, sha)
        return
    incomplete = [
        release
        for release in releases()
        if isinstance(release.get("tag_name"), str)
        and TAG.fullmatch(release["tag_name"])
        and (release.get("draft") is True or (release.get("draft") is False and not completion_marker(release)))
    ]
    if incomplete:
        print("A managed release is still pending publication; no new proposal")
        return
    automatic = automatic_version(sha)
    if automatic is None:
        print("No unreleased commits after the latest completed release")
        return
    requested = args.requested_version
    target = requested or automatic
    target_parts = parse_version(target)
    if target_parts < parse_version(automatic):
        fail(f"requested v{target} is below automatic minimum v{automatic}")
    locked = requested is not None and target != automatic
    current = current_metadata(config)["version"]
    completed = completed_releases()
    if completed and parse_version(target) <= completed[-1][0]:
        fail("next release version must exceed the latest completed version")
    if not completed and target != "1.0.0":
        fail("the first formal release must be v1.0.0")
    if parse_version(current) > target_parts:
        fail("committed version is newer than the proposed release")

    open_prs = release_prs("open")
    if len(open_prs) > 1:
        fail("multiple open managed Release PRs exist")
    if open_prs:
        existing = open_prs[0]
        body = existing.get("body")
        existing_base, existing_run = parse_provenance(body if isinstance(body, str) else "")
        existing_title = existing.get("title")
        if (
            existing_base == sha
            and existing_run == args.validation_run_id
            and existing_title == f"chore(release): v{target}"
            and existing.get("draft") is False
            and PENDING_LABEL in label_names(existing)
        ):
            print(f"Release PR #{existing['number']} already represents validated main at v{target}")
            return
        close_stale_pr(existing)

    ensure_labels()
    configure_app_git()
    prepare_candidate_tree(config, sha, target)
    candidate_sha = git("rev-parse", "HEAD")
    remote_sha = run(
        ["git", "ls-remote", "--heads", "origin", f"refs/heads/{RELEASE_BRANCH}"],
        cwd=ROOT,
    ).stdout.split(maxsplit=1)
    lease = remote_sha[0] if remote_sha else ""
    git(
        "push",
        f"--force-with-lease=refs/heads/{RELEASE_BRANCH}:{lease}",
        "origin",
        f"HEAD:refs/heads/{RELEASE_BRANCH}",
        authenticated=True,
    )
    body = (
        f"Automated stable release proposal for **v{target}**.\n\n"
        "Approve only the exact current head after `CI / Required` succeeds. "
        "The Release App performs the SHA-guarded squash merge; the managed tag "
        "workflow freezes evidence before protected publication.\n\n"
        f"<!-- release-base:{sha} -->\n"
        f"<!-- release-validation-run:{args.validation_run_id} -->\n"
    )
    created = gh_api(
        f"{REPOSITORY_ENDPOINT}/pulls",
        method="POST",
        payload={
            "title": f"chore(release): v{target}",
            "head": RELEASE_BRANCH,
            "base": "main",
            "body": body,
            "draft": True,
        },
    )
    number = created.get("number") if isinstance(created, dict) else None
    if not isinstance(number, int) or number < 1:
        fail("GitHub did not create the managed Release PR")
    if created.get("head", {}).get("sha") != candidate_sha:
        fail("created Release PR does not use the pushed candidate SHA")
    labels = [PENDING_LABEL] + ([LOCK_LABEL] if locked else [])
    gh_api(
        f"{REPOSITORY_ENDPOINT}/issues/{number}/labels",
        method="POST",
        payload={"labels": labels},
    )
    gh_cli("pr", "ready", str(number))
    print(f"Created review-ready Release PR #{number} for v{target}")


def exact_pr_ci_run(head_sha: str) -> int | None:
    value = gh_api(
        f"{REPOSITORY_ENDPOINT}/actions/workflows/ci.yml/runs",
        token=require_env("ACTIONS_TOKEN"),
        fields={
            "head_sha": head_sha,
            "event": "pull_request",
            "per_page": 100,
        },
    )
    runs = value.get("workflow_runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        fail("unable to list exact-head focused CI runs")
    matches = [
        item
        for item in runs
        if isinstance(item, dict)
        and item.get("head_sha") == head_sha
        and item.get("event") == "pull_request"
        and item.get("path") == CI_WORKFLOW
    ]
    if not matches:
        return None
    latest = max(
        matches,
        key=lambda item: (
            int(item.get("run_number", 0)),
            int(item.get("run_attempt", 0)),
            int(item.get("id", 0)),
        ),
    )
    if latest.get("status") != "completed" or latest.get("conclusion") != "success":
        return None
    identifier = latest.get("id")
    if not isinstance(identifier, int) or identifier < 1:
        fail("focused CI returned an invalid run identity")
    return identifier


def exact_push_ci_run(head_sha: str) -> int:
    value = gh_api(
        f"{REPOSITORY_ENDPOINT}/actions/workflows/ci.yml/runs",
        token=require_env("ACTIONS_TOKEN"),
        fields={
            "head_sha": head_sha,
            "event": "push",
            "per_page": 100,
        },
    )
    runs = value.get("workflow_runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        fail("unable to list exact-source push CI runs")
    matches = [
        item
        for item in runs
        if isinstance(item, dict)
        and item.get("head_sha") == head_sha
        and item.get("head_branch") == "main"
        and item.get("event") == "push"
        and item.get("path") == CI_WORKFLOW
    ]
    if not matches:
        fail("release commit has no exact-source push CI run")
    latest = max(
        matches,
        key=lambda item: (
            int(item.get("run_number", 0)),
            int(item.get("run_attempt", 0)),
            int(item.get("id", 0)),
        ),
    )
    identifier = latest.get("id")
    if (
        latest.get("status") != "completed"
        or latest.get("conclusion") != "success"
        or not isinstance(identifier, int)
        or identifier < 1
    ):
        fail("newest exact-source push CI run is not successful")
    validation_run(identifier, head_sha, event="push")
    return identifier


def authorized_review_state(number: int, head_sha: str) -> tuple[bool, bool]:
    reviews = flatten_pages(
        gh_api(
            f"{REPOSITORY_ENDPOINT}/pulls/{number}/reviews?per_page=100",
            token=require_env("ACTIONS_TOKEN"),
            paginate=True,
        )
    )
    latest: dict[str, dict[str, Any]] = {}
    for review in reviews:
        user = review.get("user", {})
        login = user.get("login") if isinstance(user, dict) else None
        if (
            not isinstance(login, str)
            or not login
            or user.get("type") == "Bot"
            or login.endswith("[bot]")
            or review.get("state") not in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}
        ):
            continue
        previous = latest.get(login)
        ordering = (str(review.get("submitted_at", "")), int(review.get("id", 0)))
        previous_ordering = (
            (
                str(previous.get("submitted_at", "")),
                int(previous.get("id", 0)),
            )
            if previous
            else ("", 0)
        )
        if previous is None or ordering > previous_ordering:
            latest[login] = review
    approved = False
    blocked = False
    for login, review in latest.items():
        permission = gh_api(f"{REPOSITORY_ENDPOINT}/collaborators/{login}/permission")
        level = permission.get("permission") if isinstance(permission, dict) else None
        if level not in {"write", "admin"}:
            continue
        state = review.get("state")
        if state == "CHANGES_REQUESTED":
            blocked = True
        if state == "APPROVED" and review.get("commit_id") == head_sha:
            approved = True
    return approved, blocked


def fetch_candidate(head_sha: str) -> None:
    git(
        "fetch",
        "--force",
        "origin",
        f"refs/heads/{RELEASE_BRANCH}:refs/remotes/origin/{RELEASE_BRANCH}",
        authenticated=True,
    )
    if git("rev-parse", f"refs/remotes/origin/{RELEASE_BRANCH}") != head_sha:
        fail("hosted release branch changed during validation")
    git("checkout", "--detach", head_sha)


def validate_open_pr(config: dict[str, Any], pr: dict[str, Any]) -> tuple[int, str, str, str, int]:
    number = pr.get("number")
    title = pr.get("title")
    head_sha = pr.get("head", {}).get("sha")
    base_sha = pr.get("base", {}).get("sha")
    if (
        not isinstance(number, int)
        or pr.get("state") != "open"
        or pr.get("draft") is not False
        or pr.get("user", {}).get("login") != release_app_login()
        or pr.get("base", {}).get("ref") != "main"
        or pr.get("head", {}).get("ref") != RELEASE_BRANCH
        or pr.get("head", {}).get("repo", {}).get("full_name") != github_repository()
        or not isinstance(head_sha, str)
        or not SHA.fullmatch(head_sha)
        or not isinstance(base_sha, str)
        or not SHA.fullmatch(base_sha)
        or not isinstance(title, str)
        or not (match := re.fullmatch(r"chore\(release\): v(.+)", title))
    ):
        fail("managed Release PR envelope is invalid")
    head_sha = canonical_sha(head_sha, "Release PR head")
    base_sha = canonical_sha(base_sha, "Release PR base")
    version = version_text(parse_version(match.group(1)))
    if match.group(1) != version:
        fail("Release PR version is not canonical")
    body = pr.get("body")
    provenance_base, validation_id = parse_provenance(body if isinstance(body, str) else "")
    if provenance_base != base_sha:
        fail("Release PR provenance does not match its exact base SHA")
    if PENDING_LABEL not in label_names(pr):
        fail("Release PR lost its managed pending label")
    validation_run(validation_id, base_sha, event="push")
    commits = gh_api(f"{REPOSITORY_ENDPOINT}/pulls/{number}/commits")
    if not isinstance(commits, list) or len(commits) != 1:
        fail("Release PR must contain exactly one generated commit")
    commit = commits[0]
    parents = commit.get("parents")
    if (
        commit.get("sha") != head_sha
        or not isinstance(parents, list)
        or len(parents) != 1
        or not isinstance(parents[0], dict)
        or parents[0].get("sha") != base_sha
        or commit.get("commit", {}).get("message") != title
        or commit.get("author", {}).get("login") != release_app_login()
        or commit.get("committer", {}).get("login") != release_app_login()
    ):
        fail("Release PR commit identity, topology, or message is invalid")
    files = flatten_pages(
        gh_api(
            f"{REPOSITORY_ENDPOINT}/pulls/{number}/files?per_page=100",
            paginate=True,
        )
    )
    names = sorted(item.get("filename") for item in files if isinstance(item.get("filename"), str))
    if names != config["allowed_files"]:
        fail("Release PR changed files outside the generated version contract")
    return number, version, head_sha, base_sha, validation_id


def merge_release(config: dict[str, Any]) -> None:
    open_prs = release_prs("open")
    if not open_prs:
        print("No open managed Release PR")
        return
    if len(open_prs) != 1:
        fail("multiple open managed Release PRs exist")
    pr = gh_api(f"{REPOSITORY_ENDPOINT}/pulls/{open_prs[0]['number']}")
    number, version, head_sha, base_sha, _ = validate_open_pr(config, pr)
    focused_run = exact_pr_ci_run(head_sha)
    approved, blocked = authorized_review_state(number, head_sha)
    if blocked:
        print(f"Release PR #{number} is blocked by an authorized change request")
        return
    if focused_run is None:
        print(f"Release PR #{number} is waiting for exact-head CI / Required")
        return
    if not approved:
        print(f"Release PR #{number} is waiting for exact-head approval")
        return
    fetch_candidate(head_sha)
    validate_generated_tree(config, version, base_sha, ROOT)
    reread = gh_api(f"{REPOSITORY_ENDPOINT}/pulls/{number}")
    if (
        reread.get("state") != "open"
        or reread.get("draft") is not False
        or reread.get("head", {}).get("sha") != head_sha
        or reread.get("base", {}).get("sha") != base_sha
    ):
        fail("Release PR changed immediately before merge")
    approved, blocked = authorized_review_state(number, head_sha)
    if blocked or not approved or exact_pr_ci_run(head_sha) != focused_run:
        fail("Release approval or exact-head CI changed before merge")
    result = gh_api(
        f"{REPOSITORY_ENDPOINT}/pulls/{number}/merge",
        method="PUT",
        payload={
            "sha": head_sha,
            "merge_method": "squash",
            "commit_title": f"chore(release): v{version}",
            "commit_message": "",
        },
    )
    if result.get("merged") is not True or not SHA.fullmatch(str(result.get("sha", ""))):
        fail("GitHub did not perform the approved SHA-guarded squash merge")
    print(f"Merged approved Release PR #{number} as {result['sha']}")


def merged_release_pr(sha: str) -> dict[str, Any]:
    matches = [
        pr for pr in release_prs("closed") if pr.get("merged_at") is not None and pr.get("merge_commit_sha") == sha
    ]
    if len(matches) != 1:
        fail("release commit must resolve to exactly one managed merged PR")
    return gh_api(f"{REPOSITORY_ENDPOINT}/pulls/{matches[0]['number']}")


def validate_merged_pr(
    config: dict[str, Any],
    pr: dict[str, Any],
    sha: str,
    *,
    require_pending: bool = True,
) -> tuple[int, str, int]:
    if type(require_pending) is not bool:
        fail("merged Release PR pending-label policy must be boolean")
    number = pr.get("number")
    title = pr.get("title")
    base_sha = pr.get("base", {}).get("sha")
    head_sha = pr.get("head", {}).get("sha")
    if (
        not isinstance(number, int)
        or pr.get("state") != "closed"
        or pr.get("merged") is not True
        or pr.get("merge_commit_sha") != sha
        or pr.get("merged_by", {}).get("login") != release_app_login()
        or pr.get("user", {}).get("login") != release_app_login()
        or not isinstance(title, str)
        or not (match := re.fullmatch(r"chore\(release\): v(.+)", title))
        or not isinstance(base_sha, str)
        or not SHA.fullmatch(base_sha)
        or not isinstance(head_sha, str)
        or not SHA.fullmatch(head_sha)
    ):
        fail("merged Release PR envelope is invalid")
    base_sha = canonical_sha(base_sha, "merged Release PR base")
    head_sha = canonical_sha(head_sha, "merged Release PR head")
    version = version_text(parse_version(match.group(1)))
    if match.group(1) != version:
        fail("merged Release PR version is not canonical")
    provenance_base, validation_id = parse_provenance(str(pr.get("body", "")))
    if provenance_base != base_sha:
        fail("merged Release PR provenance is invalid")
    if require_pending and PENDING_LABEL not in label_names(pr):
        fail("incomplete publication lost its managed pending label")
    validation_run(validation_id, base_sha, event="push")
    focused_run = exact_pr_ci_run(head_sha)
    approved, blocked = authorized_review_state(number, head_sha)
    if focused_run is None or not approved or blocked:
        fail("merged Release PR lacks exact-head CI and human authorization")
    if current_metadata(config)["version"] != version:
        fail("merged Release commit does not contain its declared version")
    changed = sorted(line for line in git("diff", "--name-only", f"{base_sha}..{sha}").splitlines() if line)
    if changed != config["allowed_files"]:
        fail("merged Release commit changed files outside the version contract")
    validate_generated_tree(config, version, base_sha, ROOT)
    return number, version, validation_id


def release_by_tag(tag: str) -> dict[str, Any] | None:
    matches = [item for item in releases() if item.get("tag_name") == tag]
    if len(matches) > 1:
        fail(f"multiple Releases use {tag}")
    return matches[0] if matches else None


def release_by_id(release_id: Any) -> dict[str, Any]:
    if type(release_id) is not int or release_id <= 0:
        fail("managed Release has an invalid identifier")
    record = gh_api(f"{REPOSITORY_ENDPOINT}/releases/{release_id}")
    if not isinstance(record, dict) or record.get("id") != release_id:
        fail("managed Release identifier did not resolve exactly")
    return record


def tag_sha(tag: str) -> str | None:
    if TAG.fullmatch(tag) is None:
        fail("managed tag must use canonical stable SemVer")
    tag = f"v{version_text(parse_version(tag.removeprefix('v')))}"
    process = run(
        ["gh", "api", f"{REPOSITORY_ENDPOINT}/git/ref/tags/{tag}"],
        env={"GH_TOKEN": require_env("GH_TOKEN")},
        check=False,
    )
    if process.returncode != 0:
        if "HTTP 404" in process.stderr or "Not Found" in process.stderr:
            return None
        fail(f"unable to read tag {tag}: {process.stderr.strip()}")
    value = json.loads(process.stdout)
    if value.get("object", {}).get("type") != "commit":
        fail(f"managed tag {tag} must be a lightweight commit ref")
    sha = value.get("object", {}).get("sha")
    if not isinstance(sha, str):
        fail(f"managed tag {tag} has an invalid target")
    return canonical_sha(sha, f"managed tag {tag} target")


def managed_release_body(config: dict[str, Any], version: str, sha: str, number: int) -> str:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        rf"^## \[{re.escape(version)}\] - [^\n]+\n(?P<body>[\s\S]*?)"
        rf"(?=^## \[|\Z)",
        changelog,
        re.MULTILINE,
    )
    if not match:
        fail(f"unable to extract v{version} release notes")
    notes = match.group(0).strip()
    return (
        f"{notes}\n\n"
        "Publication remains incomplete until all immutable assets and registry "
        "references pass public readback.\n\n"
        f"<!-- release-pr:{number} -->\n"
        f"<!-- release-commit:{sha} -->\n"
    )


def validate_release_record(
    config: dict[str, Any],
    release: dict[str, Any],
    *,
    version: str,
    sha: str,
    number: int,
) -> tuple[bool, str | None, bool]:
    tag = f"v{version}"
    if (
        release.get("tag_name") != tag
        or release.get("target_commitish") != sha
        or release.get("name") != f"{config['title']} {version}"
        or release.get("author", {}).get("login") != release_app_login()
        or not isinstance(release.get("id"), int)
    ):
        fail(f"managed Release {tag} metadata is invalid")
    draft = release.get("draft")
    immutable = release.get("immutable")
    if not isinstance(draft, bool) or not isinstance(immutable, bool):
        fail(f"managed Release {tag} state is invalid")
    if not draft and immutable is not True:
        fail(f"published Release {tag} is not immutable")
    body = release.get("body")
    if not isinstance(body, str):
        fail(f"managed Release {tag} has no body")
    if body.splitlines().count(f"<!-- release-pr:{number} -->") != 1:
        fail(f"managed Release {tag} has invalid PR metadata")
    if body.splitlines().count(f"<!-- release-commit:{sha} -->") != 1:
        fail(f"managed Release {tag} has invalid commit metadata")
    digest_matches = re.findall(
        r"^<!-- container-digest:(sha256:[0-9a-f]{64}) -->$",
        body,
        re.MULTILINE,
    )
    if body.count("<!-- container-digest:") != len(digest_matches):
        fail(f"managed Release {tag} has malformed container metadata")
    digest = digest_matches[0] if len(digest_matches) == 1 else None
    if len(digest_matches) > 1:
        fail(f"managed Release {tag} has duplicate container metadata")
    if draft and digest is not None:
        fail(f"draft Release {tag} cannot claim a published digest")
    if not draft and config["container"] and digest is None:
        fail(f"published Release {tag} must record its container digest")
    if not config["container"] and digest is not None:
        fail(f"non-container Release {tag} cannot record a container digest")
    complete = body.splitlines().count(f"<!-- release-complete:{sha} -->") == 1
    if body.count("<!-- release-complete:") != int(complete):
        fail(f"managed Release {tag} has malformed completion metadata")
    if complete and draft:
        fail(f"draft Release {tag} cannot be complete")
    return draft, digest, complete


def prepare_merged_release(config: dict[str, Any], sha: str) -> None:
    git("checkout", "--detach", sha)
    pr = merged_release_pr(sha)
    number, version, _ = validate_merged_pr(config, pr, sha)
    tag = f"v{version}"
    existing_tag = tag_sha(tag)
    release = release_by_tag(tag)
    if existing_tag is not None and existing_tag != sha:
        fail(f"managed tag {tag} points to another commit")
    if release is not None:
        validate_release_record(config, release, version=version, sha=sha, number=number)
    if release is None:
        release = gh_api(
            f"{REPOSITORY_ENDPOINT}/releases",
            method="POST",
            payload={
                "tag_name": tag,
                "target_commitish": sha,
                "name": f"{config['title']} {version}",
                "body": managed_release_body(config, version, sha, number),
                "draft": True,
                "prerelease": False,
                "make_latest": "legacy",
            },
        )
        validate_release_record(config, release, version=version, sha=sha, number=number)
    if existing_tag is None:
        gh_api(
            f"{REPOSITORY_ENDPOINT}/git/refs",
            method="POST",
            payload={"ref": f"refs/tags/{tag}", "sha": sha},
        )
    if tag_sha(tag) != sha:
        fail(f"managed tag {tag} did not converge to the release commit")
    reread = release_by_id(release.get("id"))
    validate_release_record(config, reread, version=version, sha=sha, number=number)
    print(f"Prepared managed draft Release {tag} at {sha}")


def authorize(args: argparse.Namespace, config: dict[str, Any]) -> None:
    version = version_text(parse_version(args.version))
    sha = canonical_sha(args.sha, "publication SHA")
    tag = f"v{version}"
    if args.version != version or args.tag != tag:
        fail("publication version, tag, and SHA are inconsistent")
    args.version = version
    args.sha = sha
    args.tag = tag
    git("fetch", "--force", "origin", "main", "--tags", authenticated=True)
    if git("rev-list", "-n", "1", tag) != sha or git("rev-parse", "HEAD") != sha:
        fail("publication checkout and tag do not identify the exact source")
    if (
        run(
            ["git", "merge-base", "--is-ancestor", "HEAD", "origin/main"],
            check=False,
        ).returncode
        != 0
    ):
        fail("publication commit is not on main")
    if current_metadata(config)["version"] != version:
        fail("publication source version differs from its tag")
    pr = merged_release_pr(sha)
    release_pr_number = pr.get("number")
    if type(release_pr_number) is not int or release_pr_number <= 0:
        fail("merged Release PR has no canonical number")
    release = release_by_tag(tag)
    if release is None:
        fail("Release Manager did not prepare the managed draft")
    draft, digest, complete = validate_release_record(
        config,
        release,
        version=version,
        sha=sha,
        number=release_pr_number,
    )
    number, merged_version, _ = validate_merged_pr(
        config,
        pr,
        sha,
        require_pending=not complete,
    )
    if number != release_pr_number or merged_version != version:
        fail("merged Release PR identity differs from the publication tag")
    validation_id = exact_push_ci_run(sha)
    append_output("release-id", release["id"])
    append_output("release-draft", draft)
    append_output("release-digest", digest or "")
    append_output("release-pr-number", number)
    append_output("validation-run-id", validation_id)
    append_output("release-complete", complete)
    print(f"Authorized managed Release {tag} from PR #{number}")


def complete_release(args: argparse.Namespace, config: dict[str, Any]) -> None:
    authorize(args, config)
    release = release_by_tag(args.tag)
    if release is None:
        fail("managed Release disappeared before completion")
    number = int(
        re.search(
            r"^<!-- release-pr:([1-9][0-9]*) -->$",
            release["body"],
            re.MULTILINE,
        ).group(1)
    )
    draft, _, complete = validate_release_record(
        config,
        release,
        version=args.version,
        sha=args.sha,
        number=number,
    )
    if draft:
        fail("cannot complete a draft Release")
    if not complete:
        body = release["body"].rstrip() + f"\n\n<!-- release-complete:{args.sha} -->\n"
        gh_api(
            f"{REPOSITORY_ENDPOINT}/releases/{release['id']}",
            method="PATCH",
            payload={"body": body},
        )
    reread = release_by_tag(args.tag)
    if reread is None:
        fail("managed Release disappeared after completion")
    _, _, complete = validate_release_record(
        config,
        reread,
        version=args.version,
        sha=args.sha,
        number=number,
    )
    if not complete:
        fail("managed Release did not record completion")
    remove_pending_release_label(number)
    print(f"Completed managed Release {args.tag}")


def reconcile_latest(args: argparse.Namespace, config: dict[str, Any]) -> None:
    version = version_text(parse_version(args.version))
    sha = canonical_sha(args.sha, "publication SHA")
    tag = f"v{version}"
    if args.version != version or args.tag != tag:
        fail("publication version, tag, and SHA are inconsistent")
    args.version = version
    args.sha = sha
    args.tag = tag
    release = release_by_tag(args.tag)
    if release is None:
        fail("current managed Release is unavailable")
    pr_match = re.search(
        r"^<!-- release-pr:([1-9][0-9]*) -->$",
        str(release.get("body", "")),
        re.MULTILINE,
    )
    if not pr_match:
        fail("current managed Release has no PR identity")
    _, _, complete = validate_release_record(
        config,
        release,
        version=args.version,
        sha=args.sha,
        number=int(pr_match.group(1)),
    )
    if not complete:
        fail("only a completed Release can reconcile latest")
    eligible = completed_releases()
    if not eligible:
        fail("no completed stable Release is eligible for latest")
    version_tuple, highest = eligible[-1]
    highest_tag = f"v{version_text(version_tuple)}"
    gh_cli("release", "edit", highest_tag, "--latest")
    latest = gh_api(f"{REPOSITORY_ENDPOINT}/releases/latest")
    if latest.get("tag_name") != highest_tag:
        fail("GitHub latest readback differs from the selected stable Release")
    digest_matches = re.findall(
        r"^<!-- container-digest:(sha256:[0-9a-f]{64}) -->$",
        str(highest.get("body", "")),
        re.MULTILINE,
    )
    digest = digest_matches[0] if len(digest_matches) == 1 else ""
    if config["container"] and not digest:
        fail("latest container Release has no canonical digest")
    append_output("latest-tag", highest_tag)
    append_output("latest-version", version_text(version_tuple))
    append_output("latest-digest", digest)
    append_output("owns-latest", highest_tag == args.tag)
    print(f"Latest completed stable Release is {highest_tag}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    manage = commands.add_parser("manage")
    manage.add_argument("--validated-sha", required=True)
    manage.add_argument("--validation-run-id", required=True, type=int)
    manage.add_argument("--requested-version")
    commands.add_parser("merge")
    for name in ("authorize", "complete", "reconcile-latest"):
        command = commands.add_parser(name)
        command.add_argument("--version", required=True)
        command.add_argument("--sha", required=True)
        command.add_argument("--tag", required=True)
    return result


def main() -> int:
    try:
        require_env("GH_TOKEN")
        require_env("ACTIONS_TOKEN")
        require_env("GITHUB_REPOSITORY")
        release_app_login()
        config = load_config()
        args = parser().parse_args()
        if args.command == "manage":
            if args.requested_version:
                args.requested_version = version_text(parse_version(args.requested_version))
            propose(args, config)
        elif args.command == "merge":
            merge_release(config)
        elif args.command == "authorize":
            authorize(args, config)
        elif args.command == "complete":
            complete_release(args, config)
        else:
            reconcile_latest(args, config)
        return 0
    except ReleaseError as error:
        print(f"release policy error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
