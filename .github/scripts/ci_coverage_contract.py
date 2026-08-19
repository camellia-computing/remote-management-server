"""Coverage contract and changed-line gate for the Management quality job."""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

from defusedxml import ElementTree as ET

# Floors are intentionally evidence-backed and versioned with the gate.  They
# are above the historical 45% global line-only floor while leaving room for
# the current production branches to grow toward stricter values.
GLOBAL_BRANCH_FLOOR = 55.0
MODULE_FLOORS = {
    "api/views_api.py": (65.0, 50.0),
    "api/views_front.py": (45.0, 35.0),
    "api/oidc_documents.py": (65.0, 45.0),
    "api/recording_inventory.py": (65.0, 50.0),
    "api/rate_limits.py": (75.0, 60.0),
}
SOURCE_PREFIXES = ("api/", "webui2/", "camellia_remote_management/")
NON_PRODUCTION_FILES = ("/migrations/", "/test", "/tests.py")


class CoverageContractError(RuntimeError):
    """Raised when coverage evidence does not meet the release contract."""


def _normalise_filename(value: str, root: pathlib.Path, source_roots: tuple[pathlib.Path, ...]) -> str:
    path = pathlib.PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute():
        try:
            path = pathlib.PurePosixPath(pathlib.Path(path).resolve().relative_to(root.resolve()).as_posix())
        except ValueError:
            return ""
        return path.as_posix().removeprefix("./")

    relative = path.as_posix().removeprefix("./")
    direct = (root / relative).resolve()
    candidates = []
    for source_root in source_roots:
        candidate = (source_root / relative).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            candidates.append(candidate)
    if direct.is_file():
        candidates.append(direct)
    unique = sorted(set(candidates))
    if len(unique) == 1:
        return unique[0].relative_to(root.resolve()).as_posix()
    if len(unique) > 1:
        return ""
    return relative


def parse_coverage_xml(
    path: pathlib.Path, *, root: pathlib.Path
) -> tuple[dict[str, dict[int, int]], dict[str, tuple[float, float]], float]:
    """Read hits, line rates, module branch rates, and the global branch rate."""

    document = ET.parse(path).getroot()
    source_roots = tuple(
        pathlib.Path(node.text).resolve()
        for node in document.findall("./sources/source")
        if node.text and pathlib.Path(node.text).is_absolute()
    )
    try:
        branch_rate = float(document.attrib.get("branch-rate", "0")) * 100
    except ValueError as exc:
        raise CoverageContractError("coverage XML has an invalid global branch-rate") from exc
    hits: dict[str, dict[int, int]] = {}
    module_rates: dict[str, tuple[float, float]] = {}
    for class_node in document.findall(".//class"):
        filename = _normalise_filename(class_node.attrib.get("filename", ""), root, source_roots)
        if not filename:
            continue
        line_values = hits.setdefault(filename, {})
        for line in class_node.findall("./lines/line"):
            try:
                line_values[int(line.attrib["number"])] = int(line.attrib["hits"])
            except (KeyError, ValueError) as exc:
                raise CoverageContractError(f"coverage XML has an invalid line entry in {filename}") from exc
        try:
            line_rate = float(class_node.attrib.get("line-rate", "0")) * 100
            class_branch_rate = float(class_node.attrib.get("branch-rate", "0")) * 100
        except ValueError as exc:
            raise CoverageContractError(f"coverage XML has an invalid module rate in {filename}") from exc
        if filename in module_rates:
            raise CoverageContractError(f"coverage XML has duplicate evidence for {filename}")
        module_rates[filename] = (line_rate, class_branch_rate)
    return hits, module_rates, branch_rate


def changed_line_numbers(diff: str) -> dict[str, set[int]]:
    """Extract added line numbers from a unified diff with zero context."""

    current: str | None = None
    output: dict[str, set[int]] = {}
    saw_header = False
    saw_candidate_header = False
    saw_hunk = False
    for line in diff.splitlines():
        if line.startswith("--- "):
            saw_header = True
            current = None
            saw_candidate_header = False
            continue
        if line.startswith("+++ b/"):
            current = line[6:]
            if not current or current == "/dev/null":
                raise CoverageContractError("diff contains an invalid candidate path")
            output.setdefault(current, set())
            saw_candidate_header = True
            continue
        if line == "+++ /dev/null":
            # A deletion has no candidate lines and therefore contributes no
            # changed-line obligations, but it remains a valid diff member.
            current = None
            saw_candidate_header = True
            continue
        if line.startswith("@@"):
            if not saw_header or not saw_candidate_header:
                raise CoverageContractError("diff hunk has no candidate file header")
            match = re.search(r"\+(\d+)(?:,(\d+))? @@", line)
            if match is None:
                raise CoverageContractError(f"unable to parse diff hunk: {line}")
            saw_hunk = True
            start = int(match.group(1))
            count = int(match.group(2) or "1")
            if current is not None:
                output[current].update(range(start, start + count))
            continue
        if line.startswith(("diff ", "index ", "new file mode ")):
            continue
        if line.startswith("\\ No newline at end of file"):
            continue
        if line and line[0] not in {"+", "-", " "} and saw_header:
            raise CoverageContractError(f"malformed diff record: {line}")
    if diff.strip() and (not saw_header or not saw_hunk):
        raise CoverageContractError("coverage diff has no parseable file hunk")
    return output


def _is_production_source(path: str) -> bool:
    return (
        path.startswith(SOURCE_PREFIXES)
        and path.endswith(".py")
        and not any(marker in f"/{path}" for marker in NON_PRODUCTION_FILES)
    )


def check_module_floors(module_rates: dict[str, tuple[float, float]]) -> None:
    failures = []
    for module, (line_floor, branch_floor) in MODULE_FLOORS.items():
        if module not in module_rates:
            failures.append(f"{module}: missing coverage evidence")
            continue
        line_rate, branch_rate = module_rates[module]
        if line_rate < line_floor or branch_rate < branch_floor:
            failures.append(
                f"{module}: line={line_rate:.1f}% (need {line_floor:.1f}%), "
                f"branch={branch_rate:.1f}% (need {branch_floor:.1f}%)"
            )
    if failures:
        raise CoverageContractError("critical module floor failed: " + "; ".join(failures))


def check_changed_lines(
    changed: dict[str, set[int]],
    hits: dict[str, dict[int, int]],
) -> None:
    failures = []
    for filename, lines in changed.items():
        if not _is_production_source(filename):
            continue
        if filename not in hits:
            failures.append(f"{filename}: missing coverage evidence")
            continue
        module_hits = hits.get(filename, {})
        # Coverage XML records executable statements only.  Added comments,
        # blank lines, and continuation-only lines are intentionally ignored.
        executable = sorted(line for line in lines if line in module_hits)
        uncovered = sorted(line for line in executable if module_hits[line] == 0)
        if uncovered:
            details = []
            if uncovered:
                details.append(f"uncovered lines={uncovered}")
            failures.append(f"{filename}: " + ", ".join(details))
    if failures:
        raise CoverageContractError("changed-line coverage failed: " + "; ".join(failures))


def _git_diff(root: pathlib.Path, base: str, head: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", base) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise CoverageContractError("coverage diff requires full 40-character base/head SHAs")
    result = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--unified=0", base, head, "--", *SOURCE_PREFIXES],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise CoverageContractError(f"git diff failed: {result.stderr.strip()}")
    return result.stdout


def verify(*, root: pathlib.Path, coverage_xml: pathlib.Path, base: str, head: str) -> dict[str, float | int]:
    hits, module_rates, branch_rate = parse_coverage_xml(coverage_xml, root=root)
    if branch_rate < GLOBAL_BRANCH_FLOOR:
        raise CoverageContractError(f"global branch coverage {branch_rate:.1f}% is below {GLOBAL_BRANCH_FLOOR:.1f}%")
    check_module_floors(module_rates)
    changed = changed_line_numbers(_git_diff(root, base, head))
    check_changed_lines(changed, hits)
    return {
        "global_branch_rate": round(branch_rate, 2),
        "critical_modules": len(MODULE_FLOORS),
        "changed_files": sum(1 for path in changed if _is_production_source(path)),
        "changed_lines": sum(len(lines) for path, lines in changed.items() if _is_production_source(path)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage-xml", type=pathlib.Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(root=pathlib.Path.cwd(), coverage_xml=args.coverage_xml, base=args.base, head=args.head)
    except (CoverageContractError, OSError, ET.ParseError) as exc:
        print(f"coverage contract failed: {exc}", file=sys.stderr)
        return 1
    print("coverage contract passed: " + ", ".join(f"{key}={value}" for key, value in sorted(result.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
