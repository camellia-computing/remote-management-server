from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/dynamic-boundaries.yml"
TEST = ROOT / "api/test_dynamic_input_contract.py"
DOCUMENTATION = ROOT / "docs/dynamic-boundary-testing.md"


workflow = WORKFLOW.read_text(encoding="utf-8")
required_workflow = (
    'cron: "31 3 * * 6"',
    "timeout-minutes: 10",
    'CAMELLIA_REMOTE_DEBUG: "true"',
    "CAMELLIA_REMOTE_SECRET_KEY: dynamic-boundary-ci-only-secret-key",
    "uv sync --locked --all-groups",
    "uv run pytest api/test_dynamic_input_contract.py",
)
missing = [marker for marker in required_workflow if marker not in workflow]
if missing:
    raise SystemExit(f"Management dynamic boundary workflow is incomplete: {missing}")
for forbidden in ("continue-on-error:", "|| true", "pull_request_target:"):
    if forbidden in workflow:
        raise SystemExit(f"Management dynamic boundary workflow contains forbidden marker: {forbidden}")

test = TEST.read_text(encoding="utf-8")
required_test = (
    "ITERATIONS = 512",
    "MAX_INPUT = 4 * 1024",
    "MAX_RUNTIME_SECONDS = 60.0",
    "max_examples=100",
    "derandomize=True",
    "deadline=500",
)
missing = [marker for marker in required_test if marker not in test]
if missing:
    raise SystemExit(f"Management generated-input contract is incomplete: {missing}")
documentation = DOCUMENTATION.read_text(encoding="utf-8")
for marker in ("normal Required pytest suite", "Python 3.15.1", "60-second", "reads no", "It uploads no"):
    if marker not in documentation:
        raise SystemExit(f"Management dynamic boundary documentation is incomplete: {marker}")
print("Management dynamic boundary policy passed")
