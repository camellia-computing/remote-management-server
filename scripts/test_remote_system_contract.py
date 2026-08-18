"""Management-side Remote system preflight tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    from scripts import remote_system_contract as contract
except ImportError:
    import remote_system_contract as contract


MAP = {
    "remote-client": "remote-client",
    "remote-management": "remote-management-server",
    "remote-protocol": "remote-protocol",
    "remote-server": "remote-server",
}
COMMIT = "a" * 40
COMPOSE = (
    "services:\n"
    "  postgres:\n"
    "    image: postgres:18-alpine@sha256:" + "a" * 64 + "\n"
    "  management:\n"
    "    image: " + "$" + "{CAMELLIA_REMOTE_MANAGEMENT_IMAGE:?Pin the released image by sha256 digest}\n"
)


class RemoteSystemContractTests(unittest.TestCase):
    def files(self, root: Path) -> tuple[Path, Path]:
        lock = root / "web-client.lock"
        lock.write_text(COMMIT + "\n", encoding="ascii")
        compose = root / "docker-compose.yaml"
        compose.write_text(COMPOSE, encoding="utf-8")
        return lock, compose

    def test_accepts_complete_management_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock, compose = self.files(Path(temporary))
            result = contract.validate(
                repository_map=json.dumps(MAP),
                current_repository="camellia-computing/remote-management-server",
                web_lock=lock,
                compose=compose,
            )
            self.assertEqual(result["client_web_commit"], COMMIT)

    def test_rejects_incomplete_map(self) -> None:
        value = dict(MAP)
        value.pop("remote-server")
        with self.assertRaisesRegex(contract.ContractError, "four"):
            contract.parse_map(json.dumps(value))

    def test_rejects_current_repository_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock, compose = self.files(Path(temporary))
            with self.assertRaisesRegex(contract.ContractError, "current"):
                contract.validate(
                    repository_map=json.dumps(MAP),
                    current_repository="camellia-computing/other",
                    web_lock=lock,
                    compose=compose,
                )

    def test_rejects_mutable_web_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock, compose = self.files(Path(temporary))
            lock.write_text("main\n", encoding="ascii")
            with self.assertRaisesRegex(contract.ContractError, "full"):
                contract.validate(
                    repository_map=json.dumps(MAP),
                    current_repository="camellia-computing/remote-management-server",
                    web_lock=lock,
                    compose=compose,
                )

    def test_rejects_unpinned_postgres(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock, compose = self.files(Path(temporary))
            compose.write_text(
                COMPOSE.replace("@sha256:" + "a" * 64, ""),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(contract.ContractError, "POSTGRES"):
                contract.validate(
                    repository_map=json.dumps(MAP),
                    current_repository="camellia-computing/remote-management-server",
                    web_lock=lock,
                    compose=compose,
                )


if __name__ == "__main__":
    unittest.main()
