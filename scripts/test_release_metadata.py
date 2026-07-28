import tempfile
import unittest
from pathlib import Path

from release_metadata import MetadataError, load_metadata


def write_metadata(root: Path, *, project: str, locked: str, legacy: str) -> None:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "camellia-remote-management-server"\nversion = "{project}"\n',
        encoding="utf-8",
    )
    (root / "uv.lock").write_text(
        "version = 1\n\n"
        "[[package]]\n"
        'name = "camellia-remote-management-server"\n'
        f'version = "{locked}"\n'
        'source = { virtual = "." }\n',
        encoding="utf-8",
    )
    (root / "version.py").write_text(f"APP_VERSION = {legacy!r}\n", encoding="utf-8")


class ReleaseMetadataTests(unittest.TestCase):
    def test_accepts_consistent_stable_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_metadata(root, project="3.4.5", locked="3.4.5", legacy="v3.4.5")

            metadata = load_metadata(root)

            self.assertEqual(metadata.version, "3.4.5")
            self.assertEqual(metadata.tag, "v3.4.5")
            self.assertEqual((metadata.major, metadata.minor, metadata.patch), ("3", "4", "5"))

    def test_rejects_ambiguous_or_inconsistent_versions(self) -> None:
        cases = (
            ("3.4.5", "3.4.4", "v3.4.5"),
            ("3.4.5", "3.4.5", "v3.4.4"),
            ("03.4.5", "03.4.5", "v03.4.5"),
            ("3.4.5-rc.1", "3.4.5-rc.1", "v3.4.5-rc.1"),
        )
        for project, locked, legacy in cases:
            with self.subTest(project=project, locked=locked, legacy=legacy):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_metadata(root, project=project, locked=locked, legacy=legacy)
                    with self.assertRaises(MetadataError):
                        load_metadata(root)


if __name__ == "__main__":
    unittest.main()
