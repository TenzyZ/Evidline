from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


from evidline.paths import (
    _unsafe_windows_path,
    discover_project_root,
    evaluate_mutation_path,
)


class PathSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "project"
        self.root.mkdir()
        (self.root / ".evidline").mkdir()

    def test_safe_normal_file_inside_root(self) -> None:
        target = self.root / "inside.txt"
        target.write_text("ok", encoding="utf-8")
        result = evaluate_mutation_path(self.root, target)
        self.assertTrue(result.safe)
        self.assertEqual(result.canonical_target, target.resolve())

    def test_safe_nonexistent_file_inside_root(self) -> None:
        result = evaluate_mutation_path(self.root, "output/new.txt")
        self.assertTrue(result.safe)
        self.assertEqual(result.canonical_target, self.root / "output" / "new.txt")

    def test_relative_path_is_resolved_from_project_root(self) -> None:
        original = Path.cwd()
        elsewhere = Path(self.temporary.name) / "elsewhere"
        elsewhere.mkdir()
        try:
            os.chdir(elsewhere)
            result = evaluate_mutation_path(self.root, "relative.txt")
        finally:
            os.chdir(original)
        self.assertTrue(result.safe)
        self.assertEqual(result.canonical_target, self.root / "relative.txt")

    def test_parent_escape_is_rejected(self) -> None:
        result = evaluate_mutation_path(self.root, "../outside.txt")
        self.assertFalse(result.safe)

    def test_absolute_outside_target_is_rejected(self) -> None:
        result = evaluate_mutation_path(self.root, Path(self.temporary.name) / "outside.txt")
        self.assertFalse(result.safe)

    def test_git_metadata_is_rejected(self) -> None:
        (self.root / ".git").mkdir()
        self.assertFalse(evaluate_mutation_path(self.root, ".git/config").safe)

    def test_evidline_metadata_is_rejected(self) -> None:
        self.assertFalse(evaluate_mutation_path(self.root, ".evidline/state.json").safe)

    def test_mixed_case_protected_metadata_is_rejected(self) -> None:
        for target in (
            ".GIT/config",
            ".Git/hooks/pre-commit",
            ".EVIDLINE/state.json",
            ".Evidline/state.json",
        ):
            with self.subTest(target=target):
                self.assertFalse(evaluate_mutation_path(self.root, target).safe)

    def test_similarly_named_directories_are_not_protected_metadata(self) -> None:
        for target in (".github/workflows/check.yml", ".evidline-backup/state.json"):
            with self.subTest(target=target):
                self.assertTrue(evaluate_mutation_path(self.root, target).safe)

    def test_nul_is_rejected(self) -> None:
        result = evaluate_mutation_path(self.root, "bad\0name")
        self.assertFalse(result.safe)
        self.assertIn("NUL", result.reason or "")

    def test_symlink_inside_to_outside_is_rejected(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        link = self.root / "escape"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        self.assertFalse(evaluate_mutation_path(self.root, "escape/file.txt").safe)

    def test_symlink_inside_to_inside_is_accepted(self) -> None:
        destination = self.root / "destination"
        destination.mkdir()
        link = self.root / "link"
        try:
            link.symlink_to(destination, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        result = evaluate_mutation_path(self.root, "link/file.txt")
        self.assertTrue(result.safe)
        self.assertEqual(result.canonical_target, destination / "file.txt")

    @unittest.skipUnless(os.name == "nt", "Windows-only junction behavior")
    def test_junction_inside_to_outside_is_rejected(self) -> None:
        outside = Path(self.temporary.name) / "junction-outside"
        outside.mkdir()
        link = self.root / "junction-escape"
        self._create_junction(link, outside)
        self.assertFalse(evaluate_mutation_path(self.root, link / "file.txt").safe)

    @unittest.skipUnless(os.name == "nt", "Windows-only junction behavior")
    def test_junction_inside_to_inside_is_accepted(self) -> None:
        destination = self.root / "junction-inside"
        destination.mkdir()
        link = self.root / "junction-link"
        self._create_junction(link, destination)
        result = evaluate_mutation_path(self.root, link / "file.txt")
        self.assertTrue(result.safe)
        self.assertEqual(result.canonical_target, destination / "file.txt")

    @unittest.skipUnless(os.name == "nt", "Windows-only reserved names")
    def test_windows_reserved_names_are_rejected(self) -> None:
        for target in ("CON", "aux.txt", "trailing. ", "stream:name"):
            with self.subTest(target=target):
                self.assertFalse(evaluate_mutation_path(self.root, target).safe)

    def test_pre_314_realpath_fallback_preserves_security_boundaries(self) -> None:
        existing = self.root / "existing.txt"
        existing.write_text("ok", encoding="utf-8")
        with mock.patch.object(os.path, "ALLOW_MISSING", None, create=True):
            self.assertTrue(evaluate_mutation_path(self.root, existing).safe)
            self.assertTrue(
                evaluate_mutation_path(self.root, "missing/inside.txt").safe
            )
            self.assertFalse(
                evaluate_mutation_path(self.root, "../outside.txt").safe
            )
            self.assertFalse(
                evaluate_mutation_path(self.root, ".GIT/config").safe
            )

    def test_pre_313_windows_reserved_name_fallback_fails_closed(self) -> None:
        with mock.patch.object(os.path, "isreserved", None, create=True):
            self.assertIsNone(_unsafe_windows_path("normal/inside.txt"))
            for target in (
                "CON",
                "aux.txt",
                "folder/COM1.log",
                "trailing. ",
                "stream:name",
            ):
                with self.subTest(target=target):
                    self.assertIsNotNone(_unsafe_windows_path(target))

    def test_platform_case_normalization(self) -> None:
        comparison = os.path.normcase(str(self.root / "MiXeD"))
        if os.name == "nt":
            self.assertEqual(comparison, comparison.lower())
            differently_cased = str(self.root / "case.txt").swapcase()
            self.assertTrue(evaluate_mutation_path(self.root, differently_cased).safe)
        else:
            self.assertEqual(comparison, str(self.root / "MiXeD"))

    def test_discovery_chooses_nearest_initialized_ancestor(self) -> None:
        nested_project = self.root / "nested"
        deep = nested_project / "a" / "b"
        deep.mkdir(parents=True)
        (nested_project / ".evidline").mkdir()
        self.assertEqual(discover_project_root(deep), nested_project.resolve())

    def test_discovery_without_marker_returns_none(self) -> None:
        uninitialized = Path(self.temporary.name) / "plain" / "nested"
        uninitialized.mkdir(parents=True)
        self.assertIsNone(discover_project_root(uninitialized))

    def _create_junction(self, link: Path, target: Path) -> None:
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self.skipTest(f"junction creation unavailable: {completed.stderr.strip()}")


if __name__ == "__main__":
    unittest.main()
