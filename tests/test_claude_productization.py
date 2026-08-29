from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

from evidline import state


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "integrations" / "claude-code"
MARKETPLACE_PATH = ROOT / ".claude-plugin" / "marketplace.json"


class ClaudeProductizationTests(unittest.TestCase):
    def test_console_script_metadata_maps_exact_target(self) -> None:
        metadata = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["project"]["scripts"]["evidline"], "evidline.cli:main")
        self.assertEqual(
            metadata["project"]["scripts"]["evidline-claude-hook"],
            "evidline.adapters.claude:main",
        )

    def test_entrypoint_target_matches_module_stdout_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            state.initialize_project(
                project,
                project=state.Project("project", "Synthetic project", (), 8000),
            )
            payload = json.dumps(
                {
                    "cwd": str(project),
                    "hook_event_name": "SessionStart",
                    "source": "startup",
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(ROOT / "src")
            module = subprocess.run(
                [sys.executable, "-m", "evidline.adapters.claude", "session-start"],
                cwd=ROOT,
                env=environment,
                input=payload,
                capture_output=True,
                check=False,
            )
            entrypoint = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from evidline.adapters.claude import main; raise SystemExit(main())",
                    "session-start",
                ],
                cwd=ROOT,
                env=environment,
                input=payload,
                capture_output=True,
                check=False,
            )
        self.assertEqual((module.returncode, entrypoint.returncode), (0, 0))
        self.assertEqual((module.stderr, entrypoint.stderr), (b"", b""))
        self.assertNotEqual(module.stdout, b"")
        self.assertEqual(entrypoint.stdout, module.stdout)

    def test_plugin_assets_are_exact_and_internally_consistent(self) -> None:
        manifest = json.loads(
            (PLUGIN_ROOT / ".claude-plugin" / "plugin.json").read_text(
                encoding="utf-8"
            )
        )
        hooks = json.loads(
            (PLUGIN_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8")
        )
        marketplace = json.loads(MARKETPLACE_PATH.read_text(encoding="utf-8"))
        metadata = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]

        self.assertEqual(set(hooks), {"description", "hooks"})
        self.assertEqual(set(hooks["hooks"]), {"SessionStart", "PreToolUse"})
        session = hooks["hooks"]["SessionStart"]
        pre_tool = hooks["hooks"]["PreToolUse"]
        self.assertEqual(len(session), 1)
        self.assertEqual(session[0]["matcher"], "*")
        self.assertEqual(len(pre_tool), 1)
        self.assertEqual(pre_tool[0]["matcher"], "Edit|Write|NotebookEdit")

        expected = {
            "type": "command",
            "command": "evidline-claude-hook",
            "timeout": 10,
        }
        self.assertEqual(
            session[0]["hooks"],
            [{**expected, "args": ["session-start"]}],
        )
        self.assertEqual(
            pre_tool[0]["hooks"],
            [{**expected, "args": ["pre-tool-use"]}],
        )

        self.assertEqual(len(marketplace["plugins"]), 1)
        listing = marketplace["plugins"][0]
        source = (ROOT / listing["source"]).resolve()
        self.assertEqual(source, PLUGIN_ROOT.resolve())
        self.assertTrue(source.is_dir())
        self.assertEqual(
            (manifest["name"], manifest["version"], manifest["description"]),
            (listing["name"], listing["version"], listing["description"]),
        )
        self.assertEqual(manifest["name"], metadata["name"])
        self.assertEqual(manifest["version"], metadata["version"])
        self.assertEqual(manifest["author"], marketplace["owner"])


if __name__ == "__main__":
    unittest.main()
