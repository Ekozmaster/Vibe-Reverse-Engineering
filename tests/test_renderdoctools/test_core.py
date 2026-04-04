# tests/test_renderdoctools/test_core.py
"""Unit tests for renderdoctools.core."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from renderdoctools import core


class TestFindRenderdoc:
    def test_finds_bundled_renderdoc(self, tmp_path):
        """find_renderdoc() returns path to bundled qrenderdoc.exe."""
        rd_dir = tmp_path / "tools" / "renderdoc"
        rd_dir.mkdir(parents=True)
        (rd_dir / "qrenderdoc.exe").touch()

        with patch.object(core, "WORKSPACE_ROOT", tmp_path):
            result = core.find_renderdoc()
            assert result == rd_dir / "qrenderdoc.exe"

    def test_raises_if_not_found(self, tmp_path):
        """find_renderdoc() raises FileNotFoundError when RenderDoc is missing."""
        with patch.object(core, "WORKSPACE_ROOT", tmp_path):
            with pytest.raises(FileNotFoundError, match="RenderDoc not found"):
                core.find_renderdoc()


class TestRunScript:
    def test_generates_script_and_parses_json(self, tmp_path):
        """run_script() writes temp script, executes qrenderdoc, reads JSON output."""
        output_data = {"events": [{"eid": 1, "name": "Draw"}]}

        def fake_run(cmd, **kwargs):
            script_path = cmd[2]
            script_text = Path(script_path).read_text()
            for line in script_text.splitlines():
                if "_CONFIG_PATH" in line:
                    config_path = line.split("= ")[1].strip().strip("'\"")
                    break
            cfg = json.loads(Path(config_path).read_text())
            Path(cfg["output"]).write_text(json.dumps(output_data))
            return MagicMock(returncode=0, stderr="")

        with patch.object(core, "find_renderdoc", return_value=tmp_path / "qrenderdoc.exe"):
            with patch("subprocess.run", side_effect=fake_run):
                result = core.run_script(
                    script_name="events",
                    capture_path=str(tmp_path / "test.rdc"),
                    config={"draws_only": False},
                )
                assert result == output_data
