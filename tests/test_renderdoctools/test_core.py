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

    def test_finds_versioned_renderdoc(self, tmp_path):
        """find_renderdoc() finds RenderDoc in versioned directory names."""
        rd_dir = tmp_path / "tools" / "RenderDoc_1.43_64"
        rd_dir.mkdir(parents=True)
        (rd_dir / "qrenderdoc.exe").touch()

        with patch.object(core, "WORKSPACE_ROOT", tmp_path):
            result = core.find_renderdoc()
            assert result == rd_dir / "qrenderdoc.exe"

    def test_finds_any_renderdoc_prefix(self, tmp_path):
        """find_renderdoc() falls back to any renderdoc* directory."""
        rd_dir = tmp_path / "tools" / "RenderDoc_2.0_64"
        rd_dir.mkdir(parents=True)
        (rd_dir / "qrenderdoc.exe").touch()

        with patch.object(core, "WORKSPACE_ROOT", tmp_path):
            result = core.find_renderdoc()
            assert result == rd_dir / "qrenderdoc.exe"


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

    def test_missing_script_raises(self, tmp_path):
        """run_script() raises FileNotFoundError for unknown script names."""
        with patch.object(core, "find_renderdoc", return_value=tmp_path / "qrenderdoc.exe"):
            with pytest.raises(FileNotFoundError, match="Script template not found"):
                core.run_script("nonexistent_script", str(tmp_path / "test.rdc"))

    def test_no_output_raises_runtime_error(self, tmp_path):
        """run_script() raises RuntimeError when script produces no output."""
        def fake_run(cmd, **kwargs):
            return MagicMock(returncode=1, stderr="something went wrong")

        with patch.object(core, "find_renderdoc", return_value=tmp_path / "qrenderdoc.exe"):
            with patch("subprocess.run", side_effect=fake_run):
                with pytest.raises(RuntimeError, match="failed"):
                    core.run_script("events", str(tmp_path / "test.rdc"))
