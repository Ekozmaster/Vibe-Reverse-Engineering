"""Tests for decompiler.py backend routing logic."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestBackendRouting:
    def test_auto_no_project_uses_r2(self):
        """--backend auto without --project should use r2ghidra."""
        from decompiler import decompile
        with patch("decompiler._find_r2_bin", return_value=None):
            with pytest.raises(FileNotFoundError, match="radare2 not found"):
                decompile("fake.exe", 0x401000, backend="auto")

    def test_auto_with_project_no_ghidra_falls_through(self, tmp_path):
        """--backend auto with --project but no Ghidra project falls through to r2."""
        mock_backend = MagicMock()
        mock_backend.is_analyzed.return_value = False

        with patch.dict(sys.modules, {"retools.pyghidra_backend": mock_backend}):
            from importlib import reload
            import decompiler
            reload(decompiler)
            with patch("decompiler._find_r2_bin", return_value=None):
                with pytest.raises(FileNotFoundError, match="radare2 not found"):
                    decompiler.decompile("fake.exe", 0x401000, backend="auto", project_dir=str(tmp_path))

    def test_ghidra_backend_without_project_errors(self):
        """--backend ghidra without --project returns error."""
        from decompiler import decompile
        result = decompile("fake.exe", 0x401000, backend="ghidra")
        assert "[error]" in result
        assert "--project required" in result

    def test_ghidra_backend_routes_to_pyghidra(self, tmp_path):
        """--backend ghidra with --project routes to pyghidra_backend."""
        mock_backend = MagicMock()
        mock_backend.decompile.return_value = "void func() {}"
        mock_backend.is_analyzed.return_value = True

        with patch.dict(sys.modules, {"retools.pyghidra_backend": mock_backend}):
            from importlib import reload
            import decompiler
            reload(decompiler)
            result = decompiler.decompile("fake.exe", 0x401000, backend="ghidra", project_dir=str(tmp_path))

        mock_backend.decompile.assert_called_once()
        assert result == "void func() {}"
