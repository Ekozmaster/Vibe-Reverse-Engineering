"""Tests for the install checker's discovery helpers."""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import verify_install
from retools.jdk import Jdk


class TestJavaSetup:
    """The install checker reports and installs the JDK that retools.jdk resolves for pyghidra."""

    @pytest.fixture
    def no_jdk(self, monkeypatch):
        monkeypatch.setattr(verify_install, "find_jdk", lambda: None)

    def test_check_warns_when_no_jdk_is_new_enough(self, no_jdk, monkeypatch):
        monkeypatch.setattr(verify_install, "results", [])
        assert verify_install.check_java() is False
        assert verify_install.results[0][:2] == ("java", verify_install.WARN)

    def test_check_names_the_jdk_found(self, monkeypatch, tmp_path):
        monkeypatch.setattr(verify_install, "results", [])
        monkeypatch.setattr(verify_install, "find_jdk", lambda: Jdk(tmp_path, 21))
        assert verify_install.check_java() is True
        assert verify_install.results == [("java", verify_install.PASS, f"JDK 21 ({tmp_path})")]

    def test_setup_downloads_nothing_when_a_jdk_is_found(self, monkeypatch, tmp_path):
        monkeypatch.setattr(verify_install, "find_jdk", lambda: Jdk(tmp_path, 21))
        monkeypatch.setattr(verify_install, "_download", lambda *a: pytest.fail("downloaded"))
        assert verify_install.setup_jdk() is True


class TestRetoolsModuleDiscovery:
    def test_lists_every_module_in_the_package(self):
        on_disk = {
            f"retools.{path.stem}"
            for path in (REPO_ROOT / "retools").glob("*.py")
            if path.stem != "__init__"
        }
        assert set(verify_install.retools_modules()) == on_disk
