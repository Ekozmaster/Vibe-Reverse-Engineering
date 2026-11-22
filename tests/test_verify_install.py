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

    @pytest.fixture(autouse=True)
    def no_override(self, monkeypatch):
        monkeypatch.delenv("JAVA_HOME_OVERRIDE", raising=False)

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

    def test_check_names_the_jdk_an_override_hands_to_pyghidra(self, monkeypatch, tmp_path):
        monkeypatch.setattr(verify_install, "results", [])
        monkeypatch.setenv("JAVA_HOME_OVERRIDE", str(tmp_path / "override"))
        monkeypatch.setattr(verify_install, "probe_home", lambda home: Jdk(home, 21))
        monkeypatch.setattr(verify_install, "find_jdk", lambda: pytest.fail("looked past the override"))
        assert verify_install.check_java() is True
        assert verify_install.results == [
            ("java", verify_install.PASS, f"JDK 21 ({tmp_path / 'override'}, named by JAVA_HOME_OVERRIDE)")]

    @pytest.mark.parametrize("probed", [None, 17], ids=["no JDK", "too old"])
    def test_check_warns_about_an_override_pyghidra_cannot_use(self, monkeypatch, tmp_path, probed):
        monkeypatch.setattr(verify_install, "results", [])
        monkeypatch.setenv("JAVA_HOME_OVERRIDE", str(tmp_path / "override"))
        monkeypatch.setattr(verify_install, "probe_home", lambda home: probed and Jdk(home, probed))
        monkeypatch.setattr(verify_install, "find_jdk", lambda: Jdk(tmp_path / "newer", 21))
        assert verify_install.check_java() is False
        status, message = verify_install.results[0][1:]
        assert status == verify_install.WARN
        assert "JAVA_HOME_OVERRIDE" in message and str(tmp_path / "override") in message

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
