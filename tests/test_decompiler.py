"""Tests for decompiler.py backend routing logic."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


class TestScriptModeImports:
    def test_load_types_import_resolves_in_script_mode(self, tmp_path):
        """`python retools/decompiler.py` puts only retools/ on sys.path[0];
        _load_types must still be able to import the kb parser."""
        import subprocess
        import textwrap

        retools = Path(__file__).resolve().parent.parent / "retools"
        driver = tmp_path / "driver.py"
        driver.write_text(textwrap.dedent(f"""
            import sys
            sys.path.insert(0, r"{retools}")   # simulate script-dir-only sys.path
            import decompiler

            class FakeR2:
                def cmd(self, c): pass

            decompiler._load_types(FakeR2(), "@ 0x401000 void Foo(void);")
            print("OK")
        """))
        proc = subprocess.run(
            [sys.executable, str(driver)],
            cwd=str(tmp_path), capture_output=True, text=True,
        )
        assert "OK" in proc.stdout, proc.stderr


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


class _FakeR2:
    """Stands in for an r2pipe session: records commands, answers each from *outputs* by its name.

    The name is the command before any `` @ address``; unknown commands answer "".
    """

    def __init__(self, outputs: dict | None = None):
        self.outputs, self.cmds, self.quit_called = outputs or {}, [], False

    def cmd(self, c):
        self.cmds.append(c)
        return self.outputs.get(c.split(" @ ")[0], "")

    def quit(self):
        self.quit_called = True


@pytest.fixture
def fake_r2(monkeypatch):
    """Install a factory for _FakeR2 sessions answering from the given outputs; returns those made."""
    import decompiler
    made = []

    def install(outputs):
        monkeypatch.setattr(decompiler, "_find_r2_bin", lambda: "r2")
        monkeypatch.setattr(decompiler, "_ensure_r2_in_path", lambda path: None)
        monkeypatch.setattr(decompiler, "_find_sleigh_home", lambda: None)
        monkeypatch.setattr(decompiler.r2pipe, "open",
                            lambda binary, flags: made.append(_FakeR2(outputs)) or made[-1])
        return made
    return install


class TestLoadTypesOrdering:
    def test_typedefs_emitted_before_references(self, tmp_path):
        """td must be sent to r2 before any tl/afs that could reference the type."""
        kb_path = tmp_path / "kb.h"
        kb_path.write_text(
            "struct Foo { int x; };\n"
            "$ 0x7C5548 Foo* g_mainObject\n"
            "@ 0x401000 void __cdecl ProcessInput(int key);\n"
        )

        from decompiler import _load_types
        r2 = _FakeR2()
        _load_types(r2, str(kb_path))

        td_idx = next(i for i, c in enumerate(r2.cmds) if "td " in c)
        tl_idx = next(i for i, c in enumerate(r2.cmds) if "tl " in c)
        afs_idx = next(i for i, c in enumerate(r2.cmds) if "afs " in c)

        assert td_idx < tl_idx
        assert td_idx < afs_idx

    def test_a_declaration_over_several_lines_is_one_command_radare2_does_not_split(self):
        """A leading quote makes radare2 take the rest literally; unquoted, each ';' starts a new command."""
        from decompiler import _load_types
        r2 = _FakeR2()
        _load_types(r2, "struct Foo {\n    int x;\n    float y;\n};\n")
        assert r2.cmds == ["'td struct Foo { int x; float y; };"]

    def test_an_entry_without_a_parameter_list_only_names_the_function(self):
        from decompiler import _load_types
        r2 = _FakeR2()
        _load_types(r2, "@ 0x401000 _thunk_Foo;")
        assert not [c for c in r2.cmds if "afs " in c]
        assert [c for c in r2.cmds if "afn " in c] == ["'@0x401000'afn _thunk_Foo"]

    def test_an_entry_without_a_name_only_creates_the_function(self):
        from decompiler import _load_types
        r2 = _FakeR2()
        _load_types(r2, "@ 0x401000 (int a);")
        assert r2.cmds == ["af @ 0x401000"]


def _radare2() -> str:
    """Path of a radare2 that starts. Skips the test without one."""
    import subprocess

    import decompiler
    r2_bin = decompiler._find_r2_bin()
    if r2_bin is None:
        pytest.skip("radare2 not found")
    try:
        subprocess.run([r2_bin, "-v"], capture_output=True, timeout=60, check=True)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("radare2 does not start; tools/ may hold Git LFS pointer files (git lfs pull)")
    return r2_bin


def _exported_function(binary: str) -> int:
    """Virtual address of the first function *binary* exports itself."""
    import pefile
    pe = pefile.PE(binary, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not symbol.forwarder:
            return pe.OPTIONAL_HEADER.ImageBase + symbol.address
    raise LookupError(f"{binary} exports no function of its own")


class TestKnowledgeBaseInRadare2:
    """What a radare2 session holds after a knowledge base was loaded into it."""

    @pytest.fixture
    def session(self, sample_binary):
        import decompiler
        decompiler._ensure_r2_in_path(_radare2())
        r2 = decompiler.r2pipe.open(sample_binary, flags=["-2"])
        r2.cmd("e scr.color=0")
        yield r2, _exported_function(sample_binary)
        r2.quit()

    def test_struct_written_over_several_lines_is_known_with_its_members(self, session):
        from decompiler import _load_types
        r2, _va = session
        _load_types(r2, "struct KbPoint {\n    int x;\n    float y;\n};\n")
        assert "KbPoint" in r2.cmd("ts").split()
        assert r2.cmd("ts KbPoint").split()[-2:] == ["x", "y"]

    def test_prototype_that_uses_a_struct_from_the_same_file(self, session):
        from decompiler import _load_types
        r2, va = session
        _load_types(r2, f"struct KbPoint {{ int x; float y; }};\n@ {va:#x} int __stdcall KbCount(KbPoint* point, int n);\n")
        assert r2.cmd(f"afs @ {va:#x}").strip() == "int __stdcall KbCount (KbPoint *point, int n);"

    def test_member_function_keeps_its_qualified_name_and_gets_its_parameters(self, session):
        from decompiler import _load_types
        r2, va = session
        _load_types(r2, f"@ {va:#x} void __thiscall Kb::Widget::~Widget(Widget* this, int flags);\n")
        assert r2.cmd(f"afn @ {va:#x}").strip() == "Kb::Widget::~Widget"
        assert "(Widget *this, int flags)" in r2.cmd(f"afs @ {va:#x}")

    def test_global_is_a_flag_at_its_address(self, session):
        from decompiler import _load_types
        r2, va = session
        _load_types(r2, f"$ {va + 0x10:#x} int g_kbCounter\n")
        assert f"{va + 0x10:#010x}" in r2.cmd("f~g_kbCounter")

    def test_decompiled_function_has_the_name_and_parameters_from_the_kb(self, sample_binary):
        import decompiler
        _radare2()
        va = _exported_function(sample_binary)
        kb = f"struct KbPoint {{\n    int x;\n    float y;\n}};\n@ {va:#x} int KbCount(KbPoint* point, int n);\n"
        code = decompiler.decompile(sample_binary, va, backend="pdg", types=kb)
        if decompiler._MISSING_PLUGIN_HINT in code:
            pytest.skip("r2ghidra not installed")
        assert "KbCount(KbPoint *point,int n)" in code


MISSING_PLUGIN_HINT = "You need to install the plugin with r2pm -ci r2ghidra"


class TestAutoBackendOutputSelection:
    def test_output_mentioning_install_is_kept(self, fake_r2):
        import decompiler
        code = "uint sym.MsiInstallProductW(int64_t arg1) { return 0; }"
        fake_r2({"pdg": code})
        assert decompiler.decompile("fake.exe", 0x401000, backend="auto") == code

    def test_missing_plugin_hint_falls_back_to_next_backend(self, fake_r2):
        import decompiler
        fallback = "void fcn_00401000(void) { }"
        fake_r2({"pdg": MISSING_PLUGIN_HINT, "pdc": fallback})
        assert decompiler.decompile("fake.exe", 0x401000, backend="auto") == fallback


class TestAutoBackendGhidraProjectLookup:
    def test_binary_name_with_dots_is_looked_up_by_file_name(self, tmp_path):
        """A project for `sl.common.dll` lives under ghidra/sl.common/, which
        is_analyzed derives from the file name it is given."""
        mock_backend = MagicMock()
        mock_backend.is_analyzed.return_value = True
        mock_backend.decompile.return_value = "void func() {}"

        with patch.dict(sys.modules, {"retools.pyghidra_backend": mock_backend}):
            from importlib import reload
            import decompiler
            reload(decompiler)
            result = decompiler.decompile(
                str(tmp_path / "sl.common.dll"), 0x180001000,
                backend="auto", project_dir=str(tmp_path))

        assert result == "void func() {}"
        mock_backend.is_analyzed.assert_called_once_with(
            str(tmp_path / "ghidra"), "sl.common.dll")


class TestGhidraFirstInAuto:
    def _backend(self, monkeypatch, analyzed, result):
        import decompiler
        backend = MagicMock()
        backend.is_analyzed.return_value = analyzed
        backend.decompile.return_value = result
        monkeypatch.setitem(sys.modules, "retools.pyghidra_backend", backend)
        return decompiler, backend

    def test_a_ghidra_error_falls_through_to_r2(self, monkeypatch, tmp_path, fake_r2):
        decompiler, _ = self._backend(monkeypatch, True, "[error] no function")
        fake_r2({"pdg": "int r2() {}"})
        assert decompiler.decompile("game.exe", 0x401000, project_dir=str(tmp_path)) == "int r2() {}"


class TestR2Routing:
    def test_auto_prefers_pdg(self, fake_r2):
        import decompiler
        fake_r2({"pdg": "void g() {}", "pdc": "int f() {}"})
        assert decompiler.decompile("a.exe", 0x401000) == "void g() {}"

    @pytest.mark.parametrize("outputs", [{}, {"pdg": MISSING_PLUGIN_HINT}], ids=["nothing", "only-a-plugin-hint"])
    def test_auto_with_no_output_is_an_error(self, fake_r2, outputs):
        import decompiler
        fake_r2(outputs)
        assert decompiler.decompile("a.exe", 0x401000) == "[error] No decompiler backend produced output at 0x401000"

    def test_named_backend_and_its_errors(self, fake_r2):
        import decompiler
        fake_r2({"pdd": "pseudo"})
        assert decompiler.decompile("a.exe", 0x401000, backend="pdd") == "pseudo"
        assert decompiler.decompile("a.exe", 0x401000, backend="pdc") == "[error] pdc produced no output at 0x401000"
        assert decompiler.decompile("a.exe", 0x401000, backend="nope").startswith("[error] Unknown backend 'nope'")

    def test_full_analysis_runs_aaa_instead_of_af(self, fake_r2):
        import decompiler
        made = fake_r2({"pdg": "x"})
        decompiler.decompile("a.exe", 0x401000, full_analysis=True)
        assert "aaa" in made[0].cmds and "af @ 0x401000" not in made[0].cmds
