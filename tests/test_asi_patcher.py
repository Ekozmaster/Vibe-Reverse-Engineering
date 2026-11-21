"""Tests for retools/asi_patcher.py -- JSON patch spec -> zero-CRT C source -> MSVC .asi build.

The compiler is never run: every build test replaces subprocess.run with a stub that
records the command line and fakes the linker's outputs under tmp_path.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "retools"))

import asi_patcher  # noqa: E402

VCVARS = Path(r"C:\VS\VC\Auxiliary\Build\vcvarsall.bat")


def _spec(**kw) -> dict:
    spec = {"name": "MyPatch", "arch": "x86", "verify": [], "patches": []}
    spec.update(kw)
    return spec


def _write_spec(directory: Path, spec: dict) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def _norm(text: str) -> str:
    return " ".join(text.split())


def _func(src: str, signature: str) -> str:
    """Whitespace-normalized body (between the braces) of the generated function `signature`."""
    lines = src.split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.startswith(signature))
    open_at = next(i for i in range(start, len(lines)) if lines[i] == "{")
    close_at = next(i for i in range(open_at, len(lines)) if lines[i] == "}")
    return _norm("\n".join(lines[open_at + 1:close_at]))


def _gen(**kw) -> str:
    return asi_patcher.generate_c(_spec(**kw))


# -- spec loading ----------------------------------------------------------


class TestLoadSpec:
    def _load(self, tmp_path, spec):
        return asi_patcher._load_spec(_write_spec(tmp_path, spec))

    @pytest.mark.parametrize("name", ["MyPatch", "_x", "a1_B2", "Z"])
    def test_valid_c_identifier_names_load(self, tmp_path, name):
        assert self._load(tmp_path, _spec(name=name))["name"] == name

    @pytest.mark.parametrize("name", ["", "1abc", "my-patch", "my patch", "a.b", "x$"])
    def test_name_must_be_c_identifier(self, tmp_path, name):
        with pytest.raises(SystemExit, match="spec.name must be a valid C identifier"):
            self._load(tmp_path, _spec(name=name))

    def test_missing_name_rejected(self, tmp_path):
        spec = _spec()
        del spec["name"]
        with pytest.raises(SystemExit, match="valid C identifier"):
            self._load(tmp_path, spec)

    def test_arch_defaults_to_x86_and_lists_default(self, tmp_path):
        loaded = self._load(tmp_path, {"name": "P"})
        assert loaded == {"name": "P", "arch": "x86", "verify": [], "patches": []}

    @pytest.mark.parametrize("arch", ["x86", "x64"])
    def test_supported_arches_kept(self, tmp_path, arch):
        assert self._load(tmp_path, _spec(arch=arch))["arch"] == arch

    @pytest.mark.parametrize("arch", ["X86", "x86_64", "arm64", ""])
    def test_other_arch_rejected(self, tmp_path, arch):
        with pytest.raises(SystemExit, match="spec.arch must be x86 or x64"):
            self._load(tmp_path, _spec(arch=arch))

    def test_given_verify_and_patches_kept(self, tmp_path):
        verify = [{"addr": "0x401000", "expect": "55 8B EC"}]
        patches = [{"name": "Gate", "type": "bytes", "addr": "0x401000", "data": "B0 01 C3"}]
        loaded = self._load(tmp_path, _spec(verify=verify, patches=patches))
        assert loaded["verify"] == verify
        assert loaded["patches"] == patches

    @pytest.mark.parametrize("ptype", ["bytes", "code", "nop", "float", "double", "int32", "int64"])
    def test_every_documented_patch_type_accepted(self, tmp_path, ptype):
        patches = [{"name": "P1", "type": ptype, "addr": "0x1000"}]
        assert self._load(tmp_path, _spec(patches=patches))["patches"][0]["type"] == ptype

    @pytest.mark.parametrize("ptype", ["word", "BYTES", "", None])
    def test_unknown_patch_type_rejected(self, tmp_path, ptype):
        patches = [{"name": "Gate", "type": ptype, "addr": "0x1000"}]
        with pytest.raises(SystemExit, match="Unknown patch type .* in 'Gate'"):
            self._load(tmp_path, _spec(patches=patches))

    def test_missing_patch_type_rejected(self, tmp_path):
        with pytest.raises(SystemExit, match="Unknown patch type None"):
            self._load(tmp_path, _spec(patches=[{"name": "Gate", "addr": "0x1000"}]))

    @pytest.mark.parametrize("pname", ["", "9lives", "two words", "dash-name"])
    def test_patch_name_must_be_c_identifier(self, tmp_path, pname):
        patches = [{"name": pname, "type": "nop", "addr": "0x1000", "count": 1}]
        with pytest.raises(SystemExit, match="Patch name must be a valid C identifier"):
            self._load(tmp_path, _spec(patches=patches))

    def test_every_patch_checked_not_only_the_first(self, tmp_path):
        patches = [{"name": "Ok", "type": "nop", "addr": "0x1000", "count": 1},
                   {"name": "Bad", "type": "word", "addr": "0x1000"}]
        with pytest.raises(SystemExit, match="'Bad'"):
            self._load(tmp_path, _spec(patches=patches))


# -- helpers ---------------------------------------------------------------


class TestHelpers:
    def test_hex_to_c(self):
        assert asi_patcher._hex_to_c("B0 01 C2") == "0xB0, 0x01, 0xC2"

    def test_hex_to_c_tolerates_extra_whitespace(self):
        assert asi_patcher._hex_to_c("  90\t 90\nC3 ") == "0x90, 0x90, 0xC3"

    def test_hex_to_c_single_byte(self):
        assert asi_patcher._hex_to_c("CC") == "0xCC"

    def test_addr_x86_is_8_uppercase_digits(self):
        assert asi_patcher._c_addr("0x401abc", "x86") == "(UINT_PTR)0x00401ABC"

    def test_addr_x64_is_16_uppercase_digits(self):
        assert asi_patcher._c_addr("0x140001000", "x64") == "(UINT_PTR)0x0000000140001000"

    def test_addr_accepts_bare_hex(self):
        assert asi_patcher._c_addr("401000", "x86") == "(UINT_PTR)0x00401000"


# -- generated C: preamble and runtime helpers -----------------------------


class TestGeneratedPreamble:
    def test_header_comment_names_patch_and_arch(self):
        lines = _gen(arch="x64").split("\n")
        assert lines[0] == "/* Auto-generated ASI patch: MyPatch  (x64) */"
        assert lines[1] == "/* Generated by retools/asi_patcher.py */"

    def test_each_description_line_becomes_a_comment(self):
        lines = _gen(description="first note\nsecond note").split("\n")
        assert lines[1:4] == ["/* first note */", "/* second note */",
                              "/* Generated by retools/asi_patcher.py */"]

    def test_zero_crt_windows_preamble(self):
        lines = _gen().split("\n")
        for needed in ("#define WIN32_LEAN_AND_MEAN", "#include <windows.h>",
                       '#pragma comment(lib, "kernel32.lib")', "int _fltused = 0;"):
            assert needed in lines
        assert lines.index("#define WIN32_LEAN_AND_MEAN") < lines.index("#include <windows.h>")

    def test_output_ends_with_newline_after_dllmain(self):
        src = _gen()
        assert src.endswith("}\n")
        assert src.rstrip().split("\n")[-1] == "}"

    def test_write_mem_copies_len_bytes(self):
        body = _func(_gen(), "static void write_mem(")
        assert body == "unsigned int i; for (i = 0; i < len; i++) dst[i] = src[i];"

    def test_fill_nop_writes_x86_nop_opcode(self):
        body = _func(_gen(), "static void fill_nop(")
        assert body == "unsigned int i; for (i = 0; i < len; i++) dst[i] = 0x90;"

    @pytest.mark.parametrize("sig, call", [
        ("static int patch_bytes(", "write_mem((unsigned char *)addr, data, len);"),
        ("static int patch_nop(", "fill_nop((unsigned char *)addr, len);"),
    ])
    def test_patchers_unprotect_write_reprotect(self, sig, call):
        body = _func(_gen(), sig)
        assert body == _norm(
            "DWORD old;"
            " if (!VirtualProtect((void *)addr, len, PAGE_EXECUTE_READWRITE, &old)) return 0;"
            f" {call}"
            " VirtualProtect((void *)addr, len, old, &old);"
            " return 1;")

    def test_patcher_signatures(self):
        src = _norm(_gen())
        assert ("static int patch_bytes(UINT_PTR addr, const unsigned char *data, unsigned int len)"
                in src)
        assert "static int patch_nop(UINT_PTR addr, unsigned int len)" in src
        assert ("static void write_mem(volatile unsigned char *dst, const unsigned char *src,"
                " unsigned int len)" in src)
        assert "static void fill_nop(volatile unsigned char *dst, unsigned int len)" in src

    def test_log_handle_starts_invalid(self):
        assert "static HANDLE g_log = INVALID_HANDLE_VALUE;" in _gen().split("\n")

    def test_log_file_is_name_dot_log_beside_the_exe(self):
        body = _func(_gen(name="Fixer"), "static void log_open(")
        assert body == _norm(r"""
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);
            {
                char *slash = path, *p = path;
                while (*p) { if (*p == '\\' || *p == '/') slash = p; p++; }
                slash[1] = '\0';
            }
            {
                const char nm[] = "Fixer.log";
                char *dst = path;
                const char *src;
                while (*dst) dst++;
                src = nm;
                while (*src) *dst++ = *src++;
                *dst = '\0';
            }
            g_log = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        """)

    def test_log_str_writes_strlen_bytes_when_open(self):
        body = _func(_gen(), "static void log_str(")
        assert body == _norm("""
            DWORD n;
            const char *p;
            if (g_log == INVALID_HANDLE_VALUE) return;
            p = s;
            while (*p) p++;
            WriteFile(g_log, s, (DWORD)(p - s), &n, NULL);
        """)

    def test_log_patch_line_format(self):
        body = _func(_gen(), "static void log_patch(")
        assert body == _norm(r"""
            log_str(ok ? "[OK]   " : "[FAIL] ");
            log_str(name);
            log_str(" @ ");
            log_hex(addr);
            log_str("\r\n");
        """)

    def test_log_flush_and_close(self):
        src = _gen()
        assert _func(src, "static void log_flush(") == \
            "if (g_log != INVALID_HANDLE_VALUE) FlushFileBuffers(g_log);"
        assert _func(src, "static void log_close(") == _norm(
            "if (g_log != INVALID_HANDLE_VALUE) CloseHandle(g_log);"
            " g_log = INVALID_HANDLE_VALUE;")


def _x86_hex_digits(body: str) -> dict:
    """buf index -> shift amount, from the x86 log_hex's unrolled digit stores."""
    out = {}
    for idx, shift in re.findall(r"buf\[(\d+)\]\s*=\s*hex\[\(v >>\s*(\d+)\) & 0xF\]", body):
        out[int(idx)] = int(shift)
    for idx in re.findall(r"buf\[(\d+)\]\s*=\s*hex\[v & 0xF\]", body):
        out[int(idx)] = 0
    return out


class TestLogHex:
    def test_x86_prints_0x_and_8_digits_most_significant_first(self):
        body = _func(_gen(arch="x86"), "static void log_hex(")
        assert body.startswith('char buf[11]; const char hex[] = "0123456789ABCDEF";'
                               " buf[0] = '0'; buf[1] = 'x';")
        assert _x86_hex_digits(body) == {2 + i: 28 - 4 * i for i in range(8)}
        assert body.endswith("buf[10] = '\\0'; log_str(buf);")

    def test_x64_prints_0x_and_16_digits_most_significant_first(self):
        body = _func(_gen(arch="x64"), "static void log_hex(")
        assert body == _norm(r"""
            char buf[19];
            const char hex[] = "0123456789ABCDEF";
            int i;
            buf[0] = '0'; buf[1] = 'x';
            for (i = 0; i < 16; i++)
                buf[2 + i] = hex[(v >> (60 - i * 4)) & 0xF];
            buf[18] = '\0';
            log_str(buf);
        """)

    @pytest.mark.parametrize("arch", ["x86", "x64"])
    def test_one_log_hex_per_arch(self, arch):
        assert _gen(arch=arch).count("static void log_hex(UINT_PTR v)") == 1


# -- generated C: verify ---------------------------------------------------


class TestVerify:
    def test_no_verify_entries_always_pass(self):
        assert _func(_gen(), "static int verify_exe(") == "return 1;"

    def test_each_entry_checks_readable_then_every_expected_byte(self):
        verify = [{"addr": "0x401000", "expect": "55 8B EC"},
                  {"addr": "0x402000", "expect": " 90 "}]
        body = _func(_gen(verify=verify), "static int verify_exe(")
        assert body == _norm("""
            {
                const unsigned char expect[] = { 0x55, 0x8B, 0xEC };
                if (IsBadReadPtr((void *)(UINT_PTR)0x00401000, 3))
                    return 0;
                {
                    const unsigned char *p = (const unsigned char *)(UINT_PTR)0x00401000;
                    unsigned int i;
                    for (i = 0; i < 3; i++)
                        if (p[i] != expect[i]) return 0;
                }
            }
            {
                const unsigned char expect[] = { 0x90 };
                if (IsBadReadPtr((void *)(UINT_PTR)0x00402000, 1))
                    return 0;
                {
                    const unsigned char *p = (const unsigned char *)(UINT_PTR)0x00402000;
                    unsigned int i;
                    for (i = 0; i < 1; i++)
                        if (p[i] != expect[i]) return 0;
                }
            }
            return 1;
        """)

    def test_verify_address_width_follows_arch(self):
        verify = [{"addr": "0x140001000", "expect": "48"}]
        body = _func(_gen(arch="x64", verify=verify), "static int verify_exe(")
        assert "IsBadReadPtr((void *)(UINT_PTR)0x0000000140001000, 1)" in body


# -- generated C: patch functions ------------------------------------------


def _apply(src: str, name: str) -> str:
    return _func(src, f"static int apply_{name}(void)")


class TestPatchFunctions:
    def test_bytes_patch_inline_array(self):
        p = {"name": "Gate", "type": "bytes", "addr": "0x401000", "data": "B0 01 C3"}
        assert _apply(_gen(patches=[p]), "Gate") == _norm(
            "const unsigned char data[] = { 0xB0, 0x01, 0xC3 };"
            " return patch_bytes((UINT_PTR)0x00401000, data, sizeof(data));")

    def test_code_is_alias_for_bytes(self):
        b = {"name": "P", "type": "bytes", "addr": "0x401000", "data": "B0 01 C3"}
        c = dict(b, type="code")
        assert _apply(_gen(patches=[c]), "P") == _apply(_gen(patches=[b]), "P")

    def test_twelve_bytes_stay_on_one_line(self):
        data = " ".join(f"{i:02X}" for i in range(12))
        src = _gen(patches=[{"name": "P", "type": "bytes", "addr": "0x1000", "data": data}])
        line = next(ln for ln in src.split("\n") if "const unsigned char data[]" in ln)
        assert line == "    const unsigned char data[] = { " + ", ".join(
            f"0x{i:02X}" for i in range(12)) + " };"

    @pytest.mark.parametrize("count", [13, 24, 25])
    def test_long_data_wraps_twelve_bytes_per_line(self, count):
        tokens = [f"{i:02X}" for i in range(count)]
        src = _gen(patches=[{"name": "P", "type": "bytes", "addr": "0x1000",
                             "data": " ".join(tokens)}])
        lines = src.split("\n")
        start = lines.index("    const unsigned char data[] = {")
        end = lines.index("    };", start)
        rows = lines[start + 1:end]
        chunks = [tokens[i:i + 12] for i in range(0, count, 12)]
        assert rows == ["        " + ", ".join(f"0x{t}" for t in ch) + ("," if k < len(chunks) - 1 else "")
                        for k, ch in enumerate(chunks)]
        assert lines[end + 1] == "    return patch_bytes((UINT_PTR)0x00001000, data, sizeof(data));"

    def test_nop_patch_fills_count(self):
        p = {"name": "Fill", "type": "nop", "addr": "0x402000", "count": 6}
        assert _apply(_gen(patches=[p]), "Fill") == "return patch_nop((UINT_PTR)0x00402000, 6);"

    @pytest.mark.parametrize("ptype, value, decl", [
        ("float", 99999.0, "float v = 99999.0f;"),
        ("float", 0.5, "float v = 0.5f;"),
        ("double", 1.0e12, "double v = 1000000000000.0;"),
        ("int32", -1, "int v = -1;"),
        ("int32", 2147483647, "int v = 2147483647;"),
        ("int64", 0, "long long v = 0LL;"),
        ("int64", 1 << 40, "long long v = 1099511627776LL;"),
    ])
    def test_scalar_patches_write_value_bytes(self, ptype, value, decl):
        p = {"name": "V", "type": ptype, "addr": "0x403000", "value": value}
        assert _apply(_gen(patches=[p]), "V") == _norm(
            decl + " return patch_bytes((UINT_PTR)0x00403000, (const unsigned char *)&v, sizeof(v));")

    def test_patch_address_width_follows_arch(self):
        p = {"name": "Fill", "type": "nop", "addr": "0x140002000", "count": 2}
        assert _apply(_gen(arch="x64", patches=[p]), "Fill") == \
            "return patch_nop((UINT_PTR)0x0000000140002000, 2);"

    def test_one_function_per_patch_before_dllmain(self):
        patches = [{"name": n, "type": "nop", "addr": "0x1000", "count": 1} for n in ("A", "B", "C")]
        lines = _gen(patches=patches).split("\n")
        dll = lines.index("BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)")
        for n in ("A", "B", "C"):
            assert lines.count(f"static int apply_{n}(void)") == 1
            assert lines.index(f"static int apply_{n}(void)") < dll

    def test_no_patches_no_apply_functions(self):
        assert "apply_" not in _gen()


# -- generated C: DllMain --------------------------------------------------


DOC_PATCHES = [
    {"name": "Gate", "type": "bytes", "addr": "0x401000", "data": "B0 01 C3"},
    {"name": "Fill", "type": "nop", "addr": "0x402000", "count": 6},
]


class TestDllMain:
    def test_without_verify(self):
        body = _func(_gen(patches=DOC_PATCHES), "BOOL APIENTRY DllMain(")
        assert body == _norm(r"""
            (void)lpReserved;
            if (reason != DLL_PROCESS_ATTACH)
                return TRUE;
            DisableThreadLibraryCalls(hModule);
            log_open();
            log_str("MyPatch loaded\r\n");
            log_patch("Gate", (UINT_PTR)0x00401000, apply_Gate());
            log_patch("Fill", (UINT_PTR)0x00402000, apply_Fill());
            log_str("All patches applied\r\n");
            log_flush();
            return TRUE;
        """)

    def test_verify_failure_skips_every_patch(self):
        verify = [{"addr": "0x401000", "expect": "55 8B EC"}]
        body = _func(_gen(verify=verify, patches=DOC_PATCHES), "BOOL APIENTRY DllMain(")
        assert body == _norm(r"""
            (void)lpReserved;
            if (reason != DLL_PROCESS_ATTACH)
                return TRUE;
            DisableThreadLibraryCalls(hModule);
            log_open();
            log_str("MyPatch loaded\r\n");
            if (!verify_exe()) {
                log_str("verify FAILED -- wrong binary?\r\n");
                log_close();
                return TRUE;
            }
            log_str("verify OK\r\n");
            log_patch("Gate", (UINT_PTR)0x00401000, apply_Gate());
            log_patch("Fill", (UINT_PTR)0x00402000, apply_Fill());
            log_str("All patches applied\r\n");
            log_flush();
            return TRUE;
        """)

    def test_signature_and_last_in_file(self):
        lines = _gen(patches=DOC_PATCHES).split("\n")
        dll = lines.index("BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)")
        assert lines[dll + 1] == "{"
        assert lines[dll + 2:].index("}") == len(lines) - dll - 4

    def test_x64_patch_addresses_in_log(self):
        p = {"name": "Fill", "type": "nop", "addr": "0x140002000", "count": 2}
        body = _func(_gen(arch="x64", patches=[p]), "BOOL APIENTRY DllMain(")
        assert 'log_patch("Fill", (UINT_PTR)0x0000000140002000, apply_Fill());' in body

    def test_functions_defined_before_use(self):
        lines = _gen(verify=[{"addr": "0x1", "expect": "00"}], patches=DOC_PATCHES).split("\n")
        order = ["static void write_mem(", "static void fill_nop(", "static int patch_bytes(",
                 "static int patch_nop(", "static void log_open(", "static void log_str(",
                 "static void log_hex(", "static void log_patch(", "static void log_flush(",
                 "static void log_close(", "static int verify_exe(", "static int apply_Gate(",
                 "static int apply_Fill(", "BOOL APIENTRY DllMain("]
        at = [next(i for i, ln in enumerate(lines) if ln.startswith(sig)) for sig in order]
        assert at == sorted(at)


# -- build (compiler stubbed) ----------------------------------------------


class _FakeRun:
    """Stands in for subprocess.run: records the call, fakes cl/link outputs."""

    def __init__(self, out_dir: Path, name: str, returncode=0, stdout="", stderr="",
                 asi_bytes=2048, extras=("obj", "lib", "exp")):
        self.out_dir, self.name = out_dir, name
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
        self.asi_bytes, self.extras = asi_bytes, extras
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if self.returncode == 0:
            (self.out_dir / f"{self.name}.asi").write_bytes(b"\0" * self.asi_bytes)
            for ext in self.extras:
                stem = "patch" if ext == "obj" else self.name
                (self.out_dir / f"{stem}.{ext}").write_bytes(b"x")
        return subprocess.CompletedProcess(cmd, self.returncode, self.stdout, self.stderr)


def _build(monkeypatch, tmp_path, spec, **fake_kw):
    out = tmp_path / "proj"
    spec_path = _write_spec(out, spec)
    fake = _FakeRun(out.resolve(), spec["name"], **fake_kw)
    monkeypatch.setattr(asi_patcher.subprocess, "run", fake)
    return out, spec_path, fake


class TestBuild:
    def test_writes_generated_c_beside_spec(self, monkeypatch, tmp_path):
        out, spec_path, _ = _build(monkeypatch, tmp_path, _spec(patches=DOC_PATCHES))
        asi_patcher.cmd_build(spec_path, VCVARS)
        expected = asi_patcher.generate_c(asi_patcher._load_spec(spec_path))
        assert (out / "patch.c").read_text(encoding="utf-8") == expected

    def test_x86_command_line(self, monkeypatch, tmp_path):
        out, spec_path, fake = _build(monkeypatch, tmp_path, _spec())
        asi_patcher.cmd_build(spec_path, VCVARS)
        (cmd, kw), = fake.calls
        d = out.resolve()
        assert cmd == (
            f'call "{VCVARS}" x86 >nul 2>&1'
            f' && cl.exe /nologo /O1 /GS- /W3 /Zl /D "WIN32" /D "NDEBUG"'
            f' /c /Fo"{d / "patch.obj"}" "{d / "patch.c"}"'
            f' && link.exe /nologo /DLL /NODEFAULTLIB /ENTRY:DllMain@12'
            f' /OUT:"{d / "MyPatch.asi"}" "{d / "patch.obj"}" kernel32.lib')
        assert kw.get("shell") is True
        assert kw.get("capture_output") is True
        assert kw.get("text") is True

    def test_x64_uses_x64_env_and_undecorated_entry(self, monkeypatch, tmp_path):
        _, spec_path, fake = _build(monkeypatch, tmp_path, _spec(arch="x64"))
        asi_patcher.cmd_build(spec_path, VCVARS)
        cmd = fake.calls[0][0]
        assert cmd.startswith(f'call "{VCVARS}" x64 >nul 2>&1 && ')
        assert re.search(r"/ENTRY:DllMain(\s|$)", cmd)
        assert "DllMain@12" not in cmd

    def test_relative_spec_path_gives_absolute_outputs(self, monkeypatch, tmp_path):
        out, _, fake = _build(monkeypatch, tmp_path, _spec())
        monkeypatch.chdir(out)
        asi_patcher.cmd_build(Path("spec.json"), VCVARS)
        cmd = fake.calls[0][0]
        assert f'/OUT:"{out.resolve() / "MyPatch.asi"}"' in cmd
        assert f'"{out.resolve() / "patch.c"}"' in cmd

    def test_success_removes_intermediates_keeps_asi(self, monkeypatch, tmp_path, capsys):
        out, spec_path, _ = _build(monkeypatch, tmp_path, _spec())
        asi_patcher.cmd_build(spec_path, VCVARS)
        assert sorted(p.name for p in out.iterdir()) == ["MyPatch.asi", "patch.c", "spec.json"]
        asi = out.resolve() / "MyPatch.asi"
        assert capsys.readouterr().out == f"[asi_patcher] OK  {asi}  (2.0 KB)\n"

    def test_size_reported_in_kb_one_decimal(self, monkeypatch, tmp_path, capsys):
        _, spec_path, _ = _build(monkeypatch, tmp_path, _spec(), asi_bytes=1536 + 103)
        asi_patcher.cmd_build(spec_path, VCVARS)
        assert capsys.readouterr().out.endswith("  (1.6 KB)\n")

    def test_missing_intermediates_are_fine(self, monkeypatch, tmp_path):
        out, spec_path, _ = _build(monkeypatch, tmp_path, _spec(), extras=())
        asi_patcher.cmd_build(spec_path, VCVARS)
        assert (out / "MyPatch.asi").exists()

    def test_compiler_failure_reports_and_exits(self, monkeypatch, tmp_path, capsys):
        _, spec_path, _ = _build(monkeypatch, tmp_path, _spec(), returncode=2,
                                 stdout="patch.c(9): error C2065", stderr="link failed")
        with pytest.raises(SystemExit, match=r"^Build failed \(exit 2\)$"):
            asi_patcher.cmd_build(spec_path, VCVARS)
        captured = capsys.readouterr()
        assert captured.out == "patch.c(9): error C2065\n"
        assert captured.err == "link failed\n"

    def test_invalid_spec_never_reaches_compiler(self, monkeypatch, tmp_path):
        _, spec_path, fake = _build(monkeypatch, tmp_path, _spec(name="bad-name"))
        with pytest.raises(SystemExit):
            asi_patcher.cmd_build(spec_path, VCVARS)
        assert fake.calls == []
        assert not (spec_path.parent / "patch.c").exists()


# -- show / init -----------------------------------------------------------


class TestShow:
    def test_prints_generated_source(self, tmp_path, capsys):
        spec_path = _write_spec(tmp_path, {"name": "Shown", "patches": DOC_PATCHES})
        asi_patcher.cmd_show(spec_path)
        expected = asi_patcher.generate_c(
            {"name": "Shown", "arch": "x86", "verify": [], "patches": DOC_PATCHES})
        assert capsys.readouterr().out == expected + "\n"

    def test_validates_spec(self, tmp_path):
        with pytest.raises(SystemExit):
            asi_patcher.cmd_show(_write_spec(tmp_path, _spec(arch="arm")))


class TestInit:
    def test_skeleton_is_a_loadable_spec(self, tmp_path):
        asi_patcher.cmd_init(tmp_path / "Game")
        assert asi_patcher._load_spec(tmp_path / "Game" / "spec.json")["name"] == "Game"

    @pytest.mark.parametrize("dirname", ["my-game.v2", "1game", "_hidden", "a b"])
    def test_name_made_a_valid_c_identifier(self, tmp_path, dirname):
        asi_patcher.cmd_init(tmp_path / dirname)
        name = asi_patcher._load_spec(tmp_path / dirname / "spec.json")["name"]
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)

    def test_unnamed_directory_still_gets_a_valid_name(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        asi_patcher.cmd_init(Path("."))
        name = asi_patcher._load_spec(tmp_path / "spec.json")["name"]
        assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)

    def test_existing_spec_never_overwritten(self, tmp_path):
        target = tmp_path / "game"
        target.mkdir()
        (target / "spec.json").write_text("mine", encoding="utf-8")
        with pytest.raises(SystemExit, match="already exists"):
            asi_patcher.cmd_init(target)
        assert (target / "spec.json").read_text(encoding="utf-8") == "mine"

    def test_existing_empty_directory_is_fine(self, tmp_path):
        target = tmp_path / "game"
        target.mkdir()
        asi_patcher.cmd_init(target)
        assert (target / "spec.json").exists()


# -- CLI -------------------------------------------------------------------


def _main(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["asi_patcher.py", *argv])
    asi_patcher.main()


class TestCli:
    def test_no_command_prints_help_and_exits_1(self, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            _main(monkeypatch)
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "Declarative ASI patch builder." in out
        assert "{build,show,init}" in out

    def test_build_requires_vcvarsall(self, monkeypatch, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            _main(monkeypatch, "build", str(tmp_path / "spec.json"))
        assert exc.value.code == 2
        assert "--vcvarsall" in capsys.readouterr().err

    def test_build_dispatch(self, monkeypatch, tmp_path):
        out, spec_path, fake = _build(monkeypatch, tmp_path, _spec())
        _main(monkeypatch, "build", str(spec_path), "--vcvarsall", str(VCVARS))
        assert fake.calls[0][0].startswith(f'call "{VCVARS}" x86')
        assert (out / "patch.c").exists()

    def test_show_dispatch(self, monkeypatch, tmp_path, capsys):
        spec_path = _write_spec(tmp_path, _spec(name="CliShow"))
        _main(monkeypatch, "show", str(spec_path))
        assert capsys.readouterr().out.startswith("/* Auto-generated ASI patch: CliShow  (x86) */\n")

    def test_init_dispatch(self, monkeypatch, tmp_path):
        _main(monkeypatch, "init", str(tmp_path / "CliInit"))
        assert json.loads((tmp_path / "CliInit" / "spec.json").read_text())["name"] == "CliInit"

    def test_build_help_explains_vcvarsall(self, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            _main(monkeypatch, "build", "--help")
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "vswhere -latest -property installationPath" in out
        assert "--vcvarsall PATH" in out


class TestScriptEntryPoint:
    """The documented command lines: python retools/asi_patcher.py show|init ..."""

    def _run(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "retools" / "asi_patcher.py"), *args],
                              capture_output=True, text=True, timeout=60)

    def test_show_command_line(self, tmp_path):
        spec_path = _write_spec(tmp_path, _spec(name="Script"))
        r = self._run("show", str(spec_path))
        assert r.returncode == 0
        assert r.stdout.startswith("/* Auto-generated ASI patch: Script  (x86) */")

    def test_init_command_line(self, tmp_path):
        r = self._run("init", str(tmp_path / "Scripted"))
        assert r.returncode == 0
        assert (tmp_path / "Scripted" / "spec.json").exists()
