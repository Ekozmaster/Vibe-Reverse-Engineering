"""kb-apply against a real Ghidra: what a project holds after a kb.h was applied to it.

One small system DLL is analysed into a temporary project (about 15 seconds).
Skipped without pyghidra, a Ghidra install, Java, or the 32-bit system DLL.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pefile
import pytest

import verify_install

_BINARY = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SysWOW64" / "msimg32.dll"
_DRIVER = Path(__file__).resolve().parent / "ghidra_kb_apply.py"


def _exports(binary: Path) -> dict[str, int]:
    pe = pefile.PE(str(binary), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    return {symbol.name.decode(): pe.OPTIONAL_HEADER.ImageBase + symbol.address
            for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name and not symbol.forwarder}


@pytest.fixture(scope="module")
def addresses():
    if not _BINARY.is_file():
        pytest.skip(f"{_BINARY} not present")
    return _exports(_BINARY)


@pytest.fixture(scope="module")
def report(addresses, tmp_path_factory):
    """The driver's report for a kb.h with types, prototypes, a name and a global."""
    pytest.importorskip("pyghidra")
    if verify_install.find_java() is None or verify_install._find_ghidra_dir() is None:
        pytest.skip("needs Java and a Ghidra install (python verify_install.py --setup)")

    folder = tmp_path_factory.mktemp("kb_apply")
    kb = folder / "kb.h"
    kb.write_text("\n".join([
        "struct KbVertex {",
        "    int x;",
        "    int y;",
        "    unsigned short red;",
        "};",
        "enum KbMode { KB_MODE_H = 0, KB_MODE_V = 1 };",
        "typedef struct KbVertex KbVertexAlias;",
        f"@ {addresses['GradientFill']:#x} int __stdcall KbGradientFill(void* dc, KbVertex* vertices, unsigned long count, KbMode mode);",
        f"@ {addresses['TransparentBlt']:#x} int KbTransparentBlt(void* dst, int x, int y);",
        f"@ {addresses['DllInitialize']:#x} KbDllInitialize;",
        f"@ {addresses['AlphaBlend']:#x} int KbAlphaBlend(NoSuchType thing);",
        f"$ {addresses['AlphaBlend'] + 0x2000:#x} int g_kbFlag",
    ]) + "\n", encoding="utf-8")

    wanted = [addresses[name] for name in ("GradientFill", "TransparentBlt", "DllInitialize", "AlphaBlend")]
    done = subprocess.run(
        [sys.executable, str(_DRIVER), str(_BINARY), str(folder / "project"), str(kb), *(f"{va:#x}" for va in wanted)],
        capture_output=True, text=True, timeout=600)
    lines = [line for line in done.stdout.splitlines() if line.startswith("REPORT ")]
    assert done.returncode == 0 and lines, done.stdout[-2000:] + done.stderr[-4000:]
    return json.loads(lines[-1][len("REPORT "):])


def test_summary_counts_what_was_applied(report):
    assert report["summary"] == "kb-apply complete: functions=4, labels=0, globals=1, typedefs=3, prototypes=2, skipped=1"


def test_struct_enum_and_typedef_are_in_the_program(report):
    assert report["types"]["KbVertex"] == ["x", "y", "red"]
    assert report["types"]["KbMode"] == ["KB_MODE_H", "KB_MODE_V"]
    assert "KbVertexAlias" in report["types"]


def test_applying_the_same_kb_again_adds_nothing(report):
    assert report["summary_of_second_run"] == report["summary"]
    # Ghidra names a second, different definition of a type "<name>.conflict"
    assert not [name for name in report["types"] if "conflict" in name]


def test_prototype_with_a_calling_convention_is_applied(report, addresses):
    assert report["prototypes"][f"{addresses['GradientFill']:#x}"] == (
        "int __stdcall KbGradientFill(void * dc, KbVertex * vertices, ulong count, KbMode mode)")


def test_prototype_without_a_calling_convention_keeps_the_function_s_own(report, addresses):
    assert report["prototypes"][f"{addresses['TransparentBlt']:#x}"] == (
        "int __stdcall KbTransparentBlt(void * dst, int x, int y)")


def test_entry_that_is_only_a_name_renames_the_function(report, addresses):
    assert "KbDllInitialize(" in report["prototypes"][f"{addresses['DllInitialize']:#x}"]


def test_prototype_ghidra_cannot_parse_still_leaves_the_name(report, addresses):
    assert "KbAlphaBlend(" in report["prototypes"][f"{addresses['AlphaBlend']:#x}"]
    assert "NoSuchType" not in report["prototypes"][f"{addresses['AlphaBlend']:#x}"]


def test_decompiled_function_uses_the_prototype_and_the_struct(report, addresses):
    assert "KbGradientFill(void *dc,KbVertex *vertices,ulong count,KbMode mode)" in report["decompiled"][f"{addresses['GradientFill']:#x}"]
