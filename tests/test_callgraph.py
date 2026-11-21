"""Tests for retools/callgraph.py -- caller/callee trees and the flat list."""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import callgraph  # noqa: E402
from common import Binary  # noqa: E402
from pe_fakes import IMAGE_BASE, TEXT_RVA, pe_image  # noqa: E402

D, A, B, C = (IMAGE_BASE + TEXT_RVA + off for off in (0x00, 0x10, 0x20, 0x30))


def _call(at: int, target: int) -> bytes:
    return b"\xE8" + struct.pack("<i", target - (at + 5))


def _image(tmp_path, cycle=False) -> Path:
    """D calls A; A calls B then C; B calls C (or, with cycle, B calls A back).

    Caller lookup resolves a call site to the nearest call target at or below it, so
    the one function nobody calls (D) sits first: its call site resolves to itself.
    """
    code = bytearray(b"\xCC" * 0x40)
    code[0x00:0x05] = _call(D, A)
    code[0x05] = 0xC3
    code[0x10:0x15] = _call(A, B)
    code[0x15:0x1A] = _call(A + 5, C)
    code[0x1A] = 0xC3
    code[0x20:0x25] = _call(B, A if cycle else C)
    code[0x25] = 0xC3
    code[0x30] = 0xC3
    return pe_image(tmp_path / "a.exe", bytes(code))


def _main(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["callgraph.py", *argv])
    callgraph.main()
    return capsys.readouterr().out.splitlines()


class TestTrees:
    def test_callees_one_and_two_levels_down(self, tmp_path):
        b = Binary(str(_image(tmp_path)))
        assert callgraph._find_callees(b, A) == ([B, C], [])
        tree = callgraph._build_tree(b, A, 2, "down", {}, set())
        assert [(n["va"], [g["va"] for g in n["children"]]) for n in tree["children"]] == [(B, [C]), (C, [])]
        leaf_depth = callgraph._build_tree(b, A, 1, "down", {}, set())
        assert [n["children"] for n in leaf_depth["children"]] == [[], []]

    def test_callers_are_the_calling_functions(self, tmp_path):
        b = Binary(str(_image(tmp_path)))
        assert callgraph._find_callers(b, C) == [A, B]
        assert callgraph._find_callers(b, A) == [D]
        assert callgraph._find_callers(b, D) == []

    def test_a_cycle_stops_at_the_function_already_on_the_path(self, tmp_path):
        b = Binary(str(_image(tmp_path, cycle=True)))
        tree = callgraph._build_tree(b, A, 10, "down", {}, set())
        b_node = next(n for n in tree["children"] if n["va"] == B)
        (a_again,) = b_node["children"]
        assert a_again == {"va": A, "children": [], "indirect": []}

class TestCli:
    def test_down_tree(self, tmp_path, monkeypatch, capsys):
        out = _main(monkeypatch, capsys, str(_image(tmp_path)), hex(A), "--down", "2")
        assert out == [f"0x{A:08X}  (2 children)", f"  +-0x{B:08X}", f"    +-0x{C:08X}", f"  +-0x{C:08X}"]

    def test_down_flat_leaves_out_the_target(self, tmp_path, monkeypatch, capsys):
        out = _main(monkeypatch, capsys, str(_image(tmp_path)), hex(A), "--down", "2", "--flat")
        assert out == [f"0x{B:08X}", f"0x{C:08X}", "", "2 unique callees"]

    def test_up_flat_from_a_function_entry(self, tmp_path, monkeypatch, capsys):
        out = _main(monkeypatch, capsys, str(_image(tmp_path)), hex(C), "--up", "2", "--flat")
        assert out == [f"0x{D:08X}", f"0x{A:08X}", f"0x{B:08X}", "", "3 unique callers"]

    def test_up_from_inside_a_function_walks_from_its_entry(self, tmp_path, monkeypatch, capsys):
        out = _main(monkeypatch, capsys, str(_image(tmp_path)), f"{B + 5:X}", "--up", "2", "--flat")
        assert out == [f"0x{D:08X}", f"0x{A:08X}", "", "2 unique callers"]

    def test_a_direction_is_required(self, tmp_path, monkeypatch, capsys):
        with pytest.raises(SystemExit):
            _main(monkeypatch, capsys, str(_image(tmp_path)), hex(A))
