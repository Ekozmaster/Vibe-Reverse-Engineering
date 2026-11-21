"""Tests for retools/cfg.py -- basic-block decomposition, control-flow edges and their text/mermaid output."""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import cfg  # noqa: E402
from common import Binary  # noqa: E402
from pe_fakes import IMAGE_BASE, IMAGE_BASE64, TEXT_RVA, pe_image  # noqa: E402

F = IMAGE_BASE + TEXT_RVA

# The 16 short Jcc opcodes 0x70-0x7F and the Intel mnemonic of each.
JCC = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"]

# test eax,eax / je +3 / inc eax / jmp +1 / dec eax / ret: an if/else diamond.
DIAMOND = bytes.fromhex("85c0" "7403" "40" "eb01" "48" "c3")


def _cfg(tmp_path, code: bytes, data: bytes = b"\x11" * 0x200, **kw):
    return cfg.build_cfg(Binary(str(pe_image(tmp_path / "a.exe", code, data))), F, **kw)


def _shape(blocks):
    return {va: [i.mnemonic for i in insns] for va, insns in blocks.items()}


class TestBlocksAndEdges:
    def test_diamond(self, tmp_path):
        blocks, edges = _cfg(tmp_path, DIAMOND)
        assert _shape(blocks) == {F: ["test", "je"], F + 4: ["inc", "jmp"], F + 7: ["dec"], F + 8: ["ret"]}
        assert edges == [(F, F + 7, "je"), (F, F + 4, "fall"), (F + 4, F + 8, "jmp"), (F + 7, F + 8, "fall")]

    @pytest.mark.parametrize("k", range(16))
    def test_every_short_jcc_is_a_conditional_branch(self, tmp_path, k):
        # jcc +1 / inc eax / ret
        blocks, edges = _cfg(tmp_path, bytes([0x70 + k, 0x01, 0x40, 0xC3]))
        assert _shape(blocks) == {F: [JCC[k]], F + 2: ["inc"], F + 3: ["ret"]}
        assert edges == [(F, F + 3, JCC[k]), (F, F + 2, "fall"), (F + 2, F + 3, "fall")]

    @pytest.mark.parametrize("opcode, mnemonic, is_64", [
        ("e0", "loopne", False), ("e1", "loope", False), ("e2", "loop", False),
        ("e3", "jecxz", False), ("67e3", "jcxz", False), ("e3", "jrcxz", True),
    ])
    def test_loop_and_jump_if_counter_zero_are_conditional_branches(self, tmp_path, opcode, mnemonic, is_64):
        # <branch> +1 / nop / ret
        code = bytes.fromhex(opcode + "01" + "90" + "c3")
        b = Binary(str(pe_image(tmp_path / "a.exe", code, is_64=is_64)))
        start = (IMAGE_BASE64 if is_64 else IMAGE_BASE) + TEXT_RVA
        size = len(opcode) // 2 + 1
        blocks, edges = cfg.build_cfg(b, start)
        assert _shape(blocks) == {start: [mnemonic], start + size: ["nop"], start + size + 1: ["ret"]}
        assert edges == [(start, start + size + 1, mnemonic), (start, start + size, "fall"),
                         (start + size, start + size + 1, "fall")]

    def test_near_jcc_is_a_conditional_branch(self, tmp_path):
        # jg rel32 +1 / inc eax / ret
        blocks, edges = _cfg(tmp_path, b"\x0F\x8F" + struct.pack("<i", 1) + b"\x40\xC3")
        assert _shape(blocks) == {F: ["jg"], F + 6: ["inc"], F + 7: ["ret"]}
        assert edges == [(F, F + 7, "jg"), (F, F + 6, "fall"), (F + 6, F + 7, "fall")]

    def test_instruction_after_jmp_is_a_leader(self, tmp_path):
        # jmp +1 / inc eax / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("eb01" "40" "c3"))
        assert _shape(blocks) == {F: ["jmp"], F + 2: ["inc"], F + 3: ["ret"]}
        assert edges == [(F, F + 3, "jmp"), (F + 2, F + 3, "fall")]

    def test_ret_ends_a_block_without_a_fall_through(self, tmp_path):
        # je +2 / ret / inc eax (unreachable, no leader) / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7402" "c3" "40" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"], F + 4: ["ret"]}
        assert edges == [(F, F + 4, "je"), (F, F + 2, "fall")]

    def test_ret_imm16_ends_a_block_without_a_fall_through(self, tmp_path):
        # je +3 / ret 4 / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7403" "c20400" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"], F + 5: ["ret"]}
        assert edges == [(F, F + 5, "je"), (F, F + 2, "fall")]

    def test_blocks_after_a_ret_block_still_get_edges(self, tmp_path):
        # je +1 / ret / jne -3 (to the ret) / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7401" "c3" "75fd" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"], F + 3: ["jne"], F + 5: ["ret"]}
        assert edges == [(F, F + 3, "je"), (F, F + 2, "fall"), (F + 3, F + 2, "jne"), (F + 3, F + 5, "fall")]

    def test_leaders_after_a_jmp_are_still_collected(self, tmp_path):
        # jmp +0 / inc eax / je +1 / inc eax / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("eb00" "40" "7401" "40" "c3"))
        assert _shape(blocks) == {F: ["jmp"], F + 2: ["inc", "je"], F + 5: ["inc"], F + 6: ["ret"]}
        assert edges == [(F, F + 2, "jmp"), (F + 2, F + 6, "je"), (F + 2, F + 5, "fall"), (F + 5, F + 6, "fall")]

    def test_call_does_not_split_a_block(self, tmp_path):
        # call F+0x10 / ret
        blocks, edges = _cfg(tmp_path, b"\xE8" + struct.pack("<i", 0x10 - 5) + b"\xC3")
        assert _shape(blocks) == {F: ["call", "ret"]}
        assert edges == []

    def test_indirect_jmp_has_no_edge(self, tmp_path):
        # jmp eax / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("ffe0" "c3"))
        assert _shape(blocks) == {F: ["jmp"], F + 2: ["ret"]}
        assert edges == []

    def test_indirect_memory_jmp_has_no_edge(self, tmp_path):
        # jmp dword ptr [0x402000] / ret
        blocks, edges = _cfg(tmp_path, b"\xFF\x25" + struct.pack("<I", IMAGE_BASE + 0x2000) + b"\xC3")
        assert _shape(blocks) == {F: ["jmp"], F + 6: ["ret"]}
        assert edges == []

    def test_branches_out_of_the_function_have_no_edge(self, tmp_path):
        # je +5 / jmp F+0x100 / ret ; then jne F+0x100 / ret would be past the end
        code = b"\x74\x05" + b"\xE9" + struct.pack("<i", 0x100 - 7) + b"\xC3"
        blocks, edges = _cfg(tmp_path, code)
        assert _shape(blocks) == {F: ["je"], F + 2: ["jmp"], F + 7: ["ret"]}
        assert edges == [(F, F + 7, "je"), (F, F + 2, "fall")]

    def test_conditional_out_of_the_function_keeps_its_fall_through(self, tmp_path):
        # test eax,eax / jne F+0x100 / ret
        code = b"\x85\xC0\x0F\x85" + struct.pack("<i", 0x100 - 8) + b"\xC3"
        blocks, edges = _cfg(tmp_path, code)
        assert _shape(blocks) == {F: ["test", "jne"], F + 8: ["ret"]}
        assert edges == [(F, F + 8, "fall")]

    def test_backward_branch_splits_its_target_block(self, tmp_path):
        # inc eax / dec ecx / jne -4 (to dec) / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("40" "49" "75fd" "c3"))
        assert _shape(blocks) == {F: ["inc"], F + 1: ["dec", "jne"], F + 4: ["ret"]}
        assert edges == [(F, F + 1, "fall"), (F + 1, F + 1, "jne"), (F + 1, F + 4, "fall")]

    def test_no_code_at_start_gives_empty_cfg(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", DIAMOND)))
        assert cfg.build_cfg(b, IMAGE_BASE + 0x5000) == ({}, [])

    def test_long_function_is_one_block(self, tmp_path):
        # 0x40 x inc eax / ret: well past a default 30-instruction disassembly
        blocks, edges = _cfg(tmp_path, b"\x40" * 0x40 + b"\xC3")
        assert list(blocks) == [F] and len(blocks[F]) == 0x41 and blocks[F][-1].mnemonic == "ret"
        assert edges == []

    def test_max_size_bounds_the_scan(self, tmp_path):
        # inc eax / je +2 / inc eax / inc eax / ret, cut after the je
        blocks, edges = _cfg(tmp_path, bytes.fromhex("40" "7402" "40" "40" "c3"), max_size=3)
        assert _shape(blocks) == {F: ["inc", "je"]}
        assert edges == []


class TestFunctionEnd:
    def test_ret_then_two_nops_ends_the_function(self, tmp_path):
        # je +3 / ret / nop / nop / ret: the je target lies past the end
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7403" "c3" "90" "90" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"]}
        assert edges == [(F, F + 2, "fall")]

    def test_ret_then_int3_ends_the_function(self, tmp_path):
        # je +2 / ret / int3 / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7402" "c3" "cc" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"]}
        assert edges == [(F, F + 2, "fall")]

    def test_ret_then_one_nop_and_code_continues(self, tmp_path):
        # je +2 / ret / nop / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7402" "c3" "90" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"], F + 4: ["ret"]}
        assert edges == [(F, F + 4, "je"), (F, F + 2, "fall")]

    def test_nop_count_restarts_at_each_ret(self, tmp_path):
        # je +4 / ret / nop / ret / nop / xor eax,eax / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7404" "c3" "90" "c3" "90" "31c0" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"], F + 6: ["xor", "ret"]}
        assert edges == [(F, F + 6, "je"), (F, F + 2, "fall")]

    def test_nops_after_code_after_ret_do_not_end_the_function(self, tmp_path):
        # je +5 / ret / xor eax,eax / nop / nop / inc eax / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7405" "c3" "31c0" "90" "90" "40" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"], F + 7: ["inc", "ret"]}
        assert edges == [(F, F + 7, "je"), (F, F + 2, "fall")]

    def test_end_is_found_at_a_later_ret(self, tmp_path):
        # je F+0x20 / ret / xor eax,eax / ret / int3 padding ... F+0x20: ret (past the end)
        code = bytes.fromhex("741e" "c3" "31c0" "c3").ljust(0x20, b"\xCC") + b"\xC3"
        blocks, edges = _cfg(tmp_path, code)
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"]}
        assert edges == [(F, F + 2, "fall")]

    @pytest.mark.parametrize("pad", ["cc", "9090"])
    def test_padding_after_ret_is_outside_the_function(self, tmp_path, pad):
        # je +1 (into the padding) / ret / padding
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7401" "c3" + pad))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"]}
        assert edges == [(F, F + 2, "fall")]

    def test_int3_ends_its_block_and_code_past_it_is_reached_only_by_a_branch(self, tmp_path):
        # je over / call noreturn / int3 / over: ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7406" "e820000000" "cc" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["call", "int3"], F + 8: ["ret"]}
        assert edges == [(F, F + 8, "je"), (F, F + 2, "fall")]

    def test_code_past_an_int3_that_no_branch_reaches_is_not_in_the_graph(self, tmp_path):
        # inc eax / int3 / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("40" "cc" "c3"))
        assert _shape(blocks) == {F: ["inc", "int3"]}
        assert edges == []

    def test_a_cold_call_after_the_last_ret_stops_at_its_int3(self, tmp_path):
        # je cold / ret / cold: call noreturn / int3 padding / the next function: xor eax,eax / ret
        blocks, edges = _cfg(tmp_path, bytes.fromhex("7401" "c3" "e820000000" "cccccccc" "31c0" "c3"))
        assert _shape(blocks) == {F: ["je"], F + 2: ["ret"], F + 3: ["call", "int3"]}
        assert edges == [(F, F + 3, "je"), (F, F + 2, "fall")]


def _run(monkeypatch, capsys, path, *argv):
    monkeypatch.setattr(sys, "argv", ["cfg.py", str(path), *argv])
    cfg.main()
    return capsys.readouterr().out.splitlines()


class TestCli:
    def test_text_output(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", DIAMOND), f"{F:X}")
        assert out == [
            f"Function 0x{F:08X}: 4 blocks, 4 edges",
            "",
            "",
            f"=== Block 0x{F:08X} (2 insns)  -> 0x{F + 7:08X} (je), 0x{F + 4:08X} (fall) ===",
            f"  0x{F:08X}: test     eax, eax",
            f"  0x{F + 2:08X}: je       0x{F + 7:x}",
            "",
            f"=== Block 0x{F + 4:08X} (2 insns)  -> 0x{F + 8:08X} (jmp) ===",
            f"  0x{F + 4:08X}: inc      eax",
            f"  0x{F + 5:08X}: jmp      0x{F + 8:x}",
            "",
            f"=== Block 0x{F + 7:08X} (1 insns)  -> 0x{F + 8:08X} (fall) ===",
            f"  0x{F + 7:08X}: dec      eax",
            "",
            f"=== Block 0x{F + 8:08X} (1 insns) ===",
            f"  0x{F + 8:08X}: ret      ",
        ]

    def test_mermaid_output(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", DIAMOND), f"{F:X}", "--format", "mermaid")
        assert out == [
            f"Function 0x{F:08X}: 4 blocks, 4 edges",
            "",
            "```mermaid",
            "graph TD",
            f'    B_{F:08X}["0x{F:08X}..0x{F + 2:08X} (2 insns)"]',
            f'    B_{F + 4:08X}["0x{F + 4:08X}..0x{F + 5:08X} (2 insns)"]',
            f'    B_{F + 7:08X}["0x{F + 7:08X}..0x{F + 7:08X} (1 insns)"]',
            f'    B_{F + 8:08X}["0x{F + 8:08X}..0x{F + 8:08X} (1 insns)"]',
            f'    B_{F:08X} -->|"je"| B_{F + 7:08X}',
            f'    B_{F:08X} -->|"fall"| B_{F + 4:08X}',
            f'    B_{F + 4:08X} -->|"jmp"| B_{F + 8:08X}',
            f'    B_{F + 7:08X} -->|"fall"| B_{F + 8:08X}',
            "```",
        ]

    def test_address_inside_a_function_resolves_to_its_start(self, tmp_path, monkeypatch, capsys):
        # DIAMOND at F, and a caller at F+0x40 that makes F a known entry point
        code = DIAMOND.ljust(0x40, b"\xCC") + b"\xE8" + struct.pack("<i", -0x45) + b"\xC3"
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", code), f"0x{F + 4:X}")
        assert out[0] == f"Function 0x{F:08X}: 4 blocks, 4 edges"

    def test_address_without_a_known_start_is_used_as_is(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", DIAMOND), f"{F + 4:X}")
        assert out[0] == f"Function 0x{F + 4:08X}: 3 blocks, 2 edges"

    def test_max_size_accepts_hex(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", DIAMOND), f"{F:X}", "--max-size", "0x4")
        assert out[0] == f"Function 0x{F:08X}: 1 blocks, 0 edges"

    def test_max_size_accepts_decimal(self, tmp_path, monkeypatch, capsys):
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", DIAMOND), f"{F:X}", "--max-size", "4")
        assert out[0] == f"Function 0x{F:08X}: 1 blocks, 0 edges"

    def test_max_size_defaults_to_0x4000(self, tmp_path, monkeypatch, capsys):
        seen = []
        monkeypatch.setattr(cfg, "build_cfg", lambda b, start, max_size: seen.append((start, max_size)) or ({}, []))
        out = _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", DIAMOND), f"{F:X}")
        assert seen == [(F, 0x4000)]
        assert out[0] == f"Function 0x{F:08X}: 0 blocks, 0 edges"

    def test_help_documents_the_defaults(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["cfg.py", "--help"])
        with pytest.raises(SystemExit):
            cfg.main()
        out = " ".join(capsys.readouterr().out.split())
        assert "(default: text)" in out and "(default: 0x4000)" in out

    def test_runs_as_a_script(self, tmp_path):
        path = pe_image(tmp_path / "a.exe", DIAMOND)
        res = subprocess.run([sys.executable, cfg.__file__, str(path), f"{F:X}"],
                             capture_output=True, text=True, check=True)
        assert res.stdout.splitlines()[0] == f"Function 0x{F:08X}: 4 blocks, 4 edges"

    def test_unknown_format_is_rejected(self, tmp_path, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            _run(monkeypatch, capsys, pe_image(tmp_path / "a.exe", DIAMOND), f"{F:X}", "--format", "dot")
        assert exc.value.code == 2
