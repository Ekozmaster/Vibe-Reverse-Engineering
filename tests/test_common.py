"""Tests for retools/common.py -- Binary address translation, function table and operand analysis."""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs  # noqa: E402

from common import Binary  # noqa: E402
from pe_fakes import (DATA_RAW, DATA_RVA, IMAGE_BASE, IMAGE_BASE64, TEXT_RAW, TEXT_RVA,  # noqa: E402
                      binary_from_sections, binary_over, fake_section, pe_image)

def _insn(code_hex: str, mode=CS_MODE_32, address=0x1000):
    cs = Cs(CS_ARCH_X86, mode)
    cs.detail = True
    return list(cs.disasm(bytes.fromhex(code_hex), address))[-1]


def _binary_for(mode) -> Binary:
    b = object.__new__(Binary)
    b.is_64 = mode == CS_MODE_64
    return b


class TestAddressTranslation:
    def test_section_bounds_are_start_inclusive_end_exclusive(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\x90")))
        text, data = IMAGE_BASE + TEXT_RVA, IMAGE_BASE + DATA_RVA
        assert b.va_to_offset(text) == TEXT_RAW
        assert b.va_to_offset(text + 0x1FF) == TEXT_RAW + 0x1FF
        assert b.va_to_offset(data + 0x10) == DATA_RAW + 0x10
        assert b.va_to_offset(text - 1) is None
        assert b.va_to_offset(data + 0x200) is None
        assert b.offset_to_va(TEXT_RAW) == text
        assert b.offset_to_va(DATA_RAW + 0x1FF) == data + 0x1FF
        assert b.offset_to_va(TEXT_RAW - 1) is None
        assert b.offset_to_va(DATA_RAW + 0x200) is None

    def test_in_exec_covers_only_executable_sections(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\x90")))
        assert b.in_exec(IMAGE_BASE + TEXT_RVA) and b.in_exec(IMAGE_BASE + TEXT_RVA + 0x1FF)
        assert not b.in_exec(IMAGE_BASE + TEXT_RVA + 0x200)
        assert not b.in_exec(IMAGE_BASE + DATA_RVA)
        assert not b.in_exec(IMAGE_BASE + TEXT_RVA - 1)

    def test_reads(self, tmp_path):
        data = struct.pack("<I", 0x401234) + b"\xAB\xCD"
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\x90", data)))
        assert b.read_va(IMAGE_BASE + DATA_RVA + 4, 2) == b"\xAB\xCD"
        assert b.read_va(IMAGE_BASE + 0x9000, 4) == b""
        assert b.read_ptr(IMAGE_BASE + DATA_RVA) == 0x401234
        assert b.read_ptr(IMAGE_BASE + 0x9000) is None
        assert b.read_struct(IMAGE_BASE + DATA_RVA, "<I") == (0x401234,)

    def test_a_read_ends_at_the_sections_virtual_size_when_the_file_stores_more(self):
        stored = bytes(range(1, 9)) + b"\xEE" * 8                 # 8 bytes of section, 8 of file alignment
        b = binary_from_sections(stored, [fake_section(DATA_RVA, 8, 0, len(stored))])
        data = IMAGE_BASE + DATA_RVA
        assert b.read_va(data, 0x10) == bytes(range(1, 9))
        assert b.read_va(data + 6, 4) == b"\x07\x08"
        assert b.read_va(data + 2, 4) == b"\x03\x04\x05\x06"
        assert b.read_va(data + 8, 4) == b""
        assert b.va_to_offset(data + 8) is None

    def test_pe32_pointer_size(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\x90")))
        assert (b.is_64, b.ptr_size) == (False, 4)

    def test_pe32_plus_pointer_size(self, sample_binary):
        b = Binary(sample_binary)
        if b.pe.OPTIONAL_HEADER.Magic != 0x20B:
            pytest.skip("sample binary is not PE32+")
        assert (b.is_64, b.ptr_size) == (True, 8)


class TestFuncTable:
    def test_call_and_jmp_targets_inside_executable_code(self, tmp_path):
        text = IMAGE_BASE + TEXT_RVA
        code = bytearray(b"\x90" * 0x40)
        code[0:5] = b"\xE8" + struct.pack("<i", 0x20 - 5)            # call text+0x20
        code[5:10] = b"\xE9" + struct.pack("<i", 0x30 - 10)          # jmp text+0x30
        code[10:15] = b"\xE8" + struct.pack("<i", 0x1000 - 15)       # call into .data: not code
        b = Binary(str(pe_image(tmp_path / "a.exe", bytes(code))))
        table = b.func_table
        assert {text + 0x20, text + 0x30} <= set(table)
        assert IMAGE_BASE + DATA_RVA not in table
        assert table == sorted(table)

    def test_a_backward_call_target_counts(self, tmp_path):
        code = bytearray(b"\x90" * 0x40)
        code[0x30:0x35] = b"\xE8" + struct.pack("<i", 0x10 - 0x35)   # call text+0x10 from text+0x30
        b = Binary(str(pe_image(tmp_path / "a.exe", bytes(code))))
        assert IMAGE_BASE + TEXT_RVA + 0x10 in b.func_table

    def test_every_export_is_an_entry(self, sample_binary):
        b = Binary(sample_binary)
        exports = {b.base + e.address for e in b.pe.DIRECTORY_ENTRY_EXPORT.symbols if e.address}
        assert len(exports) > 1
        assert exports <= set(b.func_table)

    def test_find_func_start(self, tmp_path):
        text = IMAGE_BASE + TEXT_RVA
        code = bytearray(b"\x90" * 0x40)
        code[0:5] = b"\xE8" + struct.pack("<i", 0x20 - 5)
        code[5:10] = b"\xE8" + struct.pack("<i", 0x30 - 10)
        b = Binary(str(pe_image(tmp_path / "a.exe", bytes(code))))
        first = b.func_table[0]
        assert b.find_func_start(text + 0x20) == text + 0x20
        assert b.find_func_start(text + 0x2F) == text + 0x20
        assert b.find_func_start(text + 0x35) == text + 0x30
        assert b.find_func_start(first - 1) is None


class TestJumpTableVas:
    def test_tables_of_jumps_indexed_by_pointer_size_in_address_order(self):
        code = (b"\xFF\x24\xBD" + struct.pack("<I", 0x402010)      # jmp [edi*4 + 0x402010]
                + b"\xFF\x24\x85" + struct.pack("<I", 0x402000)    # jmp [eax*4 + 0x402000]
                + b"\xFF\x24\x85" + struct.pack("<I", 0x402010)    # jmp [eax*4 + 0x402010]
                + b"\xFF\x24\xC5" + struct.pack("<I", 0x402020)    # jmp [eax*8 + 0x402020]
                + b"\xFF\x14\x85" + struct.pack("<I", 0x402030)    # call [eax*4 + 0x402030]
                + b"\xFF\xA4\x83" + struct.pack("<I", 0x402040))   # jmp [ebx + eax*4 + 0x402040]
        assert binary_over(code).jump_table_vas == [0x402000, 0x402010]

    def test_a_table_in_the_upper_half_of_the_address_space_has_an_unsigned_address(self):
        code = b"\xFF\x24\x85" + struct.pack("<I", 0x80402000)     # jmp [eax*4 + 0x80402000]
        assert binary_over(code).jump_table_vas == [0x80402000]

    def test_x64_tables_are_not_looked_for(self):
        code = (b"\xFF\x24\xC5" + struct.pack("<I", 0x402000)          # jmp [rax*8 + 0x402000]
                + b"\x42\xFF\x24\xCD" + struct.pack("<I", 0x402040))   # jmp [r9*8 + 0x402040]
        section = fake_section(TEXT_RVA, len(code), 0, len(code), executable=True)
        b = binary_from_sections(code, [section], is_64=True)
        assert b.jump_table_vas == []


class TestInstructionPredicates:
    def test_classification(self):
        assert Binary.is_call(_insn("e800000000"))
        assert Binary.is_jump(_insn("eb00")) and Binary.is_jump(_insn("7400"))
        assert Binary.is_ret(_insn("c3")) and Binary.is_ret(_insn("c20400"))
        assert Binary.is_nop(_insn("90")) and not Binary.is_nop(_insn("c3"))

    def test_call_target(self):
        assert Binary.call_target(_insn("e8fb0f0000", address=0x1000)) == 0x2000
        assert Binary.call_target(_insn("ff5004")) == "dword ptr [eax + 4]"
        assert Binary.call_target(_insn("c3")) is None


class TestMemOperands:
    def test_fields_and_plain_access(self):
        (op,) = Binary.mem_operands(_insn("8b4c8810"))              # mov ecx, [eax + ecx*4 + 0x10]
        assert (op.base, op.index, op.scale, op.disp, op.size, op.access) == ("eax", "ecx", 4, 0x10, 4, "r")
        assert Binary.mem_operands(_insn("894804"))[0].access == "w"   # mov [eax + 4], ecx
        assert Binary.mem_operands(_insn("830001"))[0].access == "rw"  # add dword ptr [eax], 1
        assert Binary.mem_operands(_insn("89c8")) == []                # mov eax, ecx

    @pytest.mark.parametrize("code", [
        "d918", "d910", "db18", "db10", "db08",       # fstp fst fistp fist fisttp
        "d938",                                       # fnstcw
        "0f1100", "0f2b00", "660f2b00", "0fc300",     # movups movntps movntpd movnti
        "660fd60424", "0f7f0424", "0f7e0424",         # movq from xmm0 and from mm0, movd from mm0
        "660f110424",                                 # movupd
        "0f130424", "660f130424", "0f170424", "660f170424",       # movlps movlpd movhps movhpd
        "660fe70424", "0fe70424", "f20f2b0424", "f30f2b0424",     # movntdq movntq movntsd movntss
        "0fae1c24", "c5f8ae1c24",                     # stmxcsr vstmxcsr
        "0f900424", "0f910424", "0f920424", "0f930424", "0f960424", "0f970424", "0f980424",   # seto setno setb setae setbe seta sets
        "0f990424", "0f9a0424", "0f9b0424", "0f9c0424", "0f9d0424", "0f9e0424", "0f9f0424",   # setns setp setnp setl setge setle setg
        "660f3a14042400", "660f3a15042400", "660f3a16042400", "660f3a17042400",   # pextrb pextrw pextrd extractps
        "c4e37914042400", "c4e37915042400", "c4e37916042400", "c4e3f916042400",   # vpextrb vpextrw vpextrd vpextrq
        "c4e37917042400", "c4e37d19042400", "c4e37d39042400", "c4e3791d042400",   # vextractps vextractf128 vextracti128 vcvtps2ph
        "c5f8290424", "c5f9290424", "c5f8110424", "c5f9110424",   # vmovaps vmovapd vmovups vmovupd
        "c5fa110424", "c5fb110424", "c5f97e0424", "c5f9d60424",   # vmovss vmovsd vmovd vmovq
        "c5f97f0424", "c5fe7f0424",                               # vmovdqa vmovdqu
        "c5f8130424", "c5f9130424", "c5f8170424", "c5f9170424",   # vmovlps vmovlpd vmovhps vmovhpd
        "c5f82b0424", "c5f92b0424", "c5f9e70424",                 # vmovntps vmovntpd vmovntdq
        "c4e2792e0424", "c4e2792f0424", "c4e2798e0424", "c4e2f98e0424",   # vmaskmovps vmaskmovpd vpmaskmovd vpmaskmovq
        "c5f8910424", "c5f9910424", "c4e1f9910424",   # kmovw kmovb kmovd
        "0f38f60424", "660f38f50424",                 # wrssd wrussd
        "6c", "666d", "6d",                           # insb insw insd
    ])
    def test_a_store_writes_its_memory_destination(self, code):
        """The ISA stores to operand 0; capstone reports these as reads."""
        assert Binary.mem_operands(_insn(code))[0].access == "w"

    @pytest.mark.parametrize("code", [
        "66480f3a16042400",                           # pextrq
        "c4e1f8910424",                               # kmovq
        "480f38f60424", "66480f38f50424",             # wrssq wrussq
    ])
    def test_a_64_bit_store_writes_its_memory_destination(self, code):
        assert Binary.mem_operands(_insn(code, CS_MODE_64))[0].access == "w"

    @pytest.mark.parametrize("code, mode", [
        ("0fb00424", CS_MODE_32), ("0fb10c24", CS_MODE_32),       # cmpxchg byte and dword
        ("0fc70c24", CS_MODE_32), ("480fc70c24", CS_MODE_64),     # cmpxchg8b cmpxchg16b
        ("c0042400", CS_MODE_32), ("c00c2400", CS_MODE_32),       # rol ror
        ("c0142400", CS_MODE_32), ("c01c2400", CS_MODE_32),       # rcl rcr
    ])
    def test_an_update_in_place_reads_and_writes_its_memory_operand(self, code, mode):
        """The ISA reads operand 0 and stores to it; capstone reports these as reads."""
        assert Binary.mem_operands(_insn(code, mode))[0].access == "rw"

    @pytest.mark.parametrize("code", [
        "0fa30424",         # bt [esp], eax
        "0fae1424",         # ldmxcsr [esp]
        "ff3424",           # push dword [esp]
        "660f6f0424",       # movdqa xmm0, [esp]
        "f30f7e0424",       # movq xmm0, [esp]
    ])
    def test_a_load_only_reads_its_memory_operand(self, code):
        assert Binary.mem_operands(_insn(code))[0].access == "r"


class TestReferenceExtraction:
    def test_absolute_memory_operands_only(self):
        b = _binary_for(CS_MODE_32)
        assert b.abs_mem_refs(_insn("a100007a00")) == [0x7A0000]          # mov eax, [0x7a0000]
        assert b.abs_mem_refs(_insn("8b8000007a00")) == []                # mov eax, [eax + 0x7a0000]
        assert b.abs_mem_refs(_insn("8b048500007a00")) == []              # mov eax, [eax*4 + 0x7a0000]
        assert b.abs_mem_refs(_insn("a1f0ffffff")) == [0xFFFFFFF0]        # 32-bit address, not -16
        assert b.abs_mem_refs(_insn("8b00")) == []

    def test_rip_relative_targets_on_64_bit_only(self):
        lea = _insn("488d0534120000", CS_MODE_64, address=0x140001000)    # lea rax, [rip + 0x1234]
        assert _binary_for(CS_MODE_64).rip_rel_refs(lea) == [0x140001000 + 7 + 0x1234]
        back = _insn("488d05f0ffffff", CS_MODE_64, address=0x140001000)   # lea rax, [rip - 0x10]
        assert _binary_for(CS_MODE_64).rip_rel_refs(back) == [0x140001000 + 7 - 0x10]
        assert _binary_for(CS_MODE_64).rip_rel_refs(_insn("488b4010", CS_MODE_64)) == []
        assert _binary_for(CS_MODE_64).rip_rel_refs(_insn("498d4110", CS_MODE_64)) == []  # lea rax, [r9 + 0x10]
        assert _binary_for(CS_MODE_32).rip_rel_refs(_insn("a100007a00")) == []

    def test_immediates_that_look_like_addresses(self):
        b = _binary_for(CS_MODE_32)
        assert b.abs_imm_refs(_insn("680c547c00")) == [0x7C540C]           # push 0x7c540c
        assert b.abs_imm_refs(_insn("b90c547c00")) == [0x7C540C]           # mov ecx, 0x7c540c
        assert b.abs_imm_refs(_insn("6800010000")) == []                   # push 0x10000
        assert b.abs_imm_refs(_insn("6801000100")) == [0x10001]
        assert b.abs_imm_refs(_insn("6aff")) == [0xFFFFFFFF]               # push -1, as a 32-bit value
        assert b.abs_imm_refs(_insn("8b00")) == []


class TestPe32Plus:
    TEXT64, DATA64 = IMAGE_BASE64 + TEXT_RVA, IMAGE_BASE64 + DATA_RVA
    CODE = bytes.fromhex(
        "488b0510000000"                                       # +0x00 mov rax, [rip + 0x10]
        + "48a1" + struct.pack("<Q", IMAGE_BASE64 + DATA_RVA).hex()  # +0x07 movabs rax, [0x140002000]
        + "8b0425f0ffffff"                                     # +0x11 mov eax, [-0x10] (disp32, sign-extended)
        + "48b8" + struct.pack("<Q", IMAGE_BASE64 + DATA_RVA).hex()  # +0x18 movabs rax, 0x140002000
        + "6aff"                                               # +0x22 push -1
        + "c3")                                                # +0x24 ret

    def test_builder_writes_a_well_formedpe_image(self, tmp_path, is_64=True):
        import pefile
        pe = pefile.PE(str(pe_image(tmp_path / "a.exe", b"\x90", is_64=True)))
        assert (pe.FILE_HEADER.Machine, pe.FILE_HEADER.SizeOfOptionalHeader) == (0x8664, 0xF0)
        assert (pe.OPTIONAL_HEADER.Magic, pe.OPTIONAL_HEADER.ImageBase) == (0x20B, IMAGE_BASE64)
        assert pe.OPTIONAL_HEADER.NumberOfRvaAndSizes == 16
        assert [(s.Name.rstrip(b"\0"), s.VirtualAddress, s.PointerToRawData) for s in pe.sections] == [
            (b".text", TEXT_RVA, TEXT_RAW), (b".data", DATA_RVA, DATA_RAW)]

    def test_pointer_size_and_base(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\x90", is_64=True)))
        assert (b.is_64, b.ptr_size, b.base) == (True, 8, IMAGE_BASE64)

    def test_address_translation_above_4_gb(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\x90", is_64=True)))
        assert b.va_to_offset(self.TEXT64) == TEXT_RAW
        assert b.va_to_offset(self.DATA64 + 0x1FF) == DATA_RAW + 0x1FF
        assert b.va_to_offset(self.TEXT64 & 0xFFFFFFFF) is None
        assert b.offset_to_va(DATA_RAW + 0x10) == self.DATA64 + 0x10
        assert b.in_exec(self.TEXT64) and not b.in_exec(self.DATA64)

    def test_read_ptr_is_a_little_endian_qword(self, tmp_path):
        data = struct.pack("<Q", 0x0123456789ABCDEF).ljust(0x1FC, b"\0") + b"\xAA" * 4
        b = Binary(str(pe_image(tmp_path / "a.exe", b"\x90", data, is_64=True)))
        assert b.read_ptr(self.DATA64) == 0x0123456789ABCDEF
        assert b.read_ptr(self.DATA64 + 0x1FC) is None          # only 4 bytes left in the file
        assert b.read_ptr(IMAGE_BASE64 + 0x9000) is None

    def test_disassembles_x64_code(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", self.CODE, is_64=True)))
        insns = b.disasm(self.TEXT64, count=6)
        assert [(i.address - self.TEXT64, i.mnemonic) for i in insns] == [
            (0x00, "mov"), (0x07, "movabs"), (0x11, "mov"), (0x18, "movabs"), (0x22, "push"), (0x24, "ret")]
        assert insns[0].op_str == "rax, qword ptr [rip + 0x10]"

    def test_references_are_64_bit_addresses(self, tmp_path):
        b = Binary(str(pe_image(tmp_path / "a.exe", self.CODE, is_64=True)))
        rip, moffs, neg, imm64, push = b.disasm(self.TEXT64, count=5)
        assert b.rip_rel_refs(rip) == [self.TEXT64 + 7 + 0x10]
        assert b.abs_mem_refs(rip) == []
        assert b.abs_mem_refs(moffs) == [self.DATA64]
        assert b.abs_mem_refs(neg) == [0xFFFFFFFFFFFFFFF0]
        assert b.rip_rel_refs(moffs) == []
        assert b.abs_imm_refs(imm64) == [self.DATA64]
        assert b.abs_imm_refs(push) == [0xFFFFFFFFFFFFFFFF]
        assert b.abs_imm_refs(moffs) == []
        assert b.abs_imm_refs(rip) == []                        # a memory operand is not an immediate

    def test_absolute_addresses_next_to_zero(self, tmp_path):
        code = bytes.fromhex("8b042501000000" + "8b0425ffffffff")  # mov eax, [1]; mov eax, [-1]
        b = Binary(str(pe_image(tmp_path / "a.exe", code, is_64=True)))
        one, minus_one = b.disasm(self.TEXT64, count=2)
        assert b.abs_mem_refs(one) == [1]
        assert b.abs_mem_refs(minus_one) == [0xFFFFFFFFFFFFFFFF]

    def test_an_immediate_is_not_rip_relative(self, tmp_path):
        from capstone.x86_const import X86_REG_RIP
        code = bytes.fromhex("48b8") + struct.pack("<Q", X86_REG_RIP << 32)  # movabs rax, imm64
        b = Binary(str(pe_image(tmp_path / "a.exe", code, is_64=True)))
        (movabs,) = b.disasm(self.TEXT64, count=1)
        assert b.rip_rel_refs(movabs) == []


class TestDisasmBatches:
    def test_a_batch_size_below_one_is_rejected_at_the_call(self):
        from common import disasm_batches
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        with pytest.raises(ValueError):
            disasm_batches(cs, b"\x90" * 4, 0x1000, 0)
