"""Which addresses ``Binary`` takes as function starts, and which function it names for an address."""

import struct

from pe_fakes import CODE_VA, IMAGE_BASE, binary_from_sections, binary_over, fake_section

INT3 = bytes([0xCC])
RET = bytes([0xC3])


def _rel32(opcode: int, at: int, target: int) -> bytes:
    """``call`` (0xE8) or ``jmp`` (0xE9) from the address *at* to *target*."""
    return bytes([opcode]) + struct.pack("<i", target - (at + 5))


def _laid_out(first_va: int, pieces: dict[int, bytes]) -> bytes:
    """*pieces* ({address: bytes}) as one buffer from *first_va*, int3 between them."""
    end = max(va + len(code) for va, code in pieces.items())
    buffer = bytearray(INT3 * (end - first_va))
    for va, code in pieces.items():
        buffer[va - first_va: va - first_va + len(code)] = code
    return bytes(buffer)


class TestX86:
    def test_jump_target_in_the_middle_of_code_is_not_a_function_start(self):
        function, label, caller = CODE_VA, CODE_VA + 8, CODE_VA + 0x10
        b = binary_over(_laid_out(CODE_VA, {
            function: _rel32(0xE9, function, label) + bytes([0x33, 0xC0, 0x40]),   # jmp label; xor eax, eax; inc eax
            label: RET,
            caller: _rel32(0xE8, caller, function) + RET,
        }))

        assert b.func_table == [function]
        assert b.find_func_start(label) == function

    def test_jump_target_behind_padding_is_a_function_start(self):
        called, tail_called = CODE_VA + 0x10, CODE_VA + 0x20
        b = binary_over(_laid_out(CODE_VA, {
            CODE_VA: _rel32(0xE8, CODE_VA, called) + _rel32(0xE9, CODE_VA + 5, tail_called),
            called: RET,
            tail_called: RET,
        }))

        assert b.func_table == [called, tail_called]

    def test_jump_target_right_behind_a_return_is_a_function_start(self):
        called = CODE_VA + 0x10
        tail_called = called + 1
        b = binary_over(_laid_out(CODE_VA, {
            CODE_VA: _rel32(0xE8, CODE_VA, called) + _rel32(0xE9, CODE_VA + 5, tail_called),
            called: RET,
            tail_called: RET,
        }))

        assert b.func_table == [called, tail_called]


def _x64_binary():
    """An x64 image with three functions.

    ``framed`` and ``split`` have exception table entries; ``split`` has a second
    chunk further on, chained to its first. ``leaf`` has none and is known only as
    a call target. ``framed`` holds a jump to a label of its own that follows an int3.
    """
    text_rva, pdata_rva, xdata_rva = 0x1000, 0x2000, 0x3000
    framed, label, leaf, split, split_chunk = 0x1000, 0x100A, 0x1010, 0x1020, 0x1040
    enter, leave = bytes([0x48, 0x83, 0xEC, 0x28]), bytes([0x48, 0x83, 0xC4, 0x28])   # sub/add rsp, 0x28

    text = _laid_out(IMAGE_BASE + text_rva, {
        IMAGE_BASE + framed: enter + _rel32(0xE9, IMAGE_BASE + framed + 4, IMAGE_BASE + label) + INT3 + leave + RET,
        IMAGE_BASE + leaf: RET,
        IMAGE_BASE + split: enter + _rel32(0xE8, IMAGE_BASE + split + 4, IMAGE_BASE + leaf) + leave + RET,
        IMAGE_BASE + split_chunk: bytes([0x90, 0x90]) + RET,
    })

    plain_unwind = bytes([0x01, 0, 0, 0])                 # version 1, no flags, no unwind codes
    chained_unwind = bytes([0x21, 0, 0, 0])               # version 1, UNW_FLAG_CHAININFO
    split_entry = struct.pack("<III", split, split + 14, xdata_rva + 4)
    xdata = plain_unwind + plain_unwind + chained_unwind + split_entry
    pdata = (struct.pack("<III", framed, framed + 15, xdata_rva)
             + split_entry
             + struct.pack("<III", split_chunk, split_chunk + 3, xdata_rva + 8))

    sections = [
        fake_section(text_rva, len(text), 0, len(text), executable=True),
        fake_section(pdata_rva, len(pdata), len(text), len(pdata)),
        fake_section(xdata_rva, len(xdata), len(text) + len(pdata), len(xdata)),
    ]
    b = binary_from_sections(text + pdata + xdata, sections, is_64=True, exception_table=(pdata_rva, len(pdata)))
    addresses = {"framed": framed, "label": label, "leaf": leaf, "split": split, "split_chunk": split_chunk}
    return b, {name: IMAGE_BASE + rva for name, rva in addresses.items()}


class TestX64ExceptionTable:
    def test_function_starts_are_the_table_s_functions_and_call_targets_outside_them(self):
        b, at = _x64_binary()
        assert b.func_table == [at["framed"], at["leaf"], at["split"]]

    def test_address_inside_a_function_names_that_function(self):
        b, at = _x64_binary()
        assert b.find_func_start(at["label"]) == at["framed"]
        assert b.find_func_start(at["framed"] + 14) == at["framed"]

    def test_chunk_placed_away_from_its_function_names_the_function(self):
        b, at = _x64_binary()
        assert b.find_func_start(at["split_chunk"] + 1) == at["split"]

    def test_function_without_an_entry_is_found_from_the_call_to_it(self):
        b, at = _x64_binary()
        assert b.find_func_start(at["leaf"]) == at["leaf"]

    def test_address_between_functions_belongs_to_none(self):
        b, at = _x64_binary()
        assert b.find_func_start(at["split"] + 0x10) is None
