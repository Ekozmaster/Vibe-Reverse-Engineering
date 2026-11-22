"""Tests for retools/throwmap.py -- _CxxThrowException call sites, their string arguments, and dump matching."""

import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import throwmap  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, TEXT_RVA, pe_image  # noqa: E402

TEXT = IMAGE_BASE + TEXT_RVA

# .data layout: import descriptor, ILT, IAT (malloc then _CxxThrowException), names, then the strings.
ILT, IAT, MALLOC_NAME, THROW_NAME, DLL_NAME = 0x40, 0x60, 0xA0, 0xB0, 0xD0
MSG1, MSG2, MSG3 = 0x100, 0x120, 0x140
STRINGS = {MSG1: b"bad allocation", MSG2: b"vector too long", MSG3: b"invalid map/set key"}

DATA_SECTION32 = 64 + 4 + 20 + 0xE0 + 40      # .data section header in a PE32 image
DATA_SECTION64 = 64 + 4 + 20 + 0xF0 + 40      # .data section header in a PE32+ image


def _imports_data(ptr: int, strings=STRINGS, throw_name=b"_CxxThrowException", data_rva=DATA_RVA) -> bytes:
    d = bytearray(0x200)
    struct.pack_into("<IIIII", d, 0, data_rva + ILT, 0, 0, data_rva + DLL_NAME, data_rva + IAT)
    fmt = "<Q" if ptr == 8 else "<I"
    for table in (ILT, IAT):
        struct.pack_into(fmt, d, table, data_rva + MALLOC_NAME)
        struct.pack_into(fmt, d, table + ptr, data_rva + THROW_NAME)
    d[MALLOC_NAME + 2:MALLOC_NAME + 8] = b"malloc"
    d[THROW_NAME + 2:THROW_NAME + 2 + len(throw_name)] = throw_name
    d[DLL_NAME:DLL_NAME + 10] = b"msvcrt.dll"
    for off, s in strings.items():
        d[off:off + len(s)] = s
    return bytes(d)


def _pe32_imports(path: Path, text: bytes, data_rva=DATA_RVA, **kw) -> Path:
    """A PE32 image importing malloc and _CxxThrowException, its .data at `data_rva`."""
    return pe_image(path, text, _imports_data(4, data_rva=data_rva, **kw), data_rva=data_rva,
                    import_dir=(data_rva, 40))


def _pe32_plus_imports(path: Path, text: bytes) -> Path:
    """A PE32+ image importing malloc and _CxxThrowException."""
    return pe_image(path, text, _imports_data(8), is_64=True, import_dir=(DATA_RVA, 40))


def _make_data_executable(path: Path, header: int, thunk: bytes, at=0x1F0) -> Path:
    """Mark .data executable and place `thunk` at .data+`at` (raw .data starts at file offset 0x400)."""
    image = bytearray(path.read_bytes())
    struct.pack_into("<I", image, header + 36, 0xE0000020)
    image[0x400 + at:0x400 + at + len(thunk)] = thunk
    path.write_bytes(image)
    return path


# --- x86 encodings -------------------------------------------------------------------------------
THROW_SLOT32 = IMAGE_BASE + DATA_RVA + IAT + 4
MALLOC_SLOT32 = IMAGE_BASE + DATA_RVA + IAT


def _va(off):
    return IMAGE_BASE + DATA_RVA + off


def _push(off):
    return b"\x68" + struct.pack("<I", _va(off))


def _call_iat(slot=THROW_SLOT32):
    return b"\xFF\x15" + struct.pack("<I", slot)


def _jmp_iat(slot=THROW_SLOT32):
    return b"\xFF\x25" + struct.pack("<I", slot)


def _rel32(at, target):
    return b"\xE8" + struct.pack("<i", target - (at + 5))


def _code(*parts) -> bytes:
    """NOP-filled .text with each (offset, bytes) placed."""
    code = bytearray(b"\x90" * 0x200)
    for off, b in parts:
        code[off:off + len(b)] = b
    return bytes(code)


def _x86_sample() -> bytes:
    """A direct IAT call, a call through the JMP [IAT] thunk, an unresolved site, and decoys."""
    return _code(
        (0x5B, _push(MSG1)), (0x60, _call_iat()),                       # direct: site 0x1060
        (0xBB, b"\xB9" + struct.pack("<I", _va(MSG2))), (0xC0, _rel32(0xC0, 0x1F0)),  # via thunk: 0x10C0
        (0x120, _call_iat()),                                           # nothing pushed: 0x1120
        (0x160, _push(MSG3)), (0x165, _call_iat(MALLOC_SLOT32)),        # another import: not a site
        (0x170, _rel32(0x170, 0x1E0)),                                  # call to a non-thunk: not a site
        (0x1E0, _jmp_iat(MALLOC_SLOT32)), (0x1F0, _jmp_iat()))


def _map(path):
    return throwmap.build_throw_map(str(path))[2]


class TestX86Sites:
    def test_direct_and_thunk_calls_with_their_strings(self, tmp_path):
        pe, is_64, tmap = throwmap.build_throw_map(str(_pe32_imports(tmp_path / "a.exe", _x86_sample())))
        assert is_64 is False
        assert tmap == {0x1060: (6, "bad allocation"), 0x10C0: (5, "vector too long"), 0x1120: (6, None)}

    def test_no_import_means_no_sites(self, tmp_path):
        assert _map(pe_image(tmp_path / "a.exe", _x86_sample())) == {}

    def test_import_name_with_a_decorated_prefix_matches(self, tmp_path):
        """The import is matched by substring, so `__CxxThrowException@8` style names count."""
        path = _pe32_imports(tmp_path / "a.exe", _x86_sample(), throw_name=b"__CxxThrowException@8")
        assert set(_map(path)) == {0x1060, 0x10C0, 0x1120}

    def test_other_import_is_not_a_throw_site(self, tmp_path):
        path = _pe32_imports(tmp_path / "a.exe", _x86_sample(), throw_name=b"_purecall")
        assert _map(path) == {}

    def test_thunk_is_the_jmp_to_the_throw_slot_not_the_first_jmp(self, tmp_path):
        code = _code((0x40, _rel32(0x40, 0x1D0)), (0xA0, _rel32(0xA0, 0x1E0)),
                     (0x1D0, _jmp_iat(MALLOC_SLOT32)), (0x1E0, _jmp_iat()))
        assert _map(_pe32_imports(tmp_path / "a.exe", code)) == {0x10A0: (5, None)}

    def test_every_call_to_the_thunk_is_a_site(self, tmp_path):
        code = _code((0x10, _rel32(0x10, 0x1F0)), (0x80, _rel32(0x80, 0x1F0)),
                     (0x100, _rel32(0x100, 0x1F0)), (0x1F0, _jmp_iat()))
        assert _map(_pe32_imports(tmp_path / "a.exe", code)) == {
            0x1010: (5, None), 0x1080: (5, None), 0x1100: (5, None)}

    def test_backward_and_forward_calls_to_the_thunk(self, tmp_path):
        code = _code((0x08, _jmp_iat()), (0x80, _rel32(0x80, 0x08)), (0x1F0, _rel32(0x1F0, 0x08)))
        assert set(_map(_pe32_imports(tmp_path / "a.exe", code))) == {0x1080, 0x11F0}

    def test_sites_ending_at_the_section_end(self, tmp_path):
        code = _code((0x08, _jmp_iat()), (0x1FB, _rel32(0x1FB, 0x08)))
        assert set(_map(_pe32_imports(tmp_path / "a.exe", code))) == {0x11FB}
        code = _code((0x1FA, _call_iat()))
        assert set(_map(_pe32_imports(tmp_path / "b.exe", code))) == {0x11FA}

    def test_a_thunk_ending_at_the_section_end(self, tmp_path):
        code = _code((0x80, _rel32(0x80, 0x1FA)), (0x1FA, _jmp_iat()))
        assert set(_map(_pe32_imports(tmp_path / "a.exe", code))) == {0x1080}

    def test_a_site_at_the_start_of_the_section(self, tmp_path):
        code = _code((0x00, _call_iat()), (0x80, _rel32(0x80, 0x1F0)), (0x1F0, _jmp_iat()))
        code2 = _code((0x00, _rel32(0x00, 0x1F0)), (0x1F0, _jmp_iat()))
        assert set(_map(_pe32_imports(tmp_path / "a.exe", code))) == {0x1000, 0x1080}
        assert set(_map(_pe32_imports(tmp_path / "b.exe", code2))) == {0x1000}

    def test_calls_in_a_non_executable_section_are_not_sites(self, tmp_path):
        path = _pe32_imports(tmp_path / "a.exe", _x86_sample())
        image = bytearray(path.read_bytes())
        image[0x400 + 0x1E0:0x400 + 0x1E6] = _call_iat()    # .data, past the strings
        path.write_bytes(image)
        assert set(_map(path)) == {0x1060, 0x10C0, 0x1120}

    def test_an_e8_byte_in_the_last_bytes_of_the_section_is_not_an_error(self, tmp_path):
        code = bytearray(_code((0x80, _rel32(0x80, 0x1F0)), (0x1F0, _jmp_iat())))
        code[0x1FF] = 0xE8
        assert set(_map(_pe32_imports(tmp_path / "a.exe", bytes(code)))) == {0x1080}

    def test_a_thunk_in_a_second_executable_section(self, tmp_path):
        path = _pe32_imports(tmp_path / "a.exe", _code((0x80, _rel32(0x80, DATA_RVA + 0x1F0 - TEXT_RVA))))
        _make_data_executable(path, DATA_SECTION32, _jmp_iat())
        assert set(_map(path)) == {0x1080}


class TestX86Strings:
    @pytest.mark.parametrize("opcode", [0x68, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF])
    def test_push_imm32_and_every_mov_r32_imm32(self, tmp_path, opcode):
        code = _code((0x5B, bytes([opcode]) + struct.pack("<I", _va(MSG1))), (0x60, _call_iat()))
        assert _map(_pe32_imports(tmp_path / "a.exe", code)) == {0x1060: (6, "bad allocation")}

    @pytest.mark.parametrize("opcode", [0x67, 0x69, 0xB7, 0xC0])
    def test_other_opcodes_do_not_load_the_string(self, tmp_path, opcode):
        code = _code((0x5B, bytes([opcode]) + struct.pack("<I", _va(MSG1))), (0x60, _call_iat()))
        assert _map(_pe32_imports(tmp_path / "a.exe", code)) == {0x1060: (6, None)}

    def test_a_push_of_a_non_string_or_an_rva_is_not_resolved(self, tmp_path):
        code = _code((0x50, b"\x68" + struct.pack("<I", DATA_RVA + MSG1)),      # an RVA, not a VA
                     (0x55, _push(0x1F0)),                                       # zero bytes
                     (0x5A, b"\x68" + struct.pack("<I", IMAGE_BASE + 0x9000)),         # outside every section
                     (0x60, _call_iat()))
        assert _map(_pe32_imports(tmp_path / "a.exe", code)) == {0x1060: (6, None)}

    def test_window_is_80_bytes_before_the_call(self, tmp_path):
        inside = _code((0x80, _push(MSG1)), (0xD0, _call_iat()))
        outside = _code((0x7F, _push(MSG1)), (0xD0, _call_iat()))
        assert _map(_pe32_imports(tmp_path / "a.exe", inside)) == {0x10D0: (6, "bad allocation")}
        assert _map(_pe32_imports(tmp_path / "b.exe", outside)) == {0x10D0: (6, None)}

    def test_push_after_the_call_is_not_its_argument(self, tmp_path):
        code = _code((0x60, _call_iat()), (0x66, _push(MSG1)))
        assert _map(_pe32_imports(tmp_path / "a.exe", code)) == {0x1060: (6, None)}

    @pytest.mark.parametrize("opcode", [0x68, 0xB9])
    def test_strings_beyond_twice_the_image_base(self, tmp_path, opcode):
        """A large image: .data at RVA 0x400000, so its VAs are >= 2 * ImageBase."""
        high = 0x400000
        code = _code((0x5B, bytes([opcode]) + struct.pack("<I", IMAGE_BASE + high + MSG1)),
                     (0x60, _call_iat(IMAGE_BASE + high + IAT + 4)))
        assert _map(_pe32_imports(tmp_path / "a.exe", code, data_rva=high)) == {0x1060: (6, "bad allocation")}

    def test_resolver_window_parameter(self, tmp_path):
        import pefile
        pe = pefile.PE(str(_pe32_imports(tmp_path / "a.exe", _code((0x40, _push(MSG1)), (0xD0, _call_iat())))))
        assert throwmap._resolve_string_x86(pe, 0x10D0) is None
        assert throwmap._resolve_string_x86(pe, 0x10D0, search_back=0x90) == "bad allocation"


# --- x64 encodings -------------------------------------------------------------------------------
THROW_SLOT64 = DATA_RVA + IAT + 8
MALLOC_SLOT64 = DATA_RVA + IAT


def _rip(at, size, target):
    return struct.pack("<i", target - (TEXT_RVA + at + size))


def _call_iat64(at, slot=THROW_SLOT64):
    return b"\xFF\x15" + _rip(at, 6, slot)


def _jmp_iat64(at, slot=THROW_SLOT64):
    return b"\xFF\x25" + _rip(at, 6, slot)


def _lea(at, off, rex=0x48, modrm=0x0D):
    return bytes([rex, 0x8D, modrm]) + _rip(at, 7, DATA_RVA + off)


def _x64_sample() -> bytes:
    return _code(
        (0x59, _lea(0x59, MSG1)), (0x60, _call_iat64(0x60)),                     # direct: 0x1060
        (0xB9, _lea(0xB9, MSG2, rex=0x4C, modrm=0x05)), (0xC0, _rel32(0xC0, 0x1F0)),  # via thunk: 0x10C0
        (0x120, _call_iat64(0x120)),                                             # unresolved: 0x1120
        (0x160, _call_iat64(0x160, MALLOC_SLOT64)),                              # another import
        (0x170, _rel32(0x170, 0x1E0)),                                           # non-thunk call
        (0x1E0, _jmp_iat64(0x1E0, MALLOC_SLOT64)), (0x1F0, _jmp_iat64(0x1F0)))


class TestX64:
    def test_direct_and_thunk_calls_with_their_strings(self, tmp_path):
        pe, is_64, tmap = throwmap.build_throw_map(str(_pe32_plus_imports(tmp_path / "a.dll", _x64_sample())))
        assert is_64 is True
        assert tmap == {0x1060: (6, "bad allocation"), 0x10C0: (5, "vector too long"), 0x1120: (6, None)}

    @pytest.mark.parametrize("rex,modrm", [(0x48, 0x05), (0x48, 0x3D), (0x4C, 0x0D), (0x4C, 0x3D)])
    def test_lea_r64_rip_relative(self, tmp_path, rex, modrm):
        code = _code((0x59, _lea(0x59, MSG1, rex, modrm)), (0x60, _call_iat64(0x60)))
        assert _map(_pe32_plus_imports(tmp_path / "a.dll", code)) == {0x1060: (6, "bad allocation")}

    @pytest.mark.parametrize("rex,op,modrm", [
        (0x48, 0x8D, 0x45),     # lea rax, [rbp + disp8]: not RIP-relative
        (0x48, 0x8D, 0x85),     # lea rax, [rbp + disp32]
        (0x48, 0x8D, 0x04),     # SIB form
        (0x48, 0x8B, 0x05),     # mov rax, [rip + disp32]: not a LEA
        (0x49, 0x8D, 0x05),     # REX.B: not 48/4C
        (0x40, 0x8D, 0x05),
    ])
    def test_other_forms_do_not_load_the_string(self, tmp_path, rex, op, modrm):
        code = _code((0x59, bytes([rex, op, modrm]) + _rip(0x59, 7, DATA_RVA + MSG1)), (0x60, _call_iat64(0x60)))
        assert _map(_pe32_plus_imports(tmp_path / "a.dll", code)) == {0x1060: (6, None)}

    def test_window_is_80_bytes_before_the_call(self, tmp_path):
        inside = _code((0x80, _lea(0x80, MSG1)), (0xD0, _call_iat64(0xD0)))
        outside = _code((0x7F, _lea(0x7F, MSG1)), (0xD0, _call_iat64(0xD0)))
        assert _map(_pe32_plus_imports(tmp_path / "a.dll", inside)) == {0x10D0: (6, "bad allocation")}
        assert _map(_pe32_plus_imports(tmp_path / "b.dll", outside)) == {0x10D0: (6, None)}

    def test_thunk_is_the_jmp_to_the_throw_slot(self, tmp_path):
        code = _code((0x40, _rel32(0x40, 0x1D0)), (0xA0, _rel32(0xA0, 0x1E0)),
                     (0x1D0, _jmp_iat64(0x1D0, MALLOC_SLOT64)), (0x1E0, _jmp_iat64(0x1E0)))
        assert _map(_pe32_plus_imports(tmp_path / "a.dll", code)) == {0x10A0: (5, None)}

    def test_sites_and_thunk_at_the_section_edges(self, tmp_path):
        code = _code((0x00, _call_iat64(0x00)), (0x80, _rel32(0x80, 0x1FA)), (0x1FA, _jmp_iat64(0x1FA)))
        assert set(_map(_pe32_plus_imports(tmp_path / "a.dll", code))) == {0x1000, 0x1080}
        code = _code((0x00, _rel32(0x00, 0x08)), (0x08, _jmp_iat64(0x08)),
                     (0x1FB, _rel32(0x1FB, 0x08)))
        assert set(_map(_pe32_plus_imports(tmp_path / "b.dll", code))) == {0x1000, 0x11FB}
        code = _code((0x1FA, _call_iat64(0x1FA)))
        assert set(_map(_pe32_plus_imports(tmp_path / "c.dll", code))) == {0x11FA}

    def test_an_e8_byte_in_the_last_bytes_of_the_section_is_not_an_error(self, tmp_path):
        code = bytearray(_code((0x80, _rel32(0x80, 0x1F0)), (0x1F0, _jmp_iat64(0x1F0))))
        code[0x1FF] = 0xE8
        assert set(_map(_pe32_plus_imports(tmp_path / "a.dll", bytes(code)))) == {0x1080}

    def test_a_thunk_in_a_second_executable_section(self, tmp_path):
        path = _pe32_plus_imports(tmp_path / "a.dll", _code((0x80, _rel32(0x80, DATA_RVA + 0x1F0 - TEXT_RVA))))
        thunk = b"\xFF\x25" + struct.pack("<i", THROW_SLOT64 - (DATA_RVA + 0x1F0 + 6))
        _make_data_executable(path, DATA_SECTION64, thunk)
        assert set(_map(path)) == {0x1080}

    def test_resolver_window_parameter(self, tmp_path):
        import pefile
        pe = pefile.PE(str(_pe32_plus_imports(tmp_path / "a.dll", _code((0x40, _lea(0x40, MSG1)),
                                                                        (0xD0, _call_iat64(0xD0))))))
        assert throwmap._resolve_string_x64(pe, 0x10D0) is None
        assert throwmap._resolve_string_x64(pe, 0x10D0, search_back=0x90) == "bad allocation"


# --- list ----------------------------------------------------------------------------------------
def _run(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["throwmap.py", *argv])
    throwmap.main()
    return capsys.readouterr().out.splitlines()


class TestList:
    def test_x86_report(self, tmp_path, monkeypatch, capsys):
        path = _pe32_imports(tmp_path / "a.exe", _x86_sample())
        assert _run(monkeypatch, capsys, str(path), "list") == [
            f"Binary: {path} (x86)",
            "Throw sites: 3 total, 2 with resolved strings",
            "",
            '  0x001060 (ret 0x001066): "bad allocation"',
            '  0x0010C0 (ret 0x0010C5): "vector too long"',
            "  0x001120 (ret 0x001126): <string not resolved>",
        ]

    def test_x64_report(self, tmp_path, monkeypatch, capsys):
        path = _pe32_plus_imports(tmp_path / "a.dll", _x64_sample())
        out = _run(monkeypatch, capsys, str(path), "list")
        assert out[0] == f"Binary: {path} (x64)"
        assert out[1] == "Throw sites: 3 total, 2 with resolved strings"

    def test_long_string_is_cut_at_100_characters(self, tmp_path, monkeypatch, capsys):
        long_msg = bytes(range(0x41, 0x5B)) * 5                # 130 characters
        exact = b"x" * 100
        strings = {MSG1: long_msg, 0x188: exact}
        code = _code((0x5B, _push(MSG1)), (0x60, _call_iat()), (0xBB, _push(0x188)), (0xC0, _call_iat()))
        path = _pe32_imports(tmp_path / "a.exe", code, strings=strings)
        out = _run(monkeypatch, capsys, str(path), "list")
        assert out[3] == f'  0x001060 (ret 0x001066): "{long_msg[:100].decode()}..."'
        assert out[4] == f'  0x0010C0 (ret 0x0010C6): "{exact.decode()}"'

    def test_no_sites(self, tmp_path, monkeypatch, capsys):
        path = pe_image(tmp_path / "a.exe", _x86_sample())
        assert _run(monkeypatch, capsys, str(path), "list") == [
            f"Binary: {path} (x86)", "Throw sites: 0 total, 0 with resolved strings", ""]

    def test_a_subcommand_is_required(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["throwmap.py", str(tmp_path / "a.exe")])
        with pytest.raises(SystemExit) as e:
            throwmap.main()
        assert e.value.code == 2

    def test_match_requires_a_dump(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["throwmap.py", str(tmp_path / "a.exe"), "match"])
        with pytest.raises(SystemExit) as e:
            throwmap.main()
        assert e.value.code == 2


# --- match ---------------------------------------------------------------------------------------
RUNTIME = 0x10000000
SP = 0x0019F000


class _Reader:
    """Readable stack memory from SP; any chunk starting in `holes` raises like an unmapped read."""

    def __init__(self, mem: bytes, holes=()):
        self.mem, self.holes = mem, set(holes)

    def read(self, addr, size):
        if addr in self.holes or not SP <= addr < SP + len(self.mem):
            raise Exception("unreadable")
        return self.mem[addr - SP:addr - SP + size]


def _thread(tid, sp=SP, is_64=False):
    if sp is None:
        return SimpleNamespace(ThreadId=tid, ContextObject=None)
    ctx = SimpleNamespace(Rsp=sp) if is_64 else SimpleNamespace(Esp=sp)
    return SimpleNamespace(ThreadId=tid, ContextObject=ctx)


def _dump(threads, reader, modules, exc_tid=None):
    exc = None if exc_tid is None else SimpleNamespace(exception_records=[SimpleNamespace(ThreadId=exc_tid)])
    return SimpleNamespace(
        modules=SimpleNamespace(modules=[SimpleNamespace(name=n, baseaddress=b) for n, b in modules]),
        exception=exc, threads=SimpleNamespace(threads=threads), get_reader=lambda: reader)


def _match(monkeypatch, capsys, binary, dump):
    from minidump.minidumpfile import MinidumpFile
    seen = []
    monkeypatch.setattr(MinidumpFile, "parse", staticmethod(lambda p: seen.append(p) or dump))
    out = _run(monkeypatch, capsys, str(binary), "match", "--dump", "crash.dmp")
    assert seen == ["crash.dmp"]
    return out


def _stack(size, words, fmt="<I"):
    mem = bytearray(size)
    for off, val in words.items():
        struct.pack_into(fmt, mem, off, val)
    return bytes(mem)


class TestMatch:
    def test_return_addresses_on_the_stack_are_reported_exception_thread_first(self, tmp_path, monkeypatch,
                                                                               capsys):
        path = _pe32_imports(tmp_path / "Game.exe", _x86_sample())
        mem = _stack(0x10000, {0x08: RUNTIME + 0x1066, 0xFFC: RUNTIME + 0x10C5})
        dump = _dump([_thread(7), _thread(9)], _Reader(mem),
                     [(r"C:\Windows\ntdll.dll", 0x77000000), (r"C:\Games\GAME.EXE", RUNTIME)], exc_tid=9)
        out = _match(monkeypatch, capsys, path, dump)
        assert out == [
            f"Binary: {path} (x86)",
            "Throw sites: 3 total, 2 with resolved strings",
            "Dump: crash.dmp",
            "",
            f"Module base in dump: 0x{RUNTIME:016X}",
            "",
            "Matches (4):",
            "",
            "  Thread 9 [exception thread]",
            f"    Stack 0x{SP + 8:08X} = module+0x1066 (return from throw at +0x1060)",
            '    Message: "bad allocation"',
            "",
            "  Thread 9 [exception thread]",
            f"    Stack 0x{SP + 0xFFC:08X} = module+0x10C5 (return from throw at +0x10C0)",
            '    Message: "vector too long"',
            "",
            "  Thread 7",
            f"    Stack 0x{SP + 8:08X} = module+0x1066 (return from throw at +0x1060)",
            '    Message: "bad allocation"',
            "",
            "  Thread 7",
            f"    Stack 0x{SP + 0xFFC:08X} = module+0x10C5 (return from throw at +0x10C0)",
            '    Message: "vector too long"',
            "",
        ]

    def test_only_rebased_return_addresses_on_pointer_slots_match(self, tmp_path, monkeypatch, capsys):
        path = _pe32_imports(tmp_path / "game.exe", _x86_sample())
        mem = bytearray(_stack(0x10000, {
            0x10: IMAGE_BASE + 0x1066,              # preferred-base VA, not the runtime one
            0x14: RUNTIME + 0x1060,           # the call site itself, not its return address
            0x18: RUNTIME + 0x1126,           # unresolved site
            0x2000: RUNTIME + 0x10C5,         # a later chunk
            0xFFFC: RUNTIME + 0x1066,         # last slot scanned
        }))
        struct.pack_into("<I", mem, 0x22, RUNTIME + 0x1066)   # not on a 4-byte slot
        dump = _dump([_thread(3)], _Reader(bytes(mem)), [("/opt/game.exe", RUNTIME)])
        out = _match(monkeypatch, capsys, path, dump)
        stacks = [line for line in out if line.startswith("    Stack")]
        assert stacks == [
            f"    Stack 0x{SP + 0x18:08X} = module+0x1126 (return from throw at +0x1120)",
            f"    Stack 0x{SP + 0x2000:08X} = module+0x10C5 (return from throw at +0x10C0)",
            f"    Stack 0x{SP + 0xFFFC:08X} = module+0x1066 (return from throw at +0x1060)",
        ]
        assert '    Message: "<string not resolved>"' in out
        assert "  Thread 3" in out

    def test_unreadable_chunks_are_skipped(self, tmp_path, monkeypatch, capsys):
        path = _pe32_imports(tmp_path / "game.exe", _x86_sample())
        mem = _stack(0x10000, {0x04: RUNTIME + 0x1066, 0x1004: RUNTIME + 0x1066, 0x3004: RUNTIME + 0x10C5})
        dump = _dump([_thread(3)], _Reader(mem, holes={SP, SP + 0x2000}), [("game.exe", RUNTIME)])
        out = _match(monkeypatch, capsys, path, dump)
        assert [line for line in out if line.startswith("    Stack")] == [
            f"    Stack 0x{SP + 0x1004:08X} = module+0x1066 (return from throw at +0x1060)",
            f"    Stack 0x{SP + 0x3004:08X} = module+0x10C5 (return from throw at +0x10C0)",
        ]

    def test_exception_thread_is_scanned_first_then_the_rest_in_dump_order(self, tmp_path, monkeypatch, capsys):
        path = _pe32_imports(tmp_path / "game.exe", _x86_sample())
        mem = _stack(0x10000, {0x04: RUNTIME + 0x1066})
        dump = _dump([_thread(1), _thread(2), _thread(3)], _Reader(mem), [("game.exe", RUNTIME)], exc_tid=3)
        out = _match(monkeypatch, capsys, path, dump)
        assert [line for line in out if line.startswith("  Thread")] == [
            "  Thread 3 [exception thread]", "  Thread 1", "  Thread 2"]

    def test_missing_minidump_package_exits_with_the_install_hint(self, tmp_path, monkeypatch):
        path = _pe32_imports(tmp_path / "game.exe", _x86_sample())
        monkeypatch.setitem(sys.modules, "minidump.minidumpfile", None)
        monkeypatch.setattr(sys, "argv", ["throwmap.py", str(path), "match", "--dump", "crash.dmp"])
        with pytest.raises(SystemExit) as e:
            throwmap.main()
        assert e.value.code == "minidump not installed. Run: pip install minidump"

    def test_threads_without_a_context_are_skipped(self, tmp_path, monkeypatch, capsys):
        path = _pe32_imports(tmp_path / "game.exe", _x86_sample())
        mem = _stack(0x10000, {0x04: RUNTIME + 0x1066})
        dump = _dump([_thread(1, sp=None), _thread(2)], _Reader(mem), [("game.exe", RUNTIME)], exc_tid=1)
        out = _match(monkeypatch, capsys, path, dump)
        assert out[out.index("Matches (1):") + 2] == "  Thread 2"

    def test_no_matches(self, tmp_path, monkeypatch, capsys):
        path = _pe32_imports(tmp_path / "game.exe", _x86_sample())
        dump = _dump([_thread(3)], _Reader(bytes(0x10000)), [("game.exe", RUNTIME)])
        out = _match(monkeypatch, capsys, path, dump)
        assert out[-2:] == ["", "No throw-site return addresses found on any thread's stack."]

    def test_module_missing_from_the_dump(self, tmp_path, monkeypatch, capsys):
        path = _pe32_imports(tmp_path / "Game.exe", _x86_sample())
        dump = _dump([_thread(3)], _Reader(bytes(0x10000)),
                     [(r"C:\Windows\System32\ntdll.dll", 0x77000000), ("/usr/lib/other.exe", 0x400000)])
        out = _match(monkeypatch, capsys, path, dump)
        assert out[4:] == [
            "[error] Module 'game.exe' not found in dump.",
            "Loaded modules:",
            "  0x0000000077000000  ntdll.dll",
            "  0x0000000000400000  other.exe",
        ]

    def test_x64_stack_uses_rsp_and_8_byte_slots(self, tmp_path, monkeypatch, capsys):
        path = _pe32_plus_imports(tmp_path / "game.dll", _x64_sample())
        base = 0x7FF600000000
        mem = bytearray(_stack(0x10000, {0x10: base + 0x1066, 0x1FF8: base + 0x10C5}, fmt="<Q"))
        struct.pack_into("<Q", mem, 0x24, base + 0x1066)      # not on an 8-byte slot
        dump = _dump([_thread(5, is_64=True)], _Reader(bytes(mem)), [("game.dll", base)], exc_tid=5)
        out = _match(monkeypatch, capsys, path, dump)
        assert out[0] == f"Binary: {path} (x64)"
        assert f"Module base in dump: 0x{base:016X}" in out
        assert [line for line in out if line.startswith("    Stack")] == [
            f"    Stack 0x{SP + 0x10:016X} = module+0x1066 (return from throw at +0x1060)",
            f"    Stack 0x{SP + 0x1FF8:016X} = module+0x10C5 (return from throw at +0x10C0)",
        ]
        assert "  Thread 5 [exception thread]" in out
