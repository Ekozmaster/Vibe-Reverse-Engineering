"""Tests for retools/dumpinfo.py -- minidump analysis sub-commands over synthetic dumps.

Every dump here is built from the documented minidump layout (minidumpapiset.h / winnt.h): a 32-byte
MINIDUMP_HEADER, 12-byte MINIDUMP_DIRECTORY entries, MINIDUMP_THREAD (48 bytes), MINIDUMP_MODULE
(108 bytes), MINIDUMP_EXCEPTION_STREAM (168 bytes), MINIDUMP_MEMORY_LIST, MINIDUMP_SYSTEM_INFO
(56 bytes), the x86 CONTEXT (716 bytes) and the AMD64 CONTEXT (1232 bytes).
"""

import struct
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "retools"))

import dumpinfo  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, RDATA_CHARS, TEXT_RVA, pe_image, write_pe  # noqa: E402

THREAD_LIST, MODULE_LIST, MEMORY_LIST, EXCEPTION, SYSTEM_INFO = 3, 4, 5, 6, 7
X86, AMD64 = 0, 9
CXX = 0xE06D7363
AV = 0xC0000005

# x86 CONTEXT register offsets
X86_REGS = {"Edi": 156, "Esi": 160, "Ebx": 164, "Edx": 168, "Ecx": 172, "Eax": 176,
            "Ebp": 180, "Eip": 184, "Esp": 196}
# AMD64 CONTEXT register offsets
AMD64_REGS = {"Rax": 120, "Rcx": 128, "Rdx": 136, "Rbx": 144, "Rsp": 152, "Rbp": 160,
              "Rsi": 168, "Rdi": 176, "R8": 184, "R9": 192, "Rip": 248}


def _context(arch: int, regs: dict) -> bytes:
    if arch == X86:
        ctx = bytearray(716)
        struct.pack_into("<I", ctx, 0, 0x10007)
        for name, value in regs.items():
            struct.pack_into("<I", ctx, X86_REGS[name], value)
    else:
        ctx = bytearray(1232)
        struct.pack_into("<I", ctx, 48, 0x10000B)
        for name, value in regs.items():
            struct.pack_into("<Q", ctx, AMD64_REGS[name], value)
    return bytes(ctx)


def _minidump(path: Path, arch: int = X86, modules=(), threads=(), memory=(), exception=None) -> Path:
    """Write a minidump.

    Args:
        modules: (base, size, name) per module.
        threads: (thread_id, {register: value}) per thread.
        memory: (address, bytes) per MemoryListStream range.
        exception: dict(thread_id, code, address, params) for the ExceptionStream.
    """
    blob = bytearray()

    def put(data: bytes) -> int:
        while len(blob) % 8:
            blob.append(0)
        rva = len(blob)
        blob.extend(data)
        return rva

    streams = [SYSTEM_INFO]
    if threads:
        streams.append(THREAD_LIST)
    streams.append(MODULE_LIST)
    streams.append(MEMORY_LIST)
    if exception:
        streams.append(EXCEPTION)
    put(struct.pack("<IIIIIIQ", 0x504D444D, 0xA793, len(streams), 32, 0, 0, 0))
    dir_rva = put(bytes(12 * len(streams)))
    located = {}

    si = struct.pack("<HHHBBIIIIIHH", arch, 6, 0, 1, 1, 10, 0, 19041, 2, 0, 0, 0) + bytes(24)
    located[SYSTEM_INFO] = (len(si), put(si))

    contexts = {}
    if threads:
        entries = b""
        for tid, regs in threads:
            ctx = _context(arch, regs)
            ctx_rva = put(ctx)
            contexts[tid] = (len(ctx), ctx_rva)
            entries += struct.pack("<IIIIQ", tid, 0, 0, 0, 0) + struct.pack("<QII", 0, 0, 0) \
                + struct.pack("<II", len(ctx), ctx_rva)
        data = struct.pack("<I", len(threads)) + entries
        located[THREAD_LIST] = (len(data), put(data))

    entries = b""
    for base, size, name in modules:
        encoded = name.encode("utf-16-le")
        name_rva = put(struct.pack("<I", len(encoded)) + encoded + b"\0\0")
        entries += struct.pack("<QIIII", base, size, 0, 0, name_rva) + bytes(52) \
            + struct.pack("<IIIIQQ", 0, 0, 0, 0, 0, 0)
    data = struct.pack("<I", len(modules)) + entries
    located[MODULE_LIST] = (len(data), put(data))

    entries = b""
    for addr, content in memory:
        entries += struct.pack("<QII", addr, len(content), put(content))
    data = struct.pack("<I", len(memory)) + entries
    located[MEMORY_LIST] = (len(data), put(data))

    if exception:
        params = list(exception["params"])
        info = params + [0] * (15 - len(params))
        ctx_size, ctx_rva = contexts.get(exception["thread_id"], (0, 0))
        data = struct.pack("<II", exception["thread_id"], 0) \
            + struct.pack("<IIQQII", exception["code"], 0, 0, exception["address"], len(params), 0) \
            + struct.pack("<15Q", *info) + struct.pack("<II", ctx_size, ctx_rva)
        located[EXCEPTION] = (len(data), put(data))

    for i, stype in enumerate(streams):
        size, rva = located[stype]
        struct.pack_into("<III", blob, dir_rva + 12 * i, stype, size, rva)
    path.write_bytes(bytes(blob))
    return path


def _exception_record(tid: int, code: int, address: int, params) -> bytes:
    """One MINIDUMP_EXCEPTION_STREAM without a thread context."""
    info = list(params) + [0] * (15 - len(params))
    return struct.pack("<II", tid, 0) + struct.pack("<IIQQII", code, 0, 0, address, len(params), 0) \
        + struct.pack("<15Q", *info) + struct.pack("<II", 0, 0)


def _slots(fmt: str, *values) -> bytes:
    return b"".join(struct.pack(fmt, v) for v in values)


@pytest.fixture
def run(monkeypatch, capsys):
    """Run the command line on a dump and return stdout."""
    def _run(dump: Path, *args) -> str:
        monkeypatch.setattr(sys, "argv", ["dumpinfo", str(dump), *args])
        dumpinfo.main()
        return capsys.readouterr().out
    return _run


# ---------------------------------------------------------------- PE32+ with MSVC throw metadata

RDATA_RVA = 0x1000


def _rdata_image64(path: Path, rdata: bytes) -> Path:
    """A PE32+ image whose only section is .rdata at RDATA_RVA."""
    return write_pe(path, [(b".rdata", RDATA_RVA, rdata, RDATA_CHARS)], is_64=True)


TI_RVA = 0x1000


def _throw_rdata(*names: bytes) -> bytes:
    """x64 _ThrowInfo -> _CatchableTypeArray -> _CatchableType -> TypeDescriptor, all image-relative.

    _ThrowInfo {attributes, pmfnUnwind, pForwardCompat, pCatchableTypeArray} at RVA 0x1000,
    _CatchableTypeArray {nCatchableTypes, arrayOfCatchableTypes[]} at 0x1040,
    _CatchableType {properties, pType, PMD, sizeOrOffset, copyFunction} (28 bytes) at 0x1060 + 0x20*i,
    TypeDescriptor {pVFTable (8), spare (8), name[]} at 0x1100 + 0x40*i.
    """
    d = bytearray(0x200)
    struct.pack_into("<IIII", d, 0x00, 0, 0, 0, 0x1040)
    struct.pack_into("<I", d, 0x40, len(names))
    for i, name in enumerate(names):
        ct, td = 0x1060 + 0x20 * i, 0x1100 + 0x40 * i
        struct.pack_into("<I", d, 0x44 + 4 * i, ct)
        struct.pack_into("<IIiiiII", d, ct - RDATA_RVA, 1, td, 0, -1, 0, 8, 0)
        struct.pack_into("<QQ", d, td - RDATA_RVA, 0x7FF600001234, 0)
        d[td - RDATA_RVA + 16: td - RDATA_RVA + 16 + len(name) + 1] = name + b"\0"
    return bytes(d)


# ---------------------------------------------------------------- info


class TestInfo:
    def test_modules_sorted_by_base_with_short_names(self, tmp_path, run):
        dump = _minidump(tmp_path / "a.dmp", modules=[
            (0x77000000, 0x1A0000, r"C:\Windows\System32\ntdll.dll"),
            (0x400000, 0x3000, "/home/user/game.exe"),
        ])
        out = run(dump, "info")
        lines = out.splitlines()
        assert lines[0] == "Modules (2):"
        rows = [l for l in lines if l.startswith("  0x")]
        assert rows == [
            f"  0x{0x400000:016X}  {0x3000:10d}  game.exe",
            f"  0x{0x77000000:016X}  {0x1A0000:10d}  ntdll.dll",
        ]
        assert "Exception" not in out

    def test_exception_summary_resolves_to_module_offset(self, tmp_path, run):
        dump = _minidump(tmp_path / "a.dmp", modules=[(0x400000, 0x3000, r"C:\g\game.exe")],
                         threads=[(7, {"Eip": 0x401234})],
                         exception={"thread_id": 7, "code": AV, "address": 0x401234, "params": [0, 0]})
        assert "Exception: code=0xC0000005 at game.exe+0x1234 (thread 7)" in run(dump, "info")

    @pytest.mark.parametrize("address, where", [
        (0x400000, "game.exe+0x0"),
        (0x402FFF, "game.exe+0x2FFF"),
        (0x403000, "0x403000"),
        (0x3FFFFF, "0x3FFFFF"),
    ])
    def test_module_range_is_start_inclusive_end_exclusive(self, tmp_path, run, address, where):
        dump = _minidump(tmp_path / "a.dmp", modules=[(0x400000, 0x3000, r"C:\g\game.exe")],
                         exception={"thread_id": 1, "code": AV, "address": address, "params": []})
        assert f"code=0xC0000005 at {where} (thread 1)" in run(dump, "info")


# ---------------------------------------------------------------- threads


class TestThreads:
    def _dump(self, tmp_path, arch=X86, regs1=None, regs2=None):
        if arch == X86:
            regs1 = regs1 or {"Eip": 0x401010, "Esp": 0x12F000}
            regs2 = regs2 or {"Eip": 0x77001000, "Esp": 0x22F000}
        return _minidump(tmp_path / "t.dmp", arch=arch,
                         modules=[(0x400000, 0x3000, r"C:\g\game.exe"),
                                  (0x77000000, 0x10000, r"C:\w\ntdll.dll")],
                         threads=[(5, regs1), (9, regs2)],
                         exception={"thread_id": 9, "code": AV, "address": 0x77001000, "params": []})

    def test_table_resolves_ip_and_marks_the_exception_thread(self, tmp_path, run):
        lines = run(self._dump(tmp_path), "threads").splitlines()
        assert lines[2].split() == ["5", "game.exe+0x1010"]
        assert lines[3].split() == ["9", "ntdll.dll+0x1000", "<<", "EXCEPTION"]
        assert len(lines) == 4

    def test_verbose_x86_registers(self, tmp_path, run):
        regs = {"Eip": 0x401010, "Esp": 0x12F000, "Ebp": 0x12F040, "Eax": 0x11, "Ebx": 0x22,
                "Ecx": 0x33, "Edx": 0x44}
        out = run(self._dump(tmp_path, regs1=regs), "threads", "-v")
        assert "\nThread 5:\n" in out
        assert "Thread 9: << EXCEPTION" in out
        assert "  EIP = 0x00401010  (game.exe+0x1010)" in out
        assert "  ESP = 0x0012F000  EBP = 0x0012F040" in out
        assert "  EAX = 0x00000011  EBX = 0x00000022  ECX = 0x00000033  EDX = 0x00000044" in out
        assert "TID" not in out

    def test_verbose_amd64_registers(self, tmp_path, run):
        regs = {"Rip": 0x400020, "Rsp": 0x7FF0000, "Rbp": 0x7FF0100, "Rax": 1, "Rbx": 2, "Rcx": 3,
                "Rdx": 4, "Rsi": 5, "Rdi": 6, "R8": 7, "R9": 0x123456789}
        out = run(self._dump(tmp_path, AMD64, regs, {"Rip": 0x77001000}), "threads", "--verbose")
        assert "  RIP = 0x0000000000400020  (game.exe+0x20)" in out
        assert "  RSP = 0x0000000007FF0000  RBP = 0x0000000007FF0100" in out
        assert ("  RAX = 0x0000000000000001  RBX = 0x0000000000000002  "
                "RCX = 0x0000000000000003  RDX = 0x0000000000000004") in out
        assert ("  RSI = 0x0000000000000005  RDI = 0x0000000000000006  "
                "R8  = 0x0000000000000007  R9  = 0x0000000123456789") in out
        assert "EIP" not in out

    def test_amd64_table(self, tmp_path, run):
        out = run(self._dump(tmp_path, AMD64, {"Rip": 0x400020}, {"Rip": 0x77001000}), "threads")
        assert out.splitlines()[2].split() == ["5", "game.exe+0x20"]

    def test_no_thread_list(self, tmp_path, run):
        dump = _minidump(tmp_path / "a.dmp")
        assert run(dump, "threads").strip() == "No thread information."


# ---------------------------------------------------------------- stack


SP = 0x12F000
SP64 = 0x7FF0000


class TestStack:
    def _dump(self, tmp_path, stack: bytes, module_path=None, arch=X86, sp=SP):
        pe = module_path or str(pe_image(tmp_path / "game.exe", b"\x90"))
        reg = {"Esp": sp, "Eip": IMAGE_BASE + TEXT_RVA} if arch == X86 else {"Rsp": sp, "Rip": IMAGE_BASE + TEXT_RVA}
        return _minidump(tmp_path / "s.dmp", arch=arch, modules=[(IMAGE_BASE, 0x3000, pe)],
                         threads=[(5, reg)], memory=[(sp, stack)])

    def test_code_values_in_executable_sections_are_return_candidates(self, tmp_path, run):
        stack = _slots("<I", IMAGE_BASE + TEXT_RVA + 0x10, IMAGE_BASE + DATA_RVA + 4, 0x12345678, IMAGE_BASE + TEXT_RVA + 0x1FF)
        out = run(self._dump(tmp_path, stack), "stack", "5", "--depth", "4")
        lines = out.splitlines()
        assert lines[0] == f"Stack walk for thread 5 (SP=0x{SP:08X}):"
        assert lines[2:] == [
            f"  0x{SP:08X}: 0x{IMAGE_BASE + TEXT_RVA + 0x10:08X}  game.exe+0x1010 <-- RET",
            f"  0x{SP + 4:08X}: 0x{IMAGE_BASE + DATA_RVA + 4:08X}",
            f"  0x{SP + 8:08X}: 0x12345678",
            f"  0x{SP + 12:08X}: 0x{IMAGE_BASE + TEXT_RVA + 0x1FF:08X}  game.exe+0x11FF <-- RET",
        ]

    def test_executable_range_is_the_section_virtual_size(self, tmp_path, run):
        stack = _slots("<I", IMAGE_BASE + TEXT_RVA - 1, IMAGE_BASE + TEXT_RVA, IMAGE_BASE + TEXT_RVA + 0x200)
        lines = run(self._dump(tmp_path, stack), "stack", "5", "--depth", "3").splitlines()[2:]
        assert ["RET" in l for l in lines] == [False, True, False]

    def test_module_without_a_readable_pe_counts_whole_range_as_code(self, tmp_path, run):
        stack = _slots("<I", IMAGE_BASE + DATA_RVA + 4, IMAGE_BASE + 0x3000)
        out = run(self._dump(tmp_path, stack, module_path=str(tmp_path / "missing.exe")),
                  "stack", "5", "--depth", "2")
        lines = out.splitlines()[2:]
        assert lines == [f"  0x{SP:08X}: 0x{IMAGE_BASE + DATA_RVA + 4:08X}  missing.exe+0x2004 <-- RET",
                         f"  0x{SP + 4:08X}: 0x{IMAGE_BASE + 0x3000:08X}"]

    def test_default_depth_is_512_slots(self, tmp_path, run):
        out = run(self._dump(tmp_path, bytes(512 * 4)), "stack", "5")
        assert len([l for l in out.splitlines() if l.startswith("  0x")]) == 512

    def test_depth_limits_the_walk(self, tmp_path, run):
        out = run(self._dump(tmp_path, bytes(64)), "stack", "5", "--depth", "3")
        assert len([l for l in out.splitlines() if l.startswith("  0x")]) == 3

    def test_amd64_slots_are_eight_bytes(self, tmp_path, run):
        stack = _slots("<Q", IMAGE_BASE + TEXT_RVA + 8, 0x1122334455667788)
        out = run(self._dump(tmp_path, stack, arch=AMD64, sp=SP64), "stack", "5", "--depth", "2")
        lines = out.splitlines()
        assert lines[0] == f"Stack walk for thread 5 (SP=0x{SP64:016X}):"
        assert lines[2:] == [
            f"  0x{SP64:016X}: 0x{IMAGE_BASE + TEXT_RVA + 8:016X}  game.exe+0x1008 <-- RET",
            f"  0x{SP64 + 8:016X}: 0x1122334455667788",
        ]

    def test_stack_not_in_dump(self, tmp_path, run):
        dump = _minidump(tmp_path / "n.dmp", modules=[(IMAGE_BASE, 0x3000, "x.exe")],
                         threads=[(5, {"Esp": 0x900000})], memory=[(SP, bytes(16))])
        assert "(stack memory not available in dump)" in run(dump, "stack", "5", "--depth", "2")

    def test_unknown_thread(self, tmp_path, run):
        assert run(self._dump(tmp_path, bytes(16)), "stack", "99").strip() == "Thread 99 not found."


# ---------------------------------------------------------------- stackscan


class TestStackscan:
    def _dump(self, tmp_path, memory, arch=X86, sp=SP):
        reg = {"Esp": sp} if arch == X86 else {"Rsp": sp}
        return _minidump(tmp_path / "s.dmp", arch=arch, threads=[(5, reg)], memory=memory, modules=[
            (0x400000, 0x3000, r"C:\g\game.exe"),
            (0x10000000, 0x1000, "/opt/zlib.dll"),
            (0x77000000, 0x10000, r"C:\w\NTDLL.dll"),
            (0x76000000, 0x10000, r"C:\w\kernel32.dll"),
        ])

    def test_hits_grouped_by_module_os_modules_hidden(self, tmp_path, run):
        stack = _slots("<I", 0x10000010, 0x400100, 0x77000200, 0x5, 0x400000, 0x76000004, 0x403000)
        out = run(self._dump(tmp_path, [(SP, stack)]), "stackscan", "5", "--depth", "7")
        assert out.splitlines() == [
            f"Stack scan for thread 5 (SP=0x{SP:08X}, 7 slots):",
            "",
            "  game.exe (2 hits):",
            f"    0x{SP + 4:08X}: +0x100",
            f"    0x{SP + 16:08X}: +0x0",
            "",
            "  zlib.dll (1 hits):",
            f"    0x{SP:08X}: +0x10",
            "",
            "  (+ 2 OS module hits hidden, use --module to show specific)",
        ]

    def test_module_filter_is_case_insensitive_and_shows_os_modules(self, tmp_path, run):
        stack = _slots("<I", 0x77000200, 0x400100, 0x77000300)
        out = run(self._dump(tmp_path, [(SP, stack)]), "stackscan", "5", "--depth", "3", "--module", "ntdll.DLL")
        assert out.splitlines()[2:] == [
            "  NTDLL.dll (2 hits):",
            f"    0x{SP:08X}: +0x200",
            f"    0x{SP + 8:08X}: +0x300",
            "",
        ]

    def test_depth_bounds_the_scan(self, tmp_path, run):
        stack = _slots("<I", 0, 0, 0x400100)
        out = run(self._dump(tmp_path, [(SP, stack)]), "stackscan", "5", "--depth", "2")
        assert out.strip() == "No code addresses found in 2 stack slots from thread 5."

    def test_only_os_hits_without_filter(self, tmp_path, run):
        out = run(self._dump(tmp_path, [(SP, _slots("<I", 0x77000200))]), "stackscan", "5", "--depth", "1")
        assert "(+ 1 OS module hits hidden" in out
        assert "hits):" not in out

    def test_default_depth_and_gaps_between_segments(self, tmp_path, run):
        """8192 slots by default; a gap in the captured stack does not stop the scan."""
        mem = [(SP, _slots("<I", 0x400100) + bytes(4092)), (SP + 0x2000, _slots("<I", 0x400200) + bytes(4092)),
               (SP + 0x7000, bytes(0xFFC) + _slots("<I", 0x400300))]
        out = run(self._dump(tmp_path, mem), "stackscan", "5")
        assert f"(SP=0x{SP:08X}, 8192 slots)" in out
        assert "  game.exe (3 hits):" in out
        assert f"    0x{SP + 0x2000:08X}: +0x200" in out
        assert f"    0x{SP + 8191 * 4:08X}: +0x300" in out

    def test_amd64(self, tmp_path, run):
        stack = _slots("<Q", 0x400100, 0x100400100)
        out = run(self._dump(tmp_path, [(SP64, stack)], AMD64, SP64), "stackscan", "5", "--depth", "2")
        assert out.splitlines()[2:4] == ["  game.exe (1 hits):", f"    0x{SP64:016X}: +0x100"]

    def test_unknown_thread(self, tmp_path, run):
        assert run(self._dump(tmp_path, [(SP, bytes(8))]), "stackscan", "42").strip() == "Thread 42 not found."


# ---------------------------------------------------------------- exception


RUNTIME = 0x7FF612340000


class TestException:
    def _cxx(self, tmp_path, params, address=RUNTIME + 0x1010, rdata=None, module=None):
        pe = module or str(_rdata_image64(tmp_path / "app.exe", rdata or _throw_rdata(
            b".?AVruntime_error@std@@", b".?AVexception@std@@")))
        return _minidump(tmp_path / "c.dmp", arch=AMD64, modules=[(RUNTIME, 0x3000, pe)],
                         threads=[(3, {"Rip": address})],
                         exception={"thread_id": 3, "code": CXX, "address": address, "params": params})

    def test_record_fields(self, tmp_path, run):
        dump = _minidump(tmp_path / "a.dmp", modules=[(0x400000, 0x3000, r"C:\g\game.exe")],
                         exception={"thread_id": 12, "code": AV, "address": 0x401234,
                                    "params": [1, 0xDEADBEEF]})
        assert run(dump, "exception").splitlines() == [
            "Exception code:    0xC0000005",
            "Exception address: 0x0000000000401234  (game.exe+0x1234)",
            "Thread ID:         12",
            "Parameters (2):",
            "  [0] 0x0000000000000001",
            "  [1] 0x00000000DEADBEEF",
        ]

    def test_no_exception_stream(self, tmp_path, run):
        assert run(_minidump(tmp_path / "a.dmp"), "exception").strip() == "No exception record in dump."

    def test_msvc_type_chain_from_throw_info(self, tmp_path, run):
        params = [0x19930520, 0x1000, RUNTIME + TI_RVA, RUNTIME]
        out = run(self._cxx(tmp_path, params), "exception")
        assert "\nMSVC C++ exception (_CxxThrowException)" in out
        assert "  Type: .?AVruntime_error@std@@; .?AVexception@std@@" in out
        assert "Parameters (4):" in out

    def test_without_image_base_param_the_faulting_module_is_used(self, tmp_path, run):
        params = [0x19930520, 0x1000, RUNTIME + TI_RVA, 0]
        out = run(self._cxx(tmp_path, params), "exception")
        assert "  Type: .?AVruntime_error@std@@; .?AVexception@std@@" in out

    def test_single_catchable_type(self, tmp_path, run):
        params = [0x19930520, 0x1000, RUNTIME + TI_RVA, RUNTIME]
        out = run(self._cxx(tmp_path, params, rdata=_throw_rdata(b".?AVbad_alloc@std@@")), "exception")
        assert "  Type: .?AVbad_alloc@std@@\n" in out

    @pytest.mark.parametrize("why", ["no_pe", "three_params", "outside_modules"])
    def test_unresolved_type(self, tmp_path, run, why):
        params = [0x19930520, 0x1000, RUNTIME + TI_RVA, RUNTIME]
        kwargs = {}
        if why == "no_pe":
            kwargs["module"] = str(tmp_path / "gone.exe")
        elif why == "three_params":
            params = params[:3]
        else:
            params[3] = 0x10000
            kwargs["address"] = 0x20000
        out = run(self._cxx(tmp_path, params, **kwargs), "exception")
        assert "MSVC C++ exception (_CxxThrowException)" in out
        assert "  (could not resolve type -- module/PE not accessible)" in out
        assert "Type:" not in out

    def test_other_codes_are_not_cxx(self, tmp_path, run):
        dump = _minidump(tmp_path / "a.dmp", exception={"thread_id": 1, "code": CXX + 1, "address": 0,
                                                        "params": [0x19930520, 0, 0, 0]})
        assert "MSVC" not in run(dump, "exception")

    def test_the_first_exception_record_is_reported(self, tmp_path, run):
        dump = _minidump(tmp_path / "a.dmp", exception={"thread_id": 1, "code": AV, "address": 0x1000,
                                                        "params": []})
        blob = bytearray(dump.read_bytes())
        records = _exception_record(11, AV, 0x401111, [1]) + _exception_record(22, 0xC0000094, 0x402222, [])
        n = struct.unpack_from("<I", blob, 8)[0]
        for i in range(n):
            if struct.unpack_from("<I", blob, 32 + 12 * i)[0] == EXCEPTION:
                struct.pack_into("<III", blob, 32 + 12 * i, EXCEPTION, len(records), len(blob))
        dump.write_bytes(bytes(blob) + records)
        out = run(dump, "exception")
        assert "Exception code:    0xC0000005" in out
        assert "Thread ID:         11" in out

    def test_image_base_outside_every_module_is_unresolved(self, tmp_path, run):
        """The PE is looked up in the module that holds the throw image base, end exclusive."""
        pe = str(_rdata_image64(tmp_path / "app.exe", _throw_rdata(b".?AVbad_cast@std@@")))
        past = RUNTIME + 0x3000
        dump = _minidump(tmp_path / "c.dmp", arch=AMD64, modules=[(RUNTIME, 0x3000, pe)],
                         exception={"thread_id": 3, "code": CXX, "address": RUNTIME + 0x10,
                                    "params": [0x19930520, 0x1000, past + TI_RVA, past]})
        out = run(dump, "exception")
        assert "Type:" not in out
        assert "could not resolve type" in out


# ---------------------------------------------------------------- read


MEM = 0x00600000


class TestRead:
    def _dump(self, tmp_path):
        data = bytearray(0x40)
        struct.pack_into("<i", data, 0, -2)
        struct.pack_into("<f", data, 8, 1.5)
        struct.pack_into("<d", data, 16, -3.25)
        data[0x20:0x30] = b"Hello, dump!\x00\x01\x7f\x80"
        data[0x30:0x40] = bytes(range(0x30, 0x40))
        return _minidump(tmp_path / "r.dmp", memory=[(MEM, bytes(data))])

    @pytest.mark.parametrize("type_, offset, value", [
        ("uint8", 0, 0xFE), ("int8", 0, -2),
        ("uint16", 0, 0xFFFE), ("int16", 0, -2),
        ("uint32", 0, 0xFFFFFFFE), ("int32", 0, -2),
        ("uint64", 0, 0x00000000FFFFFFFE), ("int64", 0, 0xFFFFFFFE),
        ("ptr32", 0x30, 0x33323130), ("ptr64", 0x30, 0x3736353433323130),
        ("uint32", 0x31, 0x34333231),
    ])
    def test_integers_little_endian(self, tmp_path, run, type_, offset, value):
        out = run(self._dump(tmp_path), "read", hex(MEM + offset), type_)
        assert out.split()[:2] == [f"0x{MEM + offset:016X}:", str(value)]

    def test_unsigned_value_also_in_hex(self, tmp_path, run):
        out = run(self._dump(tmp_path), "read", f"{MEM + 0x30:x}", "uint32")
        assert out.strip() == f"0x{MEM + 0x30:016X}: {0x33323130}  (0x33323130)"

    @pytest.mark.parametrize("type_, offset, value", [("float", 8, 1.5), ("double", 16, -3.25)])
    def test_floats(self, tmp_path, run, type_, offset, value):
        out = run(self._dump(tmp_path), "read", hex(MEM + offset), type_)
        assert out.strip() == f"0x{MEM + offset:016X}: {value}"

    def test_bytes_hexdump(self, tmp_path, run):
        out = run(self._dump(tmp_path), "read", hex(MEM + 0x20), "bytes", "--count", "20")
        hex1 = "48 65 6C 6C 6F 2C 20 64 75 6D 70 21 00 01 7F 80"
        assert out.splitlines() == [
            f"  0x{MEM + 0x20:016X}: {hex1:<48s} Hello, dump!....",
            f"  0x{MEM + 0x30:016X}: {'30 31 32 33':<48s} 0123",
        ]

    def test_bytes_default_count_is_64(self, tmp_path, run):
        out = run(self._dump(tmp_path), "read", hex(MEM), "bytes")
        assert len(out.splitlines()) == 4

    def test_bytes_unreadable(self, tmp_path, run):
        out = run(self._dump(tmp_path), "read", hex(MEM + 0x30), "bytes", "--count", "32")
        assert out.strip() == f"Cannot read 32 bytes at 0x{MEM + 0x30:X}"

    @pytest.mark.parametrize("type_, size", [("uint64", 8), ("int16", 2)])
    def test_unreadable_address(self, tmp_path, run, type_, size):
        out = run(self._dump(tmp_path), "read", "0x900000", type_)
        assert out.strip() == f"Cannot read {size} bytes at 0x900000"

    def test_read_past_segment_end(self, tmp_path, run):
        out = run(self._dump(tmp_path), "read", hex(MEM + 0x3C), "uint64")
        assert out.strip() == f"Cannot read 8 bytes at 0x{MEM + 0x3C:X}"

    def test_unknown_type(self, tmp_path, run):
        out = run(self._dump(tmp_path), "read", hex(MEM), "quad")
        assert out.strip() == ("Unknown type 'quad'. Valid: double, float, int16, int32, int64, int8, "
                               "ptr32, ptr64, uint16, uint32, uint64, uint8 bytes")


# ---------------------------------------------------------------- strings / memscan / memmap


class TestStrings:
    def _dump(self, tmp_path):
        seg1 = b"\x01abc\x00" + b"GoodString\x00" + b"\xffmixed\x80" + b"tail1234\x00" + b"x"
        seg2 = b"\x00\x00Another one here\x00ABCD\x00"
        return _minidump(tmp_path / "s.dmp", modules=[(0x400000, 0x3000, r"C:\g\game.exe")],
                         memory=[(0x400100, seg1), (0x600000, seg2)])

    def test_nul_terminated_printable_runs(self, tmp_path, run):
        out = run(self._dump(tmp_path), "strings")
        assert out.splitlines() == [
            f"  0x{0x400105:016X} [  10]: GoodString  (game.exe+0x105)",
            f"  0x{0x400117:016X} [   8]: tail1234  (game.exe+0x117)",
            f"  0x{0x600002:016X} [  16]: Another one here",
            f"  0x{0x600013:016X} [   4]: ABCD",
            "",
            "4 strings found.",
        ]

    def test_min_len(self, tmp_path, run):
        out = run(self._dump(tmp_path), "strings", "--min-len", "9")
        assert "GoodString" in out and "Another one here" in out
        assert "tail1234" not in out and "ABCD" not in out
        assert "2 strings found." in out
        assert "abc" in run(self._dump(tmp_path), "strings", "--min-len", "3")

    def test_pattern_filter(self, tmp_path, run):
        out = run(self._dump(tmp_path), "strings", "--pattern", "^[A-Z]{4}$|one")
        assert [l.split(": ", 1)[1] for l in out.splitlines() if l.startswith("  0x")] == \
            ["Another one here", "ABCD"]

    def test_long_strings_are_cut_at_200_chars(self, tmp_path, run):
        dump = _minidump(tmp_path / "l.dmp", memory=[(0x600000, b"A" * 250 + b"\x00")])
        line = run(dump, "strings").splitlines()[0]
        assert line == f"  0x{0x600000:016X} [ 250]: " + "A" * 200

    def test_none_found(self, tmp_path, run):
        dump = _minidump(tmp_path / "n.dmp", memory=[(0x600000, b"ab\x00\x01\x02")])
        assert run(dump, "strings").strip() == "No strings found matching criteria."


class TestMemscan:
    def _dump(self, tmp_path):
        seg1 = b"0123456789ABCDEF" + b"needle" + b"abcdefghij" + b"needle"
        seg2 = b"\x90\x90needle\x00"
        return _minidump(tmp_path / "m.dmp", modules=[(0x400000, 0x3000, r"C:\g\game.exe")],
                         memory=[(0x400000, seg1), (0x600000, seg2)])

    def test_quoted_text_every_match_with_context(self, tmp_path, run):
        out = run(self._dump(tmp_path), "memscan", '"needle"')
        lines = out.splitlines()
        assert lines[0] == "Searching for 6 bytes: b'needle'"
        ctx1 = b"89ABCDEFneedleabcdefgh"
        ctx3 = b"\x90\x90needle\x00"
        assert lines[2:] == [
            f"  0x{0x400010:016X} (game.exe+0x10):",
            "    " + " ".join(f"{b:02X}" for b in ctx1),
            "    89ABCDEFneedleabcdefgh",
            f"  0x{0x40001A + 6:016X} (game.exe+0x20):",
            "    " + " ".join(f"{b:02X}" for b in b"cdefghijneedle"),
            "    cdefghijneedle",
            f"  0x{0x600002:016X} (0x600002):",
            "    " + " ".join(f"{b:02X}" for b in ctx3),
            "    ..needle.",
            "",
            "3 matches found.",
        ]

    def test_hex_bytes_with_spaces(self, tmp_path, run):
        out = run(self._dump(tmp_path), "memscan", "6E 65 65 64 6C 65")
        assert out.splitlines()[0] == "Searching for 6 bytes: b'needle'"
        assert "3 matches found." in out

    def test_overlapping_occurrences(self, tmp_path, run):
        dump = _minidump(tmp_path / "o.dmp", memory=[(0x600000, b"\xAA\xAA\xAA\xAA")])
        out = run(dump, "memscan", "AAAA")
        assert [l.split()[0] for l in out.splitlines() if l.startswith("  0x")] == \
            [f"0x{0x600000 + i:016X}" for i in range(3)]

    def test_long_needle_preview_is_truncated(self, tmp_path, run):
        dump = _minidump(tmp_path / "o.dmp", memory=[(0x600000, b"Z" * 50)])
        out = run(dump, "memscan", '"' + "Z" * 41 + '"')
        assert out.splitlines()[0] == "Searching for 41 bytes: b'" + "Z" * 40 + "'..."
        out = run(dump, "memscan", '"' + "Z" * 40 + '"')
        assert out.splitlines()[0] == "Searching for 40 bytes: b'" + "Z" * 40 + "'"

    def test_not_found(self, tmp_path, run):
        out = run(self._dump(tmp_path), "memscan", "DE AD BE EF")
        assert out.splitlines()[-1] == "Pattern not found in dump memory."

    def test_memscan_ascii_column_dots_control_bytes(self, tmp_path, run):
        dump = _minidump(tmp_path / "m.dmp", memory=[(0x600000, b"\x09\x1fneedle\x7f")])
        lines = run(dump, "memscan", '"needle"').splitlines()
        assert lines[4] == "    ..needle."


class TestMemmap:
    def test_segments_sizes_modules_and_total(self, tmp_path, run):
        big = 0x180000
        dump = _minidump(tmp_path / "m.dmp", modules=[(0x400000, 0x3000, r"C:\g\game.exe")],
                         memory=[(0x400100, bytes(0x100)), (0x10000000, bytes(big)), (0x403000, b"x")])
        out = run(dump, "memmap")
        rows = [l for l in out.splitlines() if l.startswith("  0x")]
        assert rows == [
            f"  0x{0x400100:016X}  {'256':>10s}  game.exe+0x100",
            f"  0x{0x10000000:016X}  {'1,572,864':>10s}  ",
            f"  0x{0x403000:016X}  {'1':>10s}  ",
        ]
        assert out.splitlines()[-1] == f"3 segments, {256 + big + 1:,d} bytes total (1.5 MB)"

    def test_empty(self, tmp_path, run):
        out = run(_minidump(tmp_path / "e.dmp"), "memmap")
        assert out.splitlines()[-1] == "0 segments, 0 bytes total (0.0 MB)"


# ---------------------------------------------------------------- diagnose


class TestDiagnose:
    def _dump(self, tmp_path, stack: bytes, code=AV, params=(), extra_memory=(), modules=None, arch=X86,
              sp=SP, exc=True):
        reg = {"Esp": sp, "Eip": 0x401000} if arch == X86 else {"Rsp": sp, "Rip": 0x401000}
        mods = modules or [(0x400000, 0x3000, r"C:\g\Game.exe"), (0x77000000, 0x10000, r"C:\w\ntdll.dll")]
        exception = {"thread_id": 9, "code": code, "address": 0x401000, "params": list(params)} if exc else None
        return _minidump(tmp_path / "d.dmp", arch=arch, modules=mods,
                         threads=[(4, {"Esp": 0, "Eip": 0x77000010} if arch == X86 else {"Rip": 0x77000010}),
                                  (9, reg)],
                         memory=[(sp, stack), *extra_memory], exception=exception)

    def test_exception_threads_and_stack_scan(self, tmp_path, run):
        stack = _slots("<I", 0x400100, 0x77000004, 0x400200, 7) + bytes(4096 - 16)
        out = run(self._dump(tmp_path, stack), "diagnose")
        assert "=== Exception ===\n\n  Code:    0xC0000005\n" in out
        assert f"  Address: 0x{0x401000:016X} (Game.exe+0x1000)" in out
        assert "  Thread:  9\n" in out
        assert "=== Threads ===\n\n" in out
        assert "         4  ntdll.dll+0x10\n" in out
        assert "         9  Game.exe+0x1000 << EXCEPTION\n" in out
        scan = out.split("=== Stack Scan (exception thread) ===\n\n", 1)[1]
        assert scan.splitlines()[:3] == [
            "  Game.exe (2 frames):",
            f"    0x{SP:08X}: +0x100",
            f"    0x{SP + 8:08X}: +0x200",
        ]
        assert "ntdll" not in scan
        assert "Throw-Site" not in out

    def test_stack_scan_lists_twenty_frames_per_module(self, tmp_path, run):
        stack = _slots("<I", *[0x400000 + i for i in range(25)]) + bytes(4096 - 100)
        scan = run(self._dump(tmp_path, stack), "diagnose").split("(exception thread) ===\n\n", 1)[1]
        lines = scan.splitlines()
        assert lines[0] == "  Game.exe (25 frames):"
        assert lines[20] == f"    0x{SP + 19 * 4:08X}: +0x13"
        assert lines[21] == "    ... and 5 more"

    def test_stack_scan_reaches_8192_slots(self, tmp_path, run):
        far = SP + 8191 * 4
        stack = bytes(4096)
        out = run(self._dump(tmp_path, stack, extra_memory=[(far & ~0xFFF, bytes(0xFFC) + _slots("<I", 0x400300))]),
                  "diagnose")
        assert f"    0x{far:08X}: +0x300" in out

    def test_amd64_stack_scan(self, tmp_path, run):
        stack = _slots("<Q", 0x400100, 0x100400100) + bytes(4096 - 16)
        out = run(self._dump(tmp_path, stack, arch=AMD64, sp=SP64), "diagnose")
        scan = out.split("(exception thread) ===\n\n", 1)[1]
        assert scan.splitlines()[:2] == ["  Game.exe (1 frames):", f"    0x{SP64:016X}: +0x100"]

    def test_no_exception(self, tmp_path, run):
        out = run(self._dump(tmp_path, bytes(4096), exc=False), "diagnose")
        assert "=== Exception ===\n\n  No exception record in dump.\n" in out
        assert "Stack Scan" not in out
        assert "<< EXCEPTION" not in out

    def test_exception_thread_missing(self, tmp_path, run):
        dump = _minidump(tmp_path / "d.dmp", modules=[(0x400000, 0x3000, "g.exe")],
                         threads=[(4, {"Esp": SP})], memory=[(SP, bytes(16))],
                         exception={"thread_id": 77, "code": AV, "address": 0, "params": []})
        assert "  Exception thread not found or has no context.\n" in run(dump, "diagnose")

    def _string_object(self, data: bytes, length: int, cap: int, ptr: int = 0) -> bytes:
        """x64 MSVC std::string: 16-byte buffer/pointer union, size at +16, capacity at +24."""
        head = data.ljust(16, b"\0") if ptr == 0 else struct.pack("<Q", ptr).ljust(16, b"\0")
        return head + struct.pack("<QQ", length, cap) + bytes(32)

    def _cxx_dump(self, tmp_path, obj: bytes, extra=()):
        obj_addr = 0x500000
        return self._dump(tmp_path, bytes(4096), code=CXX, params=[0x19930520, obj_addr, 0, 0],
                          extra_memory=[(obj_addr, obj), *extra])

    def test_cxx_message_inline(self, tmp_path, run):
        out = run(self._cxx_dump(tmp_path, self._string_object(b"bad index", 9, 15)), "diagnose")
        assert '  Message (SSO): "bad index"\n' in out

    def test_cxx_message_on_heap(self, tmp_path, run):
        text = b"a message longer than fifteen bytes"
        obj = self._string_object(b"", len(text), 47, ptr=0x700000)
        out = run(self._cxx_dump(tmp_path, obj, extra=[(0x700000, text)]), "diagnose")
        assert f'  Message: "{text.decode()}"\n' in out

    def test_cxx_message_heap_not_captured(self, tmp_path, run):
        obj = self._string_object(b"", 40, 47, ptr=0x7ABC00)
        out = run(self._cxx_dump(tmp_path, obj), "diagnose")
        assert "  String length=40, heap ptr=0x7ABC00 (not in dump)\n" in out

    @pytest.mark.parametrize("length, cap", [(0, 15), (10000, 10000), (20, 19)])
    def test_cxx_object_that_is_not_a_string(self, tmp_path, run, length, cap):
        obj = self._string_object(b"abcdefghijklmnop", length, cap, ptr=0x700000)
        out = run(self._cxx_dump(tmp_path, obj, extra=[(0x700000, b"Q" * 64)]), "diagnose")
        assert "Message" not in out and "String length" not in out

    def test_cxx_type_name(self, tmp_path, run):
        pe = str(_rdata_image64(tmp_path / "app.exe", _throw_rdata(b".?AVlogic_error@std@@")))
        dump = _minidump(tmp_path / "c.dmp", arch=AMD64, modules=[(RUNTIME, 0x3000, pe)],
                         threads=[(3, {"Rip": RUNTIME + 0x1010, "Rsp": SP64})], memory=[(SP64, bytes(4096))],
                         exception={"thread_id": 3, "code": CXX, "address": RUNTIME + 0x1010,
                                    "params": [0x19930520, 0x1000, RUNTIME + TI_RVA, RUNTIME]})
        assert "  C++ type: .?AVlogic_error@std@@\n" in run(dump, "diagnose")

    # ---- throw-site matching against a throw map {call_site_rva: (insn_size, error_string)}

    @pytest.fixture
    def throw_map(self, monkeypatch):
        state = {}

        def build_throw_map(path):
            state["path"] = path
            return object(), state["is_64"], state["tmap"]

        monkeypatch.setitem(sys.modules, "retools.throwmap",
                            types.SimpleNamespace(build_throw_map=build_throw_map))
        return state

    def test_throw_site_match(self, tmp_path, run, throw_map):
        throw_map.update(is_64=False, tmap={0x1500: (6, "vector too long"), 0x1600: (5, None),
                                           0x1700: (6, "never on stack")})
        stack = _slots("<I", 0x401506, 7, 0x401605, 0x401500) + bytes(4096 - 16)
        out = run(self._dump(tmp_path, stack), "diagnose", "--binary", str(tmp_path / "game.EXE"))
        section = out.split("=== Throw-Site Match ===\n\n", 1)[1]
        assert throw_map["path"] == str(tmp_path / "game.EXE")
        assert section.splitlines() == [
            f"  Binary: {tmp_path / 'game.EXE'}",
            "  Throw sites: 3 (2 with strings)",
            "",
            "  MATCH: throw at +0x1500 (ret +0x1506)",
            f"  Stack: 0x{SP:016X}",
            '  Error: "vector too long"',
            "",
            "  MATCH: throw at +0x1600 (ret +0x1605)",
            f"  Stack: 0x{SP + 8:016X}",
            '  Error: "<string not resolved>"',
            "",
        ]

    def test_throw_site_error_cut_at_120_chars(self, tmp_path, run, throw_map):
        throw_map.update(is_64=False, tmap={0x1500: (6, "E" * 130)})
        stack = _slots("<I", 0x401506) + bytes(4092)
        out = run(self._dump(tmp_path, stack), "diagnose", "--binary", "game.exe")
        assert f'  Error: "{"E" * 120}"\n' in out

    def test_throw_site_64_bit_slots_up_to_64k(self, tmp_path, run, throw_map):
        throw_map.update(is_64=True, tmap={0x1500: (6, "x64 throw"), 0x1510: (6, "beyond")})
        near = SP64 + 0xF000
        out = run(self._dump(tmp_path, bytes(4096), arch=AMD64, sp=SP64, extra_memory=[
            (near, bytes(0xFF8) + _slots("<Q", 0x401506)),
            (SP64 + 0x10000, _slots("<Q", 0x401516) + bytes(0xFF8)),
        ]), "diagnose", "--binary", "game.exe")
        assert "  MATCH: throw at +0x1500 (ret +0x1506)" in out
        assert f"  Stack: 0x{near + 0xFF8:016X}" in out
        assert "beyond" not in out

    def test_binary_not_in_dump(self, tmp_path, run, throw_map):
        throw_map.update(is_64=False, tmap={})
        out = run(self._dump(tmp_path, bytes(4096)), "diagnose", "--binary", "other.dll")
        assert "  Module 'other.dll' not found in dump.\n" in out

    def test_no_match(self, tmp_path, run, throw_map):
        throw_map.update(is_64=False, tmap={0x1500: (6, "s")})
        out = run(self._dump(tmp_path, bytes(4096)), "diagnose", "--binary", "game.exe")
        assert "  Throw sites: 1 (1 with strings)" in out
        assert "\n  No throw-site matches on exception thread stack.\n" in out

    def test_cxx_message_inline_amd64(self, tmp_path, run):
        """x64 MSVC std::string thrown object: a one-character inline message."""
        obj = b"x".ljust(16, b"\0") + struct.pack("<QQ", 1, 15) + bytes(32)
        dump = _minidump(tmp_path / "d.dmp", arch=AMD64, modules=[(0x400000, 0x3000, "g.exe")],
                         threads=[(9, {"Rsp": SP64, "Rip": 0x401000})],
                         memory=[(SP64, bytes(4096)), (0x500000, obj)],
                         exception={"thread_id": 9, "code": CXX, "address": 0x401000,
                                    "params": [0x19930520, 0x500000, 0, 0]})
        assert '  Message (SSO): "x"\n' in run(dump, "diagnose")

    def test_throw_site_binary_matched_by_file_name_in_a_posix_path(self, tmp_path, run, monkeypatch):
        monkeypatch.setitem(sys.modules, "retools.throwmap", types.SimpleNamespace(
            build_throw_map=lambda path: (object(), False, {0x1500: (6, "posix")})))
        dump = _minidump(tmp_path / "d.dmp", modules=[(0x400000, 0x3000, "/opt/app/game.exe")],
                         threads=[(9, {"Esp": SP})], memory=[(SP, _slots("<I", 0x401506) + bytes(4092))],
                         exception={"thread_id": 9, "code": AV, "address": 0, "params": []})
        assert "  MATCH: throw at +0x1500 (ret +0x1506)" in run(dump, "diagnose", "--binary", "game.exe")

    def test_throw_site_each_stack_slot_reported_once(self, tmp_path, run, monkeypatch):
        monkeypatch.setitem(sys.modules, "retools.throwmap", types.SimpleNamespace(
            build_throw_map=lambda path: (object(), False, {0x1500: (6, "once")})))
        stack = bytes(0x100) + _slots("<I", 0x401506) + bytes(0x2000 - 0x104)
        dump = _minidump(tmp_path / "d.dmp", modules=[(0x400000, 0x3000, r"C:\g\game.exe")],
                         threads=[(9, {"Esp": SP})], memory=[(SP, stack)],
                         exception={"thread_id": 9, "code": AV, "address": 0, "params": []})
        out = run(dump, "diagnose", "--binary", "game.exe")
        assert out.count("MATCH:") == 1
        assert f"  Stack: 0x{SP + 0x100:016X}" in out


# ---------------------------------------------------------------- command line


class TestCommandLine:
    def test_a_subcommand_is_required(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["dumpinfo", str(_minidump(tmp_path / "a.dmp"))])
        with pytest.raises(SystemExit) as exc:
            dumpinfo.main()
        assert exc.value.code == 2
