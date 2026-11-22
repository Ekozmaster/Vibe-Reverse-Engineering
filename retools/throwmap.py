#!/usr/bin/env python3
"""Map MSVC C++ throw sites to their error strings in a PE binary.

Statically analyzes a PE (.exe/.dll, 32 or 64-bit) to find every call to
_CxxThrowException and resolve the string argument passed to the exception
constructor at each call site.

Sub-commands:

  list              Dump all throw sites with their error strings
  match --dump D    Match a minidump's crash stack against the throw map

Usage:
    python -m retools.throwmap binary.dll list
    python -m retools.throwmap binary.dll match --dump crash.dmp

The match algorithm is deterministic and bias-free:
  1. Build {rva: string} for every throw call site
  2. Compute return-address RVA for each site (call_rva + call_insn_size)
  3. Scan the crashing thread's full stack for module return addresses
  4. Report any stack value == module_base + return_rva

Requires: pip install pefile minidump
"""

import argparse
import struct
import sys
from pathlib import Path

import pefile


def _rva_to_file_offset(pe: pefile.PE, rva: int):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None


def _read_string_at_rva(pe: pefile.PE, rva: int, max_len: int = 500):
    off = _rva_to_file_offset(pe, rva)
    if off is None:
        return None
    data = pe.__data__
    if off >= len(data):
        return None
    end = data.find(b"\x00", off, off + max_len)
    if end < 0:
        return None
    try:
        s = data[off:end].decode("ascii")
        return s if len(s) > 3 else None
    except (UnicodeDecodeError, ValueError):
        return None


def _get_code_sections(pe: pefile.PE):
    sections = []
    for s in pe.sections:
        if s.Characteristics & 0x20:
            sections.append((s.VirtualAddress, s.get_data(), s.Misc_VirtualSize))
    return sections


def _find_iat_rva(pe: pefile.PE, func_name: bytes):
    """Find the IAT slot RVA for an imported function."""
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return None
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and func_name in imp.name:
                return imp.address - pe.OPTIONAL_HEADER.ImageBase
    return None


def _find_throw_sites_x64(pe: pefile.PE, code_sections, iat_rva: int):
    """Find all call sites to _CxxThrowException in a 64-bit PE.

    x64 binaries use JMP [rip+disp32] thunks.  Callers use E8 rel32 to
    reach the thunk, or FF 15 [rip+disp32] to call the IAT directly.
    """
    sites = []

    # Find JMP [rip+disp32] thunk pointing to the IAT slot
    thunk_rva = None
    for sec_rva, sec_data, _ in code_sections:
        for i in range(len(sec_data) - 5):
            if sec_data[i] == 0xFF and sec_data[i + 1] == 0x25:
                disp = struct.unpack_from("<i", sec_data, i + 2)[0]
                insn_rva = sec_rva + i
                if insn_rva + 6 + disp == iat_rva:
                    thunk_rva = insn_rva
                    break
        if thunk_rva is not None:
            break

    if thunk_rva is not None:
        for sec_rva, sec_data, _ in code_sections:
            for i in range(len(sec_data) - 4):
                if sec_data[i] == 0xE8:
                    disp = struct.unpack_from("<i", sec_data, i + 1)[0]
                    insn_rva = sec_rva + i
                    if insn_rva + 5 + disp == thunk_rva:
                        sites.append((insn_rva, 5))

    # Direct FF 15 [rip+disp32] calls to IAT
    for sec_rva, sec_data, _ in code_sections:
        for i in range(len(sec_data) - 5):
            if sec_data[i] == 0xFF and sec_data[i + 1] == 0x15:
                disp = struct.unpack_from("<i", sec_data, i + 2)[0]
                insn_rva = sec_rva + i
                if insn_rva + 6 + disp == iat_rva:
                    sites.append((insn_rva, 6))

    return sites


def _find_throw_sites_x86(pe: pefile.PE, code_sections, iat_rva: int):
    """Find all call sites to _CxxThrowException in a 32-bit PE.

    x86 binaries use FF 15 <abs32> for IAT calls, or E8 rel32 through a
    JMP [abs32] thunk (FF 25 <abs32>).
    """
    sites = []
    image_base = pe.OPTIONAL_HEADER.ImageBase
    iat_va = image_base + iat_rva

    # Find JMP [abs32] thunk
    thunk_rva = None
    for sec_rva, sec_data, _ in code_sections:
        for i in range(len(sec_data) - 5):
            if sec_data[i] == 0xFF and sec_data[i + 1] == 0x25:
                target_va = struct.unpack_from("<I", sec_data, i + 2)[0]
                if target_va == iat_va:
                    thunk_rva = sec_rva + i
                    break
        if thunk_rva is not None:
            break

    if thunk_rva is not None:
        for sec_rva, sec_data, _ in code_sections:
            for i in range(len(sec_data) - 4):
                if sec_data[i] == 0xE8:
                    disp = struct.unpack_from("<i", sec_data, i + 1)[0]
                    insn_rva = sec_rva + i
                    if insn_rva + 5 + disp == thunk_rva:
                        sites.append((insn_rva, 5))

    # Direct FF 15 <abs32> calls
    for sec_rva, sec_data, _ in code_sections:
        for i in range(len(sec_data) - 5):
            if sec_data[i] == 0xFF and sec_data[i + 1] == 0x15:
                target_va = struct.unpack_from("<I", sec_data, i + 2)[0]
                if target_va == iat_va:
                    sites.append((sec_rva + i, 6))

    return sites


def _resolve_string_x64(pe: pefile.PE, site_rva: int, search_back: int = 80):
    """Walk backwards from a throw site to find LEA r64,[rip+disp32] loading
    the string argument (first arg to the exception constructor)."""
    search_start = max(site_rva - search_back, 0)
    off_start = _rva_to_file_offset(pe, search_start)
    off_end = _rva_to_file_offset(pe, site_rva)
    if off_start is None or off_end is None:
        return None

    data = pe.__data__[off_start:off_end]
    best = None

    for i in range(len(data) - 7, -1, -1):
        b0 = data[i]
        if b0 in (0x48, 0x4C) and i + 1 < len(data) and data[i + 1] == 0x8D:
            modrm = data[i + 2]
            if (modrm >> 6) & 3 == 0 and (modrm & 7) == 5:
                disp = struct.unpack_from("<i", data, i + 3)[0]
                lea_rva = search_start + i
                target_rva = lea_rva + 7 + disp
                s = _read_string_at_rva(pe, target_rva)
                if s:
                    best = s
    return best


def _resolve_string_x86(pe: pefile.PE, site_rva: int, search_back: int = 80):
    """Walk backwards from a throw site to find PUSH imm32 or MOV reg,imm32
    loading the string argument."""
    image_base = pe.OPTIONAL_HEADER.ImageBase
    search_start = max(site_rva - search_back, 0)
    off_start = _rva_to_file_offset(pe, search_start)
    off_end = _rva_to_file_offset(pe, site_rva)
    if off_start is None or off_end is None:
        return None

    data = pe.__data__[off_start:off_end]
    best = None

    for i in range(len(data) - 5, -1, -1):
        b0 = data[i]
        # PUSH imm32
        if b0 == 0x68:
            va = struct.unpack_from("<I", data, i + 1)[0]
            if va > image_base:
                s = _read_string_at_rva(pe, va - image_base)
                if s:
                    best = s
        # MOV r32, imm32 (B8..BF)
        elif 0xB8 <= b0 <= 0xBF:
            va = struct.unpack_from("<I", data, i + 1)[0]
            if va > image_base:
                s = _read_string_at_rva(pe, va - image_base)
                if s:
                    best = s
    return best


def build_throw_map(binary_path: str):
    """Build {call_site_rva: (insn_size, error_string)} for all throw sites."""
    pe = pefile.PE(binary_path)
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B

    iat_rva = _find_iat_rva(pe, b"CxxThrowException")
    if iat_rva is None:
        return pe, is_64, {}

    code_sections = _get_code_sections(pe)

    if is_64:
        sites = _find_throw_sites_x64(pe, code_sections, iat_rva)
        resolver = _resolve_string_x64
    else:
        sites = _find_throw_sites_x86(pe, code_sections, iat_rva)
        resolver = _resolve_string_x86

    throw_map = {}
    for site_rva, insn_size in sites:
        s = resolver(pe, site_rva)
        if s:
            throw_map[site_rva] = (insn_size, s)
        else:
            throw_map[site_rva] = (insn_size, None)

    return pe, is_64, throw_map


def cmd_list(args):
    pe, is_64, tmap = build_throw_map(args.binary)
    arch = "x64" if is_64 else "x86"
    total = len(tmap)
    mapped = sum(1 for _, (_, s) in tmap.items() if s)

    print(f"Binary: {args.binary} ({arch})")
    print(f"Throw sites: {total} total, {mapped} with resolved strings\n")

    for rva in sorted(tmap.keys()):
        insn_size, s = tmap[rva]
        ret_rva = rva + insn_size
        if s:
            display = s[:100] + ("..." if len(s) > 100 else "")
            print(f"  0x{rva:06X} (ret 0x{ret_rva:06X}): \"{display}\"")
        else:
            print(f"  0x{rva:06X} (ret 0x{ret_rva:06X}): <string not resolved>")


def cmd_match(args):
    try:
        from minidump.minidumpfile import MinidumpFile
    except ImportError:
        sys.exit("minidump not installed. Run: pip install minidump")

    import logging
    logging.disable(logging.CRITICAL)
    dump = MinidumpFile.parse(args.dump)
    logging.disable(logging.NOTSET)

    pe, is_64, tmap = build_throw_map(args.binary)
    arch = "x64" if is_64 else "x86"

    mapped = sum(1 for _, (_, s) in tmap.items() if s)
    print(f"Binary: {args.binary} ({arch})")
    print(f"Throw sites: {len(tmap)} total, {mapped} with resolved strings")
    print(f"Dump: {args.dump}\n")

    # Find the module's runtime base from the dump
    runtime_base = None
    binary_name = Path(args.binary).name.lower()
    if dump.modules:
        for m in dump.modules.modules:
            mod_name = m.name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if mod_name == binary_name:
                runtime_base = m.baseaddress
                break

    if runtime_base is None:
        print(f"[error] Module '{binary_name}' not found in dump.")
        print("Loaded modules:")
        if dump.modules:
            for m in dump.modules.modules:
                name = m.name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                print(f"  0x{m.baseaddress:016X}  {name}")
        return

    print(f"Module base in dump: 0x{runtime_base:016X}")

    # Build return-address lookup: {runtime_va: (rva, string)}
    ret_lookup = {}
    for site_rva, (insn_size, s) in tmap.items():
        ret_rva = site_rva + insn_size
        ret_va = runtime_base + ret_rva
        ret_lookup[ret_va] = (site_rva, ret_rva, s)

    # Find the crashing thread
    exc_thread_id = None
    if dump.exception and dump.exception.exception_records:
        exc_thread_id = dump.exception.exception_records[0].ThreadId

    # Scan threads (prefer exception thread, but check all)
    threads_to_scan = []
    if dump.threads:
        for t in dump.threads.threads:
            if t.ThreadId == exc_thread_id:
                threads_to_scan.insert(0, t)
            else:
                threads_to_scan.append(t)

    ptr_size = 8 if is_64 else 4
    ptr_fmt = "<Q" if is_64 else "<I"
    reader = dump.get_reader()
    matches = []
    scan_bytes = 65536
    chunk_size = 4096

    for t in threads_to_scan:
        ctx = t.ContextObject
        if ctx is None:
            continue
        sp = ctx.Rsp if hasattr(ctx, "Rsp") else ctx.Esp

        for chunk_off in range(0, scan_bytes, chunk_size):
            try:
                chunk = reader.read(sp + chunk_off, chunk_size)
            except Exception:
                continue
            for i in range(0, len(chunk) - ptr_size + 1, ptr_size):
                val = struct.unpack_from(ptr_fmt, chunk, i)[0]
                if val in ret_lookup:
                    site_rva, ret_rva, s = ret_lookup[val]
                    stack_addr = sp + chunk_off + i
                    matches.append((t.ThreadId, stack_addr, site_rva, ret_rva, s))

    if not matches:
        print("\nNo throw-site return addresses found on any thread's stack.")
        return

    print(f"\nMatches ({len(matches)}):\n")
    for tid, stack_addr, site_rva, ret_rva, s in matches:
        is_exc = " [exception thread]" if tid == exc_thread_id else ""
        display = s[:100] if s else "<string not resolved>"
        w = 16 if is_64 else 8
        print(f"  Thread {tid}{is_exc}")
        print(f"    Stack 0x{stack_addr:0{w}X} = module+0x{ret_rva:X} "
              f"(return from throw at +0x{site_rva:X})")
        print(f"    Message: \"{display}\"")
        print()


def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("binary", help="Path to PE binary (.exe or .dll)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all throw sites and their error strings")

    s = sub.add_parser("match",
                       help="Match dump crash stack against throw map")
    s.add_argument("--dump", required=True,
                   help="Path to minidump (.dmp) file")

    args = p.parse_args()
    {"list": cmd_list, "match": cmd_match}[args.command](args)


if __name__ == "__main__":
    main()
