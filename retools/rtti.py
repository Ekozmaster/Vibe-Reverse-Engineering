#!/usr/bin/env python3
"""Resolve MSVC RTTI (Run-Time Type Information) from a PE binary.

Sub-commands:

  vtable      Given a vtable VA, resolve the C++ class name and hierarchy
  throwinfo   Given a _ThrowInfo RVA/VA, resolve the exception catchable types

MSVC RTTI structure layout (all fields are DWORDs unless noted):
────────────────────────────────────────────────────────────────

  Vtable memory layout (both 32-bit and 64-bit):

    vtable - 4:   [COL ref]    32-bit value: VA (x86) or RVA (x64)
    vtable + 0:   [vfunc 0]    pointer-sized
    vtable + P:   [vfunc 1]    pointer-sized  (P = 4 or 8)
    ...

  RTTICompleteObjectLocator (COL):
    +0x00  signature       0 = 32-bit, 1 = 64-bit
    +0x04  offset          vbtable offset (0 for most classes)
    +0x08  cdOffset        constructor displacement offset
    +0x0C  pTypeDesc       -> TypeDescriptor       (VA in x86, RVA in x64)
    +0x10  pClassHierDesc  -> ClassHierarchyDesc   (VA in x86, RVA in x64)
    +0x14  pSelf           -> self (RVA, x64 only -- used for validation)

  TypeDescriptor (TD):
    +0x00  pVFTable        pointer to type_info vtable (pointer-sized)
    +P     spare           internal (pointer-sized)
    +2P    name[]          decorated class name, e.g. ".?AVMyClass@@"

  ClassHierarchyDescriptor (CHD):
    +0x00  signature       always 0
    +0x04  attributes      bit 0 = multiple inheritance, bit 1 = virtual
    +0x08  numBaseClasses  count (includes self as first entry)
    +0x0C  pBaseClassArray -> array of BaseClassDesc refs (VA/RVA)

  BaseClassDescriptor (BCD):
    +0x00  pTypeDesc       -> TypeDescriptor (VA in x86, RVA in x64)
    +0x04  numContained    number of contained base classes
    +0x08  PMD.mdisp       member displacement
    +0x0C  PMD.pdisp       vbtable displacement (-1 = no vbtable)
    +0x10  PMD.vdisp       displacement within vbtable
    +0x14  attributes

Usage:
    python retools/rtti.py <binary> vtable <va>
    python retools/rtti.py <binary> throwinfo <rva>

Examples:
    python retools/rtti.py binary.dll vtable 0x6A0000
    python retools/rtti.py binary.exe throwinfo 0x75B888
"""

import argparse
import struct
import sys
from dataclasses import dataclass, field

import pefile

MAX_BASES = 64
MAX_CATCHABLE = 32


def _safe_read(pe: pefile.PE, rva: int, size: int) -> bytes | None:
    """Read *size* bytes at *rva*, returning None if out of bounds."""
    if rva <= 0:
        return None
    try:
        data = pe.get_data(rva, size)
        return data if len(data) == size else None
    except Exception:
        return None


def _read_u32(pe: pefile.PE, rva: int) -> int | None:
    data = _safe_read(pe, rva, 4)
    return struct.unpack_from("<I", data)[0] if data else None


def _read_cstring(pe: pefile.PE, rva: int, max_len: int = 256) -> str | None:
    data = _safe_read(pe, rva, max_len)
    if data is None:
        return None
    end = data.find(b"\x00")
    if end >= 0:
        data = data[:end]
    return data.decode("ascii", errors="replace")


def _to_rva(pe: pefile.PE, val: int, is_64: bool) -> int:
    """Convert a structure field to an RVA. In x64 it's already an RVA; in x86 it's a VA."""
    if is_64:
        return val
    return val - pe.OPTIONAL_HEADER.ImageBase


def _resolve_td_name(pe: pefile.PE, td_rva: int, is_64: bool) -> str | None:
    """Read the decorated class name from a TypeDescriptor at *td_rva*."""
    name_off = 16 if is_64 else 8
    name = _read_cstring(pe, td_rva + name_off)
    if name and name.startswith(".?A"):
        return name
    return None


def _fail(msg: str) -> None:
    print(f"[error] {msg}", file=sys.stderr)
    sys.exit(1)


@dataclass
class RttiClass:
    name: str
    vtable_va: int
    hierarchy: list[str] = field(default_factory=list)


def resolve_vtable(pe: pefile.PE, vtable_va: int) -> RttiClass | None:
    """Extract RTTI class info from a vtable address.

    Returns an RttiClass with the class name and hierarchy, or None
    if the address does not point to a valid RTTI vtable.
    """
    base = pe.OPTIONAL_HEADER.ImageBase
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    vtable_rva = vtable_va - base

    col_ref = _read_u32(pe, vtable_rva - 4)
    if col_ref is None:
        return None

    col_rva = _to_rva(pe, col_ref, is_64)
    if col_rva <= 0:
        return None

    expected_sig = 1 if is_64 else 0
    sig = _read_u32(pe, col_rva)
    if sig is None or sig != expected_sig:
        return None

    if is_64:
        self_rva = _read_u32(pe, col_rva + 0x14)
        if self_rva != col_rva:
            return None

    td_ref = _read_u32(pe, col_rva + 0x0C)
    if td_ref is None:
        return None
    td_rva = _to_rva(pe, td_ref, is_64)

    class_name = _resolve_td_name(pe, td_rva, is_64)
    if class_name is None:
        return None

    hierarchy: list[str] = []
    chd_ref = _read_u32(pe, col_rva + 0x10)
    if chd_ref is not None and chd_ref != 0:
        chd_rva = _to_rva(pe, chd_ref, is_64)
        num_bases = _read_u32(pe, chd_rva + 0x08)
        if num_bases is not None and 0 < num_bases <= MAX_BASES:
            bca_ref = _read_u32(pe, chd_rva + 0x0C)
            if bca_ref is not None:
                bca_rva = _to_rva(pe, bca_ref, is_64)
                for i in range(num_bases):
                    bcd_ref = _read_u32(pe, bca_rva + i * 4)
                    if bcd_ref is None:
                        break
                    bcd_rva = _to_rva(pe, bcd_ref, is_64)
                    bcd_td_ref = _read_u32(pe, bcd_rva)
                    if bcd_td_ref is None:
                        break
                    bcd_td_rva = _to_rva(pe, bcd_td_ref, is_64)
                    base_name = _resolve_td_name(pe, bcd_td_rva, is_64)
                    if base_name is None:
                        break
                    hierarchy.append(base_name)

    return RttiClass(name=class_name, vtable_va=vtable_va, hierarchy=hierarchy)


def scan_all_rtti(pe: pefile.PE) -> list[RttiClass]:
    """Walk all readable PE sections looking for valid RTTI vtable references.

    Returns a deduplicated list of RttiClass objects found in the binary.
    """
    base = pe.OPTIONAL_HEADER.ImageBase
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    expected_sig = 1 if is_64 else 0

    seen: dict[str, RttiClass] = {}
    for section in pe.sections:
        if not (section.Characteristics & 0x40000000):  # IMAGE_SCN_MEM_READ
            continue
        sec_rva = section.VirtualAddress
        sec_size = section.SizeOfRawData
        sec_off = section.PointerToRawData
        data = pe.get_data(sec_rva, min(sec_size, section.Misc_VirtualSize))

        for i in range(0, len(data) - 4, 4):
            val = struct.unpack_from("<I", data, i)[0]
            col_rva = _to_rva(pe, val, is_64)
            if col_rva <= 0:
                continue
            col_sig = _read_u32(pe, col_rva)
            if col_sig != expected_sig:
                continue

            # The 4-byte COL reference sits at vtable-4, so vtable VA is here + 4
            vtable_va = base + sec_rva + i + 4
            result = resolve_vtable(pe, vtable_va)
            if result is not None and result.name not in seen:
                seen[result.name] = result

    return list(seen.values())


def cmd_vtable(pe: pefile.PE, args):
    vtable_va = int(args.va, 16)
    result = resolve_vtable(pe, vtable_va)
    if result is None:
        base = pe.OPTIONAL_HEADER.ImageBase
        is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
        vtable_rva = vtable_va - base
        col_ref = _read_u32(pe, vtable_rva - 4)
        if col_ref is None:
            _fail(f"Cannot read COL reference at vtable-4 "
                  f"(vtable RVA 0x{vtable_rva:X}). Is this a valid vtable address?")
        col_rva = _to_rva(pe, col_ref, is_64)
        if col_rva <= 0:
            _fail(f"COL reference at vtable-4 is 0x{col_ref:X} which yields "
                  f"invalid RVA 0x{col_rva:X}. Not a valid RTTI vtable.")
        _fail(f"RTTI resolution failed at vtable 0x{vtable_va:X}. "
              f"Binary may lack RTTI or address is not a vtable.")
    print(f"Class: {result.name}")
    if result.hierarchy:
        print(f"Hierarchy: {' -> '.join(result.hierarchy)}")


def cmd_throwinfo(pe: pefile.PE, args):
    base = pe.OPTIONAL_HEADER.ImageBase
    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    ti_input = int(args.rva, 16)

    # x64: input is an RVA. x86: input is a VA.
    ti_rva = ti_input if is_64 else ti_input - base
    if ti_rva <= 0:
        _fail(f"ThrowInfo RVA 0x{ti_rva:X} is invalid. For 32-bit binaries, "
              f"pass the absolute VA (not RVA).")

    cta_ref = _read_u32(pe, ti_rva + 0x0C)
    if cta_ref is None or cta_ref == 0:
        _fail(f"Cannot read CatchableTypeArray pointer from ThrowInfo "
              f"at RVA 0x{ti_rva:X}.")
    cta_rva = _to_rva(pe, cta_ref, is_64)

    n_types = _read_u32(pe, cta_rva)
    if n_types is None or n_types == 0 or n_types > MAX_CATCHABLE:
        _fail(f"CatchableTypeArray at RVA 0x{cta_rva:X} reports {n_types} "
              f"types (expected 1-{MAX_CATCHABLE}).")

    name_off = 16 if is_64 else 8
    print(f"Catchable types ({n_types}):\n")
    for i in range(n_types):
        ct_ref = _read_u32(pe, cta_rva + 4 + i * 4)
        if ct_ref is None:
            print(f"  [{i}] (unreadable)")
            continue
        ct_rva = _to_rva(pe, ct_ref, is_64)

        td_ref = _read_u32(pe, ct_rva + 4)
        if td_ref is None:
            print(f"  [{i}] (unreadable TypeDescriptor)")
            continue
        td_rva = _to_rva(pe, td_ref, is_64)

        type_name = _read_cstring(pe, td_rva + name_off)
        if type_name:
            print(f"  [{i}] {type_name}")
        else:
            print(f"  [{i}] (unreadable name at TD RVA 0x{td_rva:X})")


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("vtable",
                       help="Resolve class name + hierarchy from vtable VA")
    s.add_argument("va", help="Vtable virtual address in hex")

    s = sub.add_parser("throwinfo",
                       help="Resolve exception types from _ThrowInfo RVA/VA")
    s.add_argument("rva",
                   help="ThrowInfo RVA (64-bit) or VA (32-bit) in hex")

    args = p.parse_args()
    pe = pefile.PE(args.binary, fast_load=False)
    {"vtable": cmd_vtable, "throwinfo": cmd_throwinfo}[args.command](pe, args)


if __name__ == "__main__":
    main()
