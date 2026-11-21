"""Find Direct3DCreate9 IAT entries, call sites, and D3DX shader imports.

Discovers:
  - IAT entries for d3d9.dll and d3dx9_*.dll
  - Direct3DCreate9 call sites in executable sections
  - D3DX shader-related function call sites
  - D3D9-related strings (dynamic loading detection)

Usage:
    python find_d3d_calls.py <game.exe>
"""
import argparse
import sys

_EXECUTABLE = 0x20000000
_CALL_INDIRECT = b'\xFF\x15'      # call [abs32] on x86, call [rip+rel32] on x64
_CALL_INDIRECT_SIZE = 6


def iat_call_sites(pe, iat_va, is_64):
    """Addresses of the ``call [iat_va]`` instructions in the executable sections.

    x86 code names the IAT slot by its absolute address; x64 code by its
    distance from the end of the call. A REX-prefixed x64 call is reported
    at its FF 15 opcode, one byte past the prefix.
    """
    image_base = pe.OPTIONAL_HEADER.ImageBase
    pattern = _CALL_INDIRECT if is_64 else _CALL_INDIRECT + iat_va.to_bytes(4, 'little')
    for section in pe.sections:
        if not section.Characteristics & _EXECUTABLE:
            continue
        data = section.get_data()
        section_va = image_base + section.VirtualAddress
        idx = data.find(pattern)
        while idx != -1:
            call_va = section_va + idx
            if not is_64:
                yield call_va
            else:
                rel32 = int.from_bytes(data[idx + 2:idx + _CALL_INDIRECT_SIZE], 'little', signed=True)
                if call_va + _CALL_INDIRECT_SIZE + rel32 == iat_va:
                    yield call_va
            idx = data.find(pattern, idx + 1)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    args = p.parse_args()

    try:
        import pefile
    except ImportError:
        print("ERROR: pefile not installed. Run: pip install pefile")
        sys.exit(1)

    try:
        pe = pefile.PE(args.binary)
    except (OSError, pefile.PEFormatError) as exc:
        sys.exit(f"ERROR: {args.binary}: {exc}")
    image_base = pe.OPTIONAL_HEADER.ImageBase
    is_64 = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
    print(f"ImageBase: 0x{image_base:08X}")
    print(f"Machine: 0x{pe.FILE_HEADER.Machine:04X}")

    # --- IAT entries ---
    print("\n=== D3D-related IAT entries ===")
    imports = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
    if not imports:
        print("  (no import directory found — binary may be packed or obfuscated)")
    d3d9_iat_va = None
    for entry in imports:
        dll = entry.dll.decode()
        if "d3d" in dll.lower():
            print(f"\nDLL: {dll}")
            for imp in entry.imports:
                name = imp.name.decode() if imp.name else f"ord#{imp.ordinal}"
                print(f"  IAT: 0x{imp.address:08X}  {name}")
                if name == "Direct3DCreate9":
                    d3d9_iat_va = imp.address

    # --- Delay imports ---
    print("\n=== D3D delay imports ===")
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll = entry.dll.decode()
            if 'd3d' in dll.lower():
                print(f"DLL: {dll}")
                for imp in entry.imports:
                    name = imp.name.decode() if imp.name else f"ord#{imp.ordinal}"
                    print(f"  IAT: 0x{imp.address:08X}  {name}")
    else:
        print("  (none)")

    # --- Direct3DCreate9 call sites ---
    print(f"\n=== Direct3DCreate9 call sites ===")
    if d3d9_iat_va is None:
        print("  (Direct3DCreate9 not found in IAT — may be loaded via GetProcAddress)")
    else:
        print(f"  IAT entry at 0x{d3d9_iat_va:08X}")
        call_count = 0
        for call_va in iat_call_sites(pe, d3d9_iat_va, is_64):
            print(f"  0x{call_va:08X}: call [Direct3DCreate9]")
            call_count += 1
        if call_count == 0:
            print("  (0 call sites found — may use indirect/dynamic dispatch)")

    # --- D3DX shader function call sites ---
    print("\n=== D3DX shader/vertex function call sites ===")
    d3dx_call_count = 0
    for entry in imports:
        dll = entry.dll.decode()
        if "d3dx" in dll.lower():
            for imp in entry.imports:
                name = imp.name.decode() if imp.name else ""
                if any(k in name for k in ["Shader", "Vertex", "Pixel", "Constant", "Effect"]):
                    for call_va in iat_call_sites(pe, imp.address, is_64):
                        print(f"  0x{call_va:08X}: call [{name}]")
                        d3dx_call_count += 1
    if d3dx_call_count == 0:
        print("  (no D3DX shader/vertex call sites found — D3DX may not be used)")

    # --- D3D9-related strings (dynamic loading) ---
    print("\n=== D3D-related strings ===")
    for section in pe.sections:
        data = section.get_data()
        section_va = image_base + section.VirtualAddress
        name = section.Name.rstrip(b'\x00').decode(errors='replace')

        for needle in [b'd3d9.dll', b'D3D9.DLL', b'd3d9', b'd3dx9', b'D3DX9',
                       b'Direct3DCreate9', b'Direct3DCreate9Ex']:
            pos = 0
            while True:
                idx = data.find(needle, pos)
                if idx == -1:
                    break
                ref_va = section_va + idx
                start = max(0, idx - 4)
                end = min(len(data), idx + 40)
                ctx = data[start:end]
                null_idx = ctx.find(b'\x00', 4)
                if null_idx > 0:
                    ctx = ctx[:null_idx]
                printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
                print(f"  [{name}] 0x{ref_va:08X}: {printable}")
                pos = idx + 1

    print("\n--- DONE ---")

if __name__ == "__main__":
    main()
