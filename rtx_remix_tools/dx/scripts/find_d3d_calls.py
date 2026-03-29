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
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "retools"))

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    args = p.parse_args()

    try:
        import pefile
    except ImportError:
        print("ERROR: pefile not installed. Run: pip install pefile")
        sys.exit(1)

    pe = pefile.PE(args.binary)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"ImageBase: 0x{image_base:08X}")
    print(f"Machine: 0x{pe.FILE_HEADER.Machine:04X}")

    # --- IAT entries ---
    print("\n=== D3D-related IAT entries ===")
    d3d9_iat_va = None
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("  (no import directory found — binary may be packed or obfuscated)")
        print("\n--- DONE ---")
        return
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
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
        iat_bytes = d3d9_iat_va.to_bytes(4, 'little')
        call_pattern = b'\xFF\x15' + iat_bytes
        print(f"  IAT entry at 0x{d3d9_iat_va:08X}")
        call_count = 0
        for section in pe.sections:
            if section.Characteristics & 0x20000000:
                data = section.get_data()
                section_va = image_base + section.VirtualAddress
                pos = 0
                while True:
                    idx = data.find(call_pattern, pos)
                    if idx == -1:
                        break
                    call_va = section_va + idx
                    print(f"  0x{call_va:08X}: call [Direct3DCreate9]")
                    call_count += 1
                    pos = idx + 1
        if call_count == 0:
            print("  (0 call sites found — may use indirect/dynamic dispatch)")

    # --- D3DX shader function call sites ---
    print("\n=== D3DX shader/vertex function call sites ===")
    d3dx_call_count = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        if "d3dx" in dll.lower():
            for imp in entry.imports:
                name = imp.name.decode() if imp.name else ""
                if any(k in name for k in ["Shader", "Vertex", "Pixel", "Constant", "Effect"]):
                    iat_va2 = imp.address
                    iat_bytes2 = iat_va2.to_bytes(4, 'little')
                    call_pat2 = b'\xFF\x15' + iat_bytes2

                    for section in pe.sections:
                        if section.Characteristics & 0x20000000:
                            data = section.get_data()
                            section_va = image_base + section.VirtualAddress
                            pos = 0
                            while True:
                                idx = data.find(call_pat2, pos)
                                if idx == -1:
                                    break
                                call_va = section_va + idx
                                print(f"  0x{call_va:08X}: call [{name}]")
                                d3dx_call_count += 1
                                pos = idx + 1
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
