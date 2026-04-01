"""Find CreateVertexShader/CreatePixelShader calls and extract shader bytecode.

Scans for shader creation call sites, follows the pushed bytecode pointer,
validates the shader version token, and reports:
  - Shader type (vs/ps) and version (e.g. vs_2_0, ps_3_0)
  - Bytecode size in bytes/DWORDs
  - Instruction count estimate
  - Optionally dumps raw bytecode to files

The shader bytecode format starts with a version token (0xFFFEmmMM for VS,
0xFFFFmmMM for PS) and ends with 0x0000FFFF.

Usage:
    python find_shader_bytecode.py <game.exe>
    python find_shader_bytecode.py <game.exe> --dump-dir ./shaders
"""
import argparse
import sys
import struct
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dx9_common import (
    load_binary, load_text_section, print_header,
    scan_vtable_calls, scan_vtable_mov,
    find_push_addr_near_call, va_to_offset,
    validate_shader_token, find_shader_end,
)

CREATE_VS = 0x16C  # CreateVertexShader
CREATE_PS = 0x1A8  # CreatePixelShader


def find_shaders(data, sections, image_base, text_data, text_va, vtable_offset, label):
    """Find shader bytecode at creation call sites.

    Returns: [(shader_va, shader_type, major, minor, byte_length), ...]
    """
    direct = scan_vtable_calls(text_data, text_va, vtable_offset)
    indirect = scan_vtable_mov(text_data, text_va, vtable_offset)

    print(f"\n=== {label} (vtable+0x{vtable_offset:03X}) ===")
    print(f"  Direct: {len(direct)}, Indirect: {len(indirect)}")

    all_sites = [(va, r) for va, r in direct] + [(va, 'indirect') for va, _ in indirect]
    if not all_sites:
        return []

    # CreateVertexShader(device, pFunction, ppShader)
    # pFunction is a pointer to shader bytecode — pushed as imm32
    found = []
    seen_addrs = set()

    for va, reg in all_sites:
        addr_pushes = find_push_addr_near_call(data, sections, image_base, va, window=60)
        for push_va, target_va in addr_pushes:
            if target_va in seen_addrs:
                continue
            file_off = va_to_offset(sections, image_base, target_va)
            if file_off is None:
                continue
            info = validate_shader_token(data, file_off)
            if info is None:
                continue
            shader_type, major, minor = info
            byte_len = find_shader_end(data, file_off)
            if byte_len is None:
                continue
            seen_addrs.add(target_va)
            found.append((target_va, shader_type, major, minor, byte_len))

    return found


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("binary", help="Path to PE binary (.exe / .dll)")
    p.add_argument("--dump-dir", type=Path, metavar="DIR",
                   help="Directory to dump shader bytecode files")
    args = p.parse_args()

    data, image_base, sections = load_binary(args.binary)
    text_data, text_va = load_text_section(data, image_base, sections)
    print_header(data, image_base, sections)

    if args.dump_dir:
        args.dump_dir.mkdir(parents=True, exist_ok=True)

    all_shaders = []

    for offset, label in [(CREATE_VS, "CreateVertexShader"),
                           (CREATE_PS, "CreatePixelShader")]:
        shaders = find_shaders(data, sections, image_base,
                               text_data, text_va, offset, label)
        all_shaders.extend(shaders)

        if not shaders:
            print(f"  No shader bytecode found at call sites.")
            print(f"  (shaders may be loaded from files or compiled at runtime)")
            continue

        for shader_va, stype, major, minor, byte_len in shaders:
            dword_count = byte_len // 4
            # Rough instruction estimate: subtract version + end tokens
            inst_estimate = max(0, dword_count - 2)
            version_str = f"{stype}_{major}_{minor}"

            print(f"\n  0x{shader_va:08X}: {version_str}")
            print(f"    Size: {byte_len} bytes ({dword_count} DWORDs)")
            print(f"    Instructions: ~{inst_estimate} tokens")

            if args.dump_dir:
                file_off = va_to_offset(sections, image_base, shader_va)
                bytecode = data[file_off:file_off + byte_len]
                fname = f"{version_str}_0x{shader_va:08X}.bin"
                out_path = args.dump_dir / fname
                out_path.write_bytes(bytecode)
                print(f"    Dumped to: {out_path}")

    # -- Summary --
    print(f"\n{'='*60}")
    print(f"=== Shader Bytecode Summary ===")
    print(f"{'='*60}")

    vs_shaders = [s for s in all_shaders if s[1] == 'vs']
    ps_shaders = [s for s in all_shaders if s[1] == 'ps']

    print(f"\n  Vertex shaders: {len(vs_shaders)}")
    print(f"  Pixel shaders:  {len(ps_shaders)}")
    print(f"  Total:          {len(all_shaders)}")

    if all_shaders:
        # Version distribution
        versions = defaultdict(int)
        for _, stype, major, minor, _ in all_shaders:
            versions[f"{stype}_{major}_{minor}"] += 1
        print(f"\n  Shader model distribution:")
        for ver in sorted(versions):
            print(f"    {ver:10s} {versions[ver]:3d} shaders")

        # Size stats
        sizes = [s[4] for s in all_shaders]
        print(f"\n  Bytecode sizes:")
        print(f"    Min:     {min(sizes):6d} bytes")
        print(f"    Max:     {max(sizes):6d} bytes")
        print(f"    Average: {sum(sizes) // len(sizes):6d} bytes")
        print(f"    Total:   {sum(sizes):6d} bytes")

        # Categorize
        small = sum(1 for s in sizes if s < 100)
        medium = sum(1 for s in sizes if 100 <= s < 1000)
        large = sum(1 for s in sizes if s >= 1000)
        if small:
            print(f"    Small  (<100B):   {small} -- likely passthrough/simple")
        if medium:
            print(f"    Medium (100-1KB): {medium} -- typical game shaders")
        if large:
            print(f"    Large  (>1KB):    {large} -- complex effects")
    else:
        print(f"\n  No embedded shaders found.")
        print(f"  Game may: load shaders from .fxo/.cso files, compile from HLSL at")
        print(f"  runtime (D3DXCompileShader), or use the D3DX effect framework.")

    print("\n--- DONE ---")


if __name__ == "__main__":
    main()
