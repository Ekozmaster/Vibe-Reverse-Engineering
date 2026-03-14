"""Find SetVertexShaderConstantF call sites and analyze arguments.

Scans for call [reg+0x178] patterns (D3D9 device vtable slot 94) and
inspects push instructions before each call to determine the start
register and count being written.

Also scans for DrawIndexedPrimitive, SetVertexDeclaration, and
CreateVertexDeclaration call sites.

Usage:
    python find_vs_constants.py <game.exe>
"""
import sys
import struct
from pathlib import Path

def parse_pe(data):
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    image_base = struct.unpack_from("<I", data, pe_sig_off + 52)[0]
    num_sections = struct.unpack_from("<H", data, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_sig_off + 20)[0]
    section_start = pe_sig_off + 24 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = section_start + i * 40
        s_vsz = struct.unpack_from("<I", data, off + 8)[0]
        s_va = struct.unpack_from("<I", data, off + 12)[0]
        s_rawsz = struct.unpack_from("<I", data, off + 16)[0]
        s_raw = struct.unpack_from("<I", data, off + 20)[0]
        sections.append((s_va, s_raw, s_rawsz, s_vsz))
    return image_base, sections

def va_to_offset(sections, image_base, va):
    rva = va - image_base
    for s_va, s_raw, s_rawsz, s_vsz in sections:
        if s_va <= rva < s_va + s_vsz:
            return rva - s_va + s_raw
    return None

def find_text(data, image_base, sections):
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    num_sections = struct.unpack_from("<H", data, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_sig_off + 20)[0]
    section_start = pe_sig_off + 24 + opt_hdr_size
    for i in range(num_sections):
        off = section_start + i * 40
        chars = struct.unpack_from("<I", data, off + 36)[0]
        if chars & 0x20000000:
            s_va = struct.unpack_from("<I", data, off + 12)[0]
            s_raw = struct.unpack_from("<I", data, off + 20)[0]
            s_rawsz = struct.unpack_from("<I", data, off + 16)[0]
            return s_raw, s_rawsz, image_base + s_va
    return None, None, None

def scan_vtable_calls(text_data, text_va, vtable_offset):
    """Find call [reg+vtable_offset] patterns."""
    regs = {0x90: 'eax', 0x91: 'ecx', 0x92: 'edx', 0x93: 'ebx',
            0x96: 'esi', 0x97: 'edi'}
    results = []
    offset_bytes = struct.pack('<I', vtable_offset)
    for mod_rm, reg_name in regs.items():
        pattern = bytes([0xFF, mod_rm]) + offset_bytes
        pos = 0
        while True:
            idx = text_data.find(pattern, pos)
            if idx == -1:
                break
            va = text_va + idx
            results.append((va, reg_name))
            pos = idx + 1
    results.sort()
    return results

def scan_vtable_mov(text_data, text_va, vtable_offset):
    """Find mov reg, [reg+vtable_offset] patterns (indirect dispatch)."""
    dst_regs = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}
    src_regs = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}
    results = []
    offset_bytes = struct.pack('<I', vtable_offset)
    for src_idx, src_name in src_regs.items():
        for dst_idx, dst_name in dst_regs.items():
            modrm = 0x80 | (dst_idx << 3) | src_idx
            pattern = bytes([0x8B, modrm]) + offset_bytes
            pos = 0
            while True:
                idx = text_data.find(pattern, pos)
                if idx == -1:
                    break
                va = text_va + idx
                results.append((va, f"mov {dst_name}, [{src_name}+0x{vtable_offset:03X}]"))
                pos = idx + 1
    results.sort()
    return results

def analyze_pushes(data, sections, image_base, raw_start, text_va, call_va):
    """Analyze push instructions before a call to find arguments."""
    file_off = va_to_offset(sections, image_base, call_va)
    if file_off is None:
        return []
    context_start = max(0, file_off - 40)
    context = data[context_start:file_off + 6]
    pushes = []
    i = 0
    while i < len(context) - 6:
        b = context[i]
        if b == 0x6A:
            val = context[i + 1]
            push_va = call_va - (file_off - context_start - i)
            pushes.append((push_va, val, 'imm8'))
            i += 2
        elif b == 0x68:
            val = struct.unpack_from('<I', context, i + 1)[0]
            push_va = call_va - (file_off - context_start - i)
            pushes.append((push_va, val, 'imm32'))
            i += 5
        else:
            i += 1
    return pushes

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <game.exe>")
        sys.exit(1)

    data = Path(sys.argv[1]).read_bytes()
    image_base, sections = parse_pe(data)
    raw_start, raw_size, text_va = find_text(data, image_base, sections)
    if raw_start is None:
        print("ERROR: No executable section found")
        return
    text_data = data[raw_start:raw_start + raw_size]

    # --- SetVertexShaderConstantF (0x178) ---
    print("=== SetVertexShaderConstantF call sites (call [reg+0x178]) ===")
    results = scan_vtable_calls(text_data, text_va, 0x178)
    for va, reg in results:
        print(f"  0x{va:08X}: call [{reg}+0x178]")
    print(f"Total: {len(results)} direct call sites")

    mov_results = scan_vtable_mov(text_data, text_va, 0x178)
    if mov_results:
        print(f"\n  Indirect dispatch (mov reg, [reg+0x178]): {len(mov_results)} sites")
        for va, desc in mov_results:
            print(f"    0x{va:08X}: {desc}")

    # --- Argument analysis ---
    all_sites = [(va, reg) for va, reg in results]
    all_sites += [(va, 'indirect') for va, _ in mov_results]
    if all_sites:
        print(f"\n=== SetVertexShaderConstantF argument analysis ===")
        for va, reg in all_sites[:50]:
            pushes = analyze_pushes(data, sections, image_base, raw_start, text_va, va)
            if pushes:
                print(f"\n  0x{va:08X}: call [{reg}+0x178]")
                for pva, pval, ptype in pushes[-5:]:
                    print(f"    push {ptype} {pval} (0x{pval:X})")

    # --- DrawIndexedPrimitive (0x148) ---
    print(f"\n\n=== DrawIndexedPrimitive call sites (call [reg+0x148]) ===")
    dip = scan_vtable_calls(text_data, text_va, 0x148)
    for va, reg in dip:
        print(f"  0x{va:08X}: call [{reg}+0x148]")
    print(f"Total: {len(dip)} call sites")
    dip_mov = scan_vtable_mov(text_data, text_va, 0x148)
    if dip_mov:
        print(f"  Indirect: {len(dip_mov)} sites")
        for va, desc in dip_mov:
            print(f"    0x{va:08X}: {desc}")

    # --- SetVertexDeclaration (0x15C) ---
    print(f"\n=== SetVertexDeclaration call sites (call [reg+0x15C]) ===")
    svd = scan_vtable_calls(text_data, text_va, 0x15C)
    for va, reg in svd:
        print(f"  0x{va:08X}: call [{reg}+0x15C]")
    print(f"Total: {len(svd)} call sites")
    svd_mov = scan_vtable_mov(text_data, text_va, 0x15C)
    if svd_mov:
        print(f"  Indirect: {len(svd_mov)} sites")
        for va, desc in svd_mov:
            print(f"    0x{va:08X}: {desc}")

    # --- CreateVertexDeclaration (0x158) ---
    print(f"\n=== CreateVertexDeclaration call sites (call [reg+0x158]) ===")
    cvd = scan_vtable_calls(text_data, text_va, 0x158)
    for va, reg in cvd:
        print(f"  0x{va:08X}: call [{reg}+0x158]")
    print(f"Total: {len(cvd)} call sites")
    cvd_mov = scan_vtable_mov(text_data, text_va, 0x158)
    if cvd_mov:
        print(f"  Indirect: {len(cvd_mov)} sites")
        for va, desc in cvd_mov:
            print(f"    0x{va:08X}: {desc}")

    print("\n--- DONE ---")

if __name__ == "__main__":
    main()
