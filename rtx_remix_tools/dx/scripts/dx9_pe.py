"""PE32 parsing and the loading every DX scanner script starts with."""
import struct
import sys
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════
# PE Parsing
# ═══════════════════════════════════════════════════════════════════════

_PE32_MAGIC = 0x10B
_PE32_PLUS_MAGIC = 0x20B
_OPTIONAL_HEADER_OFFSET = 24
_IMAGE_BASE_OFFSET = 52
_OPTIONAL_HEADER_SIZE_OFFSET = 20
# In a PE32 optional header: the count of data directories, then (rva, size) for each
_DIRECTORY_COUNT_OFFSET = 92
_DIRECTORIES_OFFSET = 96
_LOAD_CONFIG_DIRECTORY = 10
# In IMAGE_LOAD_CONFIG_DIRECTORY32, which starts with its own size
_GUARD_CF_CHECK_FUNCTION_POINTER_OFFSET = 72


def parse_pe(data):
    """Parse PE32 headers. Returns (image_base, sections).

    Each section: dict with name, va, raw, rawsz, vsz, chars.

    Raises:
        ValueError: *data* is not a PE file, is not a 32-bit one, or its
            section table runs past the end of the file.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file (no MZ header)")
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    if (data[pe_sig_off:pe_sig_off + 4] != b"PE\0\0"
            or len(data) < pe_sig_off + _IMAGE_BASE_OFFSET + 4):
        raise ValueError("not a PE file (no PE signature)")
    magic = struct.unpack_from("<H", data, pe_sig_off + _OPTIONAL_HEADER_OFFSET)[0]
    if magic == _PE32_PLUS_MAGIC:
        raise ValueError("64-bit binary (PE32+); these scanners read 32-bit D3D9 call sites only")
    if magic != _PE32_MAGIC:
        raise ValueError(f"not a PE32 file (optional header magic 0x{magic:X})")
    image_base = struct.unpack_from("<I", data, pe_sig_off + _IMAGE_BASE_OFFSET)[0]
    num_sections = struct.unpack_from("<H", data, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_sig_off + 20)[0]
    section_start = pe_sig_off + 24 + opt_hdr_size
    if section_start + num_sections * 40 > len(data):
        raise ValueError(f"section table of {num_sections} sections runs past the end of the file")
    sections = []
    for i in range(num_sections):
        off = section_start + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        s_vsz = struct.unpack_from("<I", data, off + 8)[0]
        s_va = struct.unpack_from("<I", data, off + 12)[0]
        s_rawsz = struct.unpack_from("<I", data, off + 16)[0]
        s_raw = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({
            'name': name, 'va': s_va, 'raw': s_raw,
            'rawsz': s_rawsz, 'vsz': s_vsz, 'chars': chars,
        })
    return image_base, sections


def va_to_offset(sections, image_base, va):
    """Convert virtual address to file offset.

    Returns None if unmapped, or in the part of a section the file holds no
    bytes for: a section can be larger in memory than in the file.
    """
    rva = va - image_base
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vsz']:
            offset = rva - s['va']
            return s['raw'] + offset if offset < s['rawsz'] else None
    return None


def offset_to_va(sections, image_base, file_off):
    """Convert file offset to virtual address. Returns None if unmapped."""
    for s in sections:
        if s['raw'] <= file_off < s['raw'] + s['rawsz']:
            return image_base + s['va'] + (file_off - s['raw'])
    return None


def guard_check_pointer(data, sections):
    """Address of the pointer the image calls its Control Flow Guard check through, None when it has none.

    That is GuardCFCheckFunctionPointer of the load configuration directory.
    A linker from before Control Flow Guard wrote a shorter directory, whose
    own size field ends before it. None too when the headers name no load
    configuration, when the bytes it is said to lie in are not all in one
    section of the file, and when the field is zero.
    """
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_sig_off + _OPTIONAL_HEADER_OFFSET
    entry = _DIRECTORIES_OFFSET + 8 * _LOAD_CONFIG_DIRECTORY
    optional_size = struct.unpack_from("<H", data, pe_sig_off + _OPTIONAL_HEADER_SIZE_OFFSET)[0]
    if optional_size < entry + 8:
        return None
    if struct.unpack_from("<I", data, optional + _DIRECTORY_COUNT_OFFSET)[0] <= _LOAD_CONFIG_DIRECTORY:
        return None
    config_rva = struct.unpack_from("<I", data, optional + entry)[0]
    field_end = _GUARD_CF_CHECK_FUNCTION_POINTER_OFFSET + 4
    config = _section_bytes(data, sections, config_rva, field_end)
    if config is None or struct.unpack_from("<I", config)[0] < field_end:
        return None
    return struct.unpack_from("<I", config, _GUARD_CF_CHECK_FUNCTION_POINTER_OFFSET)[0] or None


def _section_bytes(data, sections, rva, size):
    """The *size* bytes at *rva*, None unless the file holds them all in one section."""
    for s in sections:
        offset = rva - s['va']
        if 0 <= offset and offset + size <= s['rawsz']:
            held = data[s['raw'] + offset:s['raw'] + offset + size]
            return held if len(held) == size else None
    return None


class CodeSection(bytes):
    """The bytes of a section of code, with what the headers of its image say about the code.

    Attributes:
        guard_check_pointer: See guard_check_pointer. Two sections of the
            same bytes are different code when it differs.
    """

    def __new__(cls, code, guard_check_pointer=None):
        section = super().__new__(cls, code)
        section.guard_check_pointer = guard_check_pointer
        return section

    def __eq__(self, other):
        return (isinstance(other, CodeSection) and self.guard_check_pointer == other.guard_check_pointer
                and bytes.__eq__(self, other))

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((bytes.__hash__(self), self.guard_check_pointer))


def code_section(data, sections, raw_start, raw_size):
    """The CodeSection of the *raw_size* bytes of the file at *raw_start*."""
    return CodeSection(data[raw_start:raw_start + raw_size], guard_check_pointer(data, sections))


def find_text_section(data, image_base, sections):
    """Return (raw_offset, raw_size, section_va) for first executable section."""
    for s in sections:
        if s['chars'] & 0x20000000:
            return s['raw'], s['rawsz'], image_base + s['va']
    return None, None, None


# ═══════════════════════════════════════════════════════════════════════
# Standard CLI Setup
# ═══════════════════════════════════════════════════════════════════════

def load_binary(path):
    """Read binary + parse PE. Returns (data, image_base, sections).

    Exits with a message for a file these scanners cannot read: one that is
    missing or cannot be opened, is not a PE, or is a 64-bit one.
    """
    try:
        data = Path(path).read_bytes()
        image_base, sections = parse_pe(data)
    except OSError as exc:
        sys.exit(f"ERROR: {path}: {exc.strerror}")
    except ValueError as exc:
        sys.exit(f"ERROR: {path}: {exc}")
    return data, image_base, sections


def load_text_section(data, image_base, sections):
    """Load first executable section. Returns (its CodeSection, text_va) or exits."""
    raw_start, raw_size, text_va = find_text_section(data, image_base, sections)
    if raw_start is None:
        print("ERROR: no executable section found")
        sys.exit(1)
    return code_section(data, sections, raw_start, raw_size), text_va


def print_header(data, image_base, sections):
    """Print standard binary info header."""
    _, _, text_va = find_text_section(data, image_base, sections)
    print(f"ImageBase: 0x{image_base:08X}")
    if text_va:
        print(f"Executable section VA: 0x{text_va:08X}")
