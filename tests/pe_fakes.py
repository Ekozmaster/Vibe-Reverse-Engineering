"""Stand-ins for a PE: in-memory Binary objects, and minimal image files written to disk."""

import struct
import sys
from pathlib import Path
from types import SimpleNamespace

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

from common import Binary

IMAGE_BASE = 0x400000
CODE_VA = 0x401000

_EXECUTABLE = 0x20000000


def fake_section(rva: int, virtual_size: int, raw_offset: int, raw_size: int,
                 executable: bool = False) -> SimpleNamespace:
    """A section header with the fields ``Binary`` reads."""
    return SimpleNamespace(
        VirtualAddress=rva, Misc_VirtualSize=virtual_size,
        PointerToRawData=raw_offset, SizeOfRawData=raw_size,
        Characteristics=_EXECUTABLE if executable else 0,
    )


def binary_from_sections(raw: bytes, sections: list, *, is_64: bool = False,
                         exception_table: tuple[int, int] = (0, 0)) -> Binary:
    """A Binary over *raw* file bytes laid out by *sections*.

    Args:
        raw: The file's bytes.
        sections: Section headers from ``fake_section``.
        is_64: Make it an x64 image; 32-bit otherwise.
        exception_table: (rva, size) of the exception directory, the table of
            function extents an x64 image carries.
    """
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)]
    directories[3] = SimpleNamespace(VirtualAddress=exception_table[0], Size=exception_table[1])
    b = Binary.__new__(Binary)
    b.pe = SimpleNamespace(sections=sections, OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories))
    b.raw = raw
    b.base = IMAGE_BASE
    b.is_64 = is_64
    b.ptr_size = 8 if is_64 else 4
    b._cs = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    b._cs.detail = True
    return b


def binary_over(code: bytes) -> Binary:
    """A 32-bit Binary whose single executable section holds *code* at CODE_VA."""
    section = fake_section(CODE_VA - IMAGE_BASE, len(code), 0, len(code), executable=True)
    return binary_from_sections(code, [section])


# --- PE files on disk ---------------------------------------------------------------------------
# Section i of an image from write_pe sits at file offset 0x200 * (i + 1), 0x200 bytes long.

IMAGE_BASE64 = 0x140000000             # above 4 GB: a VA and its RVA differ beyond the low 32 bits
TEXT_RVA, DATA_RVA = 0x1000, 0x2000
TEXT_RAW, DATA_RAW = 0x200, 0x400
CODE_CHARS = 0x60000020
DATA_CHARS = 0xC0000040
RDATA_CHARS = 0x40000040

_SECTION_SIZE = 0x200
_IMPORT_DIRECTORY = 1


def write_pe(path: Path, sections: list, *, is_64: bool = False,
             import_dir: tuple[int, int] = (0, 0)) -> Path:
    """Write a minimal PE32 or PE32+ image to *path*.

    Args:
        path: Where to write the image.
        sections: (name, rva, content, characteristics) per section, in file order.
            Each section is 0x200 bytes; an executable one is padded with int3, the
            rest with zeros.
        is_64: PE32+ (x64, image base IMAGE_BASE64); PE32 (x86, IMAGE_BASE) otherwise.
        import_dir: (rva, size) of the import directory.

    Returns:
        *path*.
    """
    opt_size = 0xF0 if is_64 else 0xE0
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x8664 if is_64 else 0x14C, len(sections), 0, 0, 0, opt_size,
                       0x22 if is_64 else 0x102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if is_64 else 0x10B)
    struct.pack_into("<I", opt, 20, sections[0][1])                                # BaseOfCode
    if is_64:
        struct.pack_into("<Q", opt, 24, IMAGE_BASE64)
    else:
        struct.pack_into("<I", opt, 28, IMAGE_BASE)
    struct.pack_into("<II", opt, 32, 0x1000, _SECTION_SIZE)                       # alignments
    struct.pack_into("<H", opt, 40, 6)                                            # OS version
    struct.pack_into("<H", opt, 48, 6)                                            # subsystem version
    struct.pack_into("<II", opt, 56, max(rva for _, rva, _, _ in sections) + 0x1000, _SECTION_SIZE)
    struct.pack_into("<H", opt, 68, 3)                                            # console subsystem
    directories = 112 if is_64 else 96
    struct.pack_into("<I", opt, directories - 4, 16)                              # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, directories + 8 * _IMPORT_DIRECTORY, *import_dir)

    headers = bytes(dos) + b"PE\0\0" + coff + bytes(opt)
    body = b""
    for i, (name, rva, content, characteristics) in enumerate(sections):
        raw = _SECTION_SIZE * (i + 1)
        headers += struct.pack("<8sIIIIIIHHI", name, _SECTION_SIZE, rva, _SECTION_SIZE, raw,
                               0, 0, 0, 0, characteristics)
        body += content.ljust(_SECTION_SIZE, b"\xCC" if characteristics & _EXECUTABLE else b"\0")
    path.write_bytes(headers.ljust(_SECTION_SIZE, b"\0") + body)
    return path


def pe_image(path: Path, text: bytes, data: bytes = b"\x11" * 0x200, *, is_64: bool = False,
             data_rva: int = DATA_RVA, import_dir: tuple[int, int] = (0, 0)) -> Path:
    """An image with .text at TEXT_RVA (file offset TEXT_RAW) and .data at *data_rva* (DATA_RAW)."""
    return write_pe(path, [(b".text", TEXT_RVA, text, CODE_CHARS), (b".data", data_rva, data, DATA_CHARS)],
                    is_64=is_64, import_dir=import_dir)
