"""In-memory stand-ins for a loaded PE, for tests that need no file on disk."""

import sys
from pathlib import Path
from types import SimpleNamespace

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

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


def binary_from_sections(raw: bytes, sections: list) -> Binary:
    """A 32-bit Binary over *raw* file bytes laid out by *sections*."""
    b = Binary.__new__(Binary)
    b.pe = SimpleNamespace(sections=sections)
    b.raw = raw
    b.base = IMAGE_BASE
    b.is_64 = False
    b.ptr_size = 4
    b._cs = Cs(CS_ARCH_X86, CS_MODE_32)
    b._cs.detail = True
    return b


def binary_over(code: bytes) -> Binary:
    """A 32-bit Binary whose single executable section holds *code* at CODE_VA."""
    section = fake_section(CODE_VA - IMAGE_BASE, len(code), 0, len(code), executable=True)
    return binary_from_sections(code, [section])
