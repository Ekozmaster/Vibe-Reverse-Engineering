"""In-memory stand-ins for a loaded PE, for tests that need no file on disk."""

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
