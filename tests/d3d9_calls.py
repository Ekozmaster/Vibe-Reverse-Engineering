"""Hand-assembled 32-bit D3D9 device calls with known arguments.

The DX scanner scripts read call arguments out of machine code. These helpers
build that code byte by byte, so a test states the arguments a call was given
and checks that a scanner reports exactly those. ``write_pe32`` wraps the code
in the smallest PE32 file the scripts will load.
"""

import struct
from pathlib import Path

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
TEXT_VA = IMAGE_BASE + TEXT_RVA

_FILE_ALIGNMENT = 0x200
_PADDING = bytes([0xCC]) * 16

PUSH_EAX = bytes([0x50])
PUSH_ECX = bytes([0x51])
PUSH_ESI = bytes([0x56])


def push(value: int) -> bytes:
    """``push imm8`` when the value fits a signed byte, else ``push imm32``."""
    if 0 <= value <= 0x7F:
        return bytes([0x6A, value])
    return bytes([0x68]) + struct.pack("<I", value)


def push32(value: int) -> bytes:
    """``push imm32`` whatever the value."""
    return bytes([0x68]) + struct.pack("<I", value)


def call_method(vtable_offset: int, short: bool = False) -> bytes:
    """``call [edx + vtable_offset]``, in the disp8 form when *short*."""
    if short:
        return bytes([0xFF, 0x52, vtable_offset])
    return bytes([0xFF, 0x92]) + struct.pack("<I", vtable_offset)


def function(*chunks: bytes) -> bytes:
    """A framed function holding *chunks*, followed by int3 padding."""
    return bytes([0x55, 0x8B, 0xEC]) + b"".join(chunks) + bytes([0x5D, 0xC3]) + _PADDING


class Code:
    """Functions laid out one after another, with the address of each call in them.

    Attributes:
        data: The bytes of the code section.
        calls: Label -> virtual address of the last instruction of the function
            added under that label, which is the method call when the function
            ends with one.
    """

    def __init__(self):
        self.data = _PADDING
        self.calls: dict[str, int] = {}

    def add(self, label: str, *chunks: bytes) -> "Code":
        """Append a function made of *chunks*; record where its last chunk starts."""
        body_start = len(self.data) + 3
        self.calls[label] = TEXT_VA + body_start + sum(len(c) for c in chunks[:-1])
        self.data += function(*chunks)
        return self

    def add_data(self, label: str, blob: bytes) -> int:
        """Append *blob* as data and return its virtual address."""
        va = TEXT_VA + len(self.data)
        self.calls[label] = va
        self.data += blob + _PADDING
        return va


def _pe_headers(optional_magic: int, optional_size: int, machine: int, code_size: int) -> bytes:
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", machine, 1, 0, 0, 0, optional_size, 0x0102)
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, optional_magic)
    if optional_magic == 0x10B:
        struct.pack_into("<I", optional, 28, IMAGE_BASE)
    else:
        struct.pack_into("<Q", optional, 24, IMAGE_BASE)
    section = struct.pack("<8sIIIIIIHHI", b".text", code_size, TEXT_RVA, code_size,
                          _FILE_ALIGNMENT, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + coff + bytes(optional) + section
    return headers.ljust(_FILE_ALIGNMENT, b"\0")


def write_pe32(path: Path, code: bytes) -> Path:
    """Write a PE32 file whose one executable section holds *code* at TEXT_VA."""
    path.write_bytes(_pe_headers(0x10B, 0xE0, 0x14C, len(code)) + code)
    return path


def write_pe32_plus(path: Path, code: bytes) -> Path:
    """Write a 64-bit PE32+ file with the same layout."""
    path.write_bytes(_pe_headers(0x20B, 0xF0, 0x8664, len(code)) + code)
    return path
