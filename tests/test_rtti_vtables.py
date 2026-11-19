"""RTTI resolution on an image with one class, built for x86 and for x64.

``Widget`` derives from ``Base``. On x86 every RTTI reference is a virtual
address. On x64 the references inside the RTTI structures are image-relative,
while the slot in front of a vtable holds the full 8-byte address of the
complete object locator.
"""

import struct
import sys
from pathlib import Path

import pefile
import pytest

from d3d9_calls import IMAGE_BASE, TEXT_RVA, write_pe32, write_pe32_plus

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))

import rtti  # noqa: E402

_WIDGET, _BASE = b".?AVWidget@@", b".?AVBase@@"


class _Image:
    """Bytes of one section, with the RVA of everything placed in it."""

    def __init__(self, is_64: bool):
        self.is_64 = is_64
        self.data = bytearray(16)   # nothing sits at the section's first bytes

    def place(self, blob: bytes) -> int:
        """Append *blob* on an 8-byte boundary and return its RVA."""
        self.data += bytes(-len(self.data) % 8)
        rva = TEXT_RVA + len(self.data)
        self.data += blob
        return rva

    def ref(self, rva: int) -> bytes:
        """A reference to *rva* as RTTI structures store it."""
        return struct.pack("<I", rva if self.is_64 else IMAGE_BASE + rva)

    def pointer(self, rva: int) -> bytes:
        return struct.pack("<Q" if self.is_64 else "<I", IMAGE_BASE + rva)


def _build(is_64: bool, tmp_path) -> tuple[pefile.PE, int]:
    """(loaded image, virtual address of Widget's vtable)."""
    image = _Image(is_64)
    pointer_size = 8 if is_64 else 4

    def type_descriptor(name: bytes) -> int:
        return image.place(bytes(2 * pointer_size) + name + b"\0")

    def base_class(type_rva: int) -> int:
        return image.place(image.ref(type_rva) + struct.pack("<IiiiI", 0, 0, -1, 0, 0))

    widget_type, base_type = type_descriptor(_WIDGET), type_descriptor(_BASE)
    base_classes = image.place(image.ref(base_class(widget_type)) + image.ref(base_class(base_type)))
    hierarchy = image.place(struct.pack("<III", 0, 0, 2) + image.ref(base_classes))

    locator = TEXT_RVA + len(image.data) + (-len(image.data) % 8)
    fields = struct.pack("<III", 1 if is_64 else 0, 0, 0) + image.ref(widget_type) + image.ref(hierarchy)
    assert image.place(fields + (image.ref(locator) if is_64 else b"")) == locator

    slot = image.place(image.pointer(locator) + image.pointer(TEXT_RVA) + image.pointer(TEXT_RVA))
    vtable_va = IMAGE_BASE + slot + pointer_size

    # rtti reads names in 256-byte pieces, so the section has to go on that far behind them
    write = write_pe32_plus if is_64 else write_pe32
    path = write(tmp_path / f"rtti{'64' if is_64 else '32'}.dll", bytes(image.data) + bytes(0x200))
    return pefile.PE(str(path)), vtable_va


@pytest.fixture(params=["x86", "x64"])
def widget(request, tmp_path):
    pe, vtable_va = _build(request.param == "x64", tmp_path)
    yield pe, vtable_va
    pe.close()


def test_vtable_resolves_to_its_class_and_bases(widget):
    pe, vtable_va = widget
    found = rtti.resolve_vtable(pe, vtable_va)
    assert found is not None
    assert (found.name, found.hierarchy) == (".?AVWidget@@", [".?AVWidget@@", ".?AVBase@@"])


def test_address_that_is_not_a_vtable_resolves_to_nothing(widget):
    pe, vtable_va = widget
    assert rtti.resolve_vtable(pe, vtable_va + pe.OPTIONAL_HEADER.SizeOfHeaders + 16) is None


def test_scan_reports_the_class_at_its_vtable(widget):
    pe, vtable_va = widget
    assert [(found.name, found.vtable_va) for found in rtti.scan_all_rtti(pe)] == [(".?AVWidget@@", vtable_va)]
