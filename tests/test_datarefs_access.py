"""datarefs: how each reference to a global uses it, and what ``--access`` keeps."""

import struct

import pytest

from pe_fakes import CODE_VA, IMAGE_BASE, binary_from_sections, binary_over, fake_section

import datarefs

GLOBAL_VA = IMAGE_BASE + 0x2000


def _x86_code() -> tuple[bytes, dict[str, int]]:
    """Four instructions on the global through its absolute address."""
    target = struct.pack("<I", GLOBAL_VA)
    parts = {
        "load": bytes([0xA1]) + target,                          # mov eax, [GLOBAL]
        "store": bytes([0xA3]) + target,                         # mov [GLOBAL], eax
        "add": bytes([0x83, 0x05]) + target + bytes([0x01]),     # add dword ptr [GLOBAL], 1
        "compare": bytes([0x83, 0x3D]) + target + bytes([0x00]),  # cmp dword ptr [GLOBAL], 0
    }
    return _placed(parts)


def _x64_code() -> tuple[bytes, dict[str, int]]:
    """The same four through RIP-relative operands."""
    def relative(prefix: bytes, at: int, suffix: bytes = b"") -> bytes:
        size = len(prefix) + 4 + len(suffix)
        return prefix + struct.pack("<i", GLOBAL_VA - (at + size)) + suffix

    code, where = b"", {}
    for name, prefix, suffix in [
        ("load", bytes([0x48, 0x8B, 0x05]), b""),                # mov rax, [rip + d]
        ("store", bytes([0x48, 0x89, 0x05]), b""),               # mov [rip + d], rax
        ("add", bytes([0x83, 0x05]), bytes([0x01])),             # add dword ptr [rip + d], 1
        ("compare", bytes([0x48, 0x83, 0x3D]), bytes([0xFE])),   # cmp qword ptr [rip + d], -2
    ]:
        where[name] = CODE_VA + len(code)
        code += relative(prefix, where[name], suffix)
    return code + bytes([0xC3]), where


def _placed(parts: dict[str, bytes]) -> tuple[bytes, dict[str, int]]:
    code, where = b"", {}
    for name, encoded in parts.items():
        where[name] = CODE_VA + len(code)
        code += encoded
    return code + bytes([0xC3]), where


@pytest.fixture(params=["x86", "x64"])
def references(request):
    """(binary, {name: address}) with a load, a store, an add and a compare on GLOBAL_VA."""
    if request.param == "x86":
        code, where = _x86_code()
        return binary_over(code), where
    code, where = _x64_code()
    section = fake_section(CODE_VA - IMAGE_BASE, len(code), 0, len(code), executable=True)
    return binary_from_sections(code, [section], is_64=True), where


def _labels(b, access=None) -> dict[int, str]:
    return {va: label for va, _mnemonic, _operands, label in datarefs.scan(b, GLOBAL_VA, 4, access)}


def test_each_reference_is_labelled_by_what_it_does(references):
    b, where = references
    assert _labels(b) == {where["load"]: "r", where["store"]: "w", where["add"]: "rw", where["compare"]: "r"}


def test_write_filter_keeps_everything_that_writes(references):
    b, where = references
    assert sorted(_labels(b, "w")) == [where["store"], where["add"]]


def test_read_filter_keeps_everything_that_reads(references):
    b, where = references
    assert sorted(_labels(b, "r")) == [where["load"], where["add"], where["compare"]]


def test_read_write_filter_keeps_only_what_does_both(references):
    b, where = references
    assert sorted(_labels(b, "rw")) == [where["add"]]
