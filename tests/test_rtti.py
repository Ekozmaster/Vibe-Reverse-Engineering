"""Tests for retools/rtti.py against 32- and 64-bit images laid out like MSVC RTTI.

x86 MSVC RTTI (absolute VAs): the vtable's slot -1 points at the CompleteObjectLocator
{signature 0, offset, cdOffset, pTypeDescriptor, pClassHierarchyDescriptor}; a
TypeDescriptor is {pVFTable, spare, decorated name}; the hierarchy descriptor is
{signature, attributes, numBaseClasses, pBaseClassArray}, whose entries point at base
class descriptors starting with pTypeDescriptor. _ThrowInfo is {attributes, pmfnUnwind,
pForwardCompat, pCatchableTypeArray}; the array is {nCatchableTypes, pCatchableType[]},
and a CatchableType is {properties, pType, ...}. The throwinfo command takes a VA.
"""

import struct
import subprocess
import sys
from pathlib import Path

import pefile
import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "retools"))

import rtti  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, IMAGE_BASE64, pe_image  # noqa: E402

D = IMAGE_BASE + DATA_RVA
TD_DERIVED, TD_BASE = D + 0x00, D + 0x20
BCD_DERIVED, BCD_BASE, BCA, CHD, COL = D + 0x40, D + 0x60, D + 0x80, D + 0x90, D + 0xA0
VTABLE = D + 0xC4                      # COL pointer at VTABLE - 4
THROW_INFO, CTA, CT1, CT2 = D + 0xD0, D + 0xE0, D + 0xF0, D + 0x100
BAD_COL, BAD_VTABLE = D + 0x120, D + 0x144
COL_BASE = D + 0x150
VTABLE_BASE = D + 0x170                # slot -1 at +0x16C: 4-aligned, not a multiple of 12
COL_CUT_TD = D + 0x1F8                 # signature fits, pTypeDesc (+0x0C) lies past the section
COL_CUT_CHD = D + 0x1F0                # pTypeDesc fits, pClassHierDesc (+0x10) lies past the section
VTABLE_CUT_TD, VTABLE_CUT_CHD = D + 0x184, D + 0x18C


def _u32(*vals) -> bytes:
    return struct.pack(f"<{len(vals)}I", *vals)


def _rtti_data() -> bytes:
    data = bytearray(0x200)

    def put(va, blob):
        data[va - D:va - D + len(blob)] = blob

    put(TD_DERIVED, _u32(0, 0) + b".?AVDerived@@\0")
    put(TD_BASE, _u32(0, 0) + b".?AVBase@@\0")
    put(BCD_DERIVED, _u32(TD_DERIVED, 1, 0, 0xFFFFFFFF, 0, 0))
    put(BCD_BASE, _u32(TD_BASE, 0, 0, 0xFFFFFFFF, 0, 0))
    put(BCA, _u32(BCD_DERIVED, BCD_BASE))
    put(CHD, _u32(0, 0, 2, BCA))
    put(COL, _u32(0, 0, 0, TD_DERIVED, CHD))
    put(VTABLE - 4, _u32(COL, IMAGE_BASE + 0x1000, IMAGE_BASE + 0x1010))
    put(THROW_INFO, _u32(0, 0, 0, CTA))
    put(CTA, _u32(2, CT1, CT2))
    put(CT1, _u32(0, TD_DERIVED))
    put(CT2, _u32(0, TD_BASE))
    put(BAD_COL, _u32(1, 0, 0, TD_DERIVED, 0))          # signature 1 is x64-only
    put(BAD_VTABLE - 4, _u32(BAD_COL))
    return bytes(data)


def _image(tmp_path, *patches):
    """The x86 image, with each (va, [u32, ...]) patch written over its data."""
    data = bytearray(_rtti_data())
    for va, vals in patches:
        struct.pack_into(f"<{len(vals)}I", data, va - D, *vals)
    return pe_image(tmp_path / "a.exe", b"\xc3", bytes(data))


def _pe(tmp_path, *patches):
    return pefile.PE(str(_image(tmp_path, *patches)))


@pytest.fixture
def image(tmp_path):
    return _image(tmp_path)


class TestResolve:
    def test_class_and_hierarchy_from_a_vtable(self, image):
        pe = pefile.PE(str(image))
        assert rtti.resolve_vtable(pe, VTABLE) == rtti.RttiClass(
            name=".?AVDerived@@", vtable_va=VTABLE, hierarchy=[".?AVDerived@@", ".?AVBase@@"])

    def test_not_a_vtable(self, image):
        pe = pefile.PE(str(image))
        assert rtti.resolve_vtable(pe, BAD_VTABLE) is None      # x64 COL signature in an x86 image
        assert rtti.resolve_vtable(pe, TD_DERIVED + 4) is None  # slot -1 is not a COL pointer
        assert rtti.resolve_vtable(pe, IMAGE_BASE + 0x9000) is None   # unmapped

    def test_a_class_without_a_hierarchy(self, tmp_path):
        pe = _pe(tmp_path, (COL + 0x10, [0]))                    # pClassHierarchyDescriptor = 0
        assert rtti.resolve_vtable(pe, VTABLE).hierarchy == []

    def test_a_class_with_no_base_lists_only_itself(self, tmp_path):
        pe = _pe(tmp_path, (CHD + 0x08, [1]))                    # numBaseClasses = 1
        assert rtti.resolve_vtable(pe, VTABLE).hierarchy == [".?AVDerived@@"]

    def test_scan_finds_each_class_once(self, image):
        found = rtti.scan_all_rtti(pefile.PE(str(image)))
        assert [(c.name, c.vtable_va) for c in found] == [(".?AVDerived@@", VTABLE)]

    def test_scan_finds_every_class_in_a_section(self, tmp_path):
        pe = _pe(tmp_path, (COL_BASE, [0, 0, 0, TD_BASE, 0]), (VTABLE_BASE - 4, [COL_BASE]))
        found = {(c.name, c.vtable_va) for c in rtti.scan_all_rtti(pe)}
        assert found == {(".?AVDerived@@", VTABLE), (".?AVBase@@", VTABLE_BASE)}


class TestX86FieldsAreVAs:
    def test_a_vtable_rva_is_not_a_vtable_va(self, tmp_path):
        assert rtti.resolve_vtable(_pe(tmp_path), VTABLE - IMAGE_BASE) is None

    def test_a_col_reference_holding_an_rva_is_rejected(self, tmp_path):
        assert rtti.resolve_vtable(_pe(tmp_path, (VTABLE - 4, [COL - IMAGE_BASE])), VTABLE) is None


class TestTruncatedLocator:
    """resolve_vtable returns an RttiClass or None, also for a COL cut off by the image end."""

    def test_a_col_without_a_type_descriptor_is_not_a_vtable(self, tmp_path):
        pe = _pe(tmp_path, (COL_CUT_TD, [0, 0]), (VTABLE_CUT_TD - 4, [COL_CUT_TD]))
        assert rtti.resolve_vtable(pe, VTABLE_CUT_TD) is None

    def test_a_col_without_a_hierarchy_reference_gives_no_hierarchy(self, tmp_path):
        pe = _pe(tmp_path, (COL_CUT_CHD, [0, 0, 0, TD_DERIVED]), (VTABLE_CUT_CHD - 4, [COL_CUT_CHD]))
        assert rtti.resolve_vtable(pe, VTABLE_CUT_CHD) == rtti.RttiClass(
            name=".?AVDerived@@", vtable_va=VTABLE_CUT_CHD, hierarchy=[])

    @pytest.mark.parametrize("patches", [
        [(CHD + 0x0C, [D + 0x1FC]), (D + 0x1FC, [BCD_DERIVED])],             # array cut off by the image end
        [(CHD + 0x0C, [D + 0x1C0]), (D + 0x1C0, [BCD_DERIVED, IMAGE_BASE + 0x9000])],  # base descriptor unmapped
        [(CHD + 0x0C, [D + 0x1C0]), (D + 0x1C0, [BCD_DERIVED, D + 0x1D0]),
         (D + 0x1D0, [CHD])],                                                # base TD without a decorated name
    ])
    def test_a_broken_base_class_array_still_gives_the_class(self, tmp_path, patches):
        found = rtti.resolve_vtable(_pe(tmp_path, *patches), VTABLE)
        assert found.name == ".?AVDerived@@" and found.hierarchy[0] == ".?AVDerived@@"
        assert all(isinstance(base, str) for base in found.hierarchy)


def _main(monkeypatch, capsys, *argv) -> list[str]:
    monkeypatch.setattr(sys, "argv", ["rtti.py", *argv])
    rtti.main()
    return capsys.readouterr().out.splitlines()


def _fails(monkeypatch, capsys, *argv) -> str:
    """Run the CLI expecting exit code 1; returns what it printed to stderr."""
    with pytest.raises(SystemExit) as exc:
        _main(monkeypatch, capsys, *argv)
    assert exc.value.code == 1
    return capsys.readouterr().err


class TestCli:
    def test_vtable(self, image, monkeypatch, capsys):
        assert _main(monkeypatch, capsys, str(image), "vtable", f"{VTABLE:X}") == [
            "Class: .?AVDerived@@", "Hierarchy: .?AVDerived@@ -> .?AVBase@@"]

    def test_vtable_that_is_not_one_fails(self, image, monkeypatch, capsys):
        assert "RTTI resolution failed" in _fails(monkeypatch, capsys, str(image), "vtable", f"{BAD_VTABLE:X}")

    def test_vtable_at_an_unmapped_address_fails_and_says_why(self, image, monkeypatch, capsys):
        err = _fails(monkeypatch, capsys, str(image), "vtable", f"{IMAGE_BASE + 0x9000:X}")
        assert "Cannot read the COL pointer" in err

    def test_throwinfo_lists_the_catchable_types(self, image, monkeypatch, capsys):
        out = _main(monkeypatch, capsys, str(image), "throwinfo", f"{THROW_INFO:X}")
        assert out == ["Catchable types (2):", "", "  [0] .?AVDerived@@", "  [1] .?AVBase@@"]

    def test_throwinfo_without_a_type_array_fails(self, image, monkeypatch, capsys):
        _fails(monkeypatch, capsys, str(image), "throwinfo", f"{TD_BASE + 0x10:X}")

    def test_throwinfo_given_an_rva_on_x86_fails(self, image, monkeypatch, capsys):
        _fails(monkeypatch, capsys, str(image), "throwinfo", f"{THROW_INFO - IMAGE_BASE:X}")

    def test_a_sub_command_is_required(self, image, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            _main(monkeypatch, capsys, str(image))
        assert exc.value.code != 0

    def test_runs_as_a_script(self, image):
        proc = subprocess.run([sys.executable, str(REPO / "retools" / "rtti.py"), str(image),
                               "vtable", f"{VTABLE:X}"], capture_output=True, text=True, timeout=60)
        assert proc.returncode == 0 and proc.stdout.splitlines()[0] == "Class: .?AVDerived@@"


# x64 MSVC RTTI, per the module docstring: the 8-byte slot at vtable - 8 holds the COL's VA;
# the COL has signature 1 and RVA fields, and its pSelf at +0x14 must equal its own RVA; a
# TypeDescriptor is {pVFTable, spare} as 8-byte slots, so the name starts at +16. Every
# reference inside COL / CHD / BCD / _ThrowInfo / CatchableType is an RVA, and throwinfo
# takes an RVA. Each rejected vtable below differs from VTABLE64 in exactly one field.
D64 = IMAGE_BASE64 + DATA_RVA
TD64_DERIVED, TD64_BASE = D64 + 0x00, D64 + 0x20
BCD64_DERIVED, BCD64_BASE, BCA64, CHD64, COL64 = D64 + 0x40, D64 + 0x60, D64 + 0x80, D64 + 0x90, D64 + 0xA0
VTABLE64 = D64 + 0xC0                  # COL VA at VTABLE64 - 8, then two 8-byte slots
THROW_INFO64, CTA64, CT64_1, CT64_2 = D64 + 0xE0, D64 + 0xF0, D64 + 0x100, D64 + 0x110
BAD_SELF_COL64, BAD_SELF_VTABLE64 = D64 + 0x120, D64 + 0x140
SIG0_COL64, SIG0_VTABLE64 = D64 + 0x148, D64 + 0x168
NULL_REF_VTABLE64 = D64 + 0x178        # slot -1 holds 0


def _rva(va):
    return va - IMAGE_BASE64


def _col64(col, signature=1, pself=None) -> bytes:
    """A COL naming TD64_DERIVED and CHD64; pSelf defaults to the COL's own RVA."""
    return _u32(signature, 0, 0, _rva(TD64_DERIVED), _rva(CHD64), _rva(col) if pself is None else pself)


def _rtti_data64() -> bytes:
    data = bytearray(0x200)

    def put(va, blob):
        data[va - D64:va - D64 + len(blob)] = blob

    put(TD64_DERIVED, struct.pack("<QQ", 0, 0) + b".?AVDerived@@\0")
    put(TD64_BASE, struct.pack("<QQ", 0, 0) + b".?AVBase@@\0")
    put(BCD64_DERIVED, _u32(_rva(TD64_DERIVED), 1, 0, 0xFFFFFFFF, 0, 0))
    put(BCD64_BASE, _u32(_rva(TD64_BASE), 0, 0, 0xFFFFFFFF, 0, 0))
    put(BCA64, _u32(_rva(BCD64_DERIVED), _rva(BCD64_BASE)))
    put(CHD64, _u32(0, 0, 2, _rva(BCA64)))
    put(COL64, _col64(COL64))
    put(VTABLE64 - 8, struct.pack("<QQQ", COL64, IMAGE_BASE64 + 0x1000, IMAGE_BASE64 + 0x1010))
    put(THROW_INFO64, _u32(0, 0, 0, _rva(CTA64)))
    put(CTA64, _u32(2, _rva(CT64_1), _rva(CT64_2)))
    put(CT64_1, _u32(0, _rva(TD64_DERIVED)))
    put(CT64_2, _u32(0, _rva(TD64_BASE)))
    put(BAD_SELF_COL64, _col64(BAD_SELF_COL64, pself=_rva(BAD_SELF_COL64) + 4))
    put(BAD_SELF_VTABLE64 - 8, struct.pack("<Q", BAD_SELF_COL64))
    put(SIG0_COL64, _col64(SIG0_COL64, signature=0))                    # the x86 signature
    put(SIG0_VTABLE64 - 8, struct.pack("<Q", SIG0_COL64))
    return bytes(data)


def _image64(tmp_path, *patches):
    """The x64 image, with each (va, [u32, ...]) patch written over its data."""
    data = bytearray(_rtti_data64())
    for va, vals in patches:
        struct.pack_into(f"<{len(vals)}I", data, va - D64, *vals)
    return pe_image(tmp_path / "a64.exe", b"\xc3", bytes(data), is_64=True)


@pytest.fixture
def image64(tmp_path):
    return _image64(tmp_path)


class TestResolveX64:
    def test_class_and_hierarchy_from_a_vtable(self, image64):
        assert rtti.resolve_vtable(pefile.PE(str(image64)), VTABLE64) == rtti.RttiClass(
            name=".?AVDerived@@", vtable_va=VTABLE64, hierarchy=[".?AVDerived@@", ".?AVBase@@"])

    def test_scan_finds_the_class_once(self, image64):
        found = rtti.scan_all_rtti(pefile.PE(str(image64)))
        assert [(c.name, c.vtable_va) for c in found] == [(".?AVDerived@@", VTABLE64)]

    def test_a_col_whose_pself_is_not_its_own_rva_is_rejected(self, image64):
        assert rtti.resolve_vtable(pefile.PE(str(image64)), BAD_SELF_VTABLE64) is None

    def test_a_pself_below_its_own_rva_is_rejected(self, tmp_path):
        pe = pefile.PE(str(_image64(tmp_path, (BAD_SELF_COL64 + 0x14, [_rva(BAD_SELF_COL64) - 4]))))
        assert rtti.resolve_vtable(pe, BAD_SELF_VTABLE64) is None

    def test_an_x86_signature_is_rejected(self, image64):
        assert rtti.resolve_vtable(pefile.PE(str(image64)), SIG0_VTABLE64) is None

    def test_a_col_reference_holding_an_rva_is_rejected(self, tmp_path):
        pe = pefile.PE(str(_image64(tmp_path, (VTABLE64 - 8, [_rva(COL64), 0]))))
        assert rtti.resolve_vtable(pe, VTABLE64) is None

    def test_not_a_vtable(self, image64):
        pe = pefile.PE(str(image64))
        assert rtti.resolve_vtable(pe, NULL_REF_VTABLE64) is None
        assert rtti.resolve_vtable(pe, IMAGE_BASE64 + 0x9000) is None

    def test_a_type_descriptor_without_a_decorated_name_is_rejected(self, tmp_path):
        pe = pefile.PE(str(_image64(tmp_path, (TD64_DERIVED + 16, list(struct.unpack("<3I", b"notaclass\0\0\0"))))))
        assert rtti.resolve_vtable(pe, VTABLE64) is None


class TestCliX64:
    def test_vtable(self, image64, monkeypatch, capsys):
        assert _main(monkeypatch, capsys, str(image64), "vtable", f"{VTABLE64:X}") == [
            "Class: .?AVDerived@@", "Hierarchy: .?AVDerived@@ -> .?AVBase@@"]

    @pytest.mark.parametrize("vtable, reason", [
        (BAD_SELF_VTABLE64, "RTTI resolution failed"),
        (SIG0_VTABLE64, "RTTI resolution failed"),
        (NULL_REF_VTABLE64, "below the image base"),
    ])
    def test_vtable_that_is_not_one_fails(self, image64, monkeypatch, capsys, vtable, reason):
        assert reason in _fails(monkeypatch, capsys, str(image64), "vtable", f"{vtable:X}")

    def test_throwinfo_takes_an_rva(self, image64, monkeypatch, capsys):
        out = _main(monkeypatch, capsys, str(image64), "throwinfo", f"{_rva(THROW_INFO64):X}")
        assert out == ["Catchable types (2):", "", "  [0] .?AVDerived@@", "  [1] .?AVBase@@"]

    def test_throwinfo_given_a_va_fails(self, image64, monkeypatch, capsys):
        _fails(monkeypatch, capsys, str(image64), "throwinfo", f"{THROW_INFO64:X}")

    def _throwinfo(self, tmp_path, monkeypatch, capsys, *patches):
        path = _image64(tmp_path, *patches)
        return _main(monkeypatch, capsys, str(path), "throwinfo", f"{_rva(THROW_INFO64):X}")

    def test_throwinfo_with_one_type(self, tmp_path, monkeypatch, capsys):
        assert self._throwinfo(tmp_path, monkeypatch, capsys, (CTA64, [1])) == [
            "Catchable types (1):", "", "  [0] .?AVDerived@@"]

    def test_throwinfo_accepts_up_to_32_types(self, tmp_path, monkeypatch, capsys):
        cta = D64 + 0x170
        out = self._throwinfo(tmp_path, monkeypatch, capsys,
                              (THROW_INFO64 + 0x0C, [_rva(cta)]), (cta, [32] + [_rva(CT64_2)] * 32))
        assert out[0] == "Catchable types (32):" and out[2:] == [f"  [{i}] .?AVBase@@" for i in range(32)]

    @pytest.mark.parametrize("patch", [
        (CTA64, [0]),                         # no catchable types
        (CTA64, [33]),                        # more than 32
        (THROW_INFO64 + 0x0C, [0x9000]),      # type array outside the image
    ])
    def test_throwinfo_with_a_bad_type_array_fails(self, tmp_path, monkeypatch, capsys, patch):
        with pytest.raises(SystemExit) as exc:
            self._throwinfo(tmp_path, monkeypatch, capsys, patch)
        assert exc.value.code == 1

    def test_throwinfo_lists_unreadable_entries_and_goes_on(self, tmp_path, monkeypatch, capsys):
        empty_td = D64 + 0x1A0                # zero bytes: no name at +16
        out = self._throwinfo(tmp_path, monkeypatch, capsys,
                              (CTA64, [3, 0x9000, _rva(D64 + 0x190), _rva(CT64_2)]),
                              (D64 + 0x190, [0, _rva(empty_td)]))
        assert out[:2] == ["Catchable types (3):", ""] and out[4:] == ["  [2] .?AVBase@@"]
        assert out[2].startswith("  [0] (unreadable") and out[3].startswith("  [1] (unreadable")

    def test_throwinfo_reports_a_type_array_cut_off_by_the_image_end(self, tmp_path, monkeypatch, capsys):
        cta = D64 + 0x1F8                     # count and entry 0 fit, entry 1 lies past the end
        out = self._throwinfo(tmp_path, monkeypatch, capsys,
                              (THROW_INFO64 + 0x0C, [_rva(cta)]), (cta, [2, _rva(CT64_1)]))
        assert out[:3] == ["Catchable types (2):", "", "  [0] .?AVDerived@@"] and len(out) == 4
        assert out[3].startswith("  [1] (unreadable")
