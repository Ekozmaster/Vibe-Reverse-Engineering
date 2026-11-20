"""find_d3d_calls: the D3D imports of a 32- or 64-bit image and the calls through them."""

import contextlib
import io
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rtx_remix_tools" / "dx" / "scripts"))

import find_d3d_calls  # noqa: E402
from pe_fakes import DATA_RVA, IMAGE_BASE, IMAGE_BASE64, TEXT_RVA, pe_image  # noqa: E402

# .data layout: two import descriptors and the null one, then per DLL an ILT and
# an IAT of one name and a terminator, then the hint/name entries and DLL names
_ILT_D3D9, _IAT_D3D9, _ILT_D3DX, _IAT_D3DX = 0x40, 0x50, 0x60, 0x70
_CREATE_NAME, _SHADER_NAME, _D3D9_DLL, _D3DX_DLL = 0xA0, 0xC0, 0xE0, 0xF0
_DESCRIPTORS_SIZE = 3 * 20


def _d3d_imports(ptr_size: int, strings: bytes = b"") -> bytes:
    """.data importing Direct3DCreate9 from d3d9.dll and D3DXCompileShader from d3dx9_43.dll."""
    data = bytearray(0x200)
    thunk = "<Q" if ptr_size == 8 else "<I"
    for i, (ilt, iat, name, dll) in enumerate([(_ILT_D3D9, _IAT_D3D9, _CREATE_NAME, _D3D9_DLL),
                                               (_ILT_D3DX, _IAT_D3DX, _SHADER_NAME, _D3DX_DLL)]):
        struct.pack_into("<IIIII", data, 20 * i, DATA_RVA + ilt, 0, 0, DATA_RVA + dll, DATA_RVA + iat)
        struct.pack_into(thunk, data, ilt, DATA_RVA + name)
        struct.pack_into(thunk, data, iat, DATA_RVA + name)
    data[_CREATE_NAME + 2:_CREATE_NAME + 17] = b"Direct3DCreate9"
    data[_SHADER_NAME + 2:_SHADER_NAME + 19] = b"D3DXCompileShader"
    data[_D3D9_DLL:_D3D9_DLL + 8] = b"d3d9.dll"
    data[_D3DX_DLL:_D3DX_DLL + 12] = b"d3dx9_43.dll"
    data[0x180:0x180 + len(strings)] = strings
    return bytes(data)


def _call_rip(site_rva: int, iat_rva: int) -> bytes:
    """``call [rip+rel32]`` at *site_rva* reading the IAT slot at *iat_rva*."""
    return b"\xFF\x15" + struct.pack("<i", iat_rva - (site_rva + 6))


def _report(binary: Path) -> str:
    with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(io.StringIO()) as out:
        patch.setattr(sys, "argv", ["find_d3d_calls", str(binary)])
        find_d3d_calls.main()
    return out.getvalue()


class TestCallSites:
    def test_pe32_calls_through_the_absolute_iat_slot(self, tmp_path):
        text = (b"\xFF\x15" + struct.pack("<I", IMAGE_BASE + DATA_RVA + _IAT_D3D9)
                + b"\xFF\x15" + struct.pack("<I", IMAGE_BASE + DATA_RVA + _IAT_D3DX))
        binary = pe_image(tmp_path / "game.exe", text, _d3d_imports(4),
                          import_dir=(DATA_RVA, _DESCRIPTORS_SIZE))

        text_out = _report(binary)

        assert f"0x{IMAGE_BASE + TEXT_RVA:08X}: call [Direct3DCreate9]" in text_out
        assert f"0x{IMAGE_BASE + TEXT_RVA + 6:08X}: call [D3DXCompileShader]" in text_out

    def test_pe32_plus_calls_through_a_rip_relative_iat_slot(self, tmp_path):
        text = (_call_rip(TEXT_RVA, DATA_RVA + _IAT_D3D9)
                + _call_rip(TEXT_RVA + 6, DATA_RVA + _IAT_D3DX))
        binary = pe_image(tmp_path / "game64.exe", text, _d3d_imports(8), is_64=True,
                          import_dir=(DATA_RVA, _DESCRIPTORS_SIZE))

        text_out = _report(binary)

        assert f"IAT: 0x{IMAGE_BASE64 + DATA_RVA + _IAT_D3D9:08X}  Direct3DCreate9" in text_out
        assert f"0x{IMAGE_BASE64 + TEXT_RVA:08X}: call [Direct3DCreate9]" in text_out
        assert f"0x{IMAGE_BASE64 + TEXT_RVA + 6:08X}: call [D3DXCompileShader]" in text_out

    def test_pe32_plus_rip_relative_call_to_another_slot_is_not_counted(self, tmp_path):
        text = _call_rip(TEXT_RVA, DATA_RVA + _IAT_D3D9 + 8)
        binary = pe_image(tmp_path / "game64.exe", text, _d3d_imports(8), is_64=True,
                          import_dir=(DATA_RVA, _DESCRIPTORS_SIZE))

        assert "0 call sites found" in _report(binary)


class TestImportlessImage:
    def test_strings_naming_d3d9_are_still_reported(self, tmp_path):
        data = b"\0" * 0x80 + b"d3d9.dll\0"
        binary = pe_image(tmp_path / "packed.exe", b"\xC3", data)

        text_out = _report(binary)

        assert "no import directory" in text_out
        assert any(f"0x{IMAGE_BASE + DATA_RVA + 0x80:08X}:" in line and "d3d9.dll" in line
                   for line in text_out.splitlines())
