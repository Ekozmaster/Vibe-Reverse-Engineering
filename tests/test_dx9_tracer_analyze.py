"""Tests for the D3D9 trace analyzer, using synthetic records in the tracers' JSONL shape."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from graphics.directx.dx9.tracer import analyze
from graphics.directx.dx9.tracer.analyze import SLOT

# Shaders compiled for the same model with the same constant-table size start
# with the same four DWORDs: version, comment token, 'CTAB', table header size.
_COMMON_HEADER = "FFFE0300" "0003FFFE" "42415443" "0000001C"
_WORLD_SHADER = _COMMON_HEADER + "11111111" * 5   # 9 DWORDs
_BONE_SHADER = _COMMON_HEADER + "22222222" * 8    # 12 DWORDs
_WORLD_HANDLE = "0x0B000010"
_BONE_HANDLE = "0x0B000020"


def _ctab_disasm(name: str, register: int) -> str:
    return (
        "//   Name          Reg   Size\n"
        "//   ------------- ----- ----\n"
        f"//   {name} c{register}       4\n"
        "\n"
        "    vs_3_0\n"
    )


def _create_vertex_shader(seq: int, handle: str, bytecode: str, disasm: str) -> dict:
    return {
        "frame": -1, "seq": seq,
        "slot": SLOT["CreateVertexShader"], "method": "CreateVertexShader",
        "args": {}, "data": {"bytecode": bytecode, "disasm": disasm},
        "created_handle": handle,
    }


def _set_vertex_shader(seq: int, handle: str) -> dict:
    return {
        "frame": 0, "seq": seq,
        "slot": SLOT["SetVertexShader"], "method": "SetVertexShader",
        "args": {"pShader": handle},
    }


def _draw(seq: int, backtrace: list[str]) -> dict:
    return {
        "frame": 0, "seq": seq,
        "slot": SLOT["DrawIndexedPrimitive"], "method": "DrawIndexedPrimitive",
        "args": {"PrimitiveType": 4, "NumVertices": 24, "PrimitiveCount": 12},
        "backtrace": backtrace,
    }


def _set_transform(seq: int, backtrace: list[str]) -> dict:
    return {
        "frame": 0, "seq": seq,
        "slot": SLOT["SetTransform"], "method": "SetTransform",
        "args": {"State": 2}, "data": {"matrix": []},
        "backtrace": backtrace,
    }


def _capture_with_two_similar_shaders() -> list[dict]:
    return [
        _create_vertex_shader(0, _WORLD_HANDLE, _WORLD_SHADER, _ctab_disasm("WorldViewProj", 0)),
        _create_vertex_shader(1, _BONE_HANDLE, _BONE_SHADER, _ctab_disasm("BoneMatrices", 20)),
        _set_vertex_shader(2, _WORLD_HANDLE),
        _draw(3, ["0x00401234", "0x00405678"]),
    ]


class TestShaderIdentity:
    def test_shader_map_keeps_shaders_with_the_same_header_apart(self, capsys):
        analyze.do_shader_map(_capture_with_two_similar_shaders(), None)
        out = capsys.readouterr().out
        assert "Unique shaders captured: 2" in out
        assert f"VS:{_WORLD_HANDLE} set 1x -> VS 9 DWORDs" in out

    def test_state_snapshot_names_constants_of_the_bound_shader(self, capsys):
        analyze.do_state_snapshot(_capture_with_two_similar_shaders(), 0)
        out = capsys.readouterr().out
        assert "CTAB: WorldViewProj=c0" in out
        assert "BoneMatrices" not in out


class TestBacktraceOutput:
    def test_state_snapshot_prints_the_draw_backtrace(self, capsys):
        analyze.do_state_snapshot(_capture_with_two_similar_shaders(), 0)
        out = capsys.readouterr().out
        assert "Backtrace:" in out
        assert "0x00401234" in out

    def test_transform_calls_print_the_caller_backtrace(self, capsys):
        records = [_set_transform(0, ["0x00409ABC"]), _draw(1, [])]
        analyze.do_transform_calls(records)
        out = capsys.readouterr().out
        assert "bt: [0x00409ABC]" in out


class TestLoadRecords:
    def test_a_last_line_still_being_written_is_left_out(self, tmp_path):
        # With init capture on, the tracer keeps the file open after a capture and flushes in chunks
        capture = tmp_path / "dxtrace_frame.jsonl"
        capture.write_text('{"frame":0,"seq":0,"method":"Present"}\n{"frame":-1,"seq":1,"method":"Cre')
        assert analyze.load_records(str(capture)) == [{"frame": 0, "seq": 0, "method": "Present"}]
