"""The tracer sources generated from ``d3d9_methods.py`` and the copies checked in."""

import re
from pathlib import Path

import pytest

from graphics.directx.dx9.tracer import d3d9_methods

_REPO = Path(__file__).resolve().parent.parent
_DISPATCH = _REPO / "rtx_remix_tools" / "dx" / "remix-comp-proxy" / "src" / "comp" / "modules" / "tracer_dispatch.inc"
_HOOKS = _REPO / "graphics" / "directx" / "dx9" / "tracer" / "src" / "d3d9_trace_hooks.inc"


def _function_body(source: str, name: str) -> str:
    return re.search(rf"inline void {name}\([^)]*\)\n\{{\n(.*?)\n\}}", source, re.DOTALL).group(1)


@pytest.mark.parametrize("path, generate", [
    (_DISPATCH, d3d9_methods.generate_cpp_dispatch_inc),
    (_HOOKS, d3d9_methods.generate_hooks_inc),
], ids=["tracer_dispatch.inc", "d3d9_trace_hooks.inc"])
def test_checked_in_file_is_what_the_generator_writes(path, generate):
    assert path.read_text(encoding="utf-8") == generate()


@pytest.mark.parametrize("method", ["CreateVertexDeclaration", "CreateVertexShader", "CreatePixelShader"])
def test_record_of_a_creating_method_stays_open_for_the_created_object(method):
    body = _function_body(d3d9_methods.generate_cpp_dispatch_inc(), f"trace_{method}")
    assert "record_begin" in body
    assert "record_end" not in body


def test_other_records_are_ended_by_their_own_dispatch_function():
    body = _function_body(d3d9_methods.generate_cpp_dispatch_inc(), "trace_SetVertexShader")
    assert body.rstrip().endswith("t.record_end();")


def test_created_object_is_written_before_the_record_ends():
    body = _function_body(d3d9_methods.generate_cpp_dispatch_inc(), "trace_created")
    assert body.index("record_created_handle") < body.index("record_end")
