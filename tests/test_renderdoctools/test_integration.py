# tests/test_renderdoctools/test_integration.py
"""Integration tests for renderdoctools against real RenderDoc captures.

Requires:
- RenderDoc extracted to tools/RenderDoc_1.43_64/ (or tools/renderdoc/)
- At least one .rdc capture file

Skip automatically if RenderDoc or captures are not available.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from renderdoctools import core

# ── Fixtures ──────────────────────────────────────────────────────────────

CAPTURE_DIR = Path(__file__).resolve().parent.parent / "test_rdc"


def _find_capture() -> Path | None:
    """Find an .rdc capture in tests/test_rdc/."""
    if not CAPTURE_DIR.is_dir():
        return None
    for f in CAPTURE_DIR.iterdir():
        if f.suffix == ".rdc":
            return f
    return None


def _renderdoc_available() -> bool:
    """Check if bundled RenderDoc is available."""
    try:
        core.find_renderdoc()
        return True
    except FileNotFoundError:
        return False


_capture = _find_capture()
_has_renderdoc = _renderdoc_available()

skip_no_renderdoc = pytest.mark.skipif(
    not _has_renderdoc, reason="RenderDoc not found in tools/"
)
skip_no_capture = pytest.mark.skipif(
    _capture is None, reason="No .rdc capture found in %s" % CAPTURE_DIR
)
requires_integration = pytest.mark.skipif(
    not (_has_renderdoc and _capture),
    reason="Integration test requires RenderDoc + capture file",
)


# ── Tests ─────────────────────────────────────────────────────────────────


@requires_integration
class TestEvents:
    def test_events_returns_list(self):
        result = core.run_script("events", str(_capture), {"draws_only": False, "filter": ""})
        assert isinstance(result["events"], list)
        assert isinstance(result["total"], int) and result["total"] > 0
        assert len(result["events"]) == result["total"]

    def test_events_have_required_fields(self):
        result = core.run_script("events", str(_capture), {"draws_only": False, "filter": ""})
        ev = result["events"][0]
        assert isinstance(ev["eid"], int) and ev["eid"] > 0
        assert isinstance(ev["name"], str) and len(ev["name"]) > 0
        assert isinstance(ev["depth"], int) and ev["depth"] >= 0
        assert isinstance(ev["flags"], int) and ev["flags"] >= 0
        assert isinstance(ev["draw"], bool)
        assert isinstance(ev["numIndices"], int) and ev["numIndices"] >= 0

    def test_draws_only_filters(self):
        all_result = core.run_script("events", str(_capture), {"draws_only": False, "filter": ""})
        draws_result = core.run_script("events", str(_capture), {"draws_only": True, "filter": ""})
        # draws-only should return fewer or equal events
        assert draws_result["total"] <= all_result["total"]
        assert draws_result["total"] > 0
        # every event should be a draw with valid fields
        for ev in draws_result["events"]:
            assert ev["draw"] is True
            assert isinstance(ev["eid"], int) and ev["eid"] > 0
            assert isinstance(ev["name"], str) and len(ev["name"]) > 0
            assert isinstance(ev["numIndices"], int) and ev["numIndices"] >= 0

    def test_filter_narrows_results(self):
        all_result = core.run_script("events", str(_capture), {"draws_only": False, "filter": ""})
        filtered = core.run_script("events", str(_capture), {"draws_only": False, "filter": "DrawIndexed"})
        assert filtered["total"] <= all_result["total"]
        for ev in filtered["events"]:
            assert isinstance(ev["name"], str) and len(ev["name"]) > 0
            assert "DrawIndexed" in ev["name"]
            assert isinstance(ev["eid"], int) and ev["eid"] > 0


@requires_integration
class TestAnalyze:
    def test_summary(self):
        result = core.run_script("analyze", str(_capture), {
            "summary": True, "biggest_draws": 0, "render_targets": False,
        })
        s = result["summary"]
        assert isinstance(s["totalEvents"], int) and s["totalEvents"] > 0
        assert isinstance(s["totalDraws"], int) and s["totalDraws"] > 0
        assert isinstance(s["totalClears"], int) and s["totalClears"] >= 0
        assert isinstance(s["totalIndices"], int) and s["totalIndices"] > 0
        assert isinstance(s["totalInstances"], int) and s["totalInstances"] > 0
        assert s["totalDraws"] <= s["totalEvents"]

    def test_biggest_draws(self):
        result = core.run_script("analyze", str(_capture), {
            "summary": False, "biggest_draws": 5, "render_targets": False,
        })
        draws = result["biggestDraws"]
        assert isinstance(draws, list)
        assert len(draws) <= 5
        assert len(draws) > 0
        # should be sorted descending by numIndices
        for i in range(len(draws) - 1):
            assert draws[i]["numIndices"] >= draws[i + 1]["numIndices"]
        # validate each draw entry has meaningful values
        for d in draws:
            assert isinstance(d["eid"], int) and d["eid"] > 0
            assert isinstance(d["name"], str) and len(d["name"]) > 0
            assert isinstance(d["numIndices"], int) and d["numIndices"] > 0
            assert isinstance(d["numInstances"], int) and d["numInstances"] > 0

    def test_render_targets(self):
        result = core.run_script("analyze", str(_capture), {
            "summary": False, "biggest_draws": 0, "render_targets": True,
        })
        rts = result["renderTargets"]
        assert isinstance(rts, list) and len(rts) > 0
        for rt in rts:
            assert isinstance(rt["resourceId"], str) and int(rt["resourceId"]) > 0
            assert isinstance(rt["drawCount"], int) and rt["drawCount"] > 0
            assert isinstance(rt["firstEid"], int) and rt["firstEid"] > 0
            assert isinstance(rt["lastEid"], int) and rt["lastEid"] > 0
            assert rt["lastEid"] >= rt["firstEid"]


@requires_integration
class TestPipeline:
    def _get_first_draw_eid(self):
        result = core.run_script("events", str(_capture), {"draws_only": True, "filter": ""})
        return result["events"][0]["eid"]

    def test_pipeline_returns_stages(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("pipeline", str(_capture), {"event_id": eid, "stage": ""})
        assert isinstance(result["event_id"], int) and result["event_id"] == eid
        assert isinstance(result["stages"], dict) and len(result["stages"]) > 0
        for stage_name, info in result["stages"].items():
            assert stage_name in ("vertex", "hull", "domain", "geometry", "pixel", "compute")
            assert isinstance(info["entryPoint"], str) and len(info["entryPoint"]) > 0
            assert info["bound"] is True
            assert isinstance(info["constantBuffers"], list)
            assert isinstance(info["readOnlyResources"], list)
            assert isinstance(info["readWriteResources"], list)
            for cb in info["constantBuffers"]:
                assert isinstance(cb["index"], int) and cb["index"] >= 0
                assert isinstance(cb["name"], str)
                assert isinstance(cb["byteSize"], int) and cb["byteSize"] >= 0
            for res in info["readOnlyResources"] + info["readWriteResources"]:
                assert isinstance(res["type"], str) and len(res["type"]) > 0
                assert isinstance(res["name"], str)
                assert isinstance(res["index"], int) and res["index"] >= 0

    def test_pipeline_has_render_targets(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("pipeline", str(_capture), {"event_id": eid, "stage": ""})
        assert isinstance(result["renderTargets"], list)
        for rt in result["renderTargets"]:
            assert isinstance(rt, str) and int(rt) > 0
        # depthTarget should be present (may be None if no depth bound)
        assert "depthTarget" in result
        if result["depthTarget"] is not None:
            assert isinstance(result["depthTarget"], str) and int(result["depthTarget"]) > 0

    def test_pipeline_stage_filter(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("pipeline", str(_capture), {"event_id": eid, "stage": "vertex"})
        # should only contain vertex stage (if bound)
        assert isinstance(result["stages"], dict)
        for stage_name, info in result["stages"].items():
            assert stage_name == "vertex"
            assert isinstance(info["entryPoint"], str) and len(info["entryPoint"]) > 0
            assert info["bound"] is True


@requires_integration
class TestTextures:
    def _get_first_draw_eid(self):
        result = core.run_script("events", str(_capture), {"draws_only": True, "filter": ""})
        return result["events"][0]["eid"]

    def test_textures_list(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("textures", str(_capture), {
            "event_id": eid, "save_all": "", "save_rid": "",
            "format": "png", "save_output": "",
        })
        assert isinstance(result["textures"], list)
        assert isinstance(result["total"], int) and result["total"] > 0
        assert len(result["textures"]) == result["total"]
        tex = result["textures"][0]
        assert isinstance(tex["resourceId"], str) and int(tex["resourceId"]) > 0
        assert isinstance(tex["width"], int) and tex["width"] > 0
        assert isinstance(tex["height"], int) and tex["height"] > 0
        assert isinstance(tex["depth"], int) and tex["depth"] >= 1
        assert isinstance(tex["mips"], int) and tex["mips"] >= 1
        assert isinstance(tex["arraysize"], int) and tex["arraysize"] >= 1
        assert isinstance(tex["format"], str) and tex["format"] not in ("", "unknown")
        assert isinstance(tex["binding"], str) and len(tex["binding"]) > 0
        assert isinstance(tex["name"], str)
        assert isinstance(tex["type"], str) and len(tex["type"]) > 0

    def test_texture_values_are_valid(self):
        """Texture entries should have non-degenerate dimensions and real format strings."""
        eid = self._get_first_draw_eid()
        result = core.run_script("textures", str(_capture), {
            "event_id": eid, "save_all": "", "save_rid": "",
            "format": "png", "save_output": "",
        })
        for tex in result["textures"]:
            assert isinstance(tex["resourceId"], str) and int(tex["resourceId"]) > 0
            assert isinstance(tex["width"], int) and tex["width"] > 0
            assert isinstance(tex["height"], int) and tex["height"] > 0
            assert isinstance(tex["depth"], int) and tex["depth"] >= 1
            assert isinstance(tex["mips"], int) and tex["mips"] >= 1
            assert isinstance(tex["arraysize"], int) and tex["arraysize"] >= 1
            assert isinstance(tex["format"], str) and tex["format"] not in ("", "unknown")
            assert isinstance(tex["binding"], str) and len(tex["binding"]) > 0
            assert isinstance(tex["type"], str) and len(tex["type"]) > 0
            assert isinstance(tex["name"], str)

    def test_save_single_texture(self):
        eid = self._get_first_draw_eid()
        # First get the texture list to find a valid RID
        result = core.run_script("textures", str(_capture), {
            "event_id": eid, "save_all": "", "save_rid": "",
            "format": "png", "save_output": "",
        })
        rid = result["textures"][0]["resourceId"]
        assert isinstance(rid, str) and int(rid) > 0

        with tempfile.TemporaryDirectory(prefix="rdtools_test_") as tmpdir:
            out_path = os.path.join(tmpdir, "test_texture.png")
            result = core.run_script("textures", str(_capture), {
                "event_id": eid, "save_all": "", "save_rid": rid,
                "format": "png", "save_output": out_path,
            })
            assert isinstance(result["saved"], list) and len(result["saved"]) == 1
            assert isinstance(result["saved"][0], str) and len(result["saved"][0]) > 0
            assert os.path.isfile(out_path)
            assert os.path.getsize(out_path) > 0

    def test_save_all_textures(self):
        eid = self._get_first_draw_eid()
        with tempfile.TemporaryDirectory(prefix="rdtools_test_") as tmpdir:
            out_dir = os.path.join(tmpdir, "texdump")
            result = core.run_script("textures", str(_capture), {
                "event_id": eid, "save_all": out_dir, "save_rid": "",
                "format": "png", "save_output": "",
            })
            assert isinstance(result["saved"], list)
            assert isinstance(result["total"], int) and result["total"] > 0
            assert len(result["saved"]) == result["total"]
            for f in result["saved"]:
                assert isinstance(f, str) and f.endswith(".png")
                assert os.path.isfile(f)
                assert os.path.getsize(f) > 0


@requires_integration
class TestShaders:
    def _get_first_draw_eid(self):
        result = core.run_script("events", str(_capture), {"draws_only": True, "filter": ""})
        return result["events"][0]["eid"]

    def test_shaders_disassembly(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("shaders", str(_capture), {
            "event_id": eid, "stage": "", "cbuffers": False,
        })
        assert isinstance(result["event_id"], int) and result["event_id"] == eid
        assert isinstance(result["disasmTarget"], str) and len(result["disasmTarget"]) > 0
        assert isinstance(result["shaders"], dict) and len(result["shaders"]) > 0
        # At least one stage should have disassembly
        for stage_name, info in result["shaders"].items():
            assert stage_name in ("vertex", "hull", "domain", "geometry", "pixel", "compute")
            assert isinstance(info["disassembly"], str) and len(info["disassembly"]) > 0
            assert isinstance(info["entryPoint"], str) and len(info["entryPoint"]) > 0

    def test_shaders_stage_filter(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("shaders", str(_capture), {
            "event_id": eid, "stage": "vertex", "cbuffers": False,
        })
        assert isinstance(result["shaders"], dict)
        for stage_name, info in result["shaders"].items():
            assert stage_name == "vertex"
            assert isinstance(info["entryPoint"], str) and len(info["entryPoint"]) > 0
            assert isinstance(info["disassembly"], str) and len(info["disassembly"]) > 0

    def test_shaders_cbuffers(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("shaders", str(_capture), {
            "event_id": eid, "stage": "vertex", "cbuffers": True,
        })
        if "vertex" in result["shaders"]:
            info = result["shaders"]["vertex"]
            assert isinstance(info["constantBuffers"], list)
            # FO4 vertex shaders typically have cbuffers
            if len(info["constantBuffers"]) > 0:
                cb = info["constantBuffers"][0]
                assert isinstance(cb["name"], str)
                assert isinstance(cb["index"], int) and cb["index"] >= 0
                # Each cbuffer should have either variables or an error
                if "variables" in cb:
                    assert isinstance(cb["variables"], list)
                    for v in cb["variables"]:
                        assert isinstance(v["name"], str) and len(v["name"]) > 0
                        assert isinstance(v["rows"], int) and v["rows"] >= 1
                        assert isinstance(v["columns"], int) and v["columns"] >= 1
                elif "error" in cb:
                    assert isinstance(cb["error"], str) and len(cb["error"]) > 0


@requires_integration
class TestMesh:
    def _get_first_draw_eid(self):
        result = core.run_script("events", str(_capture), {"draws_only": True, "filter": ""})
        return result["events"][0]["eid"]

    def test_mesh_input(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("mesh", str(_capture), {
            "event_id": eid, "post_vs": False, "indices": "",
        })
        assert isinstance(result["event_id"], int) and result["event_id"] == eid
        assert result["post_vs"] is False
        assert isinstance(result["attributes"], list) and len(result["attributes"]) > 0
        assert isinstance(result["vertices"], list) and len(result["vertices"]) > 0
        # Validate attribute entries
        for attr in result["attributes"]:
            assert isinstance(attr["name"], str) and len(attr["name"]) > 0
            assert isinstance(attr["format"], str) and len(attr["format"]) > 0
            assert isinstance(attr["buffer"], int) and attr["buffer"] >= 0
            assert isinstance(attr["offset"], int) and attr["offset"] >= 0
        # Each vertex should have a non-negative index and attribute data
        for v in result["vertices"]:
            assert isinstance(v["index"], int) and v["index"] >= 0

    def test_mesh_index_range(self):
        eid = self._get_first_draw_eid()
        result = core.run_script("mesh", str(_capture), {
            "event_id": eid, "post_vs": False, "indices": "0-3",
        })
        assert isinstance(result["vertices"], list) and len(result["vertices"]) <= 3
        assert len(result["vertices"]) > 0
        for v in result["vertices"]:
            assert isinstance(v["index"], int) and v["index"] >= 0


@requires_integration
class TestInfo:
    def test_info_returns_metadata(self):
        result = core.run_script("info", str(_capture))
        assert isinstance(result["api"], str) and len(result["api"]) > 0
        assert isinstance(result["timestamp"], int) and result["timestamp"] > 0
        assert isinstance(result["machineIdent"], int) and result["machineIdent"] >= 0


@requires_integration
class TestCounters:
    def test_list_counters(self):
        result = core.run_script("counters", str(_capture), {"fetch": "", "zero_samples": False})
        assert result["mode"] == "list"
        assert isinstance(result["counters"], list) and len(result["counters"]) > 0
        for c in result["counters"]:
            assert isinstance(c["id"], int) and c["id"] > 0
            assert isinstance(c["name"], str) and len(c["name"]) > 0
            assert isinstance(c["unit"], str) and len(c["unit"]) > 0
            assert isinstance(c["description"], str) and len(c["description"]) > 0
            assert isinstance(c["resultType"], str) and len(c["resultType"]) > 0
            assert isinstance(c["resultByteWidth"], int) and c["resultByteWidth"] > 0
