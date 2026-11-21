"""Offline JSONL analysis engine for D3D9 frame traces.

Pure stdlib Python. Reads JSONL produced by the trace proxy DLL.
Provides: summary, draw-call listing, hotpath aggregation, state
reconstruction, render pass detection, matrix flow, shader disasm,
call graph building, and more.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .d3d9_methods import (
    D3D9_METHODS,
    SLOT, DRAW_SLOTS, GEOMETRY_DRAW_SLOTS, STATE_SET_SLOTS, DATA_READER_SLOTS,
    D3DRS_ZENABLE, D3DRS_FILLMODE, D3DRS_ZWRITEENABLE, D3DRS_ALPHATESTENABLE,
    D3DRS_SRCBLEND, D3DRS_DESTBLEND, D3DRS_CULLMODE, D3DRS_ALPHABLENDENABLE,
    D3DRS_FOGENABLE, D3DRS_STENCILENABLE, D3DRS_COLORWRITEENABLE, D3DRS_BLENDOP,
    D3DRS_LIGHTING, D3DRS_SRGBWRITEENABLE, D3DRS_SCISSORTESTENABLE,
    D3DRS_NAMES, D3DTS_NAMES,
    D3DCLEAR_TARGET, D3DCLEAR_ZBUFFER, D3DCLEAR_STENCIL,
    D3DPT_NAMES,
    D3DDECLTYPE_NAMES, D3DDECLUSAGE_NAMES, D3DDECLMETHOD_NAMES,
    D3DBLEND_NAMES, D3DBLENDOP_NAMES, D3DCMP_NAMES, D3DCULL_NAMES, D3DFILL_NAMES,
    MATRIX_FLOAT_COUNT,
)


# ── Data loading ────────────────────────────────────────────────────────────

def load_records(path: str, filt: str | None = None) -> list[dict]:
    records = []
    field, op, val = (None, None, None)
    if filt:
        field, op, val = _parse_filter(filt)

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if field and not _match_filter(rec, field, op, val):
                continue
            records.append(rec)
    return records


def _parse_filter(expr: str):
    for op in ("==", "!=", ">=", "<=", ">", "<"):
        idx = expr.find(op)
        if idx >= 0:
            field = expr[:idx].strip()
            val_str = expr[idx + len(op):].strip()
            try:
                val: Any = int(val_str, 16) if val_str.startswith("0x") else (
                    float(val_str) if "." in val_str else int(val_str))
            except ValueError:
                val = val_str
            return field, op, val
    return None, None, None


def _resolve(rec: dict, path: str) -> Any:
    parts = path.split(".")
    cur: Any = rec
    for p in parts:
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, (list, tuple)):
            try:
                cur = cur[int(p)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _match_filter(rec: dict, field: str, op: str, val: Any) -> bool:
    rv = _resolve(rec, field)
    if rv is None:
        return False
    if isinstance(rv, str):
        try:
            rv = int(rv, 16)
        except ValueError:
            pass
    try:
        if op == "==": return rv == val
        if op == "!=": return rv != val
        if op == ">":  return rv > val
        if op == "<":  return rv < val
        if op == ">=": return rv >= val
        if op == "<=": return rv <= val
    except TypeError:
        return str(rv) == str(val)
    return False


# ── Address resolver ────────────────────────────────────────────────────────

class AddressResolver:
    def __init__(self, binary: str | None):
        self.binary = binary
        self._cache: dict[str, str] = {}

    def resolve(self, addr: str) -> str:
        if not self.binary or addr in self._cache:
            return self._cache.get(addr, addr)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "retools.funcinfo", self.binary, addr],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if "func_start" in line.lower() or "name" in line.lower():
                    self._cache[addr] = f"{addr} ({line.strip()})"
                    return self._cache[addr]
        except Exception:
            pass
        self._cache[addr] = addr
        return addr

    def resolve_all(self, records: list[dict]) -> None:
        addrs = set()
        for r in records:
            for a in r.get("backtrace", []):
                addrs.add(a)
        print(f"  Resolving {len(addrs)} unique addresses...")
        for a in sorted(addrs):
            self.resolve(a)


# ── Matrix classifier ───────────────────────────────────────────────────────

def classify_matrix(floats: list[float]) -> str:
    if len(floats) != MATRIX_FLOAT_COUNT:
        return "non-4x4"
    m = floats
    is_ident = all(
        abs(m[i * 4 + j] - (1.0 if i == j else 0.0)) < 0.001
        for i in range(4) for j in range(4)
    )
    if is_ident:
        return "identity"

    tags = []

    is_zero = all(abs(v) < 0.001 for v in m)
    if is_zero:
        return "zero"

    is_translation_only = (
        abs(m[0] - 1.0) < 0.001 and abs(m[5] - 1.0) < 0.001 and
        abs(m[10] - 1.0) < 0.001 and abs(m[15] - 1.0) < 0.001 and
        abs(m[1]) < 0.001 and abs(m[2]) < 0.001 and abs(m[4]) < 0.001 and
        abs(m[6]) < 0.001 and abs(m[8]) < 0.001 and abs(m[9]) < 0.001 and
        (abs(m[12]) > 0.001 or abs(m[13]) > 0.001 or abs(m[14]) > 0.001)
    )
    if is_translation_only:
        return "translation"

    diag_only = (
        abs(m[1]) < 0.001 and abs(m[2]) < 0.001 and abs(m[3]) < 0.001 and
        abs(m[4]) < 0.001 and abs(m[6]) < 0.001 and abs(m[7]) < 0.001 and
        abs(m[8]) < 0.001 and abs(m[9]) < 0.001 and abs(m[11]) < 0.001 and
        abs(m[12]) < 0.001 and abs(m[13]) < 0.001 and abs(m[14]) < 0.001
    )
    if diag_only:
        return "scale"

    if abs(m[15] - 1.0) < 0.001 and abs(m[3]) < 0.001 and abs(m[7]) < 0.001 and abs(m[11]) < 0.001:
        upper3 = [m[0], m[1], m[2], m[4], m[5], m[6], m[8], m[9], m[10]]
        det = (upper3[0] * (upper3[4]*upper3[8] - upper3[5]*upper3[7])
             - upper3[1] * (upper3[3]*upper3[8] - upper3[5]*upper3[6])
             + upper3[2] * (upper3[3]*upper3[7] - upper3[4]*upper3[6]))
        if abs(abs(det) - 1.0) < 0.01:
            tags.append("rotation")
        tags.append("affine")
    elif abs(m[14]) > 0.001 and abs(m[15]) < 0.001:
        tags.append("projection")
    elif abs(m[3]) > 0.001 or abs(m[7]) > 0.001 or abs(m[11]) > 0.001:
        tags.append("projection")

    return ", ".join(tags) if tags else "general"


def format_matrix_4x4(floats: list[float]) -> str:
    if len(floats) != MATRIX_FLOAT_COUNT:
        return "  " + " ".join(f"{v:10.4f}" for v in floats)
    lines = []
    for row in range(4):
        vals = floats[row * 4: row * 4 + 4]
        lines.append("  " + " ".join(f"{v:10.4f}" for v in vals))
    return "\n".join(lines)


# ── Render state formatting ─────────────────────────────────────────────────

def _fmt_rs(state_id: int, value: int) -> str:
    """Format a render state value with human-readable enum names."""
    name = D3DRS_NAMES.get(state_id, f"RS[{state_id}]")
    if state_id in (D3DRS_SRCBLEND, D3DRS_DESTBLEND):
        return f"{name} = {D3DBLEND_NAMES.get(value, str(value))}"
    if state_id == D3DRS_BLENDOP:
        return f"{name} = {D3DBLENDOP_NAMES.get(value, str(value))}"
    if state_id == D3DRS_CULLMODE:
        return f"{name} = {D3DCULL_NAMES.get(value, str(value))}"
    if state_id == D3DRS_FILLMODE:
        return f"{name} = {D3DFILL_NAMES.get(value, str(value))}"
    if state_id in (D3DRS_ZENABLE, D3DRS_ZWRITEENABLE, D3DRS_ALPHATESTENABLE,
                     D3DRS_ALPHABLENDENABLE, D3DRS_FOGENABLE, D3DRS_STENCILENABLE,
                     D3DRS_LIGHTING, D3DRS_SRGBWRITEENABLE, D3DRS_SCISSORTESTENABLE):
        return f"{name} = {'TRUE' if value else 'FALSE'}"
    return f"{name} = {value} (0x{value:X})"


# ── State tracker ───────────────────────────────────────────────────────────

class DeviceState:
    def __init__(self):
        self.vs = None
        self.ps = None
        self.vs_constants: dict[int, list[float]] = {}
        self.ps_constants: dict[int, list[float]] = {}
        self.vs_constants_i: dict[int, list[int]] = {}
        self.ps_constants_i: dict[int, list[int]] = {}
        self.textures: dict[int, str] = {}
        self.render_states: dict[int, int] = {}
        self.render_targets: dict[int, str] = {}
        self.vertex_decl = None
        self.stream_sources: dict[int, tuple] = {}
        self.indices = None
        self.transforms: dict[int, list[float]] = {}
        self.fvf = 0
        self.sampler_states: dict[int, dict[int, int]] = defaultdict(dict)
        self.texture_stage_states: dict[int, dict[int, int]] = defaultdict(dict)
        self.depth_stencil = None

    def apply(self, rec: dict) -> None:
        slot = rec["slot"]
        args = rec.get("args", {})
        data = rec.get("data", {})

        if slot == SLOT["SetVertexShader"]:
            self.vs = args.get("pShader")
        elif slot == SLOT["SetPixelShader"]:
            self.ps = args.get("pShader")
        elif slot == SLOT["SetVertexShaderConstantF"]:
            start = _int(args.get("StartRegister", 0))
            consts = data.get("constants", [])
            for i in range(0, len(consts), 4):
                self.vs_constants[start + i // 4] = consts[i:i+4]
        elif slot == SLOT["SetPixelShaderConstantF"]:
            start = _int(args.get("StartRegister", 0))
            consts = data.get("constants", [])
            for i in range(0, len(consts), 4):
                self.ps_constants[start + i // 4] = consts[i:i+4]
        elif slot == SLOT["SetVertexShaderConstantI"]:
            start = _int(args.get("StartRegister", 0))
            consts = data.get("constants", [])
            for i in range(0, len(consts), 4):
                self.vs_constants_i[start + i // 4] = consts[i:i+4]
        elif slot == SLOT["SetPixelShaderConstantI"]:
            start = _int(args.get("StartRegister", 0))
            consts = data.get("constants", [])
            for i in range(0, len(consts), 4):
                self.ps_constants_i[start + i // 4] = consts[i:i+4]
        elif slot == SLOT["SetTexture"]:
            stage = _int(args.get("Stage", 0))
            self.textures[stage] = args.get("pTexture", "NULL")
        elif slot == SLOT["SetRenderState"]:
            state = _int(args.get("State", 0))
            self.render_states[state] = _int(args.get("Value", 0))
        elif slot == SLOT["SetRenderTarget"]:
            idx = _int(args.get("RenderTargetIndex", 0))
            self.render_targets[idx] = args.get("pRT", "NULL")
        elif slot == SLOT["SetDepthStencilSurface"]:
            self.depth_stencil = args.get("pNewZStencil", "NULL")
        elif slot == SLOT["SetVertexDeclaration"]:
            self.vertex_decl = args.get("pDecl")
        elif slot == SLOT["SetStreamSource"]:
            stream = _int(args.get("StreamNumber", 0))
            self.stream_sources[stream] = (
                args.get("pStreamData"), _int(args.get("Stride", 0)))
        elif slot == SLOT["SetIndices"]:
            self.indices = args.get("pIndexData")
        elif slot in (SLOT["SetTransform"], SLOT["MultiplyTransform"]):
            state = _int(args.get("State", 0))
            self.transforms[state] = data.get("matrix", [])
        elif slot == SLOT["SetFVF"]:
            self.fvf = _int(args.get("FVF", 0))
        elif slot == SLOT["SetSamplerState"]:
            sampler = _int(args.get("Sampler", 0))
            stype = _int(args.get("Type", 0))
            self.sampler_states[sampler][stype] = _int(args.get("Value", 0))
        elif slot == SLOT["SetTextureStageState"]:
            stage = _int(args.get("Stage", 0))
            ttype = _int(args.get("Type", 0))
            self.texture_stage_states[stage][ttype] = _int(args.get("Value", 0))

    def snapshot(self) -> dict:
        return {
            "vs": self.vs, "ps": self.ps,
            "textures": dict(self.textures),
            "render_states": dict(self.render_states),
            "render_targets": dict(self.render_targets),
            "depth_stencil": self.depth_stencil,
            "vertex_decl": self.vertex_decl,
            "fvf": self.fvf,
            "stream_sources": dict(self.stream_sources),
            "indices": self.indices,
            "vs_constants": {k: list(v) for k, v in self.vs_constants.items()},
            "ps_constants": {k: list(v) for k, v in self.ps_constants.items()},
            "sampler_states": {k: dict(v) for k, v in self.sampler_states.items()},
            "texture_stage_states": {k: dict(v) for k, v in self.texture_stage_states.items()},
        }


def _int(val) -> int:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 0)
        except ValueError:
            return 0
    return 0


# ── Analysis commands ───────────────────────────────────────────────────────

def do_summary(records: list[dict]) -> None:
    frames = set()
    method_counts: Counter = Counter()
    categories: Counter = Counter()

    for r in records:
        frames.add(r.get("frame", -1))
        name = r.get("method", "?")
        method_counts[name] += 1
        slot = r.get("slot", -1)
        if slot in D3D9_METHODS:
            categories[D3D9_METHODS[slot].category] += 1

    bt_empty = sum(1 for r in records if not r.get("backtrace"))
    init_count = sum(1 for r in records if r.get("frame") == -1)
    runtime_count = len(records) - init_count
    real_frames = sorted(f for f in frames if f >= 0)

    print(f"\n=== Trace Summary ===")
    print(f"  Total records:    {len(records)}")
    print(f"  Init records:     {init_count}")
    print(f"  Runtime records:  {runtime_count}")
    print(f"  Frames:           {len(real_frames)} ({', '.join(str(f) for f in real_frames[:10])})")
    if real_frames:
        per_frame = runtime_count / len(real_frames)
        print(f"  Avg calls/frame:  {per_frame:.0f}")
    print(f"  Empty backtraces: {bt_empty} ({100*bt_empty/max(len(records),1):.1f}%)")

    print(f"\n  By category:")
    for cat, count in categories.most_common():
        print(f"    {cat:12s}  {count:6d}")

    print(f"\n  Top 20 methods:")
    for name, count in method_counts.most_common(20):
        print(f"    {name:35s}  {count:6d}")


def do_hotpaths(records: list[dict], top: int, resolver: AddressResolver) -> None:
    path_counts: Counter = Counter()
    for r in records:
        bt = r.get("backtrace", [])
        method = r.get("method", "?")
        if not bt:
            continue
        resolved = [resolver.resolve(a) for a in reversed(bt)]
        path = " -> ".join(resolved) + f" -> [{method}]"
        path_counts[path] += 1

    print(f"\n=== Hot Paths (top {top}) ===")
    for path, count in path_counts.most_common(top):
        print(f"  {count:5d}x  {path}")


def do_callers(records: list[dict], method: str, top: int, resolver: AddressResolver) -> None:
    caller_counts: Counter = Counter()
    for r in records:
        if r.get("method") == method:
            bt = r.get("backtrace", [])
            if bt:
                caller_counts[bt[0]] += 1

    print(f"\n=== Callers of {method} (top {top}) ===")
    for addr, count in caller_counts.most_common(top):
        label = resolver.resolve(addr)
        print(f"  {count:5d}x  {label}")


def do_render_loop(records: list[dict], resolver: AddressResolver) -> None:
    depth_counts: defaultdict[str, Counter] = defaultdict(Counter)
    for r in records:
        bt = r.get("backtrace", [])
        for depth, addr in enumerate(bt):
            depth_counts[addr][depth] += 1

    candidates = []
    for addr, depths in depth_counts.items():
        max_depth = max(depths.keys())
        total_hits = sum(depths.values())
        if max_depth >= 3 and total_hits > len(records) * 0.1:
            candidates.append((total_hits, max_depth, addr))

    candidates.sort(key=lambda x: (-x[1], -x[0]))

    print(f"\n=== Render Loop Candidates ===")
    for hits, depth, addr in candidates[:10]:
        label = resolver.resolve(addr)
        print(f"  depth {depth:2d}  hits {hits:6d}  {label}")


def do_state_at(records: list[dict], target_seq: int) -> None:
    state = DeviceState()
    for r in records:
        if r.get("frame", -1) < 0:
            continue
        if r["seq"] > target_seq:
            break
        if r["slot"] in STATE_SET_SLOTS:
            state.apply(r)

    snap = state.snapshot()
    print(f"\n=== Device State at seq {target_seq} ===")
    print(f"  VS: {snap['vs']}")
    print(f"  PS: {snap['ps']}")
    print(f"  Vertex Decl: {snap['vertex_decl']}")
    print(f"  FVF: 0x{snap['fvf']:08X}" if snap['fvf'] else "  FVF: (none)")
    print(f"  Render Targets: {snap['render_targets']}")
    print(f"  Depth Stencil: {snap['depth_stencil']}")
    print(f"  Textures: {snap['textures']}")
    print(f"  Render States ({len(snap['render_states'])} set):")
    for k, v in sorted(snap['render_states'].items()):
        print(f"    {_fmt_rs(k, v)}")
    if snap['sampler_states']:
        print(f"  Sampler States:")
        for sampler, states in sorted(snap['sampler_states'].items()):
            print(f"    Sampler[{sampler}]: {states}")
    if snap['texture_stage_states']:
        print(f"  Texture Stage States:")
        for stage, states in sorted(snap['texture_stage_states'].items()):
            print(f"    Stage[{stage}]: {states}")


def do_matrix_flow(records: list[dict], resolver: AddressResolver) -> None:
    groups: defaultdict[str, list] = defaultdict(list)
    for r in records:
        if r["slot"] not in (SLOT["SetVertexShaderConstantF"],
                              SLOT["SetPixelShaderConstantF"]):
            continue
        bt = r.get("backtrace", [])
        caller = bt[0] if bt else "unknown"
        args = r.get("args", {})
        data = r.get("data", {})
        start_reg = _int(args.get("StartRegister", 0))
        count = _int(args.get("Vector4fCount", 0))
        consts = data.get("constants", [])
        groups[caller].append({
            "method": r["method"], "startReg": start_reg, "count": count,
            "constants": consts, "seq": r.get("seq", 0), "frame": r.get("frame", 0),
        })

    print(f"\n=== Matrix / Constant Flow ===")
    for caller, uploads in sorted(groups.items(), key=lambda x: -len(x[1])):
        label = resolver.resolve(caller)
        print(f"\n  Caller: {label}  ({len(uploads)} uploads)")
        seen = set()
        for u in uploads:
            key = (u["startReg"], u["count"])
            if key in seen:
                continue
            seen.add(key)
            print(f"    c{u['startReg']}..c{u['startReg'] + u['count'] - 1} ({u['count']} vec4)")
            if len(u["constants"]) == MATRIX_FLOAT_COUNT:
                cls = classify_matrix(u["constants"])
                print(f"    Classification: {cls}")
                print(format_matrix_4x4(u["constants"]))
            elif len(u["constants"]) >= 4:
                print(f"    First values: {u['constants'][:8]}")


def do_render_passes(records: list[dict]) -> None:
    runtime = [r for r in records if r.get("frame", -1) >= 0]
    passes = []
    current_pass: dict[str, Any] = {
        "rt": "default", "draws": 0, "shaders": set(),
        "start_seq": 0, "clear_flags": 0, "type": "unknown",
    }

    for r in runtime:
        slot = r["slot"]
        args = r.get("args", {})
        data = r.get("data", {})

        if slot == SLOT["SetRenderTarget"]:
            if current_pass["draws"] > 0:
                current_pass["type"] = _classify_pass(current_pass)
                passes.append(current_pass)
            rt = args.get("pRT", "NULL")
            current_pass = {
                "rt": rt, "draws": 0, "shaders": set(),
                "start_seq": r["seq"], "clear_flags": 0, "type": "unknown",
            }
        elif slot == SLOT["Clear"]:
            flags = _int(data.get("Flags", args.get("Flags", 0)))
            if current_pass["draws"] > 0:
                current_pass["type"] = _classify_pass(current_pass)
                passes.append(current_pass)
                current_pass = {
                    "rt": current_pass["rt"], "draws": 0, "shaders": set(),
                    "start_seq": r["seq"], "clear_flags": flags, "type": "unknown",
                }
            else:
                current_pass["clear_flags"] |= flags
        elif slot in GEOMETRY_DRAW_SLOTS:
            current_pass["draws"] += 1
        elif slot == SLOT["SetVertexShader"]:
            current_pass["shaders"].add(("VS", args.get("pShader", "NULL")))
        elif slot == SLOT["SetPixelShader"]:
            current_pass["shaders"].add(("PS", args.get("pShader", "NULL")))

    if current_pass["draws"] > 0:
        current_pass["type"] = _classify_pass(current_pass)
        passes.append(current_pass)

    print(f"\n=== Render Passes ({len(passes)} total) ===")
    for i, p in enumerate(passes):
        flags_str = _fmt_clear_flags(p["clear_flags"])
        shader_count = len(p["shaders"])
        print(f"  Pass {i:3d}: RT={p['rt']}  draws={p['draws']:4d}  "
              f"type={p['type']:12s}  clear={flags_str}  shaders={shader_count}")


def _classify_pass(p: dict) -> str:
    flags = p["clear_flags"]
    if flags & D3DCLEAR_ZBUFFER and not (flags & D3DCLEAR_TARGET):
        return "depth-only"
    if p["draws"] == 1 and len(p["shaders"]) <= 1:
        return "fullscreen"
    if p["draws"] > 10:
        return "scene"
    return "misc"


def _fmt_clear_flags(flags: int) -> str:
    if not flags:
        return "none"
    parts = []
    if flags & D3DCLEAR_TARGET:
        parts.append("COLOR")
    if flags & D3DCLEAR_ZBUFFER:
        parts.append("Z")
    if flags & D3DCLEAR_STENCIL:
        parts.append("STENCIL")
    return "|".join(parts)


def do_draw_calls(records: list[dict], resolver: AddressResolver) -> None:
    runtime = [r for r in records if r.get("frame", -1) >= 0]
    state = DeviceState()
    prev_snap: dict = {}
    draw_idx = 0

    print(f"\n=== Draw Calls ===")
    for r in runtime:
        if r["slot"] in STATE_SET_SLOTS:
            state.apply(r)
        elif r["slot"] in GEOMETRY_DRAW_SLOTS:
            snap = state.snapshot()
            bt = r.get("backtrace", [])
            caller = resolver.resolve(bt[0]) if bt else "?"
            args = r.get("args", {})
            prim_type = _int(args.get("PrimitiveType", 0))

            print(f"\n  Draw #{draw_idx} (seq {r['seq']}, frame {r['frame']}) "
                  f"{r['method']} {D3DPT_NAMES.get(prim_type, str(prim_type))}")
            print(f"    Caller: {caller}")
            for k, v in args.items():
                if k == "PrimitiveType":
                    continue
                print(f"    {k}: {v}")

            if snap["vs"] != prev_snap.get("vs"):
                print(f"    [delta] VS: {snap['vs']}")
            if snap["ps"] != prev_snap.get("ps"):
                print(f"    [delta] PS: {snap['ps']}")
            if snap["vertex_decl"] != prev_snap.get("vertex_decl"):
                print(f"    [delta] VDecl: {snap['vertex_decl']}")
            for stage, tex in snap["textures"].items():
                if prev_snap.get("textures", {}).get(stage) != tex:
                    print(f"    [delta] Tex[{stage}]: {tex}")

            prev_snap = snap
            draw_idx += 1

    print(f"\n  Total draws: {draw_idx}")


def do_classify_draws(records: list[dict]) -> None:
    runtime = [r for r in records if r.get("frame", -1) >= 0]
    state = DeviceState()
    tags_count: Counter = Counter()
    method_count: Counter = Counter()
    vs_count: Counter = Counter()

    for r in runtime:
        if r["slot"] in STATE_SET_SLOTS:
            state.apply(r)
        elif r["slot"] in GEOMETRY_DRAW_SLOTS:
            rs = state.render_states
            tags = []

            method = r.get("method", "?")
            method_short = {
                "DrawPrimitive": "DP",
                "DrawIndexedPrimitive": "DIP",
                "DrawPrimitiveUP": "DPUP",
                "DrawIndexedPrimitiveUP": "DIPUP",
            }.get(method, method)
            tags.append(method_short)
            method_count[method_short] += 1
            vs_count[state.vs or "NULL"] += 1

            if rs.get(D3DRS_ALPHABLENDENABLE, 0):
                src = rs.get(D3DRS_SRCBLEND, 0)
                dst = rs.get(D3DRS_DESTBLEND, 0)
                tags.append(f"alpha-blended({D3DBLEND_NAMES.get(src,'?')},{D3DBLEND_NAMES.get(dst,'?')})")
            if rs.get(D3DRS_ALPHATESTENABLE, 0):
                tags.append("alpha-tested")
            if not rs.get(D3DRS_ZWRITEENABLE, 1):
                tags.append("no-zwrite")
            cw = rs.get(D3DRS_COLORWRITEENABLE, 0xF)
            if cw == 0:
                tags.append("z-prepass")
            if rs.get(D3DRS_STENCILENABLE, 0):
                tags.append("stencil")
            if rs.get(D3DRS_FOGENABLE, 0):
                tags.append("fog")

            args = r.get("args", {})
            prim_type = _int(args.get("PrimitiveType", 0))
            prim_count = _int(args.get("PrimitiveCount", 0))
            if prim_type == 4 and prim_count == 2:
                tags.append("fullscreen-quad")
            if not rs.get(D3DRS_ZENABLE, 1):
                tags.append("no-ztest")

            if len(tags) == 1:
                tags.append("opaque")
            for t in tags:
                tags_count[t] += 1

    print(f"\n=== Draw Classification ===")
    for tag, count in tags_count.most_common():
        print(f"  {tag:40s}  {count:5d} draws")

    print(f"\n  By draw method:")
    for m, count in method_count.most_common():
        print(f"    {m:10s}  {count:5d}")

    print(f"\n  By vertex shader:")
    for vs, count in vs_count.most_common():
        print(f"    {vs:18s}  {count:5d}")


def do_redundant(records: list[dict]) -> None:
    runtime = [r for r in records if r.get("frame", -1) >= 0]
    last_state: dict[tuple, Any] = {}
    redundant: Counter = Counter()
    total_sets = 0

    for r in runtime:
        slot = r["slot"]
        if slot not in STATE_SET_SLOTS:
            continue
        total_sets += 1
        args = r.get("args", {})
        data = r.get("data", {})

        if slot == SLOT["SetRenderState"]:
            key = ("RS", _int(args.get("State", 0)))
            value = _int(args.get("Value", 0))
        elif slot == SLOT["SetTexture"]:
            key = ("Tex", _int(args.get("Stage", 0)))
            value = args.get("pTexture", "NULL")
        elif slot == SLOT["SetVertexShader"]:
            key = ("VS",)
            value = args.get("pShader", "NULL")
        elif slot == SLOT["SetPixelShader"]:
            key = ("PS",)
            value = args.get("pShader", "NULL")
        elif slot == SLOT["SetSamplerState"]:
            key = ("SS", _int(args.get("Sampler", 0)), _int(args.get("Type", 0)))
            value = _int(args.get("Value", 0))
        elif slot == SLOT["SetTextureStageState"]:
            key = ("TSS", _int(args.get("Stage", 0)), _int(args.get("Type", 0)))
            value = _int(args.get("Value", 0))
        elif slot == SLOT["SetRenderTarget"]:
            key = ("RT", _int(args.get("RenderTargetIndex", 0)))
            value = args.get("pRT", "NULL")
        elif slot == SLOT["SetVertexDeclaration"]:
            key = ("VDecl",)
            value = args.get("pDecl", "NULL")
        elif slot == SLOT["SetFVF"]:
            key = ("FVF",)
            value = _int(args.get("FVF", 0))
        elif slot == SLOT["SetIndices"]:
            key = ("IB",)
            value = args.get("pIndexData", "NULL")
        elif slot == SLOT["SetStreamSource"]:
            key = ("Stream", _int(args.get("StreamNumber", 0)))
            value = (args.get("pStreamData"), _int(args.get("Stride", 0)))
        elif slot in (SLOT["SetTransform"], SLOT["MultiplyTransform"]):
            key = ("Transform", _int(args.get("State", 0)))
            value = tuple(data.get("matrix", []))
        else:
            key = ("slot", slot)
            value = tuple(sorted(args.items()))

        if key in last_state and last_state[key] == value:
            redundant[r.get("method", "?")] += 1
        last_state[key] = value

        if r["slot"] in GEOMETRY_DRAW_SLOTS:
            last_state.clear()

    print(f"\n=== Redundant State Calls ===")
    print(f"  Total Set* calls: {total_sets}")
    total_redundant = sum(redundant.values())
    print(f"  Redundant:        {total_redundant} ({100*total_redundant/max(total_sets,1):.1f}%)")
    for method, count in redundant.most_common(20):
        print(f"    {method:35s}  {count:5d}")


def do_texture_freq(records: list[dict]) -> None:
    tex_counts: Counter = Counter()
    tex_stages: defaultdict[str, set] = defaultdict(set)

    for r in records:
        if r["slot"] == SLOT["SetTexture"]:
            args = r.get("args", {})
            tex = args.get("pTexture", "NULL")
            stage = _int(args.get("Stage", 0))
            tex_counts[tex] += 1
            tex_stages[tex].add(stage)

    print(f"\n=== Texture Binding Frequency (top 30) ===")
    for tex, count in tex_counts.most_common(30):
        stages = sorted(tex_stages[tex])
        print(f"  {tex}  bound {count}x  stages: {stages}")


def do_rt_graph(records: list[dict]) -> None:
    rt_set: set[str] = set()
    current_rt = "backbuffer"
    edges: list[tuple[str, str, str]] = []

    for r in records:
        if r["slot"] == SLOT["SetRenderTarget"]:
            rt = r.get("args", {}).get("pRT", "NULL")
            rt_set.add(rt)
            current_rt = rt
        elif r["slot"] == SLOT["SetTexture"]:
            tex = r.get("args", {}).get("pTexture", "NULL")
            if tex in rt_set:
                edges.append((tex, current_rt, f"stage_{_int(r.get('args',{}).get('Stage',0))}"))

    print(f"\n=== Render Target Dependency Graph ===")
    print(f"  Render targets: {len(rt_set)}")
    unique_edges = list(set(edges))
    print(f"  RT->Texture edges: {len(unique_edges)}")
    for src_rt, dst_rt, stage in unique_edges[:30]:
        print(f"    {src_rt} rendered-to -> sampled as {stage} while drawing to {dst_rt}")

    if unique_edges:
        print(f"\n  Mermaid diagram:")
        print(f"  ```mermaid")
        print(f"  flowchart LR")
        seen = set()
        for src_rt, dst_rt, stage in unique_edges:
            safe_src = src_rt.replace("0x", "RT_")
            safe_dst = dst_rt.replace("0x", "RT_")
            edge_key = (safe_src, safe_dst)
            if edge_key not in seen:
                print(f"    {safe_src} --> {safe_dst}")
                seen.add(edge_key)
        print(f"  ```")


def _shader_key(bytecode_hex: str) -> str:
    """Identity of a shader: a digest of its whole bytecode.

    Shaders of one model with the same constant-table size share their first
    DWORDs, so a bytecode prefix does not tell them apart.
    """
    return hashlib.sha1(bytecode_hex.encode("ascii")).hexdigest()[:16]


def do_shader_map(records: list[dict], fxc_path: str | None) -> None:
    shaders: dict[str, dict] = {}
    handle_to_bc: dict[str, str] = {}
    shader_usage: Counter = Counter()

    for r in records:
        if r["slot"] in (SLOT["CreateVertexShader"], SLOT["CreatePixelShader"]):
            data = r.get("data", {})
            bytecode = data.get("bytecode", "")
            disasm = data.get("disasm", "")
            handle = r.get("created_handle")
            if bytecode:
                kind = "VS" if r["slot"] == SLOT["CreateVertexShader"] else "PS"
                key = _shader_key(bytecode)
                shaders[key] = {
                    "kind": kind, "bytecode": bytecode,
                    "handle": handle, "slot": r["slot"],
                    "disasm": disasm,
                }
                if handle:
                    handle_to_bc[handle] = key
        elif r["slot"] in (SLOT["SetVertexShader"], SLOT["SetPixelShader"]):
            ptr = r.get("args", {}).get("pShader", "NULL")
            kind = "VS" if r["slot"] == SLOT["SetVertexShader"] else "PS"
            shader_usage[f"{kind}:{ptr}"] += 1

    print(f"\n=== Shader Map ===")
    print(f"  Unique shaders captured: {len(shaders)}")
    print(f"  Handle->bytecode links: {len(handle_to_bc)}")
    disasm_count = sum(1 for s in shaders.values() if s.get("disasm"))
    print(f"  Shaders with disassembly: {disasm_count}/{len(shaders)}")
    print(f"\n  Top shader bindings:")
    for key, count in shader_usage.most_common(10):
        kind_ptr = key.split(":", 1)
        bc_key = handle_to_bc.get(kind_ptr[1] if len(kind_ptr) > 1 else "", "")
        bc_info = f" -> {shaders[bc_key]['kind']} {len(shaders[bc_key]['bytecode'])//8} DWORDs" if bc_key in shaders else ""
        print(f"    {key} set {count}x{bc_info}")

    for key, info in shaders.items():
        handle_str = f" handle={info['handle']}" if info.get("handle") else ""
        print(f"\n  {info['kind']}{handle_str} (hash: {key})")
        bc = info["bytecode"]
        print(f"    Bytecode length: {len(bc) // 8} DWORDs")

        asm_text = info.get("disasm") or _disassemble_shader(bytes.fromhex(bc), fxc_path)
        if asm_text:
            print(f"    Disassembly:")
            for line in asm_text.splitlines():
                print(f"      {line}")
            regs = _extract_register_usage(asm_text)
            if regs:
                print(f"    Register usage: {regs}")


def _disassemble_shader(bytecode: bytes, fxc_path: str | None) -> str | None:
    result = _disasm_via_d3dcompiler(bytecode)
    if result:
        return result
    if fxc_path:
        return _disasm_via_fxc(bytecode, fxc_path)
    return None


def _disasm_via_d3dcompiler(bytecode: bytes) -> str | None:
    try:
        import ctypes
        d3dcompiler = ctypes.windll.d3dcompiler_47

        class ID3DBlob_Vtbl(ctypes.Structure):
            _fields_ = [
                ("QueryInterface", ctypes.c_void_p),
                ("AddRef", ctypes.c_void_p),
                ("Release", ctypes.c_void_p),
                ("GetBufferPointer", ctypes.c_void_p),
                ("GetBufferSize", ctypes.c_void_p),
            ]

        blob = ctypes.c_void_p()
        hr = d3dcompiler.D3DDisassemble(
            bytecode, len(bytecode), 0, None, ctypes.byref(blob)
        )
        if hr != 0 or not blob:
            return None

        vtbl_ptr = ctypes.cast(blob, ctypes.POINTER(ctypes.c_void_p)).contents
        vtbl = ctypes.cast(vtbl_ptr, ctypes.POINTER(ID3DBlob_Vtbl)).contents

        proto_getbuf = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
        proto_getsz = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.c_void_p)

        buf_ptr = proto_getbuf(vtbl.GetBufferPointer)(blob)
        buf_sz = proto_getsz(vtbl.GetBufferSize)(blob)

        text = ctypes.string_at(buf_ptr, buf_sz).decode("utf-8", errors="replace")

        proto_release = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
        proto_release(vtbl.Release)(blob)

        return text
    except Exception:
        return None


def _disasm_via_fxc(bytecode: bytes, fxc_path: str) -> str | None:
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(suffix=".cso", delete=False) as tmp:
            tmp.write(bytecode)
            tmp_path = tmp.name
        result = subprocess.run(
            [fxc_path, "/dumpbin", tmp_path],
            capture_output=True, text=True, timeout=10,
        )
        Path(tmp_path).unlink(missing_ok=True)
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return None


def _extract_register_usage(asm_text: str) -> dict[str, list[str]]:
    c_regs = set()
    v_regs = set()
    s_regs = set()
    t_regs = set()
    for line in asm_text.splitlines():
        parts = line.strip().split()
        for p in parts:
            p = p.rstrip(",")
            base = p.split(".")[0]
            if base.startswith("c") and len(base) > 1 and base[1:].isdigit():
                c_regs.add(base)
            elif base.startswith("v") and len(base) > 1 and base[1:].isdigit():
                v_regs.add(base)
            elif base.startswith("s") and len(base) > 1 and base[1:].isdigit():
                s_regs.add(base)
            elif base.startswith("t") and len(base) > 1 and base[1:].isdigit():
                t_regs.add(base)
    result = {}
    if c_regs:
        result["constant_regs"] = sorted(c_regs, key=lambda x: int(x[1:]))
    if v_regs:
        result["vertex_inputs"] = sorted(v_regs, key=lambda x: int(x[1:]))
    if s_regs:
        result["samplers"] = sorted(s_regs, key=lambda x: int(x[1:]))
    if t_regs:
        result["texcoords"] = sorted(t_regs, key=lambda x: int(x[1:]))
    return result


# ── Constant provenance ──────────────────────────────────────────────────────

def _parse_ctab_registers(disasm_text: str) -> dict[str, int]:
    """Parse CTAB register table from D3DX disassembly.

    Returns: {name: start_register_number} for each named parameter.
    """
    mapping = {}
    in_regs = False
    for line in disasm_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") and "Name" in stripped and "Reg" in stripped:
            in_regs = True
            continue
        if in_regs and stripped.startswith("//") and "----" in stripped:
            continue
        if in_regs and stripped.startswith("//"):
            parts = stripped.lstrip("/ ").split()
            if len(parts) >= 3 and parts[1].startswith("c") and parts[1][1:].isdigit():
                mapping[parts[0]] = int(parts[1][1:])
            elif len(parts) < 2 or not parts[0][0].isalpha():
                in_regs = False
        else:
            in_regs = False
    return mapping


def do_const_provenance(records: list[dict], draw_index: int | None) -> None:
    """For each draw, show which seq# last wrote each constant register.

    If draw_index is given, show detailed provenance for that single draw.
    Otherwise, show a summary across all draws.
    """
    shader_disasm: dict[str, str] = {}
    handle_to_hash: dict[str, str] = {}
    for r in records:
        if r["slot"] in (SLOT["CreateVertexShader"], SLOT["CreatePixelShader"]):
            data = r.get("data", {})
            bc = data.get("bytecode", "")
            disasm = data.get("disasm", "")
            handle = r.get("created_handle")
            if bc and handle:
                key = _shader_key(bc)
                if disasm:
                    shader_disasm[key] = disasm
                handle_to_hash[handle] = key

    vs_prov: dict[int, tuple[int, list[float]]] = {}
    ps_prov: dict[int, tuple[int, list[float]]] = {}
    state = DeviceState()
    draw_num = 0
    runtime = [r for r in records if r.get("frame", -1) >= 0]

    print(f"\n=== Constant Provenance ===")

    for r in runtime:
        slot = r["slot"]
        seq = r.get("seq", 0)
        args = r.get("args", {})
        data = r.get("data", {})

        if slot == SLOT["SetVertexShaderConstantF"]:
            start = _int(args.get("StartRegister", 0))
            consts = data.get("constants", [])
            for i in range(0, len(consts), 4):
                vs_prov[start + i // 4] = (seq, consts[i:i+4])
        elif slot == SLOT["SetPixelShaderConstantF"]:
            start = _int(args.get("StartRegister", 0))
            consts = data.get("constants", [])
            for i in range(0, len(consts), 4):
                ps_prov[start + i // 4] = (seq, consts[i:i+4])

        if slot in STATE_SET_SLOTS:
            state.apply(r)

        if slot not in GEOMETRY_DRAW_SLOTS:
            continue

        target = draw_index is None or draw_num == draw_index
        if target:
            vs_hash = handle_to_hash.get(state.vs, "")
            ps_hash = handle_to_hash.get(state.ps, "")
            vs_disasm = shader_disasm.get(vs_hash, "")
            ps_disasm = shader_disasm.get(ps_hash, "")
            vs_ctab = _parse_ctab_registers(vs_disasm) if vs_disasm else {}
            ps_ctab = _parse_ctab_registers(ps_disasm) if ps_disasm else {}

            if draw_index is not None:
                _print_draw_provenance(
                    draw_num, seq, state, vs_prov, ps_prov, vs_ctab, ps_ctab)
            else:
                _print_draw_provenance_compact(
                    draw_num, seq, state, vs_prov, ps_prov, vs_ctab, ps_ctab)

        draw_num += 1

    if draw_index is not None and draw_num <= (draw_index or 0):
        print(f"  [error] Draw #{draw_index} not found (only {draw_num} draws)")


def _print_draw_provenance(
    draw_num: int, seq: int, state: DeviceState,
    vs_prov: dict, ps_prov: dict,
    vs_ctab: dict, ps_ctab: dict,
) -> None:
    reg_name_lookup = {}
    for name, reg in vs_ctab.items():
        reg_name_lookup[("vs", reg)] = name
    for name, reg in ps_ctab.items():
        reg_name_lookup[("ps", reg)] = name

    print(f"\n  Draw #{draw_num} (seq {seq})  VS={state.vs}  PS={state.ps}")

    if vs_prov:
        print(f"    VS constants ({len(vs_prov)} registers written):")
        for reg in sorted(vs_prov):
            src_seq, vals = vs_prov[reg]
            name = reg_name_lookup.get(("vs", reg), "")
            name_str = f"  ({name})" if name else ""
            fvals = ", ".join(f"{v:9.4f}" if isinstance(v, float) else str(v) for v in vals)
            print(f"      c{reg:<3d} = [{fvals}]  set by seq#{src_seq}{name_str}")

    if ps_prov:
        print(f"    PS constants ({len(ps_prov)} registers written):")
        for reg in sorted(ps_prov):
            src_seq, vals = ps_prov[reg]
            name = reg_name_lookup.get(("ps", reg), "")
            name_str = f"  ({name})" if name else ""
            fvals = ", ".join(f"{v:9.4f}" if isinstance(v, float) else str(v) for v in vals)
            print(f"      c{reg:<3d} = [{fvals}]  set by seq#{src_seq}{name_str}")


def _print_draw_provenance_compact(
    draw_num: int, seq: int, state: DeviceState,
    vs_prov: dict, ps_prov: dict,
    vs_ctab: dict, ps_ctab: dict,
) -> None:
    vs_named = []
    for name, reg in sorted(vs_ctab.items(), key=lambda x: x[1]):
        if reg in vs_prov:
            src_seq, vals = vs_prov[reg]
            vs_named.append(f"c{reg}={name}@seq#{src_seq}")
    ps_named = []
    for name, reg in sorted(ps_ctab.items(), key=lambda x: x[1]):
        if reg in ps_prov:
            src_seq, vals = ps_prov[reg]
            ps_named.append(f"c{reg}={name}@seq#{src_seq}")

    if vs_named or ps_named:
        vs_str = " ".join(vs_named) if vs_named else "-"
        ps_str = " ".join(ps_named) if ps_named else "-"
        print(f"  Draw #{draw_num:4d} (seq {seq:6d})  VS:[{vs_str}]  PS:[{ps_str}]")


def do_vtx_formats(records: list[dict]) -> None:
    init_decls: dict[str, list[dict]] = {}
    for r in records:
        if r["slot"] == SLOT["CreateVertexDeclaration"]:
            data = r.get("data", {})
            elements = data.get("elements", [])
            handle = r.get("created_handle")
            if elements and handle:
                init_decls[handle] = elements

    runtime = [r for r in records if r.get("frame", -1) >= 0]
    state = DeviceState()
    decl_draws: defaultdict[str, int] = defaultdict(int)

    for r in runtime:
        if r["slot"] in STATE_SET_SLOTS:
            state.apply(r)
        elif r["slot"] in GEOMETRY_DRAW_SLOTS:
            key = state.vertex_decl or "NULL"
            decl_draws[key] += 1

    print(f"\n=== Vertex Format Groups ({len(decl_draws)} unique) ===")
    for decl, count in sorted(decl_draws.items(), key=lambda x: -x[1]):
        print(f"\n  VDecl {decl}:  {count:5d} draws")
        elements = init_decls.get(decl, [])
        if elements:
            for e in elements:
                usage_name = D3DDECLUSAGE_NAMES.get(e.get("Usage", -1), f"UNKNOWN({e.get('Usage')})")
                type_name = D3DDECLTYPE_NAMES.get(e.get("Type", -1), f"UNKNOWN({e.get('Type')})")
                print(f"    Stream{e.get('Stream',0)} +{e.get('Offset',0):3d}  "
                      f"{type_name:12s}  {usage_name}{e.get('UsageIndex',0)}")
        elif decl != "NULL":
            print(f"    (elements not captured in init phase)")


def do_diff_draws(records: list[dict], seq_a: int, seq_b: int) -> None:
    runtime = [r for r in records if r.get("frame", -1) >= 0]
    state = DeviceState()
    snap_a: dict = {}
    snap_b: dict = {}

    for r in runtime:
        if r["slot"] in STATE_SET_SLOTS:
            state.apply(r)
        elif r["slot"] in GEOMETRY_DRAW_SLOTS:
            if r["seq"] == seq_a:
                snap_a = state.snapshot()
            elif r["seq"] == seq_b:
                snap_b = state.snapshot()

    if not snap_a:
        print(f"  [error] No draw found at seq {seq_a}")
        return
    if not snap_b:
        print(f"  [error] No draw found at seq {seq_b}")
        return

    print(f"\n=== State Diff: Draw seq {seq_a} vs {seq_b} ===")
    for key in ("vs", "ps", "vertex_decl", "fvf", "depth_stencil", "indices"):
        va, vb = snap_a.get(key), snap_b.get(key)
        if va != vb:
            print(f"  {key}: {va} -> {vb}")
    for stage in sorted(set(snap_a.get("textures", {})) | set(snap_b.get("textures", {}))):
        ta = snap_a.get("textures", {}).get(stage)
        tb = snap_b.get("textures", {}).get(stage)
        if ta != tb:
            print(f"  Tex[{stage}]: {ta} -> {tb}")
    for rs_key in sorted(set(snap_a.get("render_states", {})) | set(snap_b.get("render_states", {}))):
        ra = snap_a.get("render_states", {}).get(rs_key)
        rb = snap_b.get("render_states", {}).get(rs_key)
        if ra != rb:
            name = D3DRS_NAMES.get(rs_key, f"RS[{rs_key}]")
            print(f"  {name}: {ra} -> {rb}")
    for reg in sorted(set(snap_a.get("vs_constants", {})) | set(snap_b.get("vs_constants", {}))):
        ca = snap_a.get("vs_constants", {}).get(reg)
        cb = snap_b.get("vs_constants", {}).get(reg)
        if ca != cb:
            print(f"  VS c{reg}: {ca} -> {cb}")


def do_diff_frames(records: list[dict], frame_a: int, frame_b: int) -> None:
    state_a = DeviceState()
    state_b = DeviceState()
    draws_a: list[dict] = []
    draws_b: list[dict] = []

    for r in records:
        f = r.get("frame", -1)
        if f == frame_a:
            if r["slot"] in STATE_SET_SLOTS:
                state_a.apply(r)
            elif r["slot"] in GEOMETRY_DRAW_SLOTS:
                draws_a.append({"method": r["method"], "args": r.get("args", {}),
                                "state": state_a.snapshot()})
        elif f == frame_b:
            if r["slot"] in STATE_SET_SLOTS:
                state_b.apply(r)
            elif r["slot"] in GEOMETRY_DRAW_SLOTS:
                draws_b.append({"method": r["method"], "args": r.get("args", {}),
                                "state": state_b.snapshot()})

    print(f"\n=== Frame Diff: Frame {frame_a} vs {frame_b} ===")
    print(f"  Frame {frame_a}: {len(draws_a)} draws")
    print(f"  Frame {frame_b}: {len(draws_b)} draws")
    print(f"  Difference:  {len(draws_b) - len(draws_a):+d} draws")

    common = min(len(draws_a), len(draws_b))
    changed = 0
    for i in range(common):
        sa, sb = draws_a[i]["state"], draws_b[i]["state"]
        if sa.get("vs") != sb.get("vs") or sa.get("ps") != sb.get("ps"):
            changed += 1
        elif sa.get("vs_constants") != sb.get("vs_constants"):
            changed += 1
    print(f"  Draws with state changes (first {common}): {changed}")


def do_animate_constants(records: list[dict]) -> None:
    frames = sorted(set(r.get("frame", -1) for r in records if r.get("frame", -1) >= 0))
    if len(frames) < 2:
        print("\n  [error] Need 2+ frames for --animate-constants")
        return

    vs_per_frame: dict[int, dict[int, list[float]]] = {f: {} for f in frames}
    ps_per_frame: dict[int, dict[int, list[float]]] = {f: {} for f in frames}

    for r in records:
        f = r.get("frame", -1)
        if f < 0:
            continue
        args = r.get("args", {})
        data = r.get("data", {})
        consts = data.get("constants", [])
        if not consts:
            continue

        if r["slot"] == SLOT["SetVertexShaderConstantF"]:
            start = _int(args.get("StartRegister", 0))
            for i in range(0, len(consts), 4):
                vs_per_frame[f][start + i // 4] = consts[i:i+4]
        elif r["slot"] == SLOT["SetPixelShaderConstantF"]:
            start = _int(args.get("StartRegister", 0))
            for i in range(0, len(consts), 4):
                ps_per_frame[f][start + i // 4] = consts[i:i+4]

    print(f"\n=== Constant Animation ({len(frames)} frames) ===")
    for label, per_frame in [("VS", vs_per_frame), ("PS", ps_per_frame)]:
        all_regs = set()
        for f in frames:
            all_regs.update(per_frame[f].keys())

        static_regs = []
        dynamic_regs = []
        per_object_regs = []

        for reg in sorted(all_regs):
            all_vals = []
            for f in frames:
                if reg in per_frame[f]:
                    all_vals.append(tuple(per_frame[f][reg]))
            if len(all_vals) < 2:
                continue
            unique = set(all_vals)
            if len(unique) == 1:
                static_regs.append(reg)
            elif len(unique) > len(frames):
                per_object_regs.append(reg)
            else:
                dynamic_regs.append(reg)

        print(f"\n  {label} Constants:")
        print(f"    Static (same across frames):      {len(static_regs)}")
        if static_regs:
            print(f"      {static_regs[:20]}")
        print(f"    Animated (change across frames):  {len(dynamic_regs)}")
        for reg in dynamic_regs[:10]:
            vals = [per_frame[f].get(reg) for f in frames]
            print(f"      c{reg}: {vals}")
        print(f"    Per-object (many unique values):  {len(per_object_regs)}")
        if per_object_regs:
            print(f"      {per_object_regs[:20]}")


def do_pipeline_diagram(records: list[dict]) -> None:
    runtime = [r for r in records if r.get("frame", -1) >= 0]

    passes = []
    current_rt = "backbuffer"
    current_draws = 0
    current_vs = set()
    current_ps = set()
    current_clear = 0
    rt_as_tex: defaultdict[str, set] = defaultdict(set)

    for r in runtime:
        slot = r["slot"]
        args = r.get("args", {})

        if slot == SLOT["SetRenderTarget"]:
            if current_draws > 0:
                passes.append({
                    "rt": current_rt, "draws": current_draws,
                    "vs": len(current_vs), "ps": len(current_ps),
                    "clear": current_clear,
                })
            current_rt = args.get("pRT", "NULL")
            current_draws = 0
            current_vs = set()
            current_ps = set()
            current_clear = 0
        elif slot == SLOT["Clear"]:
            data = r.get("data", {})
            current_clear |= _int(data.get("Flags", args.get("Flags", 0)))
        elif slot in GEOMETRY_DRAW_SLOTS:
            current_draws += 1
        elif slot == SLOT["SetVertexShader"]:
            current_vs.add(args.get("pShader", "NULL"))
        elif slot == SLOT["SetPixelShader"]:
            current_ps.add(args.get("pShader", "NULL"))
        elif slot == SLOT["SetTexture"]:
            tex = args.get("pTexture", "NULL")
            rt_as_tex[tex].add(current_rt)

    if current_draws > 0:
        passes.append({
            "rt": current_rt, "draws": current_draws,
            "vs": len(current_vs), "ps": len(current_ps),
            "clear": current_clear,
        })

    all_rts = {p["rt"] for p in passes}

    print(f"\n=== Pipeline Diagram (Mermaid) ===")
    print(f"```mermaid")
    print(f"flowchart TB")
    for i, p in enumerate(passes):
        safe_rt = p["rt"].replace("0x", "RT_")
        clear_str = _fmt_clear_flags(p["clear"])
        print(f"  pass{i}[\"{safe_rt}\\n{p['draws']} draws, {p['vs']}VS/{p['ps']}PS\\nclear: {clear_str}\"]")
        if i > 0:
            print(f"  pass{i-1} --> pass{i}")

    for tex, dst_rts in rt_as_tex.items():
        if tex in all_rts:
            src_safe = tex.replace("0x", "RT_")
            for idx, p in enumerate(passes):
                if p["rt"] in dst_rts:
                    print(f"  {src_safe} -.->|sampled| pass{idx}")
                    break
    print(f"```")


def _parse_reg_range(spec: str) -> tuple[str, int, int]:
    """Parse a register range like 'vs:c0-c6', 'ps:c0-c3', or 'c0-c6'.

    Returns: (prefix 'vs'|'ps', start_reg, end_reg inclusive).
    """
    prefix = "vs"
    body = spec
    if ":" in spec:
        prefix, body = spec.split(":", 1)
        prefix = prefix.lower()

    body = body.lstrip("c")
    if "-" in body:
        lo, hi = body.split("-", 1)
        hi = hi.lstrip("c")
        return prefix, int(lo), int(hi)
    return prefix, int(body), int(body)


def do_const_evolution(records: list[dict], range_spec: str) -> None:
    """Track how specific constant registers change across draws in a frame."""
    prefix, reg_lo, reg_hi = _parse_reg_range(range_spec)
    is_vs = prefix == "vs"
    label = "VS" if is_vs else "PS"
    set_slot = SLOT["SetVertexShaderConstantF"] if is_vs else SLOT["SetPixelShaderConstantF"]
    reg_count = reg_hi - reg_lo + 1

    runtime = [r for r in records if r.get("frame", -1) >= 0]
    consts: dict[int, list[float]] = {}
    per_draw: list[dict[int, list[float]]] = []
    draw_seqs: list[int] = []

    for r in runtime:
        if r["slot"] == set_slot:
            args = r.get("args", {})
            start = _int(args.get("StartRegister", 0))
            data = r.get("data", {}).get("constants", [])
            for i in range(0, len(data), 4):
                reg = start + i // 4
                if reg_lo <= reg <= reg_hi:
                    consts[reg] = data[i:i+4]
        elif r["slot"] in GEOMETRY_DRAW_SLOTS:
            snapshot = {reg: list(consts[reg]) for reg in range(reg_lo, reg_hi + 1) if reg in consts}
            per_draw.append(snapshot)
            draw_seqs.append(r["seq"])

    total_draws = len(per_draw)
    print(f"\n=== Constant Evolution ({label} c{reg_lo}-c{reg_hi}, {total_draws} draws) ===")

    if total_draws == 0:
        print("  No draws found.")
        return

    # Per-register uniqueness
    print(f"\n  Register stability:")
    for reg in range(reg_lo, reg_hi + 1):
        vals = [tuple(d.get(reg, [0,0,0,0])) for d in per_draw]
        unique = len(set(vals))
        if unique == 1:
            kind = "CONSTANT (same for all draws)"
        elif unique < total_draws * 0.1:
            kind = f"FEW-VALUES ({unique} unique)"
        elif unique > total_draws * 0.9:
            kind = f"PER-OBJECT ({unique} unique)"
        else:
            kind = f"MIXED ({unique} unique)"
        print(f"    c{reg:<3d}  {kind}")

    # 3x3 rotation grouping: find shared rotations across draws
    # This requires at least 3 consecutive registers with 4 components each
    if reg_count >= 3:
        _const_evolution_rotation_analysis(per_draw, draw_seqs, reg_lo, label)

    # Show first 5 + last 5 draws' values
    print(f"\n  Sample values (first 5 draws):")
    for i in range(min(5, total_draws)):
        _print_evolution_sample(per_draw[i], draw_seqs[i], i, reg_lo, reg_hi)

    if total_draws > 10:
        print(f"\n  Sample values (last 5 draws):")
        for i in range(max(0, total_draws - 5), total_draws):
            _print_evolution_sample(per_draw[i], draw_seqs[i], i, reg_lo, reg_hi)


def _print_evolution_sample(
    snap: dict[int, list[float]], seq: int, draw_idx: int,
    reg_lo: int, reg_hi: int,
) -> None:
    vals_str = []
    for reg in range(reg_lo, reg_hi + 1):
        v = snap.get(reg, [0, 0, 0, 0])
        vals_str.append(f"c{reg}=[{v[0]:10.4f} {v[1]:10.4f} {v[2]:10.4f} {v[3]:10.4f}]")
    print(f"    Draw #{draw_idx:4d} seq={seq:6d}  {' '.join(vals_str)}")


def _const_evolution_rotation_analysis(
    per_draw: list[dict[int, list[float]]],
    draw_seqs: list[int],
    reg_lo: int,
    label: str,
) -> None:
    """Group draws by the upper-left 3x3 rotation of a 4x3 matrix at reg_lo..reg_lo+2."""
    EPS = 0.001
    rot_groups: defaultdict[tuple, list[int]] = defaultdict(list)

    for i, snap in enumerate(per_draw):
        r0 = snap.get(reg_lo, [0, 0, 0, 0])
        r1 = snap.get(reg_lo + 1, [0, 0, 0, 0])
        r2 = snap.get(reg_lo + 2, [0, 0, 0, 0])
        # Round to EPS for grouping
        key = tuple(round(v / EPS) * EPS for v in [r0[0], r0[1], r0[2],
                                                     r1[0], r1[1], r1[2],
                                                     r2[0], r2[1], r2[2]])
        rot_groups[key].append(i)

    groups_sorted = sorted(rot_groups.items(), key=lambda x: -len(x[1]))

    print(f"\n  3x3 rotation grouping (c{reg_lo}.xyz, c{reg_lo+1}.xyz, c{reg_lo+2}.xyz):")
    print(f"    {len(groups_sorted)} unique rotations found across {len(per_draw)} draws")

    for rank, (rot, indices) in enumerate(groups_sorted[:5]):
        pct = 100 * len(indices) / len(per_draw)
        r = rot
        print(f"    Group {rank} ({len(indices)} draws, {pct:.1f}%):")
        print(f"      [{r[0]:9.4f} {r[1]:9.4f} {r[2]:9.4f}]")
        print(f"      [{r[3]:9.4f} {r[4]:9.4f} {r[5]:9.4f}]")
        print(f"      [{r[6]:9.4f} {r[7]:9.4f} {r[8]:9.4f}]")

        # Show translation spread for this group
        translations = []
        for idx in indices:
            snap = per_draw[idx]
            r0 = snap.get(reg_lo, [0, 0, 0, 0])
            r1 = snap.get(reg_lo + 1, [0, 0, 0, 0])
            r2 = snap.get(reg_lo + 2, [0, 0, 0, 0])
            translations.append((r0[3], r1[3], r2[3]))

        if translations:
            xs = [t[0] for t in translations]
            ys = [t[1] for t in translations]
            zs = [t[2] for t in translations]
            print(f"      Translation spread: "
                  f"x=[{min(xs):.1f}, {max(xs):.1f}]  "
                  f"y=[{min(ys):.1f}, {max(ys):.1f}]  "
                  f"z=[{min(zs):.1f}, {max(zs):.1f}]")

    if len(groups_sorted) > 5:
        remaining = sum(len(v) for _, v in groups_sorted[5:])
        print(f"    ... and {len(groups_sorted) - 5} more groups ({remaining} draws)")

    if groups_sorted:
        dominant_rot = groups_sorted[0][0]
        dominant_count = len(groups_sorted[0][1])
        if dominant_count > len(per_draw) * 0.5:
            print(f"\n    ** Dominant rotation ({dominant_count}/{len(per_draw)} draws) "
                  f"is likely the VIEW matrix rotation component.")
            print(f"       Objects in this group have identity World rotation (axis-aligned geometry).")


def do_state_snapshot(records: list[dict], draw_index: int) -> None:
    """Full D3D9 state dump at a specific draw call index."""
    shader_disasm: dict[str, str] = {}
    handle_to_hash: dict[str, str] = {}
    for r in records:
        if r["slot"] in (SLOT["CreateVertexShader"], SLOT["CreatePixelShader"]):
            data = r.get("data", {})
            bc = data.get("bytecode", "")
            disasm = data.get("disasm", "")
            handle = r.get("created_handle")
            if bc and handle:
                key = _shader_key(bc)
                if disasm:
                    shader_disasm[key] = disasm
                handle_to_hash[handle] = key

    init_decls: dict[str, list[dict]] = {}
    for r in records:
        if r["slot"] == SLOT["CreateVertexDeclaration"]:
            data = r.get("data", {})
            elements = data.get("elements", [])
            handle = r.get("created_handle")
            if elements and handle:
                init_decls[handle] = elements

    runtime = [r for r in records if r.get("frame", -1) >= 0]
    state = DeviceState()
    draw_num = 0
    draw_rec = None

    for r in runtime:
        if r["slot"] in STATE_SET_SLOTS:
            state.apply(r)
        elif r["slot"] in GEOMETRY_DRAW_SLOTS:
            if draw_num == draw_index:
                draw_rec = r
                break
            draw_num += 1

    if draw_rec is None:
        print(f"\n  [error] Draw #{draw_index} not found (only {draw_num} draws)")
        return

    args = draw_rec.get("args", {})
    prim_type = _int(args.get("PrimitiveType", 0))
    bt = draw_rec.get("backtrace", [])

    print(f"\n=== State Snapshot: Draw #{draw_index} ===")
    print(f"  seq={draw_rec['seq']}  frame={draw_rec.get('frame','?')}  "
          f"{draw_rec['method']}  {D3DPT_NAMES.get(prim_type, str(prim_type))}")

    # Draw args
    for k, v in args.items():
        if k != "PrimitiveType":
            print(f"  {k}: {v}")

    # Backtrace
    if bt:
        print(f"  Backtrace:")
        for addr in bt[:8]:
            print(f"    0x{addr:08X}" if isinstance(addr, int) else f"    {addr}")

    # Shaders
    print(f"\n  Vertex Shader: {state.vs}")
    vs_hash = handle_to_hash.get(state.vs, "")
    vs_disasm = shader_disasm.get(vs_hash, "")
    vs_ctab = _parse_ctab_registers(vs_disasm) if vs_disasm else {}
    if vs_ctab:
        print(f"    CTAB: {', '.join(f'{n}=c{r}' for n, r in sorted(vs_ctab.items(), key=lambda x: x[1]))}")

    print(f"  Pixel Shader: {state.ps}")
    ps_hash = handle_to_hash.get(state.ps, "")
    ps_disasm = shader_disasm.get(ps_hash, "")
    ps_ctab = _parse_ctab_registers(ps_disasm) if ps_disasm else {}
    if ps_ctab:
        print(f"    CTAB: {', '.join(f'{n}=c{r}' for n, r in sorted(ps_ctab.items(), key=lambda x: x[1]))}")

    # Vertex declaration
    print(f"\n  Vertex Declaration: {state.vertex_decl}")
    if state.vertex_decl and state.vertex_decl in init_decls:
        for e in init_decls[state.vertex_decl]:
            usage_name = D3DDECLUSAGE_NAMES.get(e.get("Usage", -1), f"UNKNOWN({e.get('Usage')})")
            type_name = D3DDECLTYPE_NAMES.get(e.get("Type", -1), f"UNKNOWN({e.get('Type')})")
            print(f"    Stream{e.get('Stream',0)} +{e.get('Offset',0):3d}  "
                  f"{type_name:12s}  {usage_name}{e.get('UsageIndex',0)}")
    if state.fvf:
        print(f"  FVF: 0x{state.fvf:08X}")

    # Streams and indices
    if state.stream_sources:
        print(f"\n  Stream Sources:")
        for stream, (ptr, stride) in sorted(state.stream_sources.items()):
            print(f"    Stream[{stream}]: {ptr}  stride={stride}")
    if state.indices:
        print(f"  Index Buffer: {state.indices}")

    # VS Constants with CTAB names
    if state.vs_constants:
        reg_name_lookup = {reg: name for name, reg in vs_ctab.items()}
        print(f"\n  VS Constants ({len(state.vs_constants)} registers):")
        for reg in sorted(state.vs_constants):
            vals = state.vs_constants[reg]
            name = reg_name_lookup.get(reg, "")
            name_str = f"  ({name})" if name else ""
            fvals = " ".join(f"{v:10.4f}" if isinstance(v, float) else f"{str(v):>10}" for v in vals)
            print(f"    c{reg:<3d} = [{fvals}]{name_str}")

    # PS Constants with CTAB names
    if state.ps_constants:
        reg_name_lookup = {reg: name for name, reg in ps_ctab.items()}
        print(f"\n  PS Constants ({len(state.ps_constants)} registers):")
        for reg in sorted(state.ps_constants):
            vals = state.ps_constants[reg]
            name = reg_name_lookup.get(reg, "")
            name_str = f"  ({name})" if name else ""
            fvals = " ".join(f"{v:10.4f}" if isinstance(v, float) else f"{str(v):>10}" for v in vals)
            print(f"    c{reg:<3d} = [{fvals}]{name_str}")

    # Textures
    if state.textures:
        print(f"\n  Textures:")
        for stage, tex in sorted(state.textures.items()):
            print(f"    Stage[{stage}]: {tex}")

    # Render states
    if state.render_states:
        print(f"\n  Render States ({len(state.render_states)}):")
        for k, v in sorted(state.render_states.items()):
            print(f"    {_fmt_rs(k, v)}")

    # Render targets
    if state.render_targets:
        print(f"\n  Render Targets:")
        for idx, rt in sorted(state.render_targets.items()):
            print(f"    RT[{idx}]: {rt}")
    if state.depth_stencil:
        print(f"  Depth Stencil: {state.depth_stencil}")

    # Transforms (if any SetTransform calls were made)
    if state.transforms:
        print(f"\n  Transforms:")
        for ts, matrix in sorted(state.transforms.items()):
            name = D3DTS_NAMES.get(ts, f"state={ts}")
            cls = classify_matrix(matrix) if len(matrix) == MATRIX_FLOAT_COUNT else "?"
            print(f"    {name} ({cls}):")
            if len(matrix) == MATRIX_FLOAT_COUNT:
                print(format_matrix_4x4(matrix))

    # Sampler states
    if state.sampler_states:
        print(f"\n  Sampler States:")
        for sampler, states in sorted(state.sampler_states.items()):
            print(f"    Sampler[{sampler}]: {dict(states)}")

    # Texture stage states
    if state.texture_stage_states:
        print(f"\n  Texture Stage States:")
        for stage, states in sorted(state.texture_stage_states.items()):
            print(f"    Stage[{stage}]: {dict(states)}")


def do_transform_calls(records: list[dict]) -> None:
    """Analyze all SetTransform, SetViewport, SetRenderTarget calls."""
    runtime = [r for r in records if r.get("frame", -1) >= 0]
    draw_count = 0
    svcf_count = 0
    transform_calls = []
    viewport_calls = []

    for r in runtime:
        slot = r["slot"]
        if slot in GEOMETRY_DRAW_SLOTS:
            draw_count += 1
        elif slot == SLOT["SetVertexShaderConstantF"]:
            svcf_count += 1
        elif slot == SLOT["SetTransform"]:
            args = r.get("args", {})
            data = r.get("data", {})
            state = _int(args.get("State", 0))
            matrix = data.get("matrix", [])
            transform_calls.append({
                "seq": r["seq"], "frame": r.get("frame", "?"),
                "state": state, "matrix": matrix,
                "draws_before": draw_count, "svcfs_before": svcf_count,
                "bt": r.get("backtrace", [])[:5],
            })
        elif slot == SLOT["SetViewport"]:
            args = r.get("args", {})
            viewport_calls.append({
                "seq": r["seq"], "frame": r.get("frame", "?"),
                "args": args, "draws_before": draw_count,
            })

    # Also scan init records
    init_transforms = []
    for r in records:
        if r.get("frame", -1) >= 0:
            break
        if r["slot"] == SLOT["SetTransform"]:
            args = r.get("args", {})
            data = r.get("data", {})
            init_transforms.append({
                "seq": r["seq"],
                "state": _int(args.get("State", 0)),
                "matrix": data.get("matrix", []),
            })

    total_draws = draw_count

    print(f"\n=== Transform Analysis ===")

    # Init-phase transforms
    if init_transforms:
        print(f"\n  Init-phase SetTransform ({len(init_transforms)} calls):")
        for t in init_transforms:
            name = D3DTS_NAMES.get(t["state"], f"state={t['state']}")
            cls = classify_matrix(t["matrix"]) if len(t["matrix"]) == MATRIX_FLOAT_COUNT else "?"
            print(f"    seq={t['seq']:6d}  {name:16s}  {cls}")
            if len(t["matrix"]) == MATRIX_FLOAT_COUNT:
                print(format_matrix_4x4(t["matrix"]))
    else:
        print(f"\n  Init-phase SetTransform: none")

    # Runtime transforms
    if transform_calls:
        print(f"\n  Runtime SetTransform ({len(transform_calls)} calls, {total_draws} total draws):")
        for t in transform_calls:
            name = D3DTS_NAMES.get(t["state"], f"state={t['state']}")
            cls = classify_matrix(t["matrix"]) if len(t["matrix"]) == MATRIX_FLOAT_COUNT else "?"
            pct_draws = 100 * t["draws_before"] / max(total_draws, 1)
            print(f"    seq={t['seq']:6d} frame={t['frame']}  {name:16s}  {cls}  "
                  f"(after {t['draws_before']}/{total_draws} draws = {pct_draws:.0f}%)")
            if len(t["matrix"]) == MATRIX_FLOAT_COUNT:
                print(format_matrix_4x4(t["matrix"]))
            bt = t["bt"]
            if bt:
                bt_str = " -> ".join(f"0x{a:08X}" if isinstance(a, int) else str(a) for a in bt)
                print(f"      bt: [{bt_str}]")
    else:
        print(f"\n  Runtime SetTransform: none")

    # Diagnosis
    print(f"\n  Diagnosis:")
    if not transform_calls and not init_transforms:
        print(f"    Game NEVER calls SetTransform.")
        print(f"    -> Transforms are entirely in shader constants.")
        print(f"    -> Must decompose from SetVertexShaderConstantF data.")
    elif transform_calls:
        all_identity = all(
            classify_matrix(t["matrix"]) == "identity"
            for t in transform_calls if len(t["matrix"]) == MATRIX_FLOAT_COUNT
        )
        all_post_draw = all(t["draws_before"] >= total_draws * 0.95 for t in transform_calls)
        if all_identity:
            print(f"    All runtime SetTransform calls set IDENTITY matrices.")
            print(f"    -> Game resets transforms but doesn't use FFP pipeline for rendering.")
            print(f"    -> Transforms are in shader constants (SetVertexShaderConstantF).")
        elif all_post_draw:
            print(f"    SetTransform calls happen AFTER all draws (cleanup/reset).")
            print(f"    -> Not used for actual rendering.")
        else:
            unique_states = set(t["state"] for t in transform_calls)
            state_names = [D3DTS_NAMES.get(s, str(s)) for s in sorted(unique_states)]
            print(f"    SetTransform IS used during rendering: {', '.join(state_names)}")
            print(f"    -> These can be intercepted directly for FFP conversion.")

    # Viewport analysis
    if viewport_calls:
        print(f"\n  SetViewport ({len(viewport_calls)} calls):")
        for v in viewport_calls[:10]:
            print(f"    seq={v['seq']:6d} frame={v['frame']}  {v['args']}  "
                  f"(after {v['draws_before']} draws)")
        if len(viewport_calls) > 10:
            print(f"    ... and {len(viewport_calls) - 10} more")


def do_export_csv(records: list[dict], output: str) -> None:
    if not records:
        print("No records to export.")
        return
    all_keys = set()
    for r in records:
        all_keys.update(r.keys())
    all_keys = sorted(all_keys)

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            flat = {}
            for k, v in r.items():
                if isinstance(v, (dict, list)):
                    flat[k] = json.dumps(v)
                else:
                    flat[k] = v
            writer.writerow(flat)
    print(f"Exported {len(records)} records to {output}")


# ── Main dispatch ───────────────────────────────────────────────────────────

def run_analysis(args: argparse.Namespace) -> None:
    if not Path(args.file).exists():
        print(f"[error] File not found: {args.file}")
        sys.exit(1)

    print(f"Loading {args.file}...")
    records = load_records(args.file, args.filter)
    print(f"  Loaded {len(records)} records")

    resolver = AddressResolver(args.resolve_addrs)
    if args.resolve_addrs:
        resolver.resolve_all(records)

    ran_any = False

    if args.summary:
        do_summary(records)
        ran_any = True
    if args.hotpaths:
        do_hotpaths(records, args.top, resolver)
        ran_any = True
    if args.callers:
        do_callers(records, args.callers, args.top, resolver)
        ran_any = True
    if args.render_loop:
        do_render_loop(records, resolver)
        ran_any = True
    if args.state_at is not None:
        do_state_at(records, args.state_at)
        ran_any = True
    if args.matrix_flow:
        do_matrix_flow(records, resolver)
        ran_any = True
    if args.render_passes:
        do_render_passes(records)
        ran_any = True
    if args.draw_calls:
        do_draw_calls(records, resolver)
        ran_any = True
    if args.classify_draws:
        do_classify_draws(records)
        ran_any = True
    if args.redundant:
        do_redundant(records)
        ran_any = True
    if args.texture_freq:
        do_texture_freq(records)
        ran_any = True
    if args.rt_graph:
        do_rt_graph(records)
        ran_any = True
    if args.shader_map:
        do_shader_map(records, args.fxc)
        ran_any = True
    if args.vtx_formats:
        do_vtx_formats(records)
        ran_any = True
    if args.diff_draws:
        do_diff_draws(records, args.diff_draws[0], args.diff_draws[1])
        ran_any = True
    if args.diff_frames:
        do_diff_frames(records, args.diff_frames[0], args.diff_frames[1])
        ran_any = True
    if args.const_provenance or args.const_provenance_draw is not None:
        do_const_provenance(records, args.const_provenance_draw)
        ran_any = True
    if args.const_evolution:
        do_const_evolution(records, args.const_evolution)
        ran_any = True
    if args.state_snapshot is not None:
        do_state_snapshot(records, args.state_snapshot)
        ran_any = True
    if args.transform_calls:
        do_transform_calls(records)
        ran_any = True
    if args.animate_constants:
        do_animate_constants(records)
        ran_any = True
    if args.pipeline_diagram:
        do_pipeline_diagram(records)
        ran_any = True
    if args.export_csv:
        do_export_csv(records, args.export_csv)
        ran_any = True

    if not ran_any:
        print("No analysis command specified. Use --summary, --hotpaths, etc.")
        print("Run with -h for full list of options.")
