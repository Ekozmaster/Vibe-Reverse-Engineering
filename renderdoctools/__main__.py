"""CLI entry point for renderdoctools -- RenderDoc capture analysis toolkit.

Usage:  python -m renderdoctools <command> <capture.rdc> [args]

Event browser:
    python -m renderdoctools events <capture.rdc> [--draws-only] [--filter TEXT]

Pipeline state:
    python -m renderdoctools pipeline <capture.rdc> --event <EID> [--stage STAGE]

Textures:
    python -m renderdoctools textures <capture.rdc> --event <EID> [--save-all DIR]

Shaders:
    python -m renderdoctools shaders <capture.rdc> --event <EID> [--stage STAGE]

Mesh data:
    python -m renderdoctools mesh <capture.rdc> --event <EID> [--post-vs]

GPU counters:
    python -m renderdoctools counters <capture.rdc> [--fetch NAME] [--zero-samples]

Analysis:
    python -m renderdoctools analyze <capture.rdc> [--summary] [--biggest-draws N]

Capture info:
    python -m renderdoctools info <capture.rdc>

Pixel history:
    python -m renderdoctools pixel-history <capture.rdc> --event <EID> --resource <RID> --x 100 --y 200

Debug shader:
    python -m renderdoctools debug-shader <capture.rdc> --event <EID> --mode pixel --x 100 --y 200

Resource usage:
    python -m renderdoctools usage <capture.rdc> --resource <RID> [--filter read]

Pick pixel:
    python -m renderdoctools pick-pixel <capture.rdc> --resource <RID> --x 100 --y 200

Texture stats:
    python -m renderdoctools tex-stats <capture.rdc> --resource <RID> [--histogram]

Debug messages:
    python -m renderdoctools messages <capture.rdc> [--severity high]

Frame info:
    python -m renderdoctools frame-info <capture.rdc>

Descriptors:
    python -m renderdoctools descriptors <capture.rdc> --event <EID> [--type sampler]

Custom shader:
    python -m renderdoctools custom-shader <capture.rdc> --event <EID> --source shader.hlsl --output out.dds

Texture data:
    python -m renderdoctools tex-data <capture.rdc> --resource <RID> [--output-file dump.bin]

API calls:
    python -m renderdoctools api-calls <capture.rdc> [--event <EID>] [--filter DrawIndexed]

Utilities:
    python -m renderdoctools open <capture.rdc>
    python -m renderdoctools capture <exe> [--output FILE]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import core


def cmd_events(args: argparse.Namespace) -> None:
    config = {
        "draws_only": args.draws_only,
        "filter": args.filter or "",
    }
    result = core.run_script("events", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    events = result["events"]
    print("=== %d events ===" % result["total"])

    for ev in events:
        indent = "  " * ev["depth"]
        tag = ""
        if ev["draw"]:
            tag = " [DRAW idx=%d inst=%d]" % (ev["numIndices"], ev["numInstances"])
        elif ev["clear"]:
            tag = " [CLEAR]"
        print("%s%d: %s%s" % (indent, ev["eid"], ev["name"], tag))


def cmd_open(args: argparse.Namespace) -> None:
    qrd = core.find_renderdoc()
    capture = str(Path(args.capture).resolve())
    subprocess.Popen([str(qrd), capture])
    print("Opened %s in RenderDoc." % capture)


def cmd_pipeline(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event,
        "stage": args.stage or "",
    }
    result = core.run_script("pipeline", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Pipeline State @ EID %d ===" % result["event_id"])
    for stage_name, info in result["stages"].items():
        print("\n[%s]" % stage_name.upper())
        print("  entry: %s" % info["entryPoint"])
        if info["constantBuffers"]:
            print("  cbuffers: %d" % len(info["constantBuffers"]))
            for cb in info["constantBuffers"]:
                print("    %d: %s (%d bytes)" % (cb["index"], cb["name"], cb["byteSize"]))
        if info["readOnlyResources"]:
            print("  SRVs: %d" % len(info["readOnlyResources"]))
            for r in info["readOnlyResources"]:
                print("    %d: %s (%s)" % (r["index"], r["name"], r["type"]))
        if info["readWriteResources"]:
            print("  UAVs: %d" % len(info["readWriteResources"]))
            for r in info["readWriteResources"]:
                print("    %d: %s (%s)" % (r["index"], r["name"], r["type"]))

    if result.get("renderTargets"):
        print("\nRender Targets: %s" % ", ".join(result["renderTargets"]))
    if result.get("depthTarget"):
        print("Depth Target: %s" % result["depthTarget"])


def cmd_textures(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event,
        "save_all": args.save_all or "",
        "save_rid": args.save or "",
        "format": args.format or "png",
        "save_output": args.save_output or "",
    }
    result = core.run_script("textures", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== %d textures @ EID %d ===" % (result["total"], args.event))
    for tex in result["textures"]:
        dim = "%dx%d" % (tex["width"], tex["height"])
        if tex["depth"] > 1:
            dim += "x%d" % tex["depth"]
        print("  %s  %s  %s  [%s]  %s" % (
            tex["resourceId"].rjust(10),
            dim.ljust(12),
            tex["format"][:24].ljust(24),
            tex["binding"],
            tex.get("name", ""),
        ))

    if result.get("saved"):
        print("\nSaved %d textures:" % len(result["saved"]))
        for f in result["saved"]:
            print("  %s" % f)


def cmd_shaders(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event,
        "stage": args.stage or "",
        "cbuffers": args.cbuffers,
    }
    result = core.run_script("shaders", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Shaders @ EID %d [%s] ===" % (result["event_id"], result["disasmTarget"]))
    for stage_name, info in result["shaders"].items():
        print("\n-- %s -- (entry: %s)" % (stage_name.upper(), info["entryPoint"]))
        print(info["disassembly"][:2000])
        if len(info["disassembly"]) > 2000:
            print("... (truncated, use --json for full output)")

        if "constantBuffers" in info:
            for cb in info["constantBuffers"]:
                print("\n  cbuffer %s [%d]:" % (cb["name"], cb["index"]))
                if "error" in cb:
                    print("    (error: %s)" % cb["error"])
                    continue
                for v in cb.get("variables", []):
                    if "values" in v:
                        vals = ", ".join("%.4f" % x for x in v["values"])
                        print("    %s: [%s]" % (v["name"], vals))


def cmd_mesh(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event,
        "post_vs": args.post_vs,
        "indices": args.indices or "",
    }
    result = core.run_script("mesh", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    mode = "Post-VS" if result["post_vs"] else "Input"
    print("=== Mesh %s @ EID %d ===" % (mode, result["event_id"]))
    print("Attributes: %s" % ", ".join(a["name"] for a in result["attributes"]))
    print("")

    for vert in result.get("vertices", []):
        parts = ["idx=%d" % vert["index"]]
        for a in result["attributes"]:
            val = vert.get(a["name"])
            if val:
                parts.append("%s=%s" % (a["name"], val))
        print("  ".join(parts))


def cmd_counters(args: argparse.Namespace) -> None:
    config = {
        "fetch": args.fetch or "",
        "zero_samples": args.zero_samples,
    }
    result = core.run_script("counters", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    mode = result["mode"]
    if mode == "list":
        print("=== %d GPU Counters ===" % len(result["counters"]))
        for c in result["counters"]:
            print("  %s (%s) -- %s" % (c["name"], c["unit"], c["description"][:60]))
    elif mode == "zero_samples":
        print("=== %d draws with 0 samples passed ===" % result["total"])
        for d in result["draws"]:
            print("  EID %d: %s (indices=%d)" % (d["eid"], d["name"], d["numIndices"]))
    elif mode == "fetch":
        print("=== %s (%s) ===" % (result["counter"], result["unit"]))
        for r in result["results"]:
            print("  EID %d: %s = %d" % (r["eid"], r["name"][:40], r["value"]))


def cmd_analyze(args: argparse.Namespace) -> None:
    config = {
        "summary": args.summary,
        "biggest_draws": args.biggest_draws or 0,
        "render_targets": args.render_targets,
    }
    result = core.run_script("analyze", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    if "summary" in result:
        s = result["summary"]
        print("=== Capture Summary ===")
        print("  Events:    %d" % s["totalEvents"])
        print("  Draws:     %d" % s["totalDraws"])
        print("  Clears:    %d" % s["totalClears"])
        print("  Indices:   %d" % s["totalIndices"])
        print("  Instances: %d" % s["totalInstances"])

    if "biggestDraws" in result:
        print("\n=== Top %d Draws by Index Count ===" % len(result["biggestDraws"]))
        for d in result["biggestDraws"]:
            print("  EID %d: %s (indices=%d, instances=%d)" % (
                d["eid"], d["name"], d["numIndices"], d["numInstances"]))

    if "renderTargets" in result:
        print("\n=== Render Targets ===")
        for rt in result["renderTargets"]:
            print("  RID %s: %d draws (EID %d-%d)" % (
                rt["resourceId"], rt["drawCount"], rt["firstEid"], rt["lastEid"]))


def cmd_info(args: argparse.Namespace) -> None:
    result = core.run_script("info", args.capture)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Capture Info ===")
    for k, v in result.items():
        print("  %s: %s" % (k, v))


def cmd_capture(args: argparse.Namespace) -> None:
    # renderdoccmd lives next to qrenderdoc
    qrd = core.find_renderdoc()
    renderdoccmd = qrd.parent / "renderdoccmd.exe"
    if not renderdoccmd.is_file():
        print("[error] renderdoccmd not found at %s" % renderdoccmd, file=sys.stderr)
        sys.exit(1)

    cmd = [str(renderdoccmd), "capture"]
    if args.output_file:
        cmd.extend(["-c", args.output_file])
    cmd.extend(["-w", args.exe])
    cmd.extend(args.exe_args)

    print("Launching capture: %s" % " ".join(cmd))
    subprocess.run(cmd)


def _parse_xyz(val):
    parts = val.split(",")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("expected X,Y,Z (three comma-separated ints)")
    return [int(p) for p in parts]


def cmd_pixel_history(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event,
        "resource_id": args.resource,
        "x": args.x,
        "y": args.y,
        "sub_mip": args.sub_mip or 0,
        "sub_slice": args.sub_slice or 0,
        "sub_sample": args.sub_sample or 0,
    }
    result = core.run_script("pixel_history", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Pixel History @ (%d, %d) ===" % (args.x, args.y))
    for mod in result.get("modifications", []):
        status = "PASS" if mod.get("passed") else "FAIL"
        pre = mod.get("preRGBA", [0, 0, 0, 0])
        post = mod.get("postRGBA", [0, 0, 0, 0])
        print("  EID %d [%s] pre=(%.3f, %.3f, %.3f, %.3f) post=(%.3f, %.3f, %.3f, %.3f)" % (
            mod["eid"], status, pre[0], pre[1], pre[2], pre[3],
            post[0], post[1], post[2], post[3]))


def cmd_debug_shader(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event,
        "mode": args.mode,
        "vertex_index": args.vertex_index or 0,
        "instance": args.instance or 0,
        "view": args.view or 0,
        "x": args.x or 0,
        "y": args.y or 0,
        "sample": args.sample or 0,
        "primitive": args.primitive or 0,
        "group": args.group or [0, 0, 0],
        "thread": args.thread or [0, 0, 0],
        "max_steps": args.max_steps or 10000,
    }
    result = core.run_script("debug_shader", args.capture, config, timeout=300)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Shader Debug Trace @ EID %d [%s] ===" % (args.event, args.mode))
    for step in result.get("steps", []):
        line = "  step %d: " % step["index"]
        if step.get("source"):
            line += "%s " % step["source"]
        for var in step.get("variables", []):
            line += "%s=%s " % (var["name"], var["value"])
        print(line.rstrip())


def cmd_usage(args: argparse.Namespace) -> None:
    config = {
        "resource_id": args.resource,
        "usage_filter": args.filter or "all",
    }
    result = core.run_script("usage", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Resource Usage for %s ===" % args.resource)
    for entry in result.get("usages", []):
        print("  EID %d: %s (%s)" % (entry["eventId"], entry["eventName"], entry["usage"]))


def cmd_pick_pixel(args: argparse.Namespace) -> None:
    config = {
        "resource_id": args.resource,
        "x": args.x,
        "y": args.y,
        "sub_mip": args.sub_mip or 0,
        "sub_slice": args.sub_slice or 0,
        "sub_sample": args.sub_sample or 0,
        "comp_type": args.comp_type or "",
    }
    result = core.run_script("pick_pixel", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Pixel @ (%d, %d) RID %s ===" % (args.x, args.y, args.resource))
    if "floatValue" in result:
        v = result["floatValue"]
        print("  float: (%.6f, %.6f, %.6f, %.6f)" % (v[0], v[1], v[2], v[3]))
    if "intValue" in result:
        v = result["intValue"]
        print("  int:   (%d, %d, %d, %d)" % (v[0], v[1], v[2], v[3]))
    if "uintValue" in result:
        v = result["uintValue"]
        print("  uint:  (%d, %d, %d, %d)" % (v[0], v[1], v[2], v[3]))


def cmd_tex_stats(args: argparse.Namespace) -> None:
    config = {
        "resource_id": args.resource,
        "sub_mip": args.mip or 0,
        "sub_slice": args.slice or 0,
        "sub_sample": args.sample or 0,
        "histogram": args.histogram,
        "histogram_min": args.hist_min if args.hist_min is not None else 0.0,
        "histogram_max": args.hist_max if args.hist_max is not None else 1.0,
    }
    result = core.run_script("tex_stats", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Texture Stats for %s ===" % args.resource)
    if "minRGBA" in result:
        v = result["minRGBA"]
        print("  min: (%.4f, %.4f, %.4f, %.4f)" % (v[0], v[1], v[2], v[3]))
    if "maxRGBA" in result:
        v = result["maxRGBA"]
        print("  max: (%.4f, %.4f, %.4f, %.4f)" % (v[0], v[1], v[2], v[3]))
    if "histogram" in result:
        print("  histogram: %d buckets" % len(result["histogram"]))
        for i, count in enumerate(result["histogram"]):
            print("    [%d] %d" % (i, count))


def cmd_messages(args: argparse.Namespace) -> None:
    config = {
        "severity_filter": args.severity or "all",
    }
    result = core.run_script("messages", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    msgs = result.get("messages", [])
    print("=== %d Debug Messages ===" % len(msgs))
    for m in msgs:
        print("  [%s] %s: %s" % (m.get("severity", "?"), m.get("category", "?"), m.get("description", "")))


def cmd_frame_info(args: argparse.Namespace) -> None:
    result = core.run_script("frame_info", args.capture)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Frame Info ===")
    for k, v in result.items():
        print("  %s: %s" % (k, v))


def cmd_descriptors(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event,
        "type_filter": args.type or "all",
    }
    result = core.run_script("descriptors", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    descs = result.get("descriptors", [])
    print("=== %d Descriptors @ EID %d ===" % (len(descs), args.event))
    for d in descs:
        print("  [%s] %s: %s (%s)" % (d.get("stage", "?"), d.get("type", "?"),
              d.get("resource", "?"), d.get("format", "?")))


def cmd_custom_shader(args: argparse.Namespace) -> None:
    source_path = Path(args.source)
    if not source_path.is_file():
        print("[error] shader source not found: %s" % args.source, file=sys.stderr)
        sys.exit(1)
    shader_source = source_path.read_text()

    config = {
        "event_id": args.event,
        "shader_source": shader_source,
        "output_path": str(Path(args.output_path).resolve()),
        "encoding": args.encoding or "",
        "entry_point": args.entry_point or "main",
    }
    result = core.run_script("custom_shader", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    if result.get("success"):
        print("Custom shader applied successfully.")
        if result.get("saved"):
            print("Saved to: %s" % result["saved"])
    else:
        print("Custom shader failed.")


def cmd_tex_data(args: argparse.Namespace) -> None:
    config = {
        "resource_id": args.resource,
        "sub_mip": args.sub_mip or 0,
        "sub_slice": args.sub_slice or 0,
        "sub_sample": args.sub_sample or 0,
        "output_path": str(Path(args.output_file).resolve()) if args.output_file else "",
        "hex_preview_bytes": args.preview_bytes or 256,
    }
    result = core.run_script("tex_data", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    print("=== Texture Data for %s ===" % args.resource)
    if result.get("width"):
        print("  %dx%d %s" % (result["width"], result["height"], result.get("format", "")))
    if result.get("saved"):
        print("  Saved to: %s" % result["saved"])
    if result.get("hexPreview"):
        print("  Hex preview:\n    %s" % result["hexPreview"])


def cmd_api_calls(args: argparse.Namespace) -> None:
    config = {
        "event_id": args.event or 0,
        "filter": args.filter or "",
        "range_start": args.range[0] if args.range else 0,
        "range_end": args.range[1] if args.range else 0,
    }
    result = core.run_script("api_calls", args.capture, config)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    if "error" in result:
        print("[error] %s" % result["error"], file=sys.stderr)
        sys.exit(1)

    calls = result.get("calls", [])
    print("=== %d API Calls ===" % len(calls))
    for c in calls:
        print("  EID %d: %s" % (c.get("eid", 0), c.get("name", "")))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="renderdoctools",
        description="RenderDoc capture analysis toolkit",
    )
    sub = parser.add_subparsers(dest="command")
    sub.required = True

    # events
    p_events = sub.add_parser("events", help="List events and draw calls")
    p_events.add_argument("capture", help="Path to .rdc capture file")
    p_events.add_argument("--draws-only", action="store_true", help="Only show draw calls")
    p_events.add_argument("--filter", type=str, default="", help="Filter events by name")
    p_events.add_argument("--json", action="store_true", help="Output raw JSON")
    p_events.add_argument("--output", type=str, help="Write output to file")
    p_events.set_defaults(func=cmd_events)

    # open
    p_open = sub.add_parser("open", help="Launch RenderDoc GUI with capture")
    p_open.add_argument("capture", help="Path to .rdc capture file")
    p_open.set_defaults(func=cmd_open)

    # pipeline
    p_pipe = sub.add_parser("pipeline", help="Inspect pipeline state at an event")
    p_pipe.add_argument("capture", help="Path to .rdc capture file")
    p_pipe.add_argument("--event", type=int, required=True, help="Event ID")
    p_pipe.add_argument("--stage", type=str, default="", help="Filter to stage: vertex, pixel, geometry, hull, domain, compute")
    p_pipe.add_argument("--json", action="store_true", help="Output raw JSON")
    p_pipe.add_argument("--output", type=str, help="Write output to file")
    p_pipe.set_defaults(func=cmd_pipeline)

    # textures
    p_tex = sub.add_parser("textures", help="List and export textures at an event")
    p_tex.add_argument("capture", help="Path to .rdc capture file")
    p_tex.add_argument("--event", type=int, required=True, help="Event ID")
    p_tex.add_argument("--save-all", type=str, metavar="DIR", help="Export all textures to directory")
    p_tex.add_argument("--save", type=str, metavar="RID", help="Export specific texture by resource ID")
    p_tex.add_argument("--save-output", type=str, metavar="FILE", help="Output path for --save")
    p_tex.add_argument("--format", type=str, default="png", choices=["png", "jpg", "dds", "hdr", "bmp", "tga"])
    p_tex.add_argument("--json", action="store_true", help="Output raw JSON")
    p_tex.add_argument("--output", type=str, help="Write output to file")
    p_tex.set_defaults(func=cmd_textures)

    # shaders
    p_shd = sub.add_parser("shaders", help="Disassemble shaders and inspect cbuffers")
    p_shd.add_argument("capture", help="Path to .rdc capture file")
    p_shd.add_argument("--event", type=int, required=True, help="Event ID")
    p_shd.add_argument("--stage", type=str, default="", help="Filter to stage")
    p_shd.add_argument("--cbuffers", action="store_true", help="Include constant buffer contents")
    p_shd.add_argument("--json", action="store_true", help="Output raw JSON")
    p_shd.add_argument("--output", type=str, help="Write output to file")
    p_shd.set_defaults(func=cmd_shaders)

    # mesh
    p_mesh = sub.add_parser("mesh", help="Decode vertex/mesh data at a draw call")
    p_mesh.add_argument("capture", help="Path to .rdc capture file")
    p_mesh.add_argument("--event", type=int, required=True, help="Event ID")
    p_mesh.add_argument("--post-vs", action="store_true", help="Show post-VS output instead of inputs")
    p_mesh.add_argument("--indices", type=str, help="Vertex index range, e.g. 0-10")
    p_mesh.add_argument("--json", action="store_true", help="Output raw JSON")
    p_mesh.add_argument("--output", type=str, help="Write output to file")
    p_mesh.set_defaults(func=cmd_mesh)

    # counters
    p_cnt = sub.add_parser("counters", help="GPU performance counters")
    p_cnt.add_argument("capture", help="Path to .rdc capture file")
    p_cnt.add_argument("--fetch", type=str, help="Fetch specific counter by name")
    p_cnt.add_argument("--zero-samples", action="store_true", help="Find draws with 0 samples passed")
    p_cnt.add_argument("--json", action="store_true", help="Output raw JSON")
    p_cnt.add_argument("--output", type=str, help="Write output to file")
    p_cnt.set_defaults(func=cmd_counters)

    # analyze
    p_ana = sub.add_parser("analyze", help="Capture-wide analysis and statistics")
    p_ana.add_argument("capture", help="Path to .rdc capture file")
    p_ana.add_argument("--summary", action="store_true", help="Overview statistics")
    p_ana.add_argument("--biggest-draws", type=int, metavar="N", help="Top N draws by vertex count")
    p_ana.add_argument("--render-targets", action="store_true", help="List unique render targets")
    p_ana.add_argument("--json", action="store_true", help="Output raw JSON")
    p_ana.add_argument("--output", type=str, help="Write output to file")
    p_ana.set_defaults(func=cmd_analyze)

    # info
    p_info = sub.add_parser("info", help="Show capture metadata")
    p_info.add_argument("capture", help="Path to .rdc capture file")
    p_info.add_argument("--json", action="store_true", help="Output raw JSON")
    p_info.set_defaults(func=cmd_info)

    # capture
    p_cap = sub.add_parser("capture", help="Capture a running or launched application")
    p_cap.add_argument("exe", help="Executable to capture")
    p_cap.add_argument("exe_args", nargs="*", help="Arguments to pass to executable")
    p_cap.add_argument("--output", "-o", type=str, dest="output_file", help="Output capture filename template")
    p_cap.set_defaults(func=cmd_capture)

    # pixel-history
    p_ph = sub.add_parser("pixel-history", help="Trace pixel modification history")
    p_ph.add_argument("capture", help="Path to .rdc capture file")
    p_ph.add_argument("--event", type=int, required=True, help="Event ID")
    p_ph.add_argument("--resource", type=str, required=True, help="Resource ID")
    p_ph.add_argument("--x", type=int, required=True, help="Pixel X coordinate")
    p_ph.add_argument("--y", type=int, required=True, help="Pixel Y coordinate")
    p_ph.add_argument("--sub-mip", type=int, default=0, help="Sub-resource mip level")
    p_ph.add_argument("--sub-slice", type=int, default=0, help="Sub-resource slice")
    p_ph.add_argument("--sub-sample", type=int, default=0, help="Sub-resource sample")
    p_ph.add_argument("--json", action="store_true", help="Output raw JSON")
    p_ph.add_argument("--output", type=str, help="Write output to file")
    p_ph.set_defaults(func=cmd_pixel_history)

    # debug-shader
    p_ds = sub.add_parser("debug-shader", help="Debug a shader invocation step by step")
    p_ds.add_argument("capture", help="Path to .rdc capture file")
    p_ds.add_argument("--event", type=int, required=True, help="Event ID")
    p_ds.add_argument("--mode", type=str, required=True, choices=["vertex", "pixel", "compute"], help="Shader stage to debug")
    p_ds.add_argument("--vertex-index", type=int, default=0, help="Vertex index for vertex debug")
    p_ds.add_argument("--instance", type=int, default=0, help="Instance index")
    p_ds.add_argument("--view", type=int, default=0, help="Multiview index")
    p_ds.add_argument("--x", type=int, default=0, help="Pixel X for pixel debug")
    p_ds.add_argument("--y", type=int, default=0, help="Pixel Y for pixel debug")
    p_ds.add_argument("--sample", type=int, default=0, help="MSAA sample index")
    p_ds.add_argument("--primitive", type=int, default=0, help="Primitive index")
    p_ds.add_argument("--group", type=_parse_xyz, default=None, help="Compute group X,Y,Z")
    p_ds.add_argument("--thread", type=_parse_xyz, default=None, help="Compute thread X,Y,Z")
    p_ds.add_argument("--max-steps", type=int, default=10000, help="Maximum debug steps")
    p_ds.add_argument("--json", action="store_true", help="Output raw JSON")
    p_ds.add_argument("--output", type=str, help="Write output to file")
    p_ds.set_defaults(func=cmd_debug_shader)

    # usage
    p_usg = sub.add_parser("usage", help="Show which events use a resource")
    p_usg.add_argument("capture", help="Path to .rdc capture file")
    p_usg.add_argument("--resource", type=str, required=True, help="Resource ID")
    p_usg.add_argument("--filter", type=str, default="all", choices=["read", "write", "all"], help="Filter by usage type")
    p_usg.add_argument("--json", action="store_true", help="Output raw JSON")
    p_usg.add_argument("--output", type=str, help="Write output to file")
    p_usg.set_defaults(func=cmd_usage)

    # pick-pixel
    p_pp = sub.add_parser("pick-pixel", help="Read pixel value from a texture")
    p_pp.add_argument("capture", help="Path to .rdc capture file")
    p_pp.add_argument("--resource", type=str, required=True, help="Resource ID")
    p_pp.add_argument("--x", type=int, required=True, help="Pixel X coordinate")
    p_pp.add_argument("--y", type=int, required=True, help="Pixel Y coordinate")
    p_pp.add_argument("--sub-mip", type=int, default=0, help="Sub-resource mip level")
    p_pp.add_argument("--sub-slice", type=int, default=0, help="Sub-resource slice")
    p_pp.add_argument("--sub-sample", type=int, default=0, help="Sub-resource sample")
    p_pp.add_argument("--comp-type", type=str, default="", help="Component type override")
    p_pp.add_argument("--json", action="store_true", help="Output raw JSON")
    p_pp.add_argument("--output", type=str, help="Write output to file")
    p_pp.set_defaults(func=cmd_pick_pixel)

    # tex-stats
    p_ts = sub.add_parser("tex-stats", help="Get texture min/max stats and histogram")
    p_ts.add_argument("capture", help="Path to .rdc capture file")
    p_ts.add_argument("--resource", type=str, required=True, help="Resource ID")
    p_ts.add_argument("--mip", type=int, default=0, help="Mip level")
    p_ts.add_argument("--slice", type=int, default=0, help="Array slice")
    p_ts.add_argument("--sample", type=int, default=0, help="MSAA sample")
    p_ts.add_argument("--histogram", action="store_true", help="Include histogram data")
    p_ts.add_argument("--hist-min", type=float, default=None, help="Histogram range minimum")
    p_ts.add_argument("--hist-max", type=float, default=None, help="Histogram range maximum")
    p_ts.add_argument("--json", action="store_true", help="Output raw JSON")
    p_ts.add_argument("--output", type=str, help="Write output to file")
    p_ts.set_defaults(func=cmd_tex_stats)

    # messages
    p_msg = sub.add_parser("messages", help="List debug messages from the capture")
    p_msg.add_argument("capture", help="Path to .rdc capture file")
    p_msg.add_argument("--severity", type=str, default="all", choices=["high", "medium", "low", "info", "all"], help="Filter by severity")
    p_msg.add_argument("--json", action="store_true", help="Output raw JSON")
    p_msg.add_argument("--output", type=str, help="Write output to file")
    p_msg.set_defaults(func=cmd_messages)

    # frame-info
    p_fi = sub.add_parser("frame-info", help="Show frame statistics")
    p_fi.add_argument("capture", help="Path to .rdc capture file")
    p_fi.add_argument("--json", action="store_true", help="Output raw JSON")
    p_fi.add_argument("--output", type=str, help="Write output to file")
    p_fi.set_defaults(func=cmd_frame_info)

    # descriptors
    p_desc = sub.add_parser("descriptors", help="List descriptors accessed at an event")
    p_desc.add_argument("capture", help="Path to .rdc capture file")
    p_desc.add_argument("--event", type=int, required=True, help="Event ID")
    p_desc.add_argument("--type", type=str, default="all", choices=["sampler", "cbuffer", "srv", "uav", "all"], help="Filter by descriptor type")
    p_desc.add_argument("--json", action="store_true", help="Output raw JSON")
    p_desc.add_argument("--output", type=str, help="Write output to file")
    p_desc.set_defaults(func=cmd_descriptors)

    # custom-shader
    p_cs = sub.add_parser("custom-shader", help="Apply a custom shader to a texture output")
    p_cs.add_argument("capture", help="Path to .rdc capture file")
    p_cs.add_argument("--event", type=int, required=True, help="Event ID")
    p_cs.add_argument("--source", type=str, required=True, help="Path to shader source file")
    p_cs.add_argument("--output", type=str, dest="output_path", required=True, help="Output file path")
    p_cs.add_argument("--encoding", type=str, default="", help="Texture encoding")
    p_cs.add_argument("--entry-point", type=str, default="main", help="Shader entry point name")
    p_cs.add_argument("--json", action="store_true", help="Output raw JSON")
    p_cs.set_defaults(func=cmd_custom_shader)

    # tex-data
    p_td = sub.add_parser("tex-data", help="Export raw texture data")
    p_td.add_argument("capture", help="Path to .rdc capture file")
    p_td.add_argument("--resource", type=str, required=True, help="Resource ID")
    p_td.add_argument("--sub-mip", type=int, default=0, help="Sub-resource mip level")
    p_td.add_argument("--sub-slice", type=int, default=0, help="Sub-resource slice")
    p_td.add_argument("--sub-sample", type=int, default=0, help="Sub-resource sample")
    p_td.add_argument("--output-file", type=str, default="", help="Save raw data to file")
    p_td.add_argument("--preview-bytes", type=int, default=256, help="Number of bytes for hex preview")
    p_td.add_argument("--json", action="store_true", help="Output raw JSON")
    p_td.add_argument("--output", type=str, help="Write output to file")
    p_td.set_defaults(func=cmd_tex_data)

    # api-calls
    p_api = sub.add_parser("api-calls", help="List API calls in the capture")
    p_api.add_argument("capture", help="Path to .rdc capture file")
    p_api.add_argument("--event", type=int, default=0, help="Show detail for specific event ID")
    p_api.add_argument("--filter", type=str, default="", help="Filter calls by name")
    p_api.add_argument("--range", type=int, nargs=2, metavar=("START", "END"), help="Event ID range")
    p_api.add_argument("--json", action="store_true", help="Output raw JSON")
    p_api.add_argument("--output", type=str, help="Write output to file")
    p_api.set_defaults(func=cmd_api_calls)

    args = parser.parse_args()

    # Handle --output redirect
    if hasattr(args, "output") and args.output:
        with open(args.output, "w") as f:
            old_stdout = sys.stdout
            sys.stdout = f
            args.func(args)
            sys.stdout = old_stdout
    else:
        args.func(args)


if __name__ == "__main__":
    main()
