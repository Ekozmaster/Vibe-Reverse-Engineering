---
name: dynamic-analysis
description: Frida-based live process analysis toolkit for reverse engineering. Use when attaching to a running process, setting breakpoints, tracing functions, collecting execution data, inspecting registers/memory/stack at runtime, stepping through code, patching live memory, analyzing JSONL trace dumps, or performing any dynamic analysis task. Provides blocking breakpoints, non-blocking function tracing, Stalker-based instruction recording, interval-aware data collection, offline aggregation, and module enumeration.
---

# Dynamic Analysis with livetools

For DX9 FFP proxy porting and RTX Remix compatibility, see also: @dx9-ffp-port

A live analysis toolkit for running processes. Attach, trace functions, collect data, inspect state, step through code, patch memory, analyze offline -- composable tools that chain naturally for any RE scenario.

All commands: `python -m livetools <command> [args]`

## Quick Reference

### Session
```
python -m livetools attach <name_or_pid>     # start daemon, attach Frida
python -m livetools detach                    # release target, stop daemon
python -m livetools status                    # check state
```

### Breakpoints (blocking)
```
python -m livetools bp add <addr>             # set blocking code breakpoint
python -m livetools bp del <addr>             # remove breakpoint
python -m livetools bp list                   # list all BPs + hit counts
```

### Wait for Hit
```
python -m livetools watch --timeout 60        # block until BP hit (returns snapshot)
```

### Inspect (while frozen)
```
python -m livetools regs                      # all registers
python -m livetools stack [N]                 # top N dwords from ESP (default 16)
python -m livetools mem read <addr> <size>    # hex dump + multi-type interpretation
python -m livetools mem read <addr> <size> --as float32
python -m livetools disasm [addr] [-n count]  # disassemble (default: EIP, 16 insns)
python -m livetools bt                        # call stack backtrace
```

Supported `--as` types: `float32`, `float64`, `half`, `uint8`, `int8`, `uint16`, `int16`, `uint32`, `int32`, `ptr`, `ascii`, `utf16`.

### Control
```
python -m livetools step [over|into|out]      # advance one instruction (returns snapshot)
python -m livetools resume                    # unfreeze target
```

### Patch + Scan (anytime)
```
python -m livetools mem write <addr> <hex>    # write bytes to live memory
python -m livetools scan <pattern> --range START:SIZE
```

### Non-blocking Tracing (NEW)
```
python -m livetools trace <addr> [--count N] [--read SPEC] [--read-leave SPEC] [--filter EXPR] [--timeout T] [--output FILE]
python -m livetools steptrace <addr> [--max-insn N] [--call-depth D] [--detail LEVEL] [--timeout T] [--output FILE]
python -m livetools collect <addr> [addr2 ...] [--duration N] [--read SPEC] [--fence ADDR] [--label ADDR=NAME] [--output FILE]
python -m livetools modules [--filter PATTERN]
python -m livetools analyze <file.jsonl> [--summary] [--group-by FIELD] [--filter EXPR] [--cross-tab F1 F2] [--histogram FIELD] [--export-csv FILE]
```

---

## Read Spec Format

Used by `trace`, `collect`, and related commands to specify what data to capture at function entry/exit.

Semicolon-separated fields. Each field:

| Syntax | Description | Example |
|--------|-------------|---------|
| `register` | Register value as hex | `ecx`, `eax`, `ebp` |
| `[reg+OFFSET]:SIZE:TYPE` | Read SIZE bytes from reg+OFFSET | `[esp+4]:12:float32` |
| `*[reg+OFFSET]:SIZE:TYPE` | Double-deref: follow pointer first | `*[esp+4]:64:float32` |
| `st0` | FPU top-of-stack (best-effort) | `st0` |

Types: `hex` (default), `float32`, `float64`, `uint32`, `int32`, `uint16`, `int16`, `uint8`, `int8`, `ascii`, `utf16`, `ptr`

Example read spec:
```
"ecx; [esp+4]:12:float32; *[ecx+0x10]:64:hex"
```

## Filter Spec Format

Simple comparison on a readable field. Evaluated in-agent; non-matching calls are silently skipped.

```
[esp+8]==0x2
eax!=0
[ecx+0x54]:4:float32>0.5
```

---

## Command Details

### trace -- Non-blocking enter/leave function hook

Hooks a function's entry and exit **without freezing** the target. Reads specified data at each call, returns structured results.

```bash
# 10 calls, read ECX + 12 bytes at [esp+4] as float32
python -m livetools trace 0x401000 --count 10 --read "ecx; [esp+4]:12:float32"

# Filter: only record when stack arg == 2
python -m livetools trace 0x402000 --count 5 --filter "[esp+8]==0x2" --read "[esp+c]:64:float32"

# Read different things on enter vs leave
python -m livetools trace 0x403000 --count 20 --read "ecx; [esp+4]:12:float32" --read-leave "eax"

# Write output to JSONL file
python -m livetools trace 0x401000 --count 100 --read "ecx" --output trace.jsonl
```

Output format:
```
=== TRACE 0x00401000 === 10 samples

#1  caller=00405ABC
  ENTER  ecx=10B457CC  [esp+4]:12:float32=[-622.44, -278.34, 50.00]
  LEAVE  eax=00000001  retval=00000001
#2  caller=00405ABC
  ENTER  ecx=10DE6A74  [esp+4]:12:float32=[-236.48, -322.13, 50.00]
  LEAVE  eax=00000001  retval=00000001
```

### steptrace -- Instruction-level execution recording via Stalker

Records every instruction executed from function entry through return. Uses Frida Stalker for real-time instruction tracing.

```bash
# Full trace, follow 1 level of subcalls
python -m livetools steptrace 0x401000 --max-insn 500 --call-depth 1 --detail full

# Branches only (default, lighter weight)
python -m livetools steptrace 0x402000 --max-insn 1000 --detail branches

# Block-level only (cheapest, for huge functions)
python -m livetools steptrace 0x403000 --max-insn 5000 --detail blocks

# Save to file for later analysis
python -m livetools steptrace 0x401000 --max-insn 500 --output steptrace.jsonl
```

Detail levels:
- **full**: Every instruction, register snapshots at calls/rets. Expensive but complete.
- **branches**: All instructions recorded, register snapshots at branches. Good default.
- **blocks**: Only instruction addresses. Cheapest. Good for path mapping.

### collect -- Long-running multi-function data collection

Streams data from one or more functions for a duration. Optionally partitions records into intervals via fence hooks.

```bash
# Collect two functions for 30s, partitioned by a frame-boundary function
python -m livetools collect 0x401000 0x402000 \
  --duration 30 --output trace.jsonl \
  --read "ecx; [esp+4]:12:float32" \
  --fence 0x403000 \
  --label 0x401000=FuncA --label 0x402000=FuncB

# Collect with per-address read specs
python -m livetools collect 0x401000 0x402000 \
  --read@0x401000="ecx; [esp+4]:12:float32" \
  --read@0x402000="ecx; [esp+4]:28:hex" \
  --duration 15 --output multi.jsonl
```

The **fence** concept: Hook a boundary function (e.g. DX Present) that increments an interval counter. Every trace record includes the current interval ID. Enables per-frame analysis, per-N-calls partitioning, and cross-function correlation.

Output: JSONL in `patches/<exe_name>/traces/` by default (gitignored).

### modules -- List loaded DLLs

```bash
python -m livetools modules
python -m livetools modules --filter kernel
python -m livetools modules --filter kernel
```

Returns name, base address, size, and full path for every loaded module. Essential for finding DLL bases for vtable hooks.

### analyze -- Offline JSONL aggregation (no Frida needed)

Pure Python. Reads JSONL from `collect` or `trace --output`. Deterministic, non-hallucinated aggregation.

```bash
# Overview
python -m livetools analyze trace.jsonl --summary

# Which functions were called most?
python -m livetools analyze trace.jsonl --group-by addr

# What % of calls return each value?
python -m livetools analyze trace.jsonl --filter "addr==00401000" --group-by "leave.eax"

# Cross-tab: caller vs return value
python -m livetools analyze trace.jsonl --filter "addr==00401000" --cross-tab caller leave.eax

# Per-interval call counts
python -m livetools analyze trace.jsonl --group-by interval --top 5

# What happened in interval 47?
python -m livetools analyze trace.jsonl --interval 47

# Compare two intervals
python -m livetools analyze trace.jsonl --compare-intervals 10 50

# Float distribution histogram
python -m livetools analyze trace.jsonl --filter "addr==00401000" --histogram "enter.reads.0.value.0"

# Export for external tools
python -m livetools analyze trace.jsonl --filter "addr==00401000" --export-csv output.csv
```

Field path syntax: dot-separated with array indices.
- `addr` = hooked address
- `leave.eax` = EAX at exit
- `enter.reads.0.value.0` = first read spec's first float value
- `interval` = fence counter
- `caller` = return address

---

## JSONL Record Format

Each line in a JSONL file is a self-contained JSON object:

```json
{"ts": 1710000000000, "interval": 47, "addr": "0x00401000", "label": "FuncA", "caller": "00405ABC", "enter": {"regs": {"ecx": "10B457CC", ...}, "reads": [{"spec": "[esp+4]:12:float32", "value": [-622.44, -278.34, 50.00]}]}, "leave": {"eax": "00000001", "retval": "00000001", "reads": []}}
```

---

## Output File Location

JSONL files default to `patches/<exe_name>/traces/` inside the workspace (gitignored). The exe name is auto-detected from the attached process. Override with `--output /absolute/path.jsonl`.

---

## The Debugger Snapshot

Every `watch` (on hit) and `step` (after advancing) returns a unified snapshot:

```
=== BREAKPOINT HIT === 0x00401000 (bp#1, hit #3)

Registers:
  EAX=00000001  EBX=00000000  ECX=008800A0  EDX=00405678
  ESI=008900B4  EDI=007A0000  EBP=0019FE40  ESP=0019FD00
  EIP=00401000

Stack [ESP=0019FD00]:
  +00: 00405678  +04: 0019FE80  +08: 00000000  +0C: 00000000

Disasm @ EIP:
> 00401000  sub   esp, 0x234
  00401006  push  ebp
```

Status line in every response:
```
[attached: target.exe (pid 1234) | FROZEN @ 00401000 | bps: 3]
```

---

## Workflow Recipes

### Recipe 1: Quick function behavior check (trace)

Non-blocking -- target keeps running. See what arguments a function receives and what it returns.

```
python -m livetools trace 0x401000 --count 10 --read "ecx; [esp+4]:12:float32"
```

### Recipe 2: Understand a function's code path (steptrace)

Record the actual instructions executed through a single invocation:

```
python -m livetools steptrace 0x401000 --max-insn 500 --call-depth 1 --detail branches
```

### Recipe 3: Per-frame analysis (collect + fence + analyze)

Collect data over many frames, then analyze offline:

```bash
python -m livetools collect 0x401000 0x402000 \
  --duration 30 --fence 0x403000 \
  --read "ecx; [esp+4]:12:float32" \
  --label 0x401000=FuncA --label 0x402000=FuncB \
  --output trace.jsonl

python -m livetools analyze trace.jsonl --summary
python -m livetools analyze trace.jsonl --group-by "leave.eax"
python -m livetools analyze trace.jsonl --compare-intervals 10 50
python -m livetools analyze trace.jsonl --histogram "enter.reads.0.value.0"
```

### Recipe 4: Find DLL base for vtable hooks (modules)

```
python -m livetools modules --filter kernel
```

Use the base address to compute vtable entry addresses.

### Recipe 5: Register inspection at a breakpoint

```
python -m livetools bp add 0x401000
python -m livetools watch --timeout 60
python -m livetools resume
```

### Recipe 6: Read struct fields from a register pointer

After a snapshot shows ECX=008800A0 and you suspect a float at offset +0x54:
```
python -m livetools mem read 0x008800F4 4 --as float32
```

### Recipe 7: Step through a function

```
python -m livetools bp add <function_entry>
python -m livetools watch --timeout 60
python -m livetools step over
python -m livetools step over
python -m livetools mem read <addr> 32
python -m livetools resume
```

### Recipe 8: Patch a byte and verify

```
python -m livetools mem write 0x00401000 "B0 01 C3"
python -m livetools disasm 0x00401000 -n 3
```

### Recipe 9: Multi-function data-driven investigation

Collect raw data, then ask targeted questions offline:

```bash
# 1. Collect
python -m livetools collect 0x401000 0x402000 0x403000 \
  --duration 60 --fence 0x404000 --output scene.jsonl \
  --label 0x401000=FuncA --label 0x402000=FuncB --label 0x403000=FuncC

# 2. Overview
python -m livetools analyze scene.jsonl --summary

# 3. Which function is called most?
python -m livetools analyze scene.jsonl --group-by addr

# 4. Return value distribution for FuncA
python -m livetools analyze scene.jsonl --filter "addr==0x00401000" --group-by "leave.eax"

# 5. Cross-tab: who calls FuncA and what result?
python -m livetools analyze scene.jsonl --filter "addr==0x00401000" --cross-tab caller leave.eax

# 6. Export for spreadsheet
python -m livetools analyze scene.jsonl --export-csv scene.csv
```

---

## Thinking Patterns

1. **Hypothesis first.** Form a hypothesis from static analysis BEFORE tracing. Example: "I think ECX is the visibility struct pointer. Let me verify with trace."

2. **State what you learned.** After inspecting trace data or a snapshot, explicitly state what the values tell you and what question remains.

3. **Use trace before breakpoints.** Non-blocking `trace` is less disruptive than blocking `bp`+`watch`. Start with trace to understand call frequency and typical arguments, then use breakpoints only when you need to freeze and step.

4. **Use collect for volume.** When you need data from thousands of calls across many frames, `collect` with a fence gives you structured JSONL that `analyze` can slice and dice deterministically.

5. **Use analyze for deterministic answers.** Never hallucinate statistics. Always run `analyze` on real collected data to get ground-truth numbers about call counts, return value distributions, per-frame behavior, etc.

6. **Cross-reference with static analysis.** Match live register values and call sites against static disassembly from `retools` to identify struct offsets, vtable slots, and data pointers.

7. **Use modules to find DLL bases.** Before hooking a DLL function (e.g. D3D9 vtable), use `modules` to find the actual loaded base address.

8. **Composable pipeline.** `trace` captures raw records. `collect` streams them to disk. `analyze` aggregates offline. Chain them for any investigation.
