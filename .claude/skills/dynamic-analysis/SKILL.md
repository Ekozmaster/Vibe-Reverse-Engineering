---
name: dynamic-analysis
description: Use when attaching to or spawning a process for live analysis, setting breakpoints, tracing functions, collecting execution data, inspecting registers/memory/stack at runtime, stepping through code, patching live memory, catching who writes to an address, counting D3D9 draw calls, sending keystrokes or clicks to a game window, analyzing JSONL trace dumps, or performing any dynamic analysis task.
---

# Dynamic Analysis with livetools

For DX9 FFP proxy porting and RTX Remix compatibility, invoke the `dx9-ffp-port` skill.

A live analysis toolkit for running processes. Attach, trace functions, collect data, inspect state, step through code, patch memory, analyze offline -- composable tools that chain naturally for any RE scenario.

All commands: `python -m livetools <command> [args]`

## Quick Reference

### Session
```
python -m livetools attach <name_or_pid>             # attach to running process
python -m livetools attach <exe_path> --spawn        # launch + instrument before init code runs
python -m livetools detach                            # release target, stop daemon
python -m livetools status                            # check state
```

`detach` returns once the daemon process has exited, so an `attach` right after it starts cleanly. One daemon runs at a time, on port 27042. The daemon's errors, including those the agent reports from inside the target, go to `livetools/.daemon.log`, which the next `attach` overwrites.

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
python -m livetools step [over|into|out]      # run the frozen thread one step, freeze again (returns snapshot)
python -m livetools resume                    # unfreeze target
```

`step over` (the default) runs one instruction and lets a `call` run until it returns. `step into` runs one instruction and enters a call. `step out` runs until the current function has returned to its caller. A repeated string instruction (`rep movsb`, `rep stosd`, ...) always runs to its end, in every mode. A step that has not ended after 10 seconds (a call that blocks, a function that keeps looping) is given up with an error and the thread runs on. A step also ends early, with an error naming the cause and the thread running on, when the stepped instruction raises an exception of its own, or when the instruction after a call holds an `int3` the program put there or lies in the bytes of a `trace`/`collect` hook, a fence or the vishook. If a breakpoint is reached before the step ends, by the stepping thread (inside the call a `step over` runs, or the function a `step out` leaves) or by another thread, the step is ended, the thread at that breakpoint is the one frozen, and the reply says so with a `[note]` line before the snapshot.

**What a breakpoint is.** One `int3` byte written over the first byte of the instruction. The thread that reaches it freezes before that instruction runs, with its registers, stack and code exactly as the program left them, and a breakpoint may sit on any instruction.

- One thread is frozen at a time. Every other thread keeps running; when one reaches a breakpoint its hit is counted and it runs on. The exception is the breakpoint the frozen thread sits on: its original byte is back while that thread is frozen, so other threads run through that address unseen and uncounted.
- A breakpoint on a repeated string instruction counts one hit per execution of the whole instruction. Releasing a thread from it raises one exception per iteration, so a breakpoint on a `rep movs` that copies megabytes stalls that thread noticeably.
- `bp del` on the breakpoint a thread is frozen at also resumes that thread. After a `step` the thread is frozen somewhere else, and `bp del` leaves it frozen.
- `detach` removes every breakpoint and the vishook, and releases the frozen thread.
- `disasm` and `mem read` show the `int3` (`CC`) of a breakpoint that is set, except at the address a thread is frozen at, where the original byte is back.
- Breakpoints, hooks, the vishook and `mem write` never share bytes. `trace`, `collect` and its fence refuse an address whose first bytes hold a breakpoint or the vishook's jump; `bp add` refuses an address inside the bytes of an active hook or the vishook's jump; `vishook on` refuses a site whose 5 bytes hold a breakpoint or a hook; `mem write` refuses a range that holds any of them (remove it, write, then set it again) and leaves each page it writes with the protection it had; and `steptrace` refuses to start while any breakpoint is set. `bp add` also refuses an address that already holds an `int3`, such as the padding between functions.
- A `steptrace` whose function is not called, or does not return, within its timeout is removed, and `bp add` works again.

### Patch + Scan (anytime)
```
python -m livetools mem write <addr> <hex>    # write bytes to live memory (spaces allowed; an odd digit count or non-hex is refused)
python -m livetools mem alloc <size>          # allocate rwx memory in target (for code caves)
python -m livetools scan <pattern> --range START:SIZE
```

### Memory Access Watch
```
python -m livetools memwatch start <addr> [--size N] [--max-hits N]   # first access (read or write) to each page of the range
python -m livetools memwatch read             # show captured hits
python -m livetools memwatch stop
```

### D3D9 Draw Counter
```
python -m livetools dipcnt on <dev_ptr>       # hook DrawIndexedPrimitive via global IDirect3DDevice9* address
python -m livetools dipcnt read               # current count + delta since last read
python -m livetools dipcnt callers [N]        # sample N DIP calls, histogram return addresses (default 200)
python -m livetools dipcnt off
```

### Game Window Input (no Frida; brings the game window to the foreground)
```
python -m livetools gamectl --exe <game.exe> info
python -m livetools gamectl --exe <game.exe> key RETURN
python -m livetools gamectl --exe <game.exe> keys "DOWN DOWN RETURN WAIT:1000 RETURN"
python -m livetools gamectl --exe <game.exe> click <x> <y>
python -m livetools gamectl --exe <game.exe> macro <name> --macro-file patches/<game>/macros.json
```

### Non-blocking Tracing
```
python -m livetools trace <addr> [--probe] [--count N] [--read SPEC] [--read-leave SPEC] [--filter EXPR] [--timeout T] [--output FILE]
python -m livetools steptrace <addr> [--max-insn N] [--call-depth D] [--detail LEVEL] [--timeout T] [--output FILE]
python -m livetools collect <addr> [addr2 ...] [--probe] [--duration N] [--read SPEC] [--fence ADDR] [--label ADDR=NAME] [--output FILE]
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

Offsets are decimal unless written with `0x`: `[esp+0xc]` is offset 12, `[esp+10]` is offset 10, and `[esp+c]` is not a valid spec. Negative offsets (`[ebp-8]`) are not supported. A spec that does not parse is reported as a null value, not as an error, so check the first record for nulls. `st0` always reads as null.

## Filter Spec Format

Simple comparison on a readable field. Evaluated in-agent; non-matching calls are silently skipped.

```
[esp+8]:4:uint32==0x2
eax!=0
[ecx+0x54]:4:float32>0.5
```

Give memory operands a size and type. An untyped `[esp+8]==0x2` compares the raw bytes as one big-endian number and never matches. A filter that does not parse (for example a single `=`) is ignored and every call is recorded.

---

## Command Details

### trace -- Non-blocking enter/leave function hook

Hooks a function's entry and exit **without freezing** the target. Reads specified data at each call, returns structured results.

```bash
# 10 calls, read ECX + 12 bytes at [esp+4] as float32
python -m livetools trace 0x401000 --count 10 --read "ecx; [esp+4]:12:float32"

# Filter: only record when stack arg == 2
python -m livetools trace 0x402000 --count 5 --filter "[esp+8]:4:uint32==0x2" --read "[esp+0xc]:64:float32"

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

`<addr>` must be a **function entry**. The hook traps the function's return through the slot on top of the stack, which holds a return address only at an entry. A `call` instruction is refused with an error that says so, also when a probe or fence already sits on it. The check looks at that one instruction only: a function whose first instruction is a `call` is refused as well (use `--probe` on it), and any other address inside a function is not detected, so there the hook overwrites that stack slot for as long as the trace runs.

**`--probe` records at an instruction instead.** It hooks the instruction itself and leaves the stack alone, so `<addr>` may be any instruction. Use it on the call sites that `xrefs.py`, `vtable.py calls` and the DX scripts report:

```bash
# Arguments of one call site. At a call instruction the arguments are already
# pushed: [esp] is the first stack argument, [esp+4] the second (x86).
python -m livetools trace 0x4012AB --probe --count 20 --read "[esp]:4:uint32; [esp+4]:8:uint32"
```

```
=== TRACE 0x004012AB === 20 samples

#1
  PROBE  eax=00000000 ... esp=0576FA98 [esp]:4:uint32=[1] [esp+4]:8:uint32=[2, 3]
```

A probe record holds the registers and the `--read` data at that instruction. It has no `caller` and no return value, and `--read-leave` is rejected. `--filter` and `--count` work as for a function hook.

- The hook replaces at least 5 bytes at the address (up to 14 on x64). When the instruction there is shorter, the instructions after it are moved as well, and the target crashes if other code jumps to one of them.
- While a probe or a fence sits on a `call` instruction, the function it calls sees a return address inside Frida's trampoline. A function-hook trace of that callee then reports a `caller` outside every module.

### steptrace -- Instruction-level execution recording via Stalker

Records every instruction executed from function entry through return. Uses Frida Stalker for real-time instruction tracing. `<addr>` must be a function entry; a `call` instruction is refused.

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
  --read@ 0x401000="ecx; [esp+4]:12:float32" \
  --read@ 0x402000="ecx; [esp+4]:28:hex" \
  --duration 15 --output multi.jsonl

# Collect at call sites: --probe hooks every address as an instruction probe
python -m livetools collect 0x4012AB 0x4015C0 --probe \
  --duration 15 --read "[esp]:4:uint32" --output sites.jsonl
```

The addresses are function entries, as for `trace`. If one of them is a `call` instruction the whole command is refused before anything is hooked. With `--probe` every address is an instruction probe instead (see `trace`), and the records have no `caller` and no `leave`.

The **fence** concept: `--fence ADDR` counts an interval each time ADDR is reached, for example the game's call to DX Present or the entry of a per-frame function. A fence is a probe, so ADDR may be any instruction. Every trace record includes the current interval ID. Enables per-frame analysis, per-N-calls partitioning, and cross-function correlation.

Output: JSONL in `patches/<exe_name>/traces/` by default (gitignored).

### modules -- List loaded DLLs

```bash
python -m livetools modules
python -m livetools modules --filter kernel
```

Returns name, base address, size, and full path for every loaded module. Essential for finding DLL bases for vtable hooks.

### memwatch -- First access to a memory range

Uses Frida's MemoryAccessMonitor, which works on whole memory pages and reports only the **first** access to each page, of **any** kind. It is not a write watchpoint:

- The hit can be a read, a write or an execute; each hit line says which.
- The hit can be for any address on the same 4 KiB page as the range, not only the bytes you asked for.
- A range inside one page produces at most one hit, however often it is accessed afterwards.

Use it to learn that something touches a page and from which instruction (`from`), then confirm what that instruction does with `disasm`. To find who writes a specific variable, combine static `datarefs.py` with a `trace` on the candidate functions. The backtrace lines are not reliable.

```bash
python -m livetools memwatch start 0x7A0000 --size 48 --max-hits 20
python -m livetools memwatch read
python -m livetools memwatch stop
```

One active watch at a time. Stops after `--max-hits` (default 20), which a range inside a single page never reaches.

### dipcnt -- D3D9 DrawIndexedPrimitive counter

Hooks DIP through the device vtable, given the address of the game's global `IDirect3DDevice9*` pointer. Use to measure draw call volume or find render-loop callers without a full trace.

```bash
python -m livetools dipcnt on 0x7C5548     # address of the global device pointer
python -m livetools dipcnt read            # count + delta since last read
python -m livetools dipcnt callers 200     # sample 200 calls, histogram return addresses
python -m livetools dipcnt off
```

`callers` is the fast way to locate the main render loop: the dominant return address is the draw dispatcher.

### gamectl -- Send input to the game window

Brings the game window to the foreground (`SetForegroundWindow`) and then injects real keyboard and mouse input with `SendInput`; `click` also moves the mouse cursor. No Frida is involved. It takes focus away from whatever the user is doing, and if the game window cannot be focused the keys are still sent and land in whichever window is in front. Tell the user before using it, and check `focused=` in the output. Use to navigate menus or trigger in-game actions during long traces.

```bash
python -m livetools gamectl --exe game.exe info                      # show hwnd, title, pid
python -m livetools gamectl --exe game.exe key RETURN [--hold-ms 50]
python -m livetools gamectl --exe game.exe keys "DOWN DOWN RETURN WAIT:1000 RETURN" [--delay-ms 200]
python -m livetools gamectl --exe game.exe click 400 300             # client-area coordinates
python -m livetools gamectl --exe game.exe macro navigate_menu --macro-file patches/<game>/macros.json
```

Key names: `RETURN`, `ESCAPE`, `SPACE`, arrows, `TAB`, `F1`-`F12`, `A`-`Z`, `0`-`9`, `NUMPAD0`-`9`, `SHIFT`, `CTRL`, `ALT`. Sequence tokens: `WAIT:N` (pause N ms), `HOLD:KEY:N` (hold key N ms). Window lookup: `--exe` (preferred) or `--window <title substring>`.

### vishook -- Selective visibility override via code cave

Patches a jmp trampoline to route through a code cave that forces a "visible" result (st0 = 102400.0, optional byte out = 1) for callers at/above a threshold address, while callers below it run the original function. Designed for `__thiscall` visibility checks returning float on st(0) with `ret 0x10`. The `--threshold` value is parsed as hex: the default `500000` means 0x500000. 32-bit processes only. `detach` restores the jump site as `vishook off` does.

```bash
python -m livetools vishook on <jmp_site> <orig_target> [--threshold 500000]
python -m livetools vishook stats     # override vs passthrough call counts
python -m livetools vishook off       # restore original jmp
```

### analyze -- Offline JSONL aggregation (no Frida needed)

Pure Python. Reads JSONL from `collect` or `trace --output`. Deterministic, non-hallucinated aggregation.

```bash
# Overview
python -m livetools analyze trace.jsonl --summary

# Which functions were called most?
python -m livetools analyze trace.jsonl --group-by addr

# What % of calls return each value?
python -m livetools analyze trace.jsonl --filter "addr==0x00401000" --group-by "leave.eax"

# Cross-tab: caller vs return value
python -m livetools analyze trace.jsonl --filter "addr==0x00401000" --cross-tab caller leave.eax

# Per-interval call counts
python -m livetools analyze trace.jsonl --group-by interval --top 5

# What happened in interval 47?
python -m livetools analyze trace.jsonl --interval 47

# Compare two intervals
python -m livetools analyze trace.jsonl --compare-intervals 10 50

# Float distribution histogram
python -m livetools analyze trace.jsonl --filter "addr==0x00401000" --histogram "enter.reads.0.value.0"

# Export for external tools
python -m livetools analyze trace.jsonl --filter "addr==0x00401000" --export-csv output.csv
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

A record from `--probe` has no `caller` and no `leave`; its registers and reads are under `enter` as well.

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

After a `step` the first line reads `=== STEP COMPLETE === 0x00401006`, with the breakpoint and hit count added only when the step ended on a breakpoint. A step cut short by a breakpoint (see `step`) is headed `=== BREAKPOINT HIT ===` instead.

Status line in every response:
```
[attached: target.exe (pid 1234) | FROZEN @ 0x00401000 | bps: 3]
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

### Recipe 4: Verify a hook address is correct

Before hooking, confirm the address contains real code in the live process:
```
python -m livetools modules --filter <game_name>
python -m livetools disasm <target_addr> -n 5
```

If `disasm` shows garbage or errors, the address is wrong at runtime. For DLLs, rebase from `modules` output. For game .exe code, most x86 games load at preferred base — static addresses work directly.

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
python -m livetools watch --timeout 60          # frozen at the entry
python -m livetools step                        # one instruction; a call runs until it returns
python -m livetools step into                   # one instruction; enters a call
python -m livetools mem read <addr> 32
python -m livetools step out                    # runs until this function has returned to its caller
python -m livetools bp del <function_entry>
python -m livetools resume
```

Each `step` prints the same snapshot as `watch`. To stop somewhere further on without stepping there, set a second breakpoint and `resume`. To record the whole path through a function in one go, use `steptrace <function_entry>` with no breakpoint set.

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

7. **Verify addresses before hooking.** Most 32-bit game .exe files load at their preferred base (no ASLR), so static addresses from `retools` work directly. For DLLs or ASLR binaries, run `modules --filter <name>` and rebase: `runtime_addr = runtime_base + (static_addr - preferred_base)`. When in doubt, `modules` is one command — run it.

8. **Composable pipeline.** `trace` captures raw records. `collect` streams them to disk. `analyze` aggregates offline. Chain them for any investigation.

9. **A function hook goes on a function entry; a call site takes `--probe`.** `trace` and `collect` hook a function: given its entry they record the arguments, the return value and the `caller` of every call. They trap the return through the top stack slot, so they refuse a `call` instruction, where that slot is the first stack argument (the `this`/device pointer for a COM call). There are two ways to watch a D3D9 method or any other call:
   - **One call site:** `trace <call_site> --probe` on the `call [reg+offset]` or `call <addr>` instruction in the game's code, found with `xrefs.py`, `vtable.py calls` or the DX scripts. At a call instruction the arguments are already pushed: `[esp]` is `this` and `[esp+4]` the first declared argument (x86). A probe records no return value.
   - **Every caller:** hook the entry of the method the game actually calls, read from the device vtable at runtime with three pointer reads (x86; each prints `As ptr: [-> 0x...]`): `mem read <dev_global> 4 --as ptr` gives the device object, where `<dev_global>` is the address of the game's global `IDirect3DDevice9*` variable (the same address `dipcnt on` takes); `mem read <device> 4 --as ptr` gives its vtable; `mem read <vtable + slot*4> 4 --as ptr` gives the entry. At an entry `[esp+4]` is `this` and `[esp+8]` the first declared argument. Each record's `caller` is the return address, so group or filter by `caller` to isolate one call site.

   Breakpoints (`bp add`) and the `collect --fence` address may sit on any instruction.

10. **Zero hits means something is wrong — diagnose, don't give up.** If trace/collect returns 0 samples: (a) Ask the user: is the game window focused and actively rendering? (b) Verify the address: `disasm <addr>` in livetools — confirm real code exists there. (c) Try a known-hot address: `dipcnt callers 10` lists return addresses of confirmed active call sites; trace the entry of the function containing one of them (not the return address itself) to prove the hook pipeline works. (d) Only after all three pass should you reconsider whether the original address is actually called during gameplay.

---

## Anti-Patterns

**Do NOT put a function hook on an address inside a function.** `trace`, `collect` and `steptrace` refuse a `call` instruction, but nothing detects any other mid-function address: there the return hook overwrites a stack slot for as long as it is installed. For anything that is not a function entry use `--probe` or a breakpoint (pattern #9).

**Do NOT compute a D3D9 method address from `d3d9.dll`.** `d3d9.dll base + a method offset` is the system implementation. With a proxy or wrapper d3d9.dll in the chain (RTX Remix, a tracer, an overlay) the game holds the wrapper's device, so a hook inside system d3d9.dll does not see the calls as the game made them. Probe the game's call site, or read the method pointer from the live device's vtable (pattern #9).

**Do NOT explain away zero data.** If a trace returns 0 samples, the answer is "I got no data and need to troubleshoot" — not "the game doesn't appear to use this code path." Follow the escalation in pattern #10.
