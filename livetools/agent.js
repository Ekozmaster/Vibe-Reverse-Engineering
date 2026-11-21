'use strict';

// ---------------------------------------------------------------------------
// Frida JS agent -- injected into the target process by the livetools daemon.
//
// Provides:
//   - Blocking breakpoints and single-stepping
//   - Non-blocking trace hooks with read-spec evaluation
//   - Stalker-based instruction-level execution tracing
//   - Interval fence counter
//   - Module enumeration
//   - Memory I/O, disassembly, register snapshots
// ---------------------------------------------------------------------------

var is64 = Process.pointerSize === 8;
var ptrWidth = Process.pointerSize * 2;
var _allocations = [];

// ── helpers ────────────────────────────────────────────────────────────────

function ptrToHex(p) {
    var s = ptr(p).toString(16).toUpperCase();
    if (s.indexOf('0X') === 0) s = s.slice(2);
    while (s.length < ptrWidth) s = '0' + s;
    return s;
}

function snapshotRegs(ctx) {
    if (is64) {
        return {
            rax: ptrToHex(ctx.rax), rbx: ptrToHex(ctx.rbx),
            rcx: ptrToHex(ctx.rcx), rdx: ptrToHex(ctx.rdx),
            rsi: ptrToHex(ctx.rsi), rdi: ptrToHex(ctx.rdi),
            rbp: ptrToHex(ctx.rbp), rsp: ptrToHex(ctx.rsp),
            rip: ptrToHex(ctx.pc),
            r8:  ptrToHex(ctx.r8),  r9:  ptrToHex(ctx.r9),
            r10: ptrToHex(ctx.r10), r11: ptrToHex(ctx.r11),
            r12: ptrToHex(ctx.r12), r13: ptrToHex(ctx.r13),
            r14: ptrToHex(ctx.r14), r15: ptrToHex(ctx.r15),
            _arch: 'x64'
        };
    }
    return {
        eax: ptrToHex(ctx.eax), ebx: ptrToHex(ctx.ebx),
        ecx: ptrToHex(ctx.ecx), edx: ptrToHex(ctx.edx),
        esi: ptrToHex(ctx.esi), edi: ptrToHex(ctx.edi),
        ebp: ptrToHex(ctx.ebp), esp: ptrToHex(ctx.esp),
        eip: ptrToHex(ctx.pc),
        _arch: 'x86'
    };
}

function hexToBytes(hex) {
    if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) {
        throw new Error('hex must be pairs of hex digits, got "' + hex + '"');
    }
    var bytes = [];
    for (var i = 0; i < hex.length; i += 2)
        bytes.push(parseInt(hex.substr(i, 2), 16));
    return bytes;
}

function bufToHex(buf) {
    var u8 = new Uint8Array(buf);
    var h = '';
    for (var i = 0; i < u8.length; i++) {
        var b = u8[i].toString(16);
        h += (b.length < 2 ? '0' : '') + b;
    }
    return h;
}

function getRegVal(ctx, name) {
    var n = name.toLowerCase();
    if (n === 'pc' || n === 'eip' || n === 'rip') return ctx.pc;
    try { return ctx[n]; } catch (e) { return ptr(0); }
}

// ── prologue validation ──────────────────────────────────────────────────

var MIN_HOOK_BYTES = is64 ? 14 : 5;

function checkPrologue(addrStr) {
    var target = ptr(addrStr);
    var totalBytes = 0;
    var insns = [];
    var cursor = target;
    try {
        for (var i = 0; i < 8 && totalBytes < MIN_HOOK_BYTES; i++) {
            var insn = Instruction.parse(cursor);
            insns.push({ addr: ptrToHex(cursor), mnemonic: insn.mnemonic, opStr: insn.opStr, size: insn.size });
            totalBytes += insn.size;
            cursor = cursor.add(insn.size);
        }
    } catch (e) {
        return { ok: false, totalBytes: totalBytes, insns: insns, error: 'parse failed: ' + e.message };
    }
    var origBytes = bufToHex(target.readByteArray(Math.max(totalBytes, MIN_HOOK_BYTES)));
    return { ok: totalBytes >= MIN_HOOK_BYTES, totalBytes: totalBytes, needed: MIN_HOOK_BYTES, insns: insns, origBytes: origBytes };
}

// ── code this agent has changed ───────────────────────────────────────────
//
// Four things rewrite the target's code: Interceptor hooks and the vishook,
// which replace the first bytes at their address with a jump; breakpoints,
// which replace one byte with an int3; and `mem write`. None of them may
// rewrite bytes another one owns. Frida would copy a breakpoint's int3 into
// its trampoline, where no breakpoint is registered; a breakpoint written into
// a jump would redirect it; and bytes saved for a later restore would hold the
// other one's change and write it back after it was undone. Interceptor hooks
// at one address alone share their bytes, because Frida chains them there; at
// another address inside those bytes, Frida would relocate the jump's own bytes.

var hooks = [];     // { start, size, what, interceptor, original } for every jump written
var patches = {};   // address -> the int3 written there (see "breakpoints")

// Writes `bytes` over code or data and leaves each page with the protection it had.
function patchBytes(address, bytes) {
    if (bytes.length === 0) return;
    var pageSize = Process.pageSize;
    var first = address.and(ptr(pageSize - 1).not());
    var end = address.add(bytes.length);
    var protections = [];
    for (var page = first; page.compare(end) < 0; page = page.add(pageSize)) {
        protections.push({ page: page, protection: Process.getRangeByAddress(page).protection });
    }
    try {
        Memory.patchCode(address, bytes.length, function (code) { code.writeByteArray(bytes); });
    } finally {
        protections.forEach(function (p) { Memory.protect(p.page, pageSize, p.protection); });
    }
}

function patchKey(address) {
    return ptr(address).toString();
}

function hookedBytes(address) {
    var prologue = checkPrologue('0x' + ptrToHex(address));
    return Math.max(prologue.totalBytes, MIN_HOOK_BYTES);
}

function contains(start, size, address) {
    return address.compare(start) >= 0 && address.compare(start.add(size)) < 0;
}

function overlaps(startA, sizeA, startB, sizeB) {
    return contains(startA, sizeA, startB) || contains(startB, sizeB, startA);
}

// Why `what` must not rewrite the `size` bytes at `start`, or null if it may.
function rewriteRefusal(start, size, what, interceptor) {
    for (var key in patches) {
        if (contains(start, size, patches[key].address)) {
            return 'a breakpoint is set at 0x' + ptrToHex(patches[key].address) +
                ', inside the ' + size + ' bytes the ' + what + ' at 0x' + ptrToHex(start) +
                ' would rewrite. Remove the breakpoint first (bp del).';
        }
    }
    for (var i = 0; i < hooks.length; i++) {
        var hook = hooks[i];
        if (!overlaps(hook.start, hook.size, start, size)) continue;
        if (interceptor && hook.interceptor && hook.start.equals(start)) continue;
        return 'the ' + hook.what + ' at 0x' + ptrToHex(hook.start) + ' has replaced ' + hook.size +
            ' bytes there, which overlap the ' + size + ' bytes the ' + what + ' at 0x' +
            ptrToHex(start) + ' would rewrite. ' +
            (hook.interceptor ? 'Wait for it to finish, or remove it first.'
                              : 'Remove it first (' + hook.what + ' off).');
    }
    return null;
}

// The program's own `size` bytes at `start`: what is there now, with the bytes
// this agent's jumps and int3s have replaced put back.
function originalBytes(start, size) {
    var bytes = new Uint8Array(start.readByteArray(size));
    function putBack(from, saved) {
        if (!overlaps(from, saved.length, start, size)) return;
        for (var i = 0; i < saved.length; i++) {
            var offset = from.add(i).sub(start).toInt32();
            if (offset >= 0 && offset < size) bytes[offset] = saved[i];
        }
    }
    hooks.forEach(function (hook) { putBack(hook.start, hook.original); });
    for (var key in patches) putBack(patches[key].address, [patches[key].original]);
    return bytes;
}

// The program's own instruction at `address`, whatever this agent has written over it.
function originalInstruction(address) {
    var bytes = originalBytes(address, 16);
    var current = new Uint8Array(address.readByteArray(16));
    var rewritten = bytes.some(function (b, i) { return b !== current[i]; });
    var insn;
    if (rewritten) {
        var copy = Memory.alloc(16);
        copy.writeByteArray(bytes);
        insn = Instruction.parse(copy);
    } else {
        insn = Instruction.parse(address);
    }
    // A copy elsewhere decodes a relative operand against the wrong address.
    return { str: rewritten ? insn.mnemonic : insn.toString(), isCall: isCall(insn) };
}

function isCall(insn) {
    return insn.groups.indexOf('call') >= 0;
}

function isReturn(insn) {
    return insn.groups.indexOf('ret') >= 0;
}

// Records a jump written over `size` bytes at `start`, which held `original`; returns its release.
function recordHook(start, size, what, interceptor, original) {
    var hook = { start: start, size: size, what: what, interceptor: interceptor, original: original };
    hooks.push(hook);
    return function () {
        var index = hooks.indexOf(hook);
        if (index >= 0) hooks.splice(index, 1);
    };
}

// Why an Interceptor hook for `what` must not go at `address`, or null if it may.
function hookRefusal(address, what) {
    return rewriteRefusal(address, hookedBytes(address), what + ' hook', true);
}

function attachHook(address, what, callbacks) {
    var size = hookedBytes(address);
    var refusal = hookRefusal(address, what);
    if (refusal !== null) throw new Error(refusal);
    var original = originalBytes(address, size);
    var listener = Interceptor.attach(address, callbacks);
    var release = recordHook(address, size, what + ' hook', true, original);
    return {
        detach: function () {
            listener.detach();
            release();
        }
    };
}

function verifyHook(addrStr, origFirstByte) {
    try {
        var cur = ptr(addrStr).readU8();
        var inlineHooked = (cur !== origFirstByte);
        return { inlineHooked: inlineHooked, origByte: origFirstByte, curByte: cur,
                 note: inlineHooked ? 'inline hook confirmed' : 'bytes unchanged — likely VEH/exception-based hook (normal on Windows)' };
    } catch (e) {
        return { inlineHooked: false, error: e.message };
    }
}

// ── read-spec parser & evaluator ──────────────────────────────────────────
//
// Spec format (semicolon-separated):
//   "ecx"                   -> register value
//   "[esp+0x4]:12:float32"  -> read 12 bytes at esp+4, decode as float32
//   "*[esp+4]:64:float32"   -> double-deref: read ptr at esp+4, then 64 bytes
//   "st0"                   -> FPU top (best-effort)

var REG_NAMES_32 = ['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'];
var REG_NAMES_64 = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','rip',
                    'r8','r9','r10','r11','r12','r13','r14','r15'];
var ALL_REG = REG_NAMES_32.concat(REG_NAMES_64);

function parseReadSpecs(specStr) {
    if (!specStr) return [];
    var parts = specStr.split(';');
    var specs = [];
    for (var i = 0; i < parts.length; i++) {
        var s = parts[i].replace(/^\s+|\s+$/g, '');
        if (!s) continue;
        specs.push(parseOneSpec(s));
    }
    return specs;
}

function parseOneSpec(s) {
    var lower = s.toLowerCase();
    if (lower === 'st0') return { kind: 'st0', raw: s };
    if (ALL_REG.indexOf(lower) >= 0) return { kind: 'reg', name: lower, raw: s };

    var deref = false;
    var work = s;
    if (work.charAt(0) === '*') { deref = true; work = work.substring(1); }

    var m = work.match(/^\[(\w+)(?:\s*\+\s*(0x[\da-fA-F]+|\d+))?\]\s*(?::(\d+))?(?::(\w+))?$/);
    if (m) {
        var base = m[1].toLowerCase();
        var off = m[2] ? parseInt(m[2], m[2].indexOf('0x') === 0 ? 16 : 10) : 0;
        var sz = m[3] ? parseInt(m[3], 10) : 4;
        var dtype = m[4] ? m[4].toLowerCase() : 'hex';
        return { kind: deref ? 'deref' : 'mem', base: base, offset: off,
                 size: sz, dtype: dtype, raw: s };
    }
    return { kind: 'reg', name: lower, raw: s };
}

function evalReadSpecs(specs, ctx) {
    var results = [];
    for (var i = 0; i < specs.length; i++) {
        results.push(evalOneSpec(specs[i], ctx));
    }
    return results;
}

function evalOneSpec(spec, ctx) {
    try {
        if (spec.kind === 'reg') {
            return { spec: spec.raw, value: ptrToHex(getRegVal(ctx, spec.name)) };
        }
        if (spec.kind === 'st0') {
            return { spec: spec.raw, value: null };
        }
        var baseVal = getRegVal(ctx, spec.base);
        var addr = baseVal.add(spec.offset);

        if (spec.kind === 'deref') {
            addr = addr.readPointer();
        }

        var buf = addr.readByteArray(spec.size);
        if (!buf) return { spec: spec.raw, value: null };
        return { spec: spec.raw, value: convertBuf(buf, spec.dtype) };
    } catch (e) {
        return { spec: spec.raw, value: null, error: e.message };
    }
}

function convertBuf(buf, dtype) {
    var dv = new DataView(buf);
    var arr, i;
    switch (dtype) {
        case 'float32':
            arr = [];
            for (i = 0; i + 3 < buf.byteLength; i += 4)
                arr.push(Math.round(dv.getFloat32(i, true) * 1e6) / 1e6);
            return arr;
        case 'float64':
            arr = [];
            for (i = 0; i + 7 < buf.byteLength; i += 8)
                arr.push(dv.getFloat64(i, true));
            return arr;
        case 'uint32':
            arr = [];
            for (i = 0; i + 3 < buf.byteLength; i += 4)
                arr.push(dv.getUint32(i, true));
            return arr;
        case 'int32':
            arr = [];
            for (i = 0; i + 3 < buf.byteLength; i += 4)
                arr.push(dv.getInt32(i, true));
            return arr;
        case 'uint16':
            arr = [];
            for (i = 0; i + 1 < buf.byteLength; i += 2)
                arr.push(dv.getUint16(i, true));
            return arr;
        case 'int16':
            arr = [];
            for (i = 0; i + 1 < buf.byteLength; i += 2)
                arr.push(dv.getInt16(i, true));
            return arr;
        case 'uint8':
            arr = [];
            for (i = 0; i < buf.byteLength; i++)
                arr.push(dv.getUint8(i));
            return arr;
        case 'int8':
            arr = [];
            for (i = 0; i < buf.byteLength; i++)
                arr.push(dv.getInt8(i));
            return arr;
        case 'ptr':
            arr = [];
            var ps = Process.pointerSize;
            for (i = 0; i + ps - 1 < buf.byteLength; i += ps) {
                var v = (ps === 8) ? Number(dv.getBigUint64(i, true)) : dv.getUint32(i, true);
                arr.push(v);
            }
            return arr;
        case 'ascii':
            var u8 = new Uint8Array(buf);
            var t = '';
            for (i = 0; i < u8.length && u8[i] !== 0; i++)
                t += String.fromCharCode(u8[i]);
            return t;
        case 'utf16':
            arr = [];
            for (i = 0; i + 1 < buf.byteLength; i += 2) {
                var ch = dv.getUint16(i, true);
                if (ch === 0) break;
                arr.push(String.fromCharCode(ch));
            }
            return arr.join('');
        default:
            return bufToHex(buf);
    }
}

// ── filter parser & evaluator ─────────────────────────────────────────────
//
// Format: "[esp+8]==0x2" | "eax!=0" | "[ecx+0x54]:4:float32>0.5"

function parseFilter(filterStr) {
    if (!filterStr) return null;
    var m = filterStr.match(/^(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+)$/);
    if (!m) return null;
    var lhs = parseOneSpec(m[1].replace(/^\s+|\s+$/g, ''));
    var op = m[2];
    var rhsStr = m[3].replace(/^\s+|\s+$/g, '');
    var rhs;
    if (rhsStr.indexOf('0x') === 0) rhs = parseInt(rhsStr, 16);
    else if (rhsStr.indexOf('.') >= 0) rhs = parseFloat(rhsStr);
    else rhs = parseInt(rhsStr, 10);
    return { lhs: lhs, op: op, rhs: rhs };
}

function evalFilter(filter, ctx) {
    if (!filter) return true;
    var result = evalOneSpec(filter.lhs, ctx);
    var val = result.value;
    if (val === null || val === undefined) return false;
    if (typeof val === 'string') val = parseInt(val, 16);
    if (Array.isArray(val)) val = val[0];
    switch (filter.op) {
        case '==': return val === filter.rhs;
        case '!=': return val !== filter.rhs;
        case '>':  return val > filter.rhs;
        case '<':  return val < filter.rhs;
        case '>=': return val >= filter.rhs;
        case '<=': return val <= filter.rhs;
        default:   return true;
    }
}

// ── non-blocking trace system ─────────────────────────────────────────────
//
// A trace hooks its address in one of two forms:
//
//   function hook  Interceptor.attach(target, {onEnter, onLeave}). Frida traps
//                  the return by replacing the slot on top of the stack, which
//                  holds a return address only at a function entry.
//   probe          Interceptor.attach(target, fn). The stack is left alone, so
//                  the address may be any instruction; there is no return to
//                  observe, and a record holds the enter data only.

var traces = {};
var nextTraceId = 1;
var fenceCounter = 0;
var fenceListener = null;
var BATCH_SIZE = 64;

function installTrace(addrStr, config) {
    var id = nextTraceId++;
    var enterSpecs = parseReadSpecs(config.readEnter || '');
    var leaveSpecs = parseReadSpecs(config.readLeave || '');
    var filter = parseFilter(config.filter || '');
    var maxCount = config.count || 0;
    var label = config.label || '';
    var collected = 0;
    var buffer = [];

    // Asked first: inside another hook's jump there is no prologue of the program's to check.
    var refusal = hookRefusal(ptr(addrStr), 'trace');
    if (refusal !== null) return { ok: false, error: refusal };

    var prologue = checkPrologue(addrStr);
    if (!prologue.ok) {
        return { ok: false, error: 'prologue too short at ' + addrStr +
            ': need ' + prologue.needed + ' bytes, got ' + prologue.totalBytes +
            ' (' + prologue.insns.map(function (i) { return i.mnemonic + ' ' + i.opStr + ' [' + i.size + 'B]'; }).join(', ') + ')',
            prologue: prologue };
    }

    function isFull() {
        return maxCount > 0 && collected >= maxCount;
    }

    function keep(record) {
        buffer.push(record);
        collected++;
        if (buffer.length >= BATCH_SIZE || isFull()) {
            _flushTraceBuf(id, buffer.splice(0));
        }
        if (isFull()) {
            _autoDetachTrace(id);
        }
    }

    function reportError(phase, e) {
        send({ type: 'trace_error', traceId: id, phase: phase, error: e.message, stack: e.stack || '' });
    }

    var functionHook = {
        onEnter: function (args) {
            try {
                if (isFull()) return;
                if (!evalFilter(filter, this.context)) {
                    this._traceSkip = true;
                    return;
                }
                this._traceSkip = false;
                var regs = snapshotRegs(this.context);
                var reads = evalReadSpecs(enterSpecs, this.context);
                this._traceEnter = { regs: regs, reads: reads };
                this._traceCaller = ptrToHex(this.returnAddress);
                this._traceTs = Date.now();
            } catch (e) {
                reportError('enter', e);
                this._traceSkip = true;
            }
        },
        onLeave: function (retval) {
            try {
                if (this._traceSkip) return;
                if (!this._traceEnter) return;
                if (isFull()) return;

                keep({
                    addr: addrStr,
                    label: label,
                    caller: this._traceCaller,
                    interval: fenceCounter,
                    ts: this._traceTs,
                    enter: this._traceEnter,
                    leave: {
                        eax: ptrToHex(this.context.eax || this.context.rax || ptr(0)),
                        retval: ptrToHex(retval),
                        reads: evalReadSpecs(leaveSpecs, this.context)
                    }
                });
            } catch (e) {
                reportError('leave', e);
            }
        }
    };

    var probe = function () {
        try {
            if (isFull() || !evalFilter(filter, this.context)) return;
            keep({
                addr: addrStr,
                label: label,
                interval: fenceCounter,
                ts: Date.now(),
                enter: {
                    regs: snapshotRegs(this.context),
                    reads: evalReadSpecs(enterSpecs, this.context)
                }
            });
        } catch (e) {
            reportError('probe', e);
        }
    };

    var origFirstByte = ptr(addrStr).readU8();
    var listener;
    try {
        listener = attachHook(ptr(addrStr), 'trace', config.probe ? probe : functionHook);
    } catch (e) {
        return { ok: false, error: 'cannot hook ' + addrStr + ': ' + e.message, prologue: prologue };
    }

    var hookCheck = verifyHook(addrStr, origFirstByte);

    traces[id] = {
        listener: listener, buffer: buffer, addrStr: addrStr,
        maxCount: maxCount, collected: 0, done: false,
        getCollected: function () { return collected; }
    };
    return { ok: true, traceId: id, hookVerified: hookCheck.inlineHooked, hookNote: hookCheck.note, prologue: prologue, hookCheck: hookCheck };
}

function _flushTraceBuf(traceId, samples) {
    if (samples.length === 0) return;
    send({ type: 'trace_batch', traceId: traceId, samples: samples });
}

function _autoDetachTrace(traceId) {
    var t = traces[traceId];
    if (t && !t.done) {
        t.done = true;
        try { t.listener.detach(); } catch (e) {}
        _flushTraceBuf(traceId, t.buffer.splice(0));
        send({ type: 'trace_done', traceId: traceId });
    }
}

function removeTrace(traceId) {
    var t = traces[traceId];
    if (!t) return { ok: false, error: 'no trace ' + traceId };
    if (!t.done) {
        t.done = true;
        try { t.listener.detach(); } catch (e) {}
    }
    _flushTraceBuf(traceId, t.buffer.splice(0));
    delete traces[traceId];
    return { ok: true };
}

function flushTraces(traceId) {
    var t = traces[traceId];
    if (!t) return { ok: false, samples: [], done: true, collected: 0 };
    var samples = t.buffer.splice(0);
    if (samples.length > 0) {
        _flushTraceBuf(traceId, samples);
    }
    return { ok: true, done: t.done, collected: t.getCollected() };
}

// ── fence (interval counter) ──────────────────────────────────────────────

function installFence(addrStr) {
    if (fenceListener) removeFence();
    fenceCounter = 0;
    // A probe: a fence only counts hits, so it may sit on any instruction.
    fenceListener = attachHook(ptr(addrStr), 'fence', function () { fenceCounter++; });
    return { ok: true };
}

function removeFence() {
    if (fenceListener) {
        fenceListener.detach();
        fenceListener = null;
    }
    return { ok: true, lastInterval: fenceCounter };
}

// ── steptrace (Stalker-based) ─────────────────────────────────────────────

var steptraceResult = null;
var steptrace = null;   // { listener, threadId } from install until the result is in or it is cancelled

// Stops a steptrace that has not finished: unhooks it and stops following its thread.
function cancelStepTrace() {
    if (steptrace === null) return { ok: false, error: 'no steptrace running' };
    var running = steptrace;
    steptrace = null;
    running.listener.detach();
    if (running.threadId !== null) {
        Stalker.unfollow(running.threadId);
        Stalker.garbageCollect();
    }
    return { ok: true };
}

function installStepTrace(addrStr, config) {
    var maxInsn = config.maxInsn || 1000;
    var callDepth = config.callDepth || 0;
    var detail = config.detail || 'branches';

    // Stalker runs a copy of the code it follows; a breakpoint's int3 would be
    // copied with it and raise an exception at an address no breakpoint owns.
    if (Object.keys(patches).length > 0) {
        return { ok: false, error: 'steptrace cannot run while a breakpoint is set: ' +
            'the copy of the code it executes would contain the breakpoint. ' +
            'Remove the breakpoints first (bp list, bp del).' };
    }
    if (steptrace !== null) return { ok: false, error: 'a steptrace is already running' };

    steptraceResult = null;

    var targetAddr = ptr(addrStr);
    var targetMod = Process.findModuleByAddress(targetAddr);
    var modBase = targetMod ? targetMod.base : ptr(0);
    var modEnd  = targetMod ? targetMod.base.add(targetMod.size) : ptr(0);

    var traceLog = [];
    var branchLog = [];
    var callLog = [];
    var regSnapshots = [];
    var insnCount = 0;
    var currentDepth = 0;
    var entryRegs = null;
    var session = { listener: null, threadId: null };

    var listener = attachHook(targetAddr, 'steptrace', {
        onEnter: function () {
            if (steptrace !== session || session.threadId !== null) return;
            this.followed = true;

            entryRegs = snapshotRegs(this.context);
            var tid = this.threadId;
            session.threadId = tid;
            var shouldStop = false;

            Stalker.follow(tid, {
                events: { call: true, ret: true, exec: true },
                transform: function (iterator) {
                    var instruction;
                    while ((instruction = iterator.next()) !== null) {
                        if (shouldStop) { iterator.keep(); continue; }

                        var addr = instruction.address;

                        // Skip Frida trampoline / relocated stubs -- only
                        // record instructions that live inside the target module.
                        if (targetMod && (addr.compare(modBase) < 0 || addr.compare(modEnd) >= 0)) {
                            iterator.keep();
                            continue;
                        }

                        insnCount++;
                        traceLog.push(ptrToHex(addr));

                        if (insnCount >= maxInsn) {
                            shouldStop = true;
                            iterator.keep();
                            continue;
                        }

                        var isBranch = instruction.mnemonic.charAt(0) === 'j';
                        var calls = isCall(instruction);
                        var returns = isReturn(instruction);

                        if (calls) {
                            callLog.push({
                                addr: ptrToHex(addr), type: 'call',
                                target: instruction.opStr, depth: currentDepth,
                                skipped: (callDepth >= 0 && currentDepth >= callDepth)
                            });
                            currentDepth++;
                        }

                        if (returns) {
                            currentDepth--;
                            callLog.push({
                                addr: ptrToHex(addr), type: 'ret',
                                depth: currentDepth
                            });
                            if (currentDepth < 0) {
                                shouldStop = true;
                            }
                        }

                        if (isBranch && detail !== 'blocks') {
                            (function (a) {
                                iterator.putCallout(function (context) {
                                    branchLog.push({
                                        addr: a,
                                        regs: snapshotRegs(context)
                                    });
                                });
                            })(ptrToHex(addr));
                        }

                        if (detail === 'full' && (calls || returns)) {
                            (function (a) {
                                iterator.putCallout(function (context) {
                                    regSnapshots.push({
                                        addr: a,
                                        regs: snapshotRegs(context)
                                    });
                                });
                            })(ptrToHex(addr));
                        }

                        iterator.keep();
                    }
                }
            });
        },
        onLeave: function () {
            if (!this.followed || steptrace !== session) return;
            steptrace = null;

            Stalker.unfollow(this.threadId);
            Stalker.flush();
            Stalker.garbageCollect();

            steptraceResult = {
                addr: addrStr,
                entryRegs: entryRegs,
                insnCount: insnCount,
                trace: traceLog,
                branches: branchLog,
                calls: callLog,
                regSnapshots: regSnapshots,
                detail: detail
            };

            send({ type: 'steptrace_done', addr: addrStr, insnCount: insnCount });

            listener.detach();
        }
    });
    session.listener = listener;
    steptrace = session;

    return { ok: true };
}

// ── breakpoints and single-stepping ──────────────────────────────────────
//
// A breakpoint is an int3 byte written over the first byte of an instruction.
// The thread that executes it raises a breakpoint exception, and the handler
// below freezes it there: its registers, its stack and the code around it are
// the program's own. To let the thread continue, the handler puts the original
// byte back and sets the CPU trap flag, so the thread raises a single-step
// exception after that one instruction, and the int3 is written again from
// there. `step` uses the same trap flag to stop after one instruction.
//
// A repeated string instruction (rep movs, rep stos, ...) raises a single-step
// exception after every iteration with the pc left on it, so a trap set on one
// is armed again until the pc moves on: the thread passes the whole
// instruction in one go, at the cost of one exception per iteration.
//
// An exception nobody claims ends the process, so the handler returns true for
// every exception this agent caused, whatever else goes wrong.
//
// Win32 only: the trap flag is set in the CONTEXT record the handler is given,
// and a frozen thread waits on an event object. A thread waiting in
// recv().wait() instead would crash the process when the script is unloaded.
// The Win32 functions are resolved when the first breakpoint is set, so the
// rest of the agent loads in a process that has none.

var INT3 = 0xCC;
var TRAP_FLAG = 0x100;
var EFLAGS_OFFSET = is64 ? 0x44 : 0xC0;
var WAIT_FOREVER = 0xFFFFFFFF;
var THREAD_CONTEXT_ACCESS = 0x1A;    // THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
var SUSPEND_FAILED = 0xFFFFFFFF;
var CONTEXT_FLAGS_OFFSET = is64 ? 0x30 : 0;
var CONTEXT_CONTROL = is64 ? 0x100001 : 0x10001;

var win32 = null;    // the functions below, once a breakpoint was set

function resolveWin32() {
    var kernel32 = Process.getModuleByName('kernel32.dll');
    // A thread suspended while it holds the script lock would never give it back,
    // so the calls made on a suspended thread keep the lock themselves.
    function onSuspendedThread(name, returns, args) {
        return new NativeFunction(kernel32.getExportByName(name), returns, args, { scheduling: 'exclusive' });
    }
    return {
        openThread: new NativeFunction(kernel32.getExportByName('OpenThread'),
            'pointer', ['uint32', 'int', 'uint32']),
        suspendThread: onSuspendedThread('SuspendThread', 'uint32', ['pointer']),
        getThreadContext: onSuspendedThread('GetThreadContext', 'int', ['pointer', 'pointer']),
        setThreadContext: onSuspendedThread('SetThreadContext', 'int', ['pointer', 'pointer']),
        resumeThread: onSuspendedThread('ResumeThread', 'uint32', ['pointer']),
        createEvent: new NativeFunction(kernel32.getExportByName('CreateEventW'),
            'pointer', ['pointer', 'int', 'int', 'pointer']),
        setEvent: new NativeFunction(kernel32.getExportByName('SetEvent'), 'int', ['pointer']),
        closeHandle: new NativeFunction(kernel32.getExportByName('CloseHandle'), 'int', ['pointer']),
        waitForSingleObject: new NativeFunction(kernel32.getExportByName('WaitForSingleObject'),
            'uint32', ['pointer', 'uint32'])
    };
}

// Why no thread of this process can be frozen, or null if one can.
function freezeRefusal() {
    if (Process.platform === 'windows') return null;
    return 'breakpoints and stepping need a Windows process: they are built on Win32 exception ' +
        'handling, and this is a ' + Process.platform + ' process. trace, collect, steptrace ' +
        'and mem work here.';
}

var nextBpId = 1;
var retired = {};         // address -> true where this agent has taken an int3 away
var pendingTraps = {};    // thread id -> what that thread's coming single-step exception is for
var activeStep = null;    // { threadId, mode, target, minSp } while a step spans exceptions
var handlersRunning = 0;
var shuttingDown = false;

var frozen = false;
var frozenCtx = null;
var frozenRawCtx = null;
var frozenThreadId = null;
var frozenAddr = null;
var frozenBpId = null;
var frozenHitCount = 0;
var frozenStepCut = false; // a breakpoint stopped the thread before its step ended
var frozenTicket = null;  // { wake, step }: how the frozen thread is woken and what it does next
var grantedStep = null;   // the ticket of a thread woken with a step it has not started yet

function writeCodeByte(address, value) {
    patchBytes(address, [value]);
}

function addPatch(address) {
    var patch = { address: address, original: address.readU8(), lifted: 0, bp: null, stepTarget: false };
    patches[patchKey(address)] = patch;
    delete retired[patchKey(address)];
    writeCodeByte(address, INT3);
    return patch;
}

function isInstalled(patch) {
    return patches[patchKey(patch.address)] === patch;
}

// Only an int3 is ever replaced, so bytes written there by anything else survive.
function restoreByte(patch) {
    if (patch.address.readU8() === INT3) writeCodeByte(patch.address, patch.original);
}

function removePatch(patch) {
    delete patches[patchKey(patch.address)];
    retired[patchKey(patch.address)] = true;
    if (patch.lifted === 0) restoreByte(patch);
}

// A thread stopped on a patch needs the original instruction there. The int3
// goes back once every such thread has stepped past it.
function lift(patch) {
    if (patch.lifted++ === 0) restoreByte(patch);
}

function lower(patch) {
    patch.lifted--;
    if (patch.lifted > 0 || !isInstalled(patch)) return;
    var current = patch.address.readU8();
    if (current === INT3) return;
    patch.original = current;
    writeCodeByte(patch.address, INT3);
}

function breakpointRefusal(address) {
    var unsupported = freezeRefusal();
    if (unsupported !== null) return unsupported;
    if (steptrace !== null) {
        return 'a steptrace is running, and the copy of the code it executes cannot carry a ' +
            'breakpoint. Wait for it to finish.';
    }
    var refusal = rewriteRefusal(address, 1, 'breakpoint', false);
    if (refusal !== null) return refusal;
    if (address.readU8() === INT3) {
        return 'the byte at this address is already an int3: padding between functions, or a ' +
            'breakpoint built into the program.';
    }
    return null;
}

function installBp(addrStr) {
    var address = ptr(addrStr);
    var patch = patches[patchKey(address)];
    if (patch && patch.bp !== null) {
        return { ok: true, id: patch.bp.id, msg: 'already set' };
    }
    if (!patch) {
        var refusal = breakpointRefusal(address);
        if (refusal !== null) return { ok: false, error: refusal };
        if (win32 === null) win32 = resolveWin32();
        patch = addPatch(address);
    }
    patch.bp = { id: nextBpId++, addr: addrStr, hitCount: 0 };
    return { ok: true, id: patch.bp.id };
}

// A thread frozen at the breakpoint is released with it.
function removeBp(addrStr) {
    var patch = patches[patchKey(addrStr)];
    if (!patch || patch.bp === null) return { ok: false, error: 'no bp at ' + addrStr };
    patch.bp = null;
    if (!patch.stepTarget) removePatch(patch);
    if (frozen && ptr(frozenAddr).equals(patch.address)) unfreeze(null);
    return { ok: true };
}

function listBps() {
    var result = [];
    for (var key in patches) {
        var bp = patches[key].bp;
        if (bp !== null) result.push({ addr: bp.addr, id: bp.id, hitCount: bp.hitCount });
    }
    return result;
}

// Blocks the calling thread inside the exception handler until unfreeze() sets
// `wake`. Returns the step mode the thread is to continue with, or null to run.
function freeze(details, threadId, patch, wake, stepCut) {
    var ticket = { wake: wake, step: null };
    var bp = patch !== null ? patch.bp : null;
    frozen = true;
    frozenTicket = ticket;
    frozenRawCtx = details.context;
    frozenThreadId = threadId;
    frozenAddr = '0x' + ptrToHex(details.context.pc);
    frozenBpId = bp !== null ? bp.id : 0;
    frozenHitCount = bp !== null ? bp.hitCount : 0;
    frozenStepCut = stepCut;
    frozenCtx = snapshotRegs(details.context);
    send({
        type: 'bp_hit', addr: frozenAddr, bpId: frozenBpId,
        hitCount: frozenHitCount, regs: frozenCtx
    });
    win32.waitForSingleObject(ticket.wake, WAIT_FOREVER);
    if (grantedStep === ticket) grantedStep = null;
    return ticket.step;
}

function unfreeze(step) {
    if (!frozen) return false;
    var ticket = frozenTicket;
    ticket.step = step || null;
    frozen = false;
    frozenTicket = null;
    frozenCtx = null;
    frozenRawCtx = null;
    frozenThreadId = null;
    frozenAddr = null;
    frozenBpId = null;
    frozenHitCount = 0;
    frozenStepCut = false;
    if (ticket.step !== null) grantedStep = ticket;
    win32.setEvent(ticket.wake);
    return true;
}

function setTrapFlag(nativeContext) {
    var flags = nativeContext.add(EFLAGS_OFFSET);
    flags.writeU32(flags.readU32() | TRAP_FLAG);
}

function clearTrapFlag(nativeContext) {
    var flags = nativeContext.add(EFLAGS_OFFSET);
    flags.writeU32(flags.readU32() & ~TRAP_FLAG);
}

// A pushf stepped with the trap flag set pushed the flag too; the program must not see it.
function clearPushedTrapFlag(sp) {
    sp.writeU16(sp.readU16() & ~TRAP_FLAG);
}

// Ends the step of the thread now running it, and tells the daemon why.
function failStep(reason) {
    endStep();
    send({ type: 'step_failed', error: reason });
}

// While a step runs a call to its end, an int3 waits on the instruction after it.
// Returns why it cannot be placed there, or null once it is.
function setStepTarget(step, address, sp) {
    var patch = patches[patchKey(address)];
    if (!patch) {
        var refusal = rewriteRefusal(address, 1, 'step', false);
        if (refusal !== null) return refusal;
        if (address.readU8() === INT3) {
            return 'the byte there is an int3 the program put there, so no breakpoint can be set on it.';
        }
        patch = addPatch(address);
    }
    patch.stepTarget = true;
    step.target = patch;
    step.minSp = sp;
    return null;
}

function clearStepTarget(step) {
    var patch = step.target;
    step.target = null;
    patch.stepTarget = false;
    if (patch.bp === null) removePatch(patch);
}

function endStep() {
    if (activeStep === null) return;
    if (activeStep.target !== null) clearStepTarget(activeStep);
    activeStep = null;
}

// Give up a step that has not ended, or that its thread has not started: the
// thread runs on and does not freeze.
function cancelStep() {
    endStep();
    for (var threadId in pendingTraps) pendingTraps[threadId].stop = false;
    if (grantedStep !== null) grantedStep.step = null;
    grantedStep = null;
}

// The thread has stopped at details.context.pc: on `patch` if one is there,
// after the single-step described by `pending` if it had asked for one. If it
// is to freeze, it waits on `wake`.
function arrive(details, threadId, patch, pending, wake) {
    if (patch !== null) {
        lift(patch);
        if (patch.bp !== null) patch.bp.hitCount++;
    }

    var step = (activeStep !== null && activeStep.threadId === threadId) ? activeStep : null;
    var stepEnds = pending !== null && pending.stop;
    var stop = (patch !== null && patch.bp !== null) || stepEnds;
    var mode = null;
    if (step !== null) {
        // Running a call to its end: only the instruction after it, back in
        // the caller's frame, ends the wait. A deeper frame is recursion.
        var callReturned = step.target !== null && patch === step.target &&
            details.context.sp.compare(step.minSp) >= 0;
        if (callReturned && step.mode === 'over') stepEnds = true;
        if (!stop) {
            if (callReturned) {
                clearStepTarget(step);
                if (step.mode === 'over') stop = true;
                else mode = 'out';
            } else if (step.target === null && pending !== null) {
                mode = step.mode;
            }
        }
    }

    if (stop) {
        // Only one thread is frozen at a time; a thread that cannot freeze runs on.
        if (!frozen && !shuttingDown) {
            // The step in progress, on whichever thread, ends here: its thread runs on.
            cancelStep();
            mode = freeze(details, threadId, patch, wake, step !== null && !stepEnds);
        } else {
            if (step !== null) endStep();
            mode = null;
        }
    }
    depart(details, threadId, patch, mode);
}

// Send the thread on from an exception: past `lifted` if it stopped on a
// patch, and for one more leg of a step if `mode` names one.
function depart(details, threadId, lifted, mode) {
    if (lifted !== null && !isInstalled(lifted)) lifted = null;
    if (lifted === null && mode === null) return;
    var pc = details.context.pc;
    var insn = Instruction.parse(pc);
    var repeated = /^rep/.test(insn.mnemonic) && !isReturn(insn);
    var pending = {
        lower: lifted, stop: false, from: pc, repeated: repeated,
        pushesFlags: insn.mnemonic.indexOf('pushf') === 0
    };
    var trap = lifted !== null;
    if (mode !== null) {
        var runsToNext = isCall(insn) || repeated;
        var lastInstruction = mode === 'into' || (mode === 'over' && !runsToNext) ||
            (mode === 'out' && isReturn(insn));
        if (lastInstruction) {
            pending.stop = true;
            trap = true;
        } else {
            if (activeStep === null) {
                activeStep = { threadId: threadId, mode: mode, target: null, minSp: null };
            }
            if (!runsToNext) {
                trap = true;
            } else {
                var refusal = setStepTarget(activeStep, insn.next, details.context.sp);
                if (refusal !== null) {
                    failStep('the step cannot wait for the ' + insn.mnemonic + ' at 0x' + ptrToHex(pc) +
                        ' to finish at 0x' + ptrToHex(insn.next) + ': ' + refusal + ' The thread is ' +
                        'running. Set a breakpoint further on and wait with watch.');
                }
            }
        }
    }
    if (trap) {
        pendingTraps[threadId] = pending;
        setTrapFlag(details.nativeContext);
    }
}

// Handles an exception of this agent's: the thread's pending single-step, if
// `pending` is not null, and its arrival at details.context.pc.
//
// A native call lets other threads and the daemon's commands into this script,
// where they delete breakpoints, give up steps and freeze threads. The event a
// stop would wait on is therefore made first, and the stop is decided from what
// is found afterwards: no native call is made between that decision and
// freeze() taking `frozen`, nor between a thread waking and its departure.
function handle(details, threadId, pending) {
    handlersRunning++;
    try {
        var key = patchKey(details.context.pc);
        var mayStop = patches[key] !== undefined || (pending !== null && pending.stop);
        var wake = mayStop ? win32.createEvent(NULL, 0, 0, NULL) : null;
        if (pending !== null) {
            delete pendingTraps[threadId];
            if (pending.pushesFlags) clearPushedTrapFlag(details.context.sp);
            if (pending.lower !== null) lower(pending.lower);
        }
        arrive(details, threadId, patches[key] || null, pending, wake);
        if (wake !== null) win32.closeHandle(wake);
    } catch (e) {
        send({ type: 'agent_error', where: 'breakpoint handler', error: e.message, stack: e.stack || '' });
    }
    handlersRunning--;
    return true;
}

function onBreakpoint(details, threadId) {
    var pc = details.context.pc;
    if (patches[patchKey(pc)] !== undefined) return handle(details, threadId, null);
    // An int3 this agent took away while the exception was on its way: the
    // instruction back in its place runs. Every other int3 is the program's.
    return retired[patchKey(pc)] === true && pc.readU8() !== INT3;
}

function onSingleStep(details, threadId) {
    var pending = pendingTraps[threadId] || null;
    if (pending === null) return false;
    var pc = details.context.pc;
    // Once the agent is unloading, the rest of the instruction runs untrapped:
    // a trap flag still set after the unload raises an exception nobody claims.
    // So does it once the trap has nothing left to do: its step was cancelled
    // and no int3 waits to go back.
    var trapNeeded = pending.stop || pending.lower !== null;
    if (pending.repeated && pc.equals(pending.from) && !shuttingDown && trapNeeded) {
        setTrapFlag(details.nativeContext);
        return true;
    }
    return handle(details, threadId, pending);
}

// The instruction a thread was sent past raised an exception of its own, which
// is the program's to handle. The thread will not raise the single-step
// exception it was given the trap flag for, so that trap is taken back.
function abandonTrap(details, threadId) {
    var pending = pendingTraps[threadId] || null;
    if (pending === null) return;
    delete pendingTraps[threadId];
    clearTrapFlag(details.nativeContext);
    if (pending.lower !== null) lower(pending.lower);
    if (pending.stop || (activeStep !== null && activeStep.threadId === threadId)) {
        failStep('the instruction at 0x' + ptrToHex(pending.from) + ' raised a ' + details.type +
            ' exception, which the program handles. The step ended there and the thread is running.');
    }
}

Process.setExceptionHandler(function (details) {
    var threadId = Process.getCurrentThreadId();
    if (details.type === 'breakpoint') return onBreakpoint(details, threadId);
    if (details.type === 'single-step') return onSingleStep(details, threadId);
    try {
        abandonTrap(details, threadId);
    } catch (e) {
        send({ type: 'agent_error', where: 'exception handler', error: e.message, stack: e.stack || '' });
    }
    return false;
});

// Takes back the trap flag a thread was given, and returns whether its
// single-step exception is coming all the same. The flag stays in the thread's
// registers for as long as the instruction has not finished, which a system
// call that blocks may take any time over; a thread that shows no flag has
// raised the exception, or has not left the handler's return yet. A thread
// whose registers cannot be reached is given up. `context` is memory for a CONTEXT.
function withdrawTrap(threadId, context) {
    var thread = win32.openThread(THREAD_CONTEXT_ACCESS, 0, threadId);
    if (thread.isNull()) return false;
    var coming = false;
    if (win32.suspendThread(thread) !== SUSPEND_FAILED) {
        context.add(CONTEXT_FLAGS_OFFSET).writeU32(CONTEXT_CONTROL);
        if (win32.getThreadContext(thread, context) !== 0) {
            coming = (context.add(EFLAGS_OFFSET).readU32() & TRAP_FLAG) === 0;
            if (!coming) {
                clearTrapFlag(context);
                win32.setThreadContext(thread, context);
            }
        }
        win32.resumeThread(thread);
    }
    win32.closeHandle(thread);
    return coming;
}

// Returns whether a thread is left whose single-step exception is still to come.
function withdrawPendingTraps(context) {
    Object.keys(pendingTraps).forEach(function (threadId) {
        if (!withdrawTrap(parseInt(threadId, 10), context)) delete pendingTraps[threadId];
    });
    for (var left in pendingTraps) return true;
    return false;
}

// Runs when the script is unloaded, which includes the daemon going away.
// Afterwards no int3 or jump of this agent's is left in the target, no thread
// is frozen and none has a trap flag of this agent's. Frida removes the
// Interceptor hooks itself.
function shutdown() {
    shuttingDown = true;
    removeVisOverride();
    endStep();
    Object.keys(patches).forEach(function (key) { removePatch(patches[key]); });
    unfreeze(null);
    // A thread in the handler, or with its single-step exception on the way to
    // it, needs the handler to be there, and runs while this thread sleeps. A
    // thread between the handler and its instruction shows no trap flag yet,
    // so the flags are looked for again after every wait.
    var context = Memory.alloc(Process.pageSize);
    while (withdrawPendingTraps(context) || handlersRunning > 0) Thread.sleep(0.01);
}

// ── visibility override (code cave) ──────────────────────────────────────
//
// Patches a jmp-trampoline to route through a code cave that selectively
// forces "fully visible" for callers above a threshold address while
// letting callers below the threshold run the original function.

var visOverride = null;   // { cave, origBytes, stats, jmpSite, release }
var VIS_JMP_BYTES = 5;

function installVisOverride(thresholdHex, jmpSiteHex, origTargetHex) {
    if (visOverride) return { ok: false, error: 'already installed' };
    if (is64) return { ok: false, error: 'vishook builds 32-bit code; this process is 64-bit' };

    var threshold = parseInt(thresholdHex, 16);
    var jmpSite = ptr(jmpSiteHex);
    var origTarget = ptr(origTargetHex);

    var refusal = rewriteRefusal(jmpSite, VIS_JMP_BYTES, 'vishook', false);
    if (refusal !== null) return { ok: false, error: refusal };

    var origBytes = new Uint8Array(jmpSite.readByteArray(VIS_JMP_BYTES));

    // Allocate code cave (64 bytes code + 8 bytes counters)
    var cave = Memory.alloc(72);
    Memory.protect(cave, 72, 'rwx');

    // Stats: cave+64 = override count (u32), cave+68 = passthrough count (u32)
    var statsPtr = cave.add(64);
    statsPtr.writeU32(0);
    statsPtr.add(4).writeU32(0);

    // Build x86 trampoline
    //
    // Expected calling convention: __thiscall, ecx=this
    //   [esp+0]  = return address
    //   [esp+4]  = arg1 (position ptr)
    //   [esp+8]  = arg2 (int output ptr, often NULL)
    //   [esp+C]  = arg3 (vec3 output ptr, often NULL)
    //   [esp+10] = arg4 (byte output ptr, often NULL)
    //   Returns: float on st(0), ret 0x10
    //
    // Trampoline layout:
    //   0: mov eax, [esp]           ; 8B 04 24
    //   3: cmp eax, <threshold>     ; 3D xx xx xx xx
    //   8: jb call_original         ; 72 20  (jump to offset 42)
    //  10: mov eax, [esp+0x10]      ; 8B 44 24 10
    //  14: test eax, eax            ; 85 C0
    //  16: jz skip_byte             ; 74 03
    //  18: mov byte [eax], 1        ; C6 00 01
    //  21: push 0x47C80000          ; 68 00 00 C8 47  (102400.0f)
    //  26: fld dword [esp]          ; D9 04 24
    //  29: add esp, 4               ; 83 C4 04
    //  32: lock inc dword [statsA]  ; F0 FF 05 xx xx xx xx
    //  39: ret 0x10                 ; C2 10 00
    //  42: (call_original)
    //  42: lock inc dword [statsB]  ; F0 FF 05 xx xx xx xx
    //  49: jmp origTarget            ; E9 xx xx xx xx

    var code = new Uint8Array(54);
    var dv = new DataView(code.buffer);

    // mov eax, [esp]
    code[0] = 0x8B; code[1] = 0x04; code[2] = 0x24;
    // cmp eax, threshold
    code[3] = 0x3D;
    dv.setUint32(4, threshold, true);
    // jb call_original (offset 42 - 10 = 32 = 0x20)
    code[8] = 0x72; code[9] = 0x20;
    // mov eax, [esp+0x10]
    code[10] = 0x8B; code[11] = 0x44; code[12] = 0x24; code[13] = 0x10;
    // test eax, eax
    code[14] = 0x85; code[15] = 0xC0;
    // jz skip_byte (+3)
    code[16] = 0x74; code[17] = 0x03;
    // mov byte [eax], 1
    code[18] = 0xC6; code[19] = 0x00; code[20] = 0x01;
    // push 0x47C80000 (102400.0f)
    code[21] = 0x68; code[22] = 0x00; code[23] = 0x00; code[24] = 0xC8; code[25] = 0x47;
    // fld dword [esp]
    code[26] = 0xD9; code[27] = 0x04; code[28] = 0x24;
    // add esp, 4
    code[29] = 0x83; code[30] = 0xC4; code[31] = 0x04;
    // lock inc dword [statsPtr]  (override counter at cave+64)
    code[32] = 0xF0; code[33] = 0xFF; code[34] = 0x05;
    dv.setUint32(35, statsPtr.toInt32() >>> 0, true);
    // ret 0x10
    code[39] = 0xC2; code[40] = 0x10; code[41] = 0x00;
    // call_original: lock inc dword [statsPtr+4] (passthrough counter)
    code[42] = 0xF0; code[43] = 0xFF; code[44] = 0x05;
    dv.setUint32(45, statsPtr.add(4).toInt32() >>> 0, true);
    // jmp origTarget (relative)
    code[49] = 0xE9;
    var jmpFrom = cave.add(54);
    var rel = origTarget.sub(jmpFrom).toInt32();
    dv.setInt32(50, rel, true);

    // Write code cave
    cave.writeByteArray(code.buffer);

    // Patch jmp site: E9 <rel32 to cave>
    var patchBuf = new Uint8Array(5);
    var patchDv = new DataView(patchBuf.buffer);
    patchBuf[0] = 0xE9;
    patchDv.setInt32(1, cave.sub(jmpSite.add(5)).toInt32(), true);
    patchBytes(jmpSite, Array.from(patchBuf));

    visOverride = {
        cave: cave, origBytes: origBytes, stats: statsPtr, jmpSite: jmpSite,
        release: recordHook(jmpSite, VIS_JMP_BYTES, 'vishook', false, origBytes)
    };
    return { ok: true, cave: ptrToHex(cave), threshold: threshold };
}

function removeVisOverride() {
    if (!visOverride) return { ok: false, error: 'not installed' };
    patchBytes(visOverride.jmpSite, Array.from(visOverride.origBytes));
    visOverride.release();
    visOverride = null;
    return { ok: true };
}

function getVisStats() {
    if (!visOverride) return { installed: false };
    return {
        installed: true,
        overrideCount: visOverride.stats.readU32(),
        passthroughCount: visOverride.stats.add(4).readU32()
    };
}

// ── DIP counter (DrawIndexedPrimitive Interceptor hook) ──────────────────
//
// Hooks DrawIndexedPrimitive via Frida Interceptor on the resolved function
// address (read from D3D9 device vtable at a known global pointer).

var dipHook = null;  // { listener: InvocationListener, counter: NativePointer }

function installDipCounter(devPtrAddr) {
    if (dipHook) return { ok: false, error: 'already installed' };

    var devPtrPtr = ptr(devPtrAddr);
    var devPtr;
    try { devPtr = devPtrPtr.readPointer(); } catch (e) {
        return { ok: false, error: 'cannot read device pointer: ' + e.message };
    }
    if (devPtr.isNull()) return { ok: false, error: 'D3D9 device is NULL' };

    var vtable = devPtr.readPointer();
    var dipAddr = vtable.add(0x148).readPointer();

    var counter = Memory.alloc(8);
    counter.writeU32(0);
    counter.add(4).writeU32(0);

    var cPtr = counter;
    var listener = attachHook(dipAddr, 'dipcnt', {
        onEnter: function () {
            cPtr.writeU32((cPtr.readU32() + 1) >>> 0);
        }
    });

    dipHook = { listener: listener, counter: counter, addr: dipAddr };
    return { ok: true, dipAddr: ptrToHex(dipAddr) };
}

function removeDipCounter() {
    if (!dipHook) return { ok: false, error: 'not installed' };
    dipHook.listener.detach();
    dipHook = null;
    return { ok: true };
}

function sampleDipCallers(count) {
    if (!dipHook) return { ok: false, error: 'dipcnt not installed' };
    var n = count || 200;
    var callers = {};
    var remaining = n;
    var dipAddr = dipHook.addr;

    var sampler = attachHook(ptr(dipAddr), 'dipcnt', {
        onEnter: function () {
            if (remaining <= 0) return;
            remaining--;
            var ret = this.returnAddress;
            var key = ptrToHex(ret);
            callers[key] = (callers[key] || 0) + 1;
            if (remaining <= 0) {
                sampler.detach();
            }
        }
    });

    // Spin-wait up to 2 seconds for samples
    var deadline = Date.now() + 2000;
    while (remaining > 0 && Date.now() < deadline) {
        Thread.sleep(0.01);
    }
    if (remaining > 0) sampler.detach();

    var result = [];
    for (var k in callers) {
        result.push({ addr: k, count: callers[k] });
    }
    result.sort(function (a, b) { return b.count - a.count; });
    return { ok: true, sampled: n - remaining, callers: result };
}

function getDipCount() {
    if (!dipHook) return { installed: false };
    var total = dipHook.counter.readU32();
    var prev = dipHook.counter.add(4).readU32();
    dipHook.counter.add(4).writeU32(total);
    return { installed: true, total: total, delta: (total - prev) >>> 0 };
}

// ── memory write watchpoint ───────────────────────────────────────────────

var memWatch = null;

function watchMemWrite(addrStr, size, maxHits) {
    if (memWatch) stopMemWatch();

    var target = ptr(addrStr);
    var hits = [];
    var hitCount = 0;
    var stopped = false;

    memWatch = { target: target, size: size, hits: hits, maxHits: maxHits };

    try {
        MemoryAccessMonitor.enable([
            { base: target, size: size }
        ], {
            onAccess: function (details) {
                if (stopped) return;
                hitCount++;
                var entry = {
                    addr: ptrToHex(details.address),
                    from: ptrToHex(details.from),
                    operation: details.operation,
                    rangeIndex: details.rangeIndex
                };
                try {
                    var bt = Thread.backtrace(details.nativeContext, Backtracer.FUZZY);
                    entry.backtrace = bt.map(function (a) { return ptrToHex(a); });
                } catch (e) {
                    entry.backtrace = [];
                }
                hits.push(entry);
                if (hitCount >= maxHits) {
                    stopped = true;
                    MemoryAccessMonitor.disable();
                }
            }
        });
        return { ok: true, watching: addrStr, size: size, maxHits: maxHits };
    } catch (e) {
        memWatch = null;
        return { ok: false, error: e.message };
    }
}

function stopMemWatch() {
    if (!memWatch) return { ok: false, error: "no active watch" };
    try { MemoryAccessMonitor.disable(); } catch (e) {}
    var result = { ok: true, hits: memWatch.hits.length };
    memWatch = null;
    return result;
}

function getMemWatchHits() {
    if (!memWatch) return { ok: false, hits: [], error: "no active watch" };
    return { ok: true, hits: memWatch.hits };
}

// ── rpc exports ───────────────────────────────────────────────────────────

rpc.exports = {

    // breakpoint management
    installBp: function (a) { return installBp(a); },
    removeBp: function (a) { return removeBp(a); },
    listBps: function () { return listBps(); },

    // Called by Frida when the script is unloaded.
    dispose: function () { shutdown(); },

    // frozen state
    unfreeze: function (step) { return unfreeze(step); },
    cancelStep: function () { cancelStep(); },
    freezeRefusal: function () { return freezeRefusal(); },
    isFrozen: function () { return frozen; },
    getFrozenAddr: function () { return frozenAddr; },
    getFrozenBpId: function () { return frozenBpId; },

    getRegisters: function () { return frozenCtx || null; },

    getSnapshot: function (stackCount, disasmCount) {
        if (!frozenCtx) return null;
        stackCount = stackCount || 8;
        disasmCount = disasmCount || 8;
        var spKey = is64 ? 'rsp' : 'esp';
        var ipKey = is64 ? 'rip' : 'eip';
        var slotSize = Process.pointerSize;
        var espVal = ptr('0x' + frozenCtx[spKey]);
        var eipVal = ptr('0x' + frozenCtx[ipKey]);

        var stackEntries = [];
        for (var i = 0; i < stackCount; i++) {
            try { stackEntries.push(ptrToHex(espVal.add(i * slotSize).readPointer())); }
            catch (e) { stackEntries.push(is64 ? '????????????????' : '????????'); }
        }
        var disasmLines = [];
        var cursor = eipVal;
        for (var j = 0; j < disasmCount; j++) {
            try {
                var insn = Instruction.parse(cursor);
                disasmLines.push({
                    addr: ptrToHex(cursor), mnemonic: insn.mnemonic,
                    opStr: insn.opStr, size: insn.size, str: insn.toString()
                });
                cursor = cursor.add(insn.size);
            } catch (e) {
                disasmLines.push({ addr: ptrToHex(cursor), mnemonic: '??', opStr: '', size: 0, str: '??' });
                break;
            }
        }
        return {
            regs: frozenCtx, threadId: frozenThreadId, bpId: frozenBpId, hitCount: frozenHitCount,
            addr: frozenAddr, stepCut: frozenStepCut, stack: stackEntries, disasm: disasmLines
        };
    },

    // memory operations
    readMemory: function (addrStr, size) {
        try { return ptr(addrStr).readByteArray(size); }
        catch (e) { return null; }
    },
    // Refused over a breakpoint or a hook: either would later restore the
    // bytes it saved and undo the write, or run on in bytes it no longer owns.
    writeMemory: function (addrStr, hexStr) {
        try {
            var bytes = hexToBytes(hexStr);
            var refusal = rewriteRefusal(ptr(addrStr), bytes.length, 'mem write', false);
            if (refusal !== null) return { ok: false, error: refusal };
            patchBytes(ptr(addrStr), bytes);
            return { ok: true };
        } catch (e) { return { ok: false, error: e.message }; }
    },
    allocMemory: function (size) {
        try {
            var p = Memory.alloc(size);
            Memory.protect(p, size, 'rwx');
            _allocations.push(p);
            return { ok: true, addr: ptrToHex(p) };
        } catch (e) { return { ok: false, error: e.message }; }
    },

    // disassembly
    disasmAt: function (addrStr, count) {
        count = count || 16;
        var lines = [], cursor = ptr(addrStr);
        for (var i = 0; i < count; i++) {
            try {
                var insn = Instruction.parse(cursor);
                lines.push({ addr: ptrToHex(cursor), mnemonic: insn.mnemonic,
                             opStr: insn.opStr, size: insn.size, str: insn.toString() });
                cursor = cursor.add(insn.size);
            } catch (e) {
                lines.push({ addr: ptrToHex(cursor), mnemonic: '??', opStr: '', size: 0, str: '??' });
                break;
            }
        }
        return lines;
    },

    // backtrace
    backtrace: function () {
        if (!frozenRawCtx) return [];
        try {
            return Thread.backtrace(frozenRawCtx, Backtracer.FUZZY)
                         .map(function (a) { return ptrToHex(a); });
        } catch (e) { return []; }
    },

    // memory scan
    scanSync: function (startStr, size, patternStr) {
        try {
            return Memory.scanSync(ptr(startStr), size, patternStr)
                         .map(function (m) { return { addr: ptrToHex(m.address), size: m.size }; });
        } catch (e) { return []; }
    },

    // stack read
    readStack: function (count) {
        if (!frozenCtx) return [];
        count = count || 16;
        var spKey = is64 ? 'rsp' : 'esp';
        var espVal = ptr('0x' + frozenCtx[spKey]);
        var slotSize = Process.pointerSize;
        var entries = [];
        for (var i = 0; i < count; i++) {
            try { entries.push(ptrToHex(espVal.add(i * slotSize).readPointer())); }
            catch (e) { entries.push(is64 ? '????????????????' : '????????'); }
        }
        return entries;
    },

    // tracing
    originalInstruction: function (addrStr) { return originalInstruction(ptr(addrStr)); },
    installTrace: function (addrStr, config) { return installTrace(addrStr, config); },
    removeTrace: function (traceId) { return removeTrace(traceId); },
    flushTraces: function (traceId) { return flushTraces(traceId); },
    checkPrologue: function (addrStr) { return checkPrologue(addrStr); },

    // steptrace
    installStepTrace: function (addrStr, config) { return installStepTrace(addrStr, config); },
    getStepTraceResult: function () { return steptraceResult; },
    cancelStepTrace: function () { return cancelStepTrace(); },

    // fence
    installFence: function (addrStr) { return installFence(addrStr); },
    removeFence: function () { return removeFence(); },
    getFenceCounter: function () { return fenceCounter; },

    // modules
    enumerateModules: function () {
        return Process.enumerateModules().map(function (m) {
            return { name: m.name, base: ptrToHex(m.base), size: m.size, path: m.path };
        });
    },

    // ── visibility override ──
    installVisOverride: function (thresholdHex, jmpSiteHex, origTargetHex) {
        return installVisOverride(thresholdHex, jmpSiteHex, origTargetHex);
    },
    removeVisOverride: function () { return removeVisOverride(); },
    getVisStats: function () { return getVisStats(); },

    // ── DIP counter (vtable hook) ──
    installDipCounter: function (devPtrAddr) { return installDipCounter(devPtrAddr); },
    removeDipCounter: function () { return removeDipCounter(); },
    getDipCount: function () { return getDipCount(); },
    sampleDipCallers: function (count) { return sampleDipCallers(count); },

    // memory access watch
    watchMemWrite: function (addrStr, size, maxHits) {
        return watchMemWrite(addrStr, size || 4, maxHits || 20);
    },
    stopMemWatch: function () { return stopMemWatch(); },
    getMemWatchHits: function () { return getMemWatchHits(); }
};
