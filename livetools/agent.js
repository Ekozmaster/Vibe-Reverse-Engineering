'use strict';

// ---------------------------------------------------------------------------
// Frida JS agent -- injected into the target process by the livetools daemon.
//
// Provides:
//   - Blocking breakpoints (existing)
//   - Non-blocking trace hooks with read-spec evaluation (new)
//   - Stalker-based instruction-level execution tracing (new)
//   - Interval fence counter (new)
//   - Module enumeration (new)
//   - Memory I/O, disassembly, register snapshots (existing)
// ---------------------------------------------------------------------------

var breakpoints = {};
var nextBpId = 1;
var frozen = false;
var frozenCtx = null;
var frozenRawCtx = null;
var frozenThreadId = null;
var frozenAddr = null;
var frozenBpId = null;

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
//   "[entry.r8]:4:uint32"   -> leave specs only: the register's value at ENTRY,
//                              memory read at LEAVE -- how an out-parameter is read,
//                              since the register itself is clobbered by then

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

    var m = work.match(/^\[((?:entry\.)?\w+)(?:\s*\+\s*(0x[\da-fA-F]+|\d+))?\]\s*(?::(\d+))?(?::(\w+))?$/);
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

// entryRegs: the snapshotRegs() taken at entry, which "entry.<reg>" names resolve against.
function evalReadSpecs(specs, ctx, entryRegs) {
    var results = [];
    for (var i = 0; i < specs.length; i++) {
        results.push(evalOneSpec(specs[i], ctx, entryRegs));
    }
    return results;
}

function specRegVal(ctx, name, entryRegs) {
    if (name.indexOf('entry.') !== 0) return getRegVal(ctx, name);
    if (!entryRegs) throw new Error(name + ' is only valid in a leave spec');
    var reg = name.substring(6);
    if (reg === 'pc') reg = is64 ? 'rip' : 'eip';
    var hex = entryRegs[reg];
    if (hex === undefined) throw new Error('no entry register ' + reg);
    return ptr('0x' + hex);
}

function evalOneSpec(spec, ctx, entryRegs) {
    try {
        if (spec.kind === 'reg') {
            return { spec: spec.raw, value: ptrToHex(specRegVal(ctx, spec.name, entryRegs)) };
        }
        if (spec.kind === 'st0') {
            return { spec: spec.raw, value: null };
        }
        var baseVal = specRegVal(ctx, spec.base, entryRegs);
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

    var prologue = checkPrologue(addrStr);
    if (!prologue.ok) {
        return { ok: false, error: 'prologue too short at ' + addrStr +
            ': need ' + prologue.needed + ' bytes, got ' + prologue.totalBytes +
            ' (' + prologue.insns.map(function (i) { return i.mnemonic + ' ' + i.opStr + ' [' + i.size + 'B]'; }).join(', ') + ')',
            prologue: prologue };
    }

    var origFirstByte = ptr(addrStr).readU8();
    var listener;
    try {
        listener = Interceptor.attach(ptr(addrStr), {
            onEnter: function (args) {
                try {
                    if (maxCount > 0 && collected >= maxCount) return;
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
                    send({ type: 'trace_error', traceId: id, phase: 'enter', error: e.message, stack: e.stack || '' });
                    this._traceSkip = true;
                }
            },
            onLeave: function (retval) {
                try {
                    if (this._traceSkip) return;
                    if (!this._traceEnter) return;
                    if (maxCount > 0 && collected >= maxCount) return;

                    var leaveData = {
                        eax: ptrToHex(this.context.eax || this.context.rax || ptr(0)),
                        retval: ptrToHex(retval),
                        reads: evalReadSpecs(leaveSpecs, this.context, this._traceEnter.regs)
                    };

                    var record = {
                        addr: addrStr,
                        label: label,
                        caller: this._traceCaller,
                        interval: fenceCounter,
                        ts: this._traceTs,
                        enter: this._traceEnter,
                        leave: leaveData
                    };

                    buffer.push(record);
                    collected++;

                    if (buffer.length >= BATCH_SIZE || (maxCount > 0 && collected >= maxCount)) {
                        _flushTraceBuf(id, buffer.splice(0));
                    }
                    if (maxCount > 0 && collected >= maxCount) {
                        _autoDetachTrace(id);
                    }
                } catch (e) {
                    send({ type: 'trace_error', traceId: id, phase: 'leave', error: e.message, stack: e.stack || '' });
                }
            }
        });
    } catch (e) {
        return { ok: false, error: 'Interceptor.attach failed at ' + addrStr + ': ' + e.message, prologue: prologue };
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
    if (!t) return { ok: false, msg: 'no trace ' + traceId };
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
    fenceListener = Interceptor.attach(ptr(addrStr), {
        onEnter: function () { fenceCounter++; }
    });
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
var steptraceActive = false;

function installStepTrace(addrStr, config) {
    var maxInsn = config.maxInsn || 1000;
    var callDepth = config.callDepth || 0;
    var detail = config.detail || 'branches';

    steptraceResult = null;
    steptraceActive = true;

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
    var traced = false;

    var listener = Interceptor.attach(targetAddr, {
        onEnter: function () {
            if (traced || !steptraceActive) return;
            traced = true;

            entryRegs = snapshotRegs(this.context);
            var tid = this.threadId;
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

                        var mn = instruction.mnemonic;
                        var isBranch = (mn.charAt(0) === 'j');
                        var isCall = (mn === 'call');
                        var isRet = (mn === 'ret' || mn === 'retn');

                        if (isCall) {
                            callLog.push({
                                addr: ptrToHex(addr), type: 'call',
                                target: instruction.opStr, depth: currentDepth,
                                skipped: (callDepth >= 0 && currentDepth >= callDepth)
                            });
                            currentDepth++;
                        }

                        if (isRet) {
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

                        if (detail === 'full' && (isCall || isRet)) {
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
            if (!traced) return;

            var tid = this.threadId;
            Stalker.unfollow(tid);
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
            steptraceActive = false;

            send({ type: 'steptrace_done', addr: addrStr, insnCount: insnCount });

            listener.detach();
        }
    });

    return { ok: true };
}

// ── breakpoints (existing, unchanged) ─────────────────────────────────────

function installBp(addrStr) {
    if (breakpoints[addrStr]) {
        return { ok: true, id: breakpoints[addrStr].id, msg: 'already set' };
    }
    var id = nextBpId++;
    var listener = Interceptor.attach(ptr(addrStr), {
        onEnter: function () {
            var bp = breakpoints[addrStr];
            if (bp) bp.hitCount++;
            if (frozen) return;
            frozen = true;
            frozenRawCtx = this.context;
            frozenThreadId = this.threadId;
            frozenAddr = addrStr;
            frozenBpId = bp ? bp.id : 0;
            frozenCtx = snapshotRegs(this.context);
            send({
                type: 'bp_hit', addr: addrStr,
                bpId: frozenBpId,
                hitCount: bp ? bp.hitCount : 1,
                regs: frozenCtx
            });
            recv('resume', function () {
                frozen = false;
                frozenCtx = null;
                frozenRawCtx = null;
                frozenThreadId = null;
                frozenAddr = null;
                frozenBpId = null;
            }).wait();
        }
    });
    breakpoints[addrStr] = { id: id, listener: listener, hitCount: 0 };
    return { ok: true, id: id };
}

function removeBp(addrStr) {
    var bp = breakpoints[addrStr];
    if (!bp) return { ok: false, msg: 'no bp at ' + addrStr };
    bp.listener.detach();
    delete breakpoints[addrStr];
    return { ok: true };
}

function listBps() {
    var result = [];
    for (var addr in breakpoints) {
        var bp = breakpoints[addr];
        result.push({ addr: addr, id: bp.id, hitCount: bp.hitCount });
    }
    return result;
}

// ── visibility override (code cave) ──────────────────────────────────────
//
// Patches a jmp-trampoline to route through a code cave that selectively
// forces "fully visible" for callers above a threshold address while
// letting callers below the threshold run the original function.

var visOverride = null;   // { cave: NativePointer, origBytes: ArrayBuffer, stats: NativePointer }

function installVisOverride(thresholdHex, jmpSiteHex, origTargetHex) {
    if (visOverride) return { ok: false, msg: 'already installed' };

    var threshold = parseInt(thresholdHex, 16);
    var jmpSite = ptr(jmpSiteHex);
    var origTarget = ptr(origTargetHex);

    // Save original 5 bytes at jmp site
    var origBytes = jmpSite.readByteArray(5);

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
    Memory.protect(jmpSite, 5, 'rwx');
    var patchBuf = new Uint8Array(5);
    var patchDv = new DataView(patchBuf.buffer);
    patchBuf[0] = 0xE9;
    patchDv.setInt32(1, cave.sub(jmpSite.add(5)).toInt32(), true);
    jmpSite.writeByteArray(patchBuf.buffer);

    visOverride = { cave: cave, origBytes: origBytes, stats: statsPtr, jmpSite: jmpSite };
    return { ok: true, cave: ptrToHex(cave), threshold: threshold };
}

function removeVisOverride() {
    if (!visOverride) return { ok: false, msg: 'not installed' };
    var jmpSite = visOverride.jmpSite;
    Memory.protect(jmpSite, 5, 'rwx');
    jmpSite.writeByteArray(visOverride.origBytes);
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
    if (dipHook) return { ok: false, msg: 'already installed' };

    var devPtrPtr = ptr(devPtrAddr);
    var devPtr;
    try { devPtr = devPtrPtr.readPointer(); } catch (e) {
        return { ok: false, msg: 'cannot read device pointer: ' + e.message };
    }
    if (devPtr.isNull()) return { ok: false, msg: 'D3D9 device is NULL' };

    var vtable = devPtr.readPointer();
    var dipAddr = vtable.add(0x148).readPointer();

    var counter = Memory.alloc(8);
    counter.writeU32(0);
    counter.add(4).writeU32(0);

    var cPtr = counter;
    var listener = Interceptor.attach(dipAddr, {
        onEnter: function () {
            cPtr.writeU32((cPtr.readU32() + 1) >>> 0);
        }
    });

    dipHook = { listener: listener, counter: counter, addr: dipAddr };
    return { ok: true, dipAddr: ptrToHex(dipAddr) };
}

function removeDipCounter() {
    if (!dipHook) return { ok: false, msg: 'not installed' };
    dipHook.listener.detach();
    dipHook = null;
    return { ok: true };
}

function sampleDipCallers(count) {
    if (!dipHook) return { ok: false, msg: 'dipcnt not installed' };
    var n = count || 200;
    var callers = {};
    var remaining = n;
    var dipAddr = dipHook.addr;

    var sampler = Interceptor.attach(ptr(dipAddr), {
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

    // frozen state
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
            regs: frozenCtx, threadId: frozenThreadId, bpId: frozenBpId,
            addr: frozenAddr, stack: stackEntries, disasm: disasmLines
        };
    },

    // memory operations
    readMemory: function (addrStr, size) {
        try { return ptr(addrStr).readByteArray(size); }
        catch (e) { return null; }
    },
    writeMemory: function (addrStr, hexStr) {
        try {
            var bytes = hexToBytes(hexStr);
            Memory.protect(ptr(addrStr), bytes.length, 'rwx');
            ptr(addrStr).writeByteArray(bytes);
            return { ok: true };
        } catch (e) { return { ok: false, msg: e.message }; }
    },
    allocMemory: function (size) {
        try {
            var p = Memory.alloc(size);
            Memory.protect(p, size, 'rwx');
            _allocations.push(p);
            return { ok: true, addr: ptrToHex(p) };
        } catch (e) { return { ok: false, msg: e.message }; }
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

    // ── NEW: trace ──
    installTrace: function (addrStr, config) { return installTrace(addrStr, config); },
    removeTrace: function (traceId) { return removeTrace(traceId); },
    flushTraces: function (traceId) { return flushTraces(traceId); },
    checkPrologue: function (addrStr) { return checkPrologue(addrStr); },

    // ── NEW: steptrace ──
    installStepTrace: function (addrStr, config) { return installStepTrace(addrStr, config); },
    getStepTraceResult: function () { return steptraceResult; },

    // ── NEW: fence ──
    installFence: function (addrStr) { return installFence(addrStr); },
    removeFence: function () { return removeFence(); },
    getFenceCounter: function () { return fenceCounter; },

    // ── NEW: modules ──
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

    // ── NEW: memory write watchpoint ──
    watchMemWrite: function (addrStr, size, maxHits) {
        return watchMemWrite(addrStr, size || 4, maxHits || 20);
    },
    stopMemWatch: function () { return stopMemWatch(); },
    getMemWatchHits: function () { return getMemWatchHits(); }
};
