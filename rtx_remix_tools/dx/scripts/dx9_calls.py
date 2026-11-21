"""Scans for COM method calls in 32-bit code, and what the code in front of them shows.

Byte-pattern scans for IDirect3DDevice9 (or ID3DXConstantTable) vtable calls
and method-pointer loads, the checks that drop calls of other classes, the
recovery of the stack arguments in front of a call, and where the code keeps
its device.
"""
import enum
import re
import struct
import sys
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from capstone import CS_AC_WRITE, CS_ARCH_X86, CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs
from capstone import x86_const as x86

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from graphics.directx.dx9.tracer.d3d9_methods import D3D9_METHODS
from retools.common import disasm_batches


# ═══════════════════════════════════════════════════════════════════════
# Pattern Scanning
# ═══════════════════════════════════════════════════════════════════════

# ModRM r/m values of the registers that can be a base without a SIB byte
_GP_REGS = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}

# ModRM mod bits: mod 10 takes a disp32, mod 01 a disp8, mod 00 none
_MOD_DISP32 = 0x80
_MOD_DISP8 = 0x40
_MOD_NO_DISP = 0x00
_MAX_DISP8 = 0x7F
_RM_EBP = 5             # under mod 00 this r/m value means [disp32], not [ebp]
_CALL_REG = 2 << 3      # reg field of "call r/m32" (FF /2)

# IDirect3DDevice9: declared parameter count by x86 vtable offset, `this` not counted
DEVICE = {spec.slot * 4: spec.argc for spec in D3D9_METHODS.values()}


def _displacement_encodings(vtable_offset):
    """(mod bits, displacement bytes, base registers) of every way [reg+vtable_offset] is encoded.

    Compilers use the one-byte displacement for the first 32 vtable slots,
    and none for the first slot. [ebp] has no form without a displacement:
    it takes the disp8 one.
    """
    encodings = [(_MOD_DISP32, struct.pack('<I', vtable_offset), _GP_REGS)]
    if vtable_offset <= _MAX_DISP8:
        encodings.append((_MOD_DISP8, bytes([vtable_offset]), _GP_REGS))
    if vtable_offset == 0:
        encodings.append((_MOD_NO_DISP, b"", {rm: name for rm, name in _GP_REGS.items() if rm != _RM_EBP}))
    return encodings


def _find_modrm(text_data, text_va, opcode, modrms, displacement, first_va, end_va):
    """Every place from *first_va* up to *end_va* where *opcode*, one of the ModRM bytes *modrms*, then *displacement* sit.

    One pass over the stretch for all the ModRM bytes; hits may overlap, and
    one that starts before *end_va* may run past it.

    Returns: [(va, modrm), ...] in address order.
    """
    modrm_class = b"".join(re.escape(bytes([modrm])) for modrm in sorted(modrms))
    pattern = re.compile(re.escape(bytes([opcode])) + b"([" + modrm_class + b"])" + re.escape(displacement),
                         re.DOTALL)
    stop = end_va - text_va + 1 + len(displacement)
    hits = []
    hit = pattern.search(text_data, first_va - text_va, stop)
    while hit is not None:
        hits.append((text_va + hit.start(), hit.group(1)[0]))
        hit = pattern.search(text_data, hit.start() + 1, stop)
    return hits


def _whole_section(text_data, text_va):
    return text_va, text_va + len(text_data)


def scan_vtable_calls(text_data, text_va, vtable_offset, interface=DEVICE, region=None):
    """Find COM method calls: call [reg+vtable_offset], in each encoding (see _displacement_encodings).

    A hit counts only when it is a whole call instruction that is not shown
    to be a call of another method (see _is_com_method_call).

    Args:
        interface: Declared parameter count by vtable offset of the interface
            whose method is sought.
        region: (start va, end va) the sites are sought in, the end left
            out; the whole section when None. Only the hits in it are
            checked, against the code in front of them wherever in the
            section that lies.

    Returns: [(va, reg_name), ...] in address order.
    """
    start_va, end_va = region or _whole_section(text_data, text_va)
    param_count = interface.get(vtable_offset)
    results = []
    for mod_bits, displacement, bases in _displacement_encodings(vtable_offset):
        reg_by_modrm = {mod_bits | _CALL_REG | rm: reg_name for rm, reg_name in bases.items()}
        results.extend((va, reg_by_modrm[modrm])
                       for va, modrm in _find_modrm(text_data, text_va, 0xFF, reg_by_modrm, displacement,
                                                    start_va, end_va)
                       if _is_com_method_call(text_data, text_va, va, param_count))
    results.sort()
    return results


def scan_vtable_mov(text_data, text_va, vtable_offset, interface=DEVICE, region=None):
    """Find method-pointer loads: mov reg, [reg+vtable_offset] that the code then calls through.

    In each encoding (see _displacement_encodings). A load counts only when it is a
    whole instruction and a call through the loaded register follows it, so a
    read of a data field that happens to sit at the same offset is left out,
    and when that call is not shown to be a call of another method (see
    _is_com_method_call).

    A method pointer kept in a register that calls preserve serves several
    calls. The load is the site of the first; each later one is a site of
    its own, at its call instruction, kept unless its own arguments show
    another method.

    Args:
        interface: Declared parameter count by vtable offset of the interface
            whose method is sought.
        region: (start va, end va) the sites are sought in, the end left
            out; the whole section when None. A later call in it is a site
            wherever its load is. Only the loads that can lead to a site in
            it are checked.

    Returns: [(va, description), ...] in address order.
    """
    start_va, end_va = region or _whole_section(text_data, text_va)
    first_load_va = _earliest_load_called_from(text_data, text_va, start_va)
    param_count = interface.get(vtable_offset)
    results = []
    for mod_bits, displacement, bases in _displacement_encodings(vtable_offset):
        description_by_modrm = {mod_bits | (dst_idx << 3) | src_idx: f"mov {dst_name}, [{src_name}+0x{vtable_offset:03X}]"
                                for src_idx, src_name in bases.items() for dst_idx, dst_name in _GP_REGS.items()}
        for va, modrm in _find_modrm(text_data, text_va, 0x8B, description_by_modrm, displacement,
                                     first_load_va, end_va):
            if not _is_com_method_call(text_data, text_va, va, param_count):
                continue
            load = description_by_modrm[modrm]
            results.append((va, load))
            results.extend((call.address, f"call {call.op_str} ({load} at 0x{va:08X})")
                           for call in _later_calls(text_data, text_va, va)
                           if _is_com_method_call(text_data, text_va, call.address, param_count))
    return sorted(site for site in results if start_va <= site[0] < end_va)


def scan_all_patterns(text_data, text_va, vtable_offset, interface=DEVICE, region=None):
    """Find call and mov patterns for a vtable offset of *interface*, in *region* when one is given.

    Returns: [(va, description), ...]
    """
    results = [(va, f"call [{reg}+0x{vtable_offset:03X}]")
               for va, reg in scan_vtable_calls(text_data, text_va, vtable_offset, interface, region)]
    results.extend(scan_vtable_mov(text_data, text_va, vtable_offset, interface, region))
    results.sort()
    return results


# ═══════════════════════════════════════════════════════════════════════
# Call Arguments
# ═══════════════════════════════════════════════════════════════════════
#
# A stdcall method call finds `this` at the top of the stack and its declared
# parameters in the dwords above it, in order. Code puts them there with pushes
# (last parameter first, `this` last of all) or with stores to [esp+disp] after
# reserving the space. A register is an argument like any other.

_METHODS = {spec.name: spec for spec in D3D9_METHODS.values()}

_decoder = Cs(CS_ARCH_X86, CS_MODE_32)
_decoder.detail = True

# x86 cannot be decoded backwards. Decoding forwards from an arbitrary earlier
# byte falls into step with the real instructions after a few of them. So the
# bytes before a site are decoded from every offset in a stretch well before
# it, and an instruction near the site is trusted only when all of those
# decodings pass through it.
_LOOKBACK = 96          # bytes before a site that decoding may start from
_TRUSTED = 48           # bytes before a site that instructions are taken from
_MAX_INSN = 15          # longest x86 instruction
_FUNCTION_ALIGNMENT = 16    # compilers pad up to a multiple of this before a function
_PADDING_BYTES = frozenset((0xCC, 0x90))    # int3 and nop
_SWEEP_BATCH_INSNS = 4096  # instructions per capstone call in the section sweep
# Registers a called function returns unchanged, in every x86 calling convention
_CALLEE_SAVED = frozenset((x86.X86_REG_EBX, x86.X86_REG_ESI, x86.X86_REG_EDI, x86.X86_REG_EBP))
# Capstone names the part of a register an instruction writes (al, cx); a write
# to any part changes the 32-bit register that holds it
_ENCLOSING_REGISTER = {part: whole for whole, parts in {
    x86.X86_REG_EAX: (x86.X86_REG_AL, x86.X86_REG_AH, x86.X86_REG_AX),
    x86.X86_REG_ECX: (x86.X86_REG_CL, x86.X86_REG_CH, x86.X86_REG_CX),
    x86.X86_REG_EDX: (x86.X86_REG_DL, x86.X86_REG_DH, x86.X86_REG_DX),
    x86.X86_REG_EBX: (x86.X86_REG_BL, x86.X86_REG_BH, x86.X86_REG_BX),
    x86.X86_REG_ESP: (x86.X86_REG_SP,),
    x86.X86_REG_EBP: (x86.X86_REG_BP,),
    x86.X86_REG_ESI: (x86.X86_REG_SI,),
    x86.X86_REG_EDI: (x86.X86_REG_DI,),
}.items() for part in parts}
_LOOKAHEAD = 64         # bytes after a method-pointer load, and after each call through it, searched for the next

_END_GROUPS = (CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET)


class _Flow(enum.Enum):
    """How an instruction moves control on; the walks over the code react to each in their own way."""
    STRAIGHT = enum.auto()      # falls through to the next instruction only
    CONDITIONAL = enum.auto()   # a conditional jump: the walks pass it by its fall-through
    CALL = enum.auto()
    END = enum.auto()           # jmp, ret, int or iret: nothing falls through it


def _flow(insn):
    if insn.group(CS_GRP_CALL):
        return _Flow.CALL
    if insn.id == x86.X86_INS_JMP or any(insn.group(group) for group in _END_GROUPS):
        return _Flow.END
    if insn.group(CS_GRP_JUMP):
        return _Flow.CONDITIONAL
    return _Flow.STRAIGHT


def _joined_after(insn, jump_targets):
    """Whether another path joins right after *insn*: a jump goes to the address that follows it."""
    return insn.address + insn.size in jump_targets


class StackArg(NamedTuple):
    """One argument put on the stack for a call.

    Attributes:
        va: Address of the push, or of the store to [esp+disp].
        value: The immediate that was put there, or None for a register or a
            memory operand.
        source: That operand as text: "0x14", "eax", "dword ptr [ebp - 8]".
    """
    va: int
    value: int | None
    source: str


def _trusted_start(text_data, text_va, site_va):
    """Address of the earliest instruction before *site_va* that is certain.

    *site_va* itself when none is. None when the site lies inside another
    instruction, or in data: no decoding ends exactly at *site_va*, or the
    decodings from the stretch more than _TRUSTED bytes before it step over
    it and none of them ends at it. A decoding that starts nearer can begin
    inside the instruction that holds the site and still arrive, so it
    speaks for the site only when it starts where a function does (data in
    front of a function decodes into instructions that run over its first
    bytes), or when no decoding from the far stretch gets anywhere near the
    site: the section, or a function that follows data, starts too close to
    it.
    """
    site_off = site_va - text_va
    first = max(0, site_off - _LOOKBACK)
    trusted_from = site_off - _TRUSTED

    # following[o]: where the instruction at offset o ends, kept only for
    # offsets from which decoding arrives exactly at the site.
    # stepping_over: the offsets from which decoding runs past the site
    # without stopping at it.
    following = {}
    stepping_over = set()
    for off in range(site_off - 1, first - 1, -1):
        insn = next(_decoder.disasm_lite(text_data[off:off + _MAX_INSN], text_va + off), None)
        if insn is None:
            continue
        end = off + insn[1]
        if end == site_off or end in following:
            following[off] = end
        elif end > site_off or end in stepping_over:
            stepping_over.add(off)
    if not following:
        return None

    arriving = sorted(following)
    voters = [off for off in arriving if off < trusted_from]
    if not voters:
        if any(off < trusted_from for off in stepping_over):
            voters = [off for off in arriving if _starts_function(text_data, text_va, off)]
            if not voters:
                return None
        else:
            voters = arriving[:1]
    passing = dict.fromkeys(arriving, 0)
    for off in voters:
        passing[off] = 1
    for off in arriving:
        if following[off] != site_off:
            passing[following[off]] += passing[off]

    certain = [off for off in arriving
               if off >= trusted_from and passing[off] == len(voters)]
    return text_va + (certain[0] if certain else site_off)


def _starts_function(text_data, text_va, off):
    """Whether a function is seen to start at offset *off*: a direct call goes there, or alignment padding ends there."""
    va = text_va + off
    return va in _call_targets(text_data, text_va) or (
        va % _FUNCTION_ALIGNMENT == 0
        and text_data[off - 1] in _PADDING_BYTES and text_data[off] not in _PADDING_BYTES)


def _instructions_before_call(text_data, text_va, site_va):
    """Instructions that run just before the call a scan hit leads to, oldest first.

    The hit is either the call itself, or a load of the method pointer into a
    register that is then called; the load and what runs between it and the
    first call through it are part of the list. The last instruction ends
    where the call starts. None when the hit is not an instruction, or leads
    to no call (a field that happens to sit at the method's offset).
    """
    path = _path_to_call(text_data, text_va, site_va)
    if path is None:
        return None
    start = _trusted_start(text_data, text_va, site_va)
    if start is None:
        return None
    site_off = site_va - text_va
    return list(_decoder.disasm(text_data[start - text_va:site_off], start)) + path


def _path_to_call(text_data, text_va, site_va):
    """Instructions from *site_va* up to the call it leads to, the call left out.

    Empty when the site is a call. None when it is neither a call nor a load
    of a register that the code then calls through (see _calls_through).
    """
    site = _site_instruction(text_data, text_va, site_va)
    if site is None:
        return None
    if site.id == x86.X86_INS_CALL:
        return []
    if site.id != x86.X86_INS_MOV or site.operands[0].type != x86.X86_OP_REG:
        return None
    first = next(_calls_through(text_data, text_va, site), None)
    return None if first is None else first[1]


def _later_calls(text_data, text_va, load_va):
    """The calls through the register the load at *load_va* sets that follow the first one."""
    calls = _calls_through(text_data, text_va, _site_instruction(text_data, text_va, load_va))
    next(calls)
    return [call for call, _path in calls]


def _site_instruction(text_data, text_va, site_va):
    """The instruction at a scan hit, None when the bytes there are not one."""
    site_off = site_va - text_va
    return next(_decoder.disasm(text_data[site_off:site_off + _MAX_INSN], site_va, 1), None)


def _calls_through(text_data, text_va, load):
    """Each call through the register *load* sets, in turn, while the register still holds what was loaded.

    The search ends at an unconditional jump or a return, where the register
    is written, and _LOOKAHEAD bytes after the load or the last call found.
    A conditional jump is passed by its fall-through: compilers often test
    something between loading a method and calling it. A call, the sought
    one included, is passed only when the method sits in ebx, esi, edi or
    ebp, which every x86 calling convention preserves; it may overwrite eax,
    ecx and edx.

    Yields:
        (call instruction, instructions from *load* up to it).
    """
    method_reg = load.operands[0].reg
    path = [load]
    start = load.address + load.size - text_va
    end = load.address - text_va + _LOOKAHEAD
    while True:
        call = None
        for insn in _decoder.disasm(text_data[start:end], text_va + start):
            flow = _flow(insn)
            if flow is _Flow.CALL:
                target = insn.operands[0]
                if target.type == x86.X86_OP_REG and target.reg == method_reg:
                    call = insn
                    break
                if method_reg not in _CALLEE_SAVED:
                    return
            if flow is _Flow.END or _writes(insn, method_reg):
                return
            path.append(insn)
        if call is None:
            return
        yield call, list(path)
        if method_reg not in _CALLEE_SAVED:
            return
        path.append(call)
        start = call.address + call.size - text_va
        end = start + _LOOKAHEAD


# call ebx / ebp / esi / edi: the calls a method pointer is kept across (see _calls_through)
_CALL_KEPT_REGISTER = re.compile(rb"\xFF[\xD3\xD5\xD6\xD7]")


def _earliest_load_called_from(text_data, text_va, va):
    """Lowest address of a method-pointer load that _calls_through can find a call at or after *va* for.

    The first call lies within _LOOKAHEAD bytes of its load, and each later
    one that close to the call before it.
    """
    off = va - text_va
    while True:
        earlier_call = _CALL_KEPT_REGISTER.search(text_data, max(0, off - _LOOKAHEAD), off + 1)
        if earlier_call is None:
            return text_va + max(0, off - _LOOKAHEAD)
        off = earlier_call.start()


def _stack_arg(insn, operand, source):
    if operand.type == x86.X86_OP_IMM:
        return StackArg(insn.address, operand.imm & 0xFFFFFFFF, source)
    return StackArg(insn.address, None, source)


# Instructions whose first operand, when it is memory, is only read
_READS_FIRST_OPERAND = frozenset((x86.X86_INS_PUSH, x86.X86_INS_CMP, x86.X86_INS_TEST, x86.X86_INS_BT))


def _stack_stores(insn):
    """The memory operands *insn* may write at an address based on esp.

    Capstone marks the destination of fstp, fistp, movq and movups as read, so
    a memory operand in first position counts as written whatever capstone
    says, unless *insn* only compares or pushes it. An FPU load from the stack
    counts as a write too; that only leaves its slot unsettled.
    """
    return [op for position, op in enumerate(insn.operands)
            if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_ESP
            and (op.access & CS_AC_WRITE
                 or (position == 0 and insn.id not in _READS_FIRST_OPERAND))]


def _is_dword_store(insn, store):
    """A mov of a register or an immediate into one whole stack slot."""
    return (insn.id == x86.X86_INS_MOV and store.size == 4
            and store.mem.index == x86.X86_REG_INVALID and store.mem.disp % 4 == 0)


def _jump_targets(text_data, text_va):
    """Every address a direct jump in the code section goes to.

    Data in the section decodes into jumps that do not exist; their targets
    only make the argument walk stop early.
    """
    return _branch_targets(text_data, text_va)[0]


def _call_targets(text_data, text_va):
    """Every address a direct call in the code section goes to."""
    return _branch_targets(text_data, text_va)[1]


@lru_cache(maxsize=2)
def _branch_targets(text_data, text_va):
    """(direct jump targets, direct call targets) of the code section.

    One linear sweep of the whole section, so a branch is found however far
    it is from its target and whichever side of it.
    """
    sweep = Cs(CS_ARCH_X86, CS_MODE_32)
    sweep.skipdata = True
    jumps, calls = set(), set()
    for _address, _size, mnemonic, operands in disasm_batches(sweep, text_data, text_va, _SWEEP_BATCH_INSNS, lite=True):
        if mnemonic[0] == 'j' or mnemonic.startswith('loop'):
            targets = jumps
        elif mnemonic == 'call':
            targets = calls
        else:
            continue
        try:
            targets.add(int(operands, 16))
        except ValueError:
            pass  # through a register or memory: no target to read
    return frozenset(jumps), frozenset(calls)


class _WalkEnd(enum.Enum):
    """Where the walk back from a call stopped, which decides what the slots it left unwritten can hold."""
    SETTLED = enum.auto()   # every slot asked for was written
    ENTRY = enum.auto()     # the entry of the code (after a ret, a jmp or int3 padding): nothing older exists
    RESERVED = enum.auto()  # a reservation of stack space that covers an unwritten slot: nothing older is in it
    CALL = enum.auto()      # an earlier call: how many of the dwords pushed before it are left is not known
    UNKNOWN = enum.auto()   # a join, a change of esp or a store the walk cannot follow, or the instructions ran out


class _StackWalk(NamedTuple):
    """What the walk back from a call found on the stack.

    Attributes:
        slots: Slot -> the StackArg written there, or None for a write whose
            dword the walk cannot read. Only slots the walk saw written.
        end: Where the walk stopped.
    """
    slots: dict
    end: _WalkEnd


def _stack_args(insns, count, jump_targets):
    """The *count* dwords on top of the stack once *insns* have run, top first.

    None for a slot the code before the call does not settle (see _walk_stack).
    """
    slots = _walk_stack(insns, count, jump_targets).slots
    return [slots.get(slot) for slot in range(count)]


def _walk_stack(insns, count, jump_targets):
    """Walk back from the end of *insns* until the *count* top slots of the stack are written.

    Keeps, for each slot, the last write to it: a push, or a store to
    [esp+disp]. A write the walk cannot read a dword from (a byte store, an
    fstp) settles its slot as None, so an older write to that slot is never
    taken for it. An add or sub of a constant to esp and a pop shift the
    slots that older writes land in, and a conditional jump is passed by its
    fall-through.

    An earlier call is passed only when the top slot is written and the
    caller cleans up after the call (see _caller_cleans_up): the callee then
    left the stack as it found it. Any other callee may have taken its
    arguments off the stack or left them, so the slots older writes land in
    are not known and the walk ends there.
    It also ends at any other change of esp, at a store whose address
    depends on a register, and before an instruction followed by an address
    in *jump_targets*: another path joins there, and what it put on the
    stack is not in front of us.

    Returns:
        _StackWalk.
    """
    slots = {}
    pushed = 0              # dwords pushed between this point and the end
    for index in range(len(insns) - 1, -1, -1):
        insn = insns[index]
        if all(slot in slots for slot in range(count)):
            return _StackWalk(slots, _WalkEnd.SETTLED)
        if _joined_after(insn, jump_targets):
            return _StackWalk(slots, _WalkEnd.UNKNOWN)
        if insn.id == x86.X86_INS_PUSH:
            slots.setdefault(pushed, _stack_arg(insn, insn.operands[0], insn.op_str))
            pushed += 1
            continue
        flow = _flow(insn)
        if flow is _Flow.CONDITIONAL:
            continue    # the call is on its fall-through path
        if flow is _Flow.CALL:
            if 0 not in slots or not _caller_cleans_up(insns, index):
                return _StackWalk(slots, _WalkEnd.CALL)
            continue
        if flow is _Flow.END:
            return _StackWalk(slots, _WalkEnd.ENTRY)
        if _writes(insn, x86.X86_REG_ESP):
            popped = _dwords_released(insn)
            if popped is None:
                return _StackWalk(slots, _WalkEnd.UNKNOWN)
            pushed -= popped
            # Older writes land at slot `pushed` and above: a slot below it
            # that this reservation left unwritten stays unwritten.
            if not all(slot in slots for slot in range(min(pushed, count))):
                return _StackWalk(slots, _WalkEnd.RESERVED)
            continue
        stores = _stack_stores(insn)
        if any(store.mem.index != x86.X86_REG_INVALID for store in stores):
            return _StackWalk(slots, _WalkEnd.UNKNOWN)
        for store in stores:
            _settle_store(slots, pushed, insn, store)
    return _StackWalk(slots, _WalkEnd.UNKNOWN)


def _caller_cleans_up(insns, call_index):
    """Whether the call at insns[call_index] is followed at once by add esp, imm.

    That is how the caller of a cdecl function takes the arguments off the
    stack, so the function itself returned with esp where it found it.
    """
    if call_index + 1 == len(insns):
        return False
    after = insns[call_index + 1]
    return after.id == x86.X86_INS_ADD and (_dwords_released(after) or 0) > 0


def _dwords_released(insn):
    """How many dwords *insn* takes off the stack: pop reg, add esp, imm, sub esp, imm (negative)
    or lea esp, [esp+disp].

    None for any other write to esp, or a constant that is not whole dwords.
    """
    if insn.id == x86.X86_INS_POP and insn.operands[0].type == x86.X86_OP_REG:
        return 1
    if insn.id == x86.X86_INS_LEA:
        target, address = insn.operands
        mem = address.mem
        if (target.reg != x86.X86_REG_ESP or mem.base != x86.X86_REG_ESP
                or mem.index != x86.X86_REG_INVALID or mem.disp % 4):
            return None
        return mem.disp // 4
    if insn.id not in (x86.X86_INS_ADD, x86.X86_INS_SUB):
        return None
    target, amount = insn.operands
    if (target.type != x86.X86_OP_REG or target.reg != x86.X86_REG_ESP
            or amount.type != x86.X86_OP_IMM or amount.imm % 4):
        return None
    dwords = amount.imm // 4
    return dwords if insn.id == x86.X86_INS_ADD else -dwords


def _settle_store(slots, pushed, insn, store):
    """Record what *insn* stores at [esp+disp] in each slot no later write has settled."""
    first = pushed + store.mem.disp // 4
    if _is_dword_store(insn, store):
        source = insn.op_str.split(", ")[-1]
        slots.setdefault(first, _stack_arg(insn, insn.operands[1], source))
        return
    last = pushed + (store.mem.disp + store.size - 1) // 4
    for slot in range(first, last + 1):
        slots.setdefault(slot, None)


# ═══════════════════════════════════════════════════════════════════════
# Calls of other methods
# ═══════════════════════════════════════════════════════════════════════
#
# A call through the sought slot may belong to another class. Four things
# the code in front of the call can show drop it; when it shows none, the call
# is kept.
#
# Argument count: a stdcall method finds its parameters and `this` on the
# stack, so the code must have put that many dwords there. When the walk back
# reaches a point nothing older can come from (the entry of the code, or a
# reservation of stack space the code then leaves partly unwritten) with
# fewer slots written, the call takes fewer arguments than the method. An
# earlier call is no such point: what was pushed before it is still there
# unless the callee took it off (dev->SetRenderState(State(), value) is
# push value / call State / push eax). More slots never drop a call: an
# outer call's arguments precede an inner one's (f(g(y), x) is push x /
# push y / call g).
#
# COM `this`: `this` is the last thing put on the stack, and it is the object
# the vtable was read from (mov eax, [esi] / push esi / call [eax+X]). An MSVC
# __thiscall method passes `this` in ecx and pushes only its parameters, so
# the dword on top of the stack there is a parameter. The call is dropped when
# the code shows that the top dword differs from the vtable's object, or that
# ecx holds the object. A COM call on another interface that shares the slot
# passes this check.
#
# No `this`: an argument that is itself a call is evaluated before `this` is
# pushed, so a COM call writes the top of the stack after every call made on
# the way to it. A call reached with nothing put on the stack since is a
# __thiscall without stack parameters (mov ecx, obj / mov eax, [ecx] /
# call [eax+X]).
#
# Register argument: a stdcall method takes nothing in registers, and no call
# preserves ecx. Code that loads ecx and reads it nowhere before the call
# loads it for the callee (mov ecx, obj / push eax / call [edx+X]).

# What _register_value cannot follow. _holds_object treats it as undecided.
_UNKNOWN = ("unknown",)


def _is_com_method_call(text_data, text_va, site_va, param_count):
    """A scan hit that leads to a call not shown to be a call of another method.

    Args:
        param_count: Declared parameter count of the sought method, `this`
            not counted; None when unknown, which skips the argument count.
    """
    insns = _instructions_before_call(text_data, text_va, site_va)
    if insns is None:
        return False
    jump_targets = _jump_targets(text_data, text_va)
    walk = _walk_stack(insns, (param_count or 0) + 1, jump_targets)
    if _pushes_no_this(walk):
        return False
    if param_count is not None and _passes_too_few_arguments(walk, param_count):
        return False
    call = _site_instruction(text_data, text_va, insns[-1].address + insns[-1].size if insns else site_va)
    if _loads_ecx_for_the_callee(insns, call, jump_targets):
        return False
    return not _passes_another_this(text_data, text_va, site_va, insns)


def _pushes_no_this(walk):
    """Whether nothing was put on top of the stack between the call before and this one."""
    return walk.end is _WalkEnd.CALL and 0 not in walk.slots


def _passes_too_few_arguments(walk, param_count):
    """Whether the stack is shown to hold fewer than *param_count* + 1 dwords at the call."""
    return (walk.end in (_WalkEnd.ENTRY, _WalkEnd.RESERVED)
            and not all(slot in walk.slots for slot in range(param_count + 1)))


def _loads_ecx_for_the_callee(insns, call, jump_targets):
    """Whether the code loads ecx and only *call* can read what it loaded.

    Nothing between the load and the call reads ecx, and no conditional
    jump lies between them that could take the value elsewhere (see
    _gives_ecx_a_value for what counts as a load).
    """
    first, _entered = _straight_line_start(insns, len(insns), jump_targets)
    for index in range(len(insns) - 1, first - 1, -1):
        insn = insns[index]
        if _flow(insn) is not _Flow.STRAIGHT:
            return False
        if _writes(insn, x86.X86_REG_ECX):
            return (_gives_ecx_a_value(insn)
                    and not any(_reads(later, x86.X86_REG_ECX) for later in (*insns[index + 1:], call)))
    return False


def _gives_ecx_a_value(insn):
    """A mov or lea that sets all 32 bits of ecx to something other than what ecx held.

    A pop or a string instruction writes ecx by the way, a mov into cl or
    cx leaves the rest of it, and mov ecx, ecx and lea ecx, [ecx+0] are
    the padding compilers align code with.
    """
    if insn.id not in (x86.X86_INS_MOV, x86.X86_INS_LEA):
        return False
    target, source = insn.operands
    if target.type != x86.X86_OP_REG or target.reg != x86.X86_REG_ECX:
        return False
    if source.type == x86.X86_OP_REG:
        return source.reg != x86.X86_REG_ECX
    if insn.id == x86.X86_INS_LEA:
        address = source.mem
        return (address.base, address.index, address.disp) != (x86.X86_REG_ECX, x86.X86_REG_INVALID, 0)
    return True


def _passes_another_this(text_data, text_va, site_va, insns):
    """Whether the code shows that the call passes another `this` than the vtable's object.

    That needs the load of the vtable register from [obj], and then either a
    dword on top of the stack that is not obj's value, or ecx set to obj for
    the call while something else is on top of the stack: the __thiscall
    form of passing obj.
    """
    jump_targets = _jump_targets(text_data, text_va)
    [this] = _stack_args(insns, 1, jump_targets)
    if this is None:
        return False
    vtable_reg = _vtable_register(text_data, text_va, site_va)
    if vtable_reg is None:
        return False
    site_index = next((k for k, insn in enumerate(insns) if insn.address == site_va), len(insns))
    load_index = _last_write(insns, site_index, vtable_reg, jump_targets)
    if load_index is None:
        return False
    obj = _object_of_vtable_load(insns[load_index])
    if obj is None:
        return False

    push_index = next(k for k, insn in enumerate(insns) if insn.address == this.va)
    push = insns[push_index]
    pushed = push.operands[0] if push.id == x86.X86_INS_PUSH else push.operands[1]
    this_is_obj = _holds_object(insns, load_index, obj, push_index, pushed, jump_targets)
    if this_is_obj:
        return False
    ecx_index = _last_write(insns, len(insns), x86.X86_REG_ECX, jump_targets)
    if ecx_index is not None and _is_register_copy(insns[ecx_index]):
        if _holds_object(insns, load_index, obj, ecx_index, insns[ecx_index].operands[1], jump_targets):
            return True
    return this_is_obj is False


def _vtable_register(text_data, text_va, site_va):
    """The register a scan hit reads the method pointer through: reg in call [reg+X] or mov r, [reg+X].

    None for a later call through a loaded method pointer (see scan_vtable_mov):
    the vtable was read before the calls made through the pointer since.
    """
    site = _site_instruction(text_data, text_va, site_va)
    method_slots = [op for op in site.operands if op.type == x86.X86_OP_MEM]
    return method_slots[0].mem.base if method_slots else None


def _holds_object(insns, load_index, obj, index, operand, jump_targets):
    """Whether *operand*, as insns[index] reads it, is the object insns[load_index] read a vtable from.

    None when the code does not show either way.
    """
    if operand.type == x86.X86_OP_IMM:
        return False
    if operand.type == x86.X86_OP_REG and operand.reg == obj:
        # A load after *index* reads obj before it writes; one before it
        # overwrites obj when obj is also the vtable register.
        first, last = (index + 1, load_index) if index < load_index else (load_index, index)
        if _unchanged(insns, first, last, obj, jump_targets):
            return True
    obj_value = _register_value(insns, load_index, obj, jump_targets)
    operand_value = _operand_value(insns, index, operand, jump_targets)
    if _UNKNOWN in (obj_value, operand_value):
        return None
    return obj_value == operand_value


def _is_whole_register_mov(insn):
    """A mov that sets all 32 bits of its destination; a mov into al or cx leaves the rest as it was."""
    return insn.id == x86.X86_INS_MOV and insn.operands[0].size == 4


def _is_register_copy(insn):
    return _is_whole_register_mov(insn) and insn.operands[1].type == x86.X86_OP_REG


def _object_of_vtable_load(insn):
    """obj when *insn* is mov reg, [obj]; None for any other instruction."""
    if not _is_whole_register_mov(insn) or insn.operands[1].type != x86.X86_OP_MEM:
        return None
    mem = insn.operands[1].mem
    if mem.disp or mem.index != x86.X86_REG_INVALID or mem.base in (x86.X86_REG_INVALID, x86.X86_REG_ESP):
        return None
    return mem.base


def _straight_line_start(insns, index, jump_targets):
    """Where the run of instructions that falls straight into insns[index] begins.

    Returns:
        (first, entered): insns[first:index] run one after another with no
        other path joining and no call. *entered* is True when nothing falls
        into insns[first] (it follows a jump, a return or padding), so the
        registers there are whatever the code jumping or calling to it left;
        False when what precedes it is unknown.
    """
    for k in range(index - 1, -1, -1):
        insn = insns[k]
        flow = _flow(insn)
        if _joined_after(insn, jump_targets) or flow is _Flow.CALL:
            return k + 1, False
        if flow is _Flow.END:
            return k + 1, True
    return 0, False


def _writes(insn, reg):
    """Whether *insn* writes *reg*, or any part of the 32-bit register that holds it."""
    whole = _ENCLOSING_REGISTER.get(reg, reg)
    return any(_ENCLOSING_REGISTER.get(written, written) == whole for written in insn.regs_access()[1])


def _reads(insn, reg):
    """Whether *insn* reads *reg* or any part of it, as an operand or in an address."""
    whole = _ENCLOSING_REGISTER.get(reg, reg)
    return any(_ENCLOSING_REGISTER.get(read, read) == whole for read in insn.regs_access()[0])


def _last_write(insns, index, reg, jump_targets):
    """Index of the instruction that set *reg* for insns[index], None when the straight run does not show it."""
    first, _entered = _straight_line_start(insns, index, jump_targets)
    return next((k for k in range(index - 1, first - 1, -1) if _writes(insns[k], reg)), None)


def _unchanged(insns, first, last, reg, jump_targets):
    """*reg* holds one value from insns[first] to insns[last]: no write to it, no other path joining."""
    return (_straight_line_start(insns, last, jump_targets)[0] <= first
            and not any(_writes(insn, reg) for insn in insns[first:last]))


def _register_value(insns, index, reg, jump_targets):
    """What *reg* holds just before insns[index], in a form two values can be compared by.

    A register copy is followed to its source, a load from memory to the
    value of that memory (see _operand_value); any other write is the
    instruction that made it. A register the run does not write is its value
    on entry to the run, or _UNKNOWN when another path joins or a call
    intervenes before it.
    """
    first, entered = _straight_line_start(insns, index, jump_targets)
    for k in range(index - 1, first - 1, -1):
        insn = insns[k]
        if not _writes(insn, reg):
            continue
        if _is_whole_register_mov(insn) and insn.operands[1].type != x86.X86_OP_IMM:
            return _operand_value(insns, k, insn.operands[1], jump_targets)
        return ("written by", insn.address)
    return ("on entry", reg) if entered else _UNKNOWN


def _operand_value(insns, index, operand, jump_targets):
    """The value of *operand*, a register or memory, as insns[index] reads it.

    Memory not addressed through esp is the memory operand itself. A stack
    slot is the slot, counted from esp at the end of *insns*, with what last
    wrote it (see _stack_value).
    """
    if operand.type == x86.X86_OP_REG:
        return _register_value(insns, index, operand.reg, jump_targets)
    mem = operand.mem
    if mem.base != x86.X86_REG_ESP:
        return _memory_value(operand)
    if mem.index != x86.X86_REG_INVALID:
        return ("written by", insns[index].address)
    return _stack_value(insns, index, mem.disp, jump_targets)


def _stack_value(insns, index, disp, jump_targets):
    """The dword at [esp+disp] as insns[index] reads it, in a form two values can be compared by.

    A slot a push or a dword mov filled is the value it was filled with.
    Otherwise two reads of one slot compare equal when the same write, or
    nothing since the entry of the run, put the value there, however far
    esp moved in between. _UNKNOWN when esp moves in a way that cannot be
    followed, or the run reaches a join or a call before the slot is
    written.
    """
    base = _esp_offset(insns, index)
    if base is None:
        return _UNKNOWN
    slot = base + disp
    first, entered = _straight_line_start(insns, index, jump_targets)
    for k in range(index - 1, first - 1, -1):
        written = _stack_bytes_written(insns, k)
        if written is None:
            return _UNKNOWN
        if any(low < slot + 4 and slot < high for low, high in written):
            source = _dword_source(insns[k]) if written == [(slot, slot + 4)] else None
            if source is None or source.type == x86.X86_OP_IMM:
                return ("written by", insns[k].address)
            return _operand_value(insns, k, source, jump_targets)
    return ("stack on entry", slot) if entered else _UNKNOWN


def _dword_source(insn):
    """The operand a push, or a mov into one whole stack slot, puts on the stack; None for any other write."""
    if insn.id == x86.X86_INS_PUSH:
        return insn.operands[0]
    [store] = _stack_stores(insn)
    return insn.operands[1] if _is_dword_store(insn, store) else None


def _esp_offset(insns, index):
    """Bytes from esp at the end of *insns* up to esp before insns[index].

    None when a call, or a change of esp that is not a push, a pop or an
    add or sub of whole dwords, lies on the way.
    """
    dwords = 0
    for insn in insns[index:]:
        if insn.id == x86.X86_INS_PUSH:
            dwords += 1
        elif _flow(insn) is _Flow.CALL:
            return None
        elif _writes(insn, x86.X86_REG_ESP):
            released = _dwords_released(insn)
            if released is None:
                return None
            dwords -= released
    return 4 * dwords


def _stack_bytes_written(insns, index):
    """[(low, high), ...] byte ranges insns[index] writes, counted like _esp_offset; None when unknown."""
    base = _esp_offset(insns, index)
    if base is None:
        return None
    insn = insns[index]
    if insn.id == x86.X86_INS_PUSH:
        return [(base - 4, base)]
    written = []
    for store in _stack_stores(insn):
        if store.mem.index != x86.X86_REG_INVALID:
            return None
        written.append((base + store.mem.disp, base + store.mem.disp + store.size))
    return written


def _memory_value(operand):
    mem = operand.mem
    return ("memory", mem.segment, mem.base, mem.index, mem.scale, mem.disp)


def method_args(text_data, text_va, site_va, method):
    """Stack arguments of the device method call a scan hit leads to, by parameter name.

    Args:
        text_data: Bytes of the code section the scan ran on.
        text_va: Virtual address of its first byte.
        site_va: A hit of scan_vtable_calls or scan_vtable_mov.
        method: IDirect3DDevice9 method name, e.g. "SetRenderState".

    Returns:
        {"this": ..., <parameter name>: ...} in declaration order, holding a
        StackArg for each argument the code before the call settles and None
        for the rest.
    """
    names = ["this"] + [name for name, _type in _METHODS[method].args]
    insns = _instructions_before_call(text_data, text_va, site_va)
    if insns is None:
        return dict.fromkeys(names)
    values = _stack_args(insns, len(names), _jump_targets(text_data, text_va))
    return dict(zip(names, values))


def immediates(args):
    """The constants among the arguments method_args returned.

    Returns:
        {"this": ..., <parameter name>: ...} with the immediate put on the
        stack for each argument, or None where the argument came from a
        register or memory, or was not recovered.
    """
    return {name: arg.value if arg else None for name, arg in args.items()}


def arg_text(arg):
    """A stack argument as it reads in a report.

    The number for a constant, the operand in angle brackets for a register
    or memory operand, <unknown> when the code before the call does not show
    what was put on the stack.
    """
    if arg is None:
        return "<unknown>"
    if arg.value is None:
        return f"<{arg.source}>"
    return str(arg.value)


def args_text(args):
    """The arguments of one call as they read in a report, `this` left out: "State=22  Value=<eax>"."""
    return "  ".join(f"{name}={arg_text(arg)}" for name, arg in args.items() if name != "this")


_UNDECODED_CALLS_LISTED = 10


def print_undecoded_calls(method, undecoded, show_all):
    """List the calls of *method* a report leaves out because an argument it needs is not a constant.

    Prints nothing when there are none.

    Args:
        undecoded: [(site va, arguments from method_args), ...].
        show_all: List every call rather than the first _UNDECODED_CALLS_LISTED.
    """
    if not undecoded:
        return
    print(f"\n  {method}: {len(undecoded)} call site(s) not decoded, an argument is not a constant:")
    calls = sorted(undecoded, key=lambda call: call[0])
    listed = calls if show_all else calls[:_UNDECODED_CALLS_LISTED]
    for va, args in listed:
        print("    " + ": ".join(filter(None, (f"0x{va:08X}", args_text(args)))))
    if len(listed) < len(calls):
        print(f"    ... and {len(calls) - len(listed)} more")


# ═══════════════════════════════════════════════════════════════════════
# Device provenance
# ═══════════════════════════════════════════════════════════════════════
#
# The checks above keep a call through the sought slot whatever object it is
# made on. Every COM interface and every C++ class with virtual methods has
# slots below 0x80, so a hit there is as likely another object's method as a
# device method. A game keeps its device in one place, or a few: a global, or
# a field of an object held in a global. Those places are learned from the
# hits at and above vtable+0x80, where few classes reach, and a hit below
# that is confirmed as a device call only when its object is read from one
# of them. An object read through a field of a register the code does not
# trace to a global (`this`, an argument) is never learned: the same field
# offset holds unrelated objects in other classes.

DEVICE_LOW_SLOT_END = 0x80      # vtable offsets below this are shared with most classes

# A place counts as the device's when the hits on objects read from it call
# one of the draw methods, at least _MIN_DEVICE_METHODS different device
# methods at and above vtable+0x80, and at least half as many of them as the
# place with the most. The device is the object a D3D9 game calls the most
# different methods of up there (render states, textures, transforms, draws,
# shaders: 25 or more in a full renderer). The busiest other object is an
# ID3DXEffect, called through a dozen or more slots from +0x80 on (SetVector
# at +0x88, SetMatrixTranspose at +0xB0, SetTexture at +0xD0), which can be
# half of the device's; its vtable ends at +0x138, before the draws. The
# floor and the half hold out a class of the game's own whose vtable reaches
# the draw slots.
_MIN_DEVICE_METHODS = 12
_DRAW_METHODS = frozenset(spec.slot * 4 for spec in D3D9_METHODS.values() if spec.name in (
    "DrawPrimitive", "DrawIndexedPrimitive", "DrawPrimitiveUP", "DrawIndexedPrimitiveUP"))

_PROVENANCE_REACH = 512         # bytes before a hit that the object's origin is followed back
_MAX_FIELD_HOPS = 2             # [[[g]+a]+b]: fields followed from the global to the object


def _instructions_back_from(text_data, text_va, site_va):
    """The instructions before *site_va*, newest first, as far back as they decode with certainty.

    Steps back one trusted stretch (see _trusted_start) at a time, so a walk
    that finds what it needs close to the site decodes no further.
    """
    end = site_va
    while site_va - end < _PROVENANCE_REACH:
        start = _trusted_start(text_data, text_va, end)
        if start is None or start == end:
            return
        yield from reversed(list(_decoder.disasm(text_data[start - text_va:end - text_va], start)))
        end = start


def _global_load_chain(back, reg, jump_targets, max_loads):
    """Follow *reg* back through register copies and loads from [base+disp] to the global it was read from.

    Passes a call when *reg* is one it preserves, and a conditional jump by
    its fall-through, like the argument walk.

    Args:
        back: Instructions before the point where *reg* is read, newest first.

    Returns:
        (global address, [displacement of each load, outermost first]), or
        None when the chain does not reach a global: it meets a join, a
        jump, a return, a call that clobbers the register, any write other
        than a mov, a load from the stack, or more than *max_loads* loads.
    """
    displacements = []
    for insn in back:
        if _joined_after(insn, jump_targets):
            return None
        flow = _flow(insn)
        if flow is _Flow.CALL and reg in _CALLEE_SAVED or flow is _Flow.CONDITIONAL:
            continue
        if flow is not _Flow.STRAIGHT:
            return None
        if not _writes(insn, reg):
            continue
        if not _is_whole_register_mov(insn):
            return None
        source = insn.operands[1]
        if source.type == x86.X86_OP_REG:
            reg = source.reg
            continue
        if source.type != x86.X86_OP_MEM:
            return None
        mem = source.mem
        if mem.index != x86.X86_REG_INVALID or mem.segment != x86.X86_REG_INVALID:
            return None
        if mem.base == x86.X86_REG_INVALID:
            return mem.disp & 0xFFFFFFFF, displacements
        if mem.base in (x86.X86_REG_ESP, x86.X86_REG_EBP) or len(displacements) == max_loads:
            return None
        displacements.append(mem.disp)
        reg = mem.base
    return None


def object_origin(text_data, text_va, site_va):
    """The global the object a scan hit calls a method of was read from, and the fields in between.

    Follows the register the method pointer is read through back to the
    load of the vtable, mov vt, [obj], and obj back through register copies
    and loads, across calls for a register they preserve. A later call
    through a loaded method pointer is followed back to that load first.

    Args:
        site_va: A hit of scan_vtable_calls or scan_vtable_mov.

    Returns:
        The object's location as text: "[0x009D915C]" for an object read
        from a global, "[[0x009D915C]+0x1C]" for one read from a field of
        such an object. None when the code before the hit does not lead
        back to a global, or the vtable is not read from the start of the
        object.
    """
    back = _instructions_back_from(text_data, text_va, site_va)
    jump_targets = _jump_targets(text_data, text_va)
    vtable_reg = _vtable_register(text_data, text_va, site_va)
    if vtable_reg is None:
        method_reg = _site_instruction(text_data, text_va, site_va).operands[0].reg
        chain = _global_load_chain(back, method_reg, jump_targets, _MAX_FIELD_HOPS + 2)
    else:
        chain = _global_load_chain(back, vtable_reg, jump_targets, _MAX_FIELD_HOPS + 1)
    if chain is None:
        return None
    address, displacements = chain
    if vtable_reg is None:
        displacements = displacements[1:]   # the first is the load of the method pointer out of the vtable
    if not displacements or displacements[0] != 0:
        return None
    location = f"[0x{address:08X}]"
    for disp in reversed(displacements[1:]):
        sign = "-" if disp < 0 else "+"
        location = f"[{location}{sign}0x{abs(disp):X}]"
    return location


@lru_cache(maxsize=2)
def device_origins(text_data, text_va):
    """Where the code keeps its IDirect3DDevice9, learned from the calls at and above vtable+0x80.

    Scans every device method from vtable+0x80 on, once per code section,
    and keeps the object locations (see object_origin) that the hits on them
    draw with and call enough different methods of (see _MIN_DEVICE_METHODS).

    Returns:
        frozenset of locations, empty when none qualifies: the game reaches
        its device in a way object_origin does not follow, such as a field
        of `this`.
    """
    methods_by_origin = {}
    for offset in DEVICE:
        if offset < DEVICE_LOW_SLOT_END:
            continue
        hits = scan_vtable_calls(text_data, text_va, offset) + scan_vtable_mov(text_data, text_va, offset)
        for va, _ in hits:
            origin = object_origin(text_data, text_va, va)
            if origin is not None:
                methods_by_origin.setdefault(origin, set()).add(offset)
    if not methods_by_origin:
        return frozenset()
    most = max(len(methods) for methods in methods_by_origin.values())
    needed = max(_MIN_DEVICE_METHODS, (most + 1) // 2)
    return frozenset(origin for origin, methods in methods_by_origin.items()
                     if len(methods) >= needed and methods & _DRAW_METHODS)


class DeviceHits(NamedTuple):
    """Scan hits of one device method, split by whether their object is shown to be the device.

    Attributes:
        confirmed: Hits at vtable+0x80 and above, and hits below it whose
            object is read from a place device_origins learned.
        unconfirmed: The other hits below vtable+0x80: calls of that slot
            on an object not shown to be the device.
    """
    confirmed: list
    unconfirmed: list


def split_device_hits(text_data, text_va, vtable_offset, hits):
    """Split *hits* of the device method at *vtable_offset* into confirmed and unconfirmed device calls.

    Args:
        hits: [(va, description), ...] from scan_vtable_calls or scan_vtable_mov.

    Returns:
        DeviceHits, each list in the order of *hits*.
    """
    if vtable_offset >= DEVICE_LOW_SLOT_END:
        return DeviceHits(list(hits), [])
    origins = device_origins(text_data, text_va)
    confirmed, unconfirmed = [], []
    for hit in hits:
        is_device = object_origin(text_data, text_va, hit[0]) in origins
        (confirmed if is_device else unconfirmed).append(hit)
    return DeviceHits(confirmed, unconfirmed)


def device_origin_summary(text_data, text_va):
    """One line for a report: where the device was learned to live, or that no place was learned."""
    origins = device_origins(text_data, text_va)
    if not origins:
        return ("Device location: none learned from the calls at vtable+0x80 and above (the device "
                "is not read from a global or a field of one); every call below vtable+0x80 is unconfirmed")
    return (f"Device location, learned from the calls at vtable+0x80 and above: {', '.join(sorted(origins))}. "
            "Calls below vtable+0x80 on other objects are unconfirmed")


# ═══════════════════════════════════════════════════════════════════════
# ID3DXConstantTable methods in vtable order (d3dx9shader.h)
# ═══════════════════════════════════════════════════════════════════════

# The interface derives from ID3DXBuffer, so its own methods start after
# IUnknown's three and ID3DXBuffer's two. x86 vtable offset = index * 4.
# (name, declared parameter count without `this`); every parameter is a dword.
D3DX_CONSTANT_TABLE_METHODS = (
    ("QueryInterface", 2), ("AddRef", 0), ("Release", 0),
    ("GetBufferPointer", 0), ("GetBufferSize", 0),
    ("GetDesc", 1), ("GetConstantDesc", 3), ("GetSamplerIndex", 1),
    ("GetConstant", 2), ("GetConstantByName", 2), ("GetConstantElement", 2),
    ("SetDefaults", 1), ("SetValue", 4),
    ("SetBool", 3), ("SetBoolArray", 4), ("SetInt", 3), ("SetIntArray", 4),
    ("SetFloat", 3), ("SetFloatArray", 4), ("SetVector", 3), ("SetVectorArray", 4),
    ("SetMatrix", 3), ("SetMatrixArray", 4), ("SetMatrixPointerArray", 4),
    ("SetMatrixTranspose", 3), ("SetMatrixTransposeArray", 4),
    ("SetMatrixTransposePointerArray", 4),
)

# ID3DXConstantTable: declared parameter count by x86 vtable offset, for the scans
D3DX_CONSTANT_TABLE = {slot * 4: param_count
                       for slot, (_name, param_count) in enumerate(D3DX_CONSTANT_TABLE_METHODS)}
