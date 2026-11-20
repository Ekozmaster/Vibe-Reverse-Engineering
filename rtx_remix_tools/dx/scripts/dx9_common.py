"""D3D9 binary analysis primitives shared by the DX scanner scripts.

PE32 parsing, byte-pattern scans for IDirect3DDevice9 vtable calls and
method-pointer loads, recovery of the stack arguments in front of such a call,
and the D3D9 enums the scripts decode those arguments with.
"""
import struct
import sys
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from capstone import CS_AC_WRITE, CS_ARCH_X86, CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, Cs
from capstone import x86_const as x86

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from graphics.directx.dx9.tracer.d3d9_methods import D3D9_METHODS


# ═══════════════════════════════════════════════════════════════════════
# PE Parsing
# ═══════════════════════════════════════════════════════════════════════

_PE32_MAGIC = 0x10B
_PE32_PLUS_MAGIC = 0x20B
_OPTIONAL_HEADER_OFFSET = 24
_IMAGE_BASE_OFFSET = 52


def parse_pe(data):
    """Parse PE32 headers. Returns (image_base, sections).

    Each section: dict with name, va, raw, rawsz, vsz, chars.

    Raises:
        ValueError: *data* is not a PE file, or is not a 32-bit one.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a PE file (no MZ header)")
    pe_sig_off = struct.unpack_from("<I", data, 0x3C)[0]
    if (data[pe_sig_off:pe_sig_off + 4] != b"PE\0\0"
            or len(data) < pe_sig_off + _IMAGE_BASE_OFFSET + 4):
        raise ValueError("not a PE file (no PE signature)")
    magic = struct.unpack_from("<H", data, pe_sig_off + _OPTIONAL_HEADER_OFFSET)[0]
    if magic == _PE32_PLUS_MAGIC:
        raise ValueError("64-bit binary (PE32+); these scanners read 32-bit D3D9 call sites only")
    if magic != _PE32_MAGIC:
        raise ValueError(f"not a PE32 file (optional header magic 0x{magic:X})")
    image_base = struct.unpack_from("<I", data, pe_sig_off + _IMAGE_BASE_OFFSET)[0]
    num_sections = struct.unpack_from("<H", data, pe_sig_off + 6)[0]
    opt_hdr_size = struct.unpack_from("<H", data, pe_sig_off + 20)[0]
    section_start = pe_sig_off + 24 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = section_start + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        s_vsz = struct.unpack_from("<I", data, off + 8)[0]
        s_va = struct.unpack_from("<I", data, off + 12)[0]
        s_rawsz = struct.unpack_from("<I", data, off + 16)[0]
        s_raw = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({
            'name': name, 'va': s_va, 'raw': s_raw,
            'rawsz': s_rawsz, 'vsz': s_vsz, 'chars': chars,
        })
    return image_base, sections


def va_to_offset(sections, image_base, va):
    """Convert virtual address to file offset. Returns None if unmapped."""
    rva = va - image_base
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vsz']:
            return rva - s['va'] + s['raw']
    return None


def offset_to_va(sections, image_base, file_off):
    """Convert file offset to virtual address. Returns None if unmapped."""
    for s in sections:
        if s['raw'] <= file_off < s['raw'] + s['rawsz']:
            return image_base + s['va'] + (file_off - s['raw'])
    return None


def get_executable_sections(data, image_base, sections):
    """Return list of (raw_offset, raw_size, section_va) for code sections."""
    result = []
    for s in sections:
        if s['chars'] & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            result.append((s['raw'], s['rawsz'], image_base + s['va']))
    return result


def get_data_sections(data, image_base, sections):
    """Return list of (raw_offset, raw_size, section_va) for data sections."""
    result = []
    for s in sections:
        if s['chars'] & 0x40000000 and not (s['chars'] & 0x20000000):
            result.append((s['raw'], s['rawsz'], image_base + s['va']))
    return result


def find_text_section(data, image_base, sections):
    """Return (raw_offset, raw_size, section_va) for first executable section."""
    for s in sections:
        if s['chars'] & 0x20000000:
            return s['raw'], s['rawsz'], image_base + s['va']
    return None, None, None


# ═══════════════════════════════════════════════════════════════════════
# Pattern Scanning
# ═══════════════════════════════════════════════════════════════════════

# ModRM r/m values of the registers that can be a base without a SIB byte
_GP_REGS = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx', 5: 'ebp', 6: 'esi', 7: 'edi'}

# ModRM mod bits: mod 10 takes a disp32, mod 01 a disp8
_MOD_DISP32 = 0x80
_MOD_DISP8 = 0x40
_MAX_DISP8 = 0x7F
_CALL_REG = 2 << 3      # reg field of "call r/m32" (FF /2)

# IDirect3DDevice9: declared parameter count by x86 vtable offset, `this` not counted
DEVICE = {spec.slot * 4: spec.argc for spec in D3D9_METHODS.values()}


def _displacement_encodings(vtable_offset):
    """(mod bits, displacement bytes) of every way [reg+vtable_offset] is encoded.

    Compilers use the one-byte displacement for the first 32 vtable slots.
    """
    encodings = [(_MOD_DISP32, struct.pack('<I', vtable_offset))]
    if vtable_offset <= _MAX_DISP8:
        encodings.append((_MOD_DISP8, bytes([vtable_offset])))
    return encodings


def _find_all(text_data, text_va, pattern):
    pos = text_data.find(pattern)
    while pos != -1:
        yield text_va + pos
        pos = text_data.find(pattern, pos + 1)


def scan_vtable_calls(text_data, text_va, vtable_offset, interface=DEVICE):
    """Find COM method calls: call [reg+vtable_offset], in the disp32 and the disp8 encoding.

    A hit counts only when it is a whole call instruction that is not shown
    to be a call of another method (see _is_com_method_call).

    Args:
        interface: Declared parameter count by vtable offset of the interface
            whose method is sought.

    Returns: [(va, reg_name), ...] in address order.
    """
    param_count = interface.get(vtable_offset)
    results = []
    for mod_bits, displacement in _displacement_encodings(vtable_offset):
        for rm, reg_name in _GP_REGS.items():
            pattern = bytes([0xFF, mod_bits | _CALL_REG | rm]) + displacement
            results.extend((va, reg_name) for va in _find_all(text_data, text_va, pattern)
                           if _is_com_method_call(text_data, text_va, va, param_count))
    results.sort()
    return results


def scan_vtable_mov(text_data, text_va, vtable_offset, interface=DEVICE):
    """Find method-pointer loads: mov reg, [reg+vtable_offset] that the code then calls through.

    Both the disp32 and the disp8 encoding. A load counts only when it is a
    whole instruction and a call through the loaded register follows it, so a
    read of a data field that happens to sit at the same offset is left out,
    and when that call is not shown to be a call of another method (see
    _is_com_method_call).

    Args:
        interface: Declared parameter count by vtable offset of the interface
            whose method is sought.

    Returns: [(va, description), ...] in address order.
    """
    param_count = interface.get(vtable_offset)
    results = []
    for mod_bits, displacement in _displacement_encodings(vtable_offset):
        for src_idx, src_name in _GP_REGS.items():
            for dst_idx, dst_name in _GP_REGS.items():
                pattern = bytes([0x8B, mod_bits | (dst_idx << 3) | src_idx]) + displacement
                description = f"mov {dst_name}, [{src_name}+0x{vtable_offset:03X}]"
                results.extend((va, description) for va in _find_all(text_data, text_va, pattern)
                               if _is_com_method_call(text_data, text_va, va, param_count))
    results.sort()
    return results


def scan_all_patterns(text_data, text_va, vtable_offset, interface=DEVICE):
    """Find call and mov patterns for a vtable offset of *interface*.

    Returns: [(va, description), ...]
    """
    results = [(va, f"call [{reg}+0x{vtable_offset:03X}]")
               for va, reg in scan_vtable_calls(text_data, text_va, vtable_offset, interface)]
    results.extend(scan_vtable_mov(text_data, text_va, vtable_offset, interface))
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
_LOOKAHEAD = 64         # bytes after a method-pointer load searched for the call through it

_FLOW_GROUPS = (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET)


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

    *site_va* itself when none is. None when no decoding ends exactly at
    *site_va*: the site then lies inside another instruction, or in data.
    """
    site_off = site_va - text_va
    first = max(0, site_off - _LOOKBACK)

    # following[o]: where the instruction at offset o ends, kept only for
    # offsets from which decoding arrives exactly at the site
    following = {}
    for off in range(site_off - 1, first - 1, -1):
        insn = next(_decoder.disasm_lite(text_data[off:off + _MAX_INSN], text_va + off), None)
        if insn is None:
            continue
        end = off + insn[1]
        if end == site_off or end in following:
            following[off] = end
    if not following:
        return None

    arriving = sorted(following)
    voters = [off for off in arriving if off < site_off - _TRUSTED] or arriving[:1]
    passing = dict.fromkeys(arriving, 0)
    for off in voters:
        passing[off] = 1
    for off in arriving:
        if following[off] != site_off:
            passing[following[off]] += passing[off]

    certain = [off for off in arriving
               if off >= site_off - _TRUSTED and passing[off] == len(voters)]
    return text_va + (certain[0] if certain else site_off)


def _instructions_before_call(text_data, text_va, site_va):
    """Instructions that run just before the call a scan hit leads to, oldest first.

    The hit is either the call itself, or a load of the method pointer into a
    register that is then called; the load and what runs between it and the
    call are part of the list. The last instruction ends where the call
    starts. None when the hit is not an instruction, or leads to no call (a
    field that happens to sit at the method's offset).
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

    Empty when the site is the call. None when it is neither a call nor a
    load of a register that the code then calls through, before any other
    call, unconditional jump or return and before the register is
    overwritten. A conditional jump is passed by its fall-through: compilers
    often test something between loading a method and calling it.
    """
    site_off = site_va - text_va
    ahead = _decoder.disasm(text_data[site_off:site_off + _LOOKAHEAD], site_va)
    site = next(ahead, None)
    if site is None:
        return None
    if site.id == x86.X86_INS_CALL:
        return []
    if site.id != x86.X86_INS_MOV or site.operands[0].type != x86.X86_OP_REG:
        return None

    method_reg = site.operands[0].reg
    path = [site]
    for insn in ahead:
        if insn.id == x86.X86_INS_CALL:
            target = insn.operands[0]
            called_through_it = target.type == x86.X86_OP_REG and target.reg == method_reg
            return path if called_through_it else None
        if insn.id == x86.X86_INS_JMP or any(insn.group(group) for group in _FLOW_GROUPS
                                             if group != CS_GRP_JUMP):
            return None
        if method_reg in insn.regs_access()[1]:
            return None
        path.append(insn)
    return None


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


@lru_cache(maxsize=2)
def _jump_targets(text_data, text_va):
    """Every address a direct jump in the code section goes to.

    One linear sweep of the whole section, so a jump is found however far it
    is from its target and whichever side of it. Data in the section decodes
    into jumps that do not exist; their targets only make the argument walk
    stop early.
    """
    sweep = Cs(CS_ARCH_X86, CS_MODE_32)
    sweep.skipdata = True
    targets = set()
    for _address, _size, mnemonic, operands in sweep.disasm_lite(text_data, text_va):
        if mnemonic[0] == 'j' or mnemonic.startswith('loop'):
            try:
                targets.add(int(operands, 16))
            except ValueError:
                pass  # through a register or memory: no target to read
    return frozenset(targets)


class _StackWalk(NamedTuple):
    """What the walk back from a call found on the stack.

    Attributes:
        slots: Slot -> the StackArg written there, or None for a write whose
            dword the walk cannot read. Only slots the walk saw written.
        bounded: The walk ended where nothing older can be on the stack for
            the call: at an earlier call, at a change of esp it cannot follow,
            or at the entry of the code (after a ret, a jmp or int3 padding).
            False when it ended at a join, an indexed store or the start of
            the instructions it was given, or once every slot was written.
    """
    slots: dict
    bounded: bool


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
    fall-through. The walk ends at anything else that moves the stack pointer
    or transfers control, at a store whose address depends on a register,
    and before an instruction followed by an address in *jump_targets*:
    another path joins there, and what it put on the stack is not in front
    of us.

    Returns:
        _StackWalk.
    """
    slots = {}
    pushed = 0              # dwords pushed between this point and the end
    for insn in reversed(insns):
        if all(slot in slots for slot in range(count)):
            return _StackWalk(slots, bounded=False)
        if insn.address + insn.size in jump_targets:
            return _StackWalk(slots, bounded=False)
        if insn.id == x86.X86_INS_PUSH:
            slots.setdefault(pushed, _stack_arg(insn, insn.operands[0], insn.op_str))
            pushed += 1
            continue
        if insn.group(CS_GRP_JUMP) and insn.id != x86.X86_INS_JMP:
            continue    # the call is on its fall-through path
        if any(insn.group(group) for group in _FLOW_GROUPS):
            return _StackWalk(slots, bounded=True)
        if x86.X86_REG_ESP in insn.regs_access()[1]:
            popped = _dwords_released(insn)
            if popped is None:
                return _StackWalk(slots, bounded=True)
            pushed -= popped
            continue
        stores = _stack_stores(insn)
        if any(store.mem.index != x86.X86_REG_INVALID for store in stores):
            return _StackWalk(slots, bounded=False)
        for store in stores:
            _settle_store(slots, pushed, insn, store)
    return _StackWalk(slots, bounded=False)


def _dwords_released(insn):
    """How many dwords *insn* takes off the stack: pop reg, add esp, imm or sub esp, imm (negative).

    None for any other write to esp, or a constant that is not whole dwords.
    """
    if insn.id == x86.X86_INS_POP and insn.operands[0].type == x86.X86_OP_REG:
        return 1
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
# A call through the sought slot may belong to another class. Two things the
# code in front of the call can show drop it; when it shows neither, the call
# is kept.
#
# Argument count: a stdcall method finds its parameters and `this` on the
# stack, so the code must have put that many dwords there. When the walk back
# reaches a point nothing older can come from (an earlier call, a change of
# esp it cannot follow, the entry of the code) with fewer slots written, the
# call takes fewer arguments than the method. More slots never drop a call:
# an outer call's arguments precede an inner one's (f(g(y), x) is push x /
# push y / call g).
#
# COM `this`: `this` is the last thing put on the stack, and it is the object
# the vtable was read from (mov eax, [esi] / push esi / call [eax+X]). An MSVC
# __thiscall method passes `this` in ecx and pushes only its parameters, so
# the dword on top of the stack there is a parameter. The call is dropped when
# the code shows that the top dword differs from the vtable's object, or that
# ecx holds the object. A COM call on another interface that shares the slot
# passes this check.

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
    if param_count is not None and _passes_too_few_arguments(insns, param_count, jump_targets):
        return False
    return not _passes_another_this(text_data, text_va, site_va, insns)


def _passes_too_few_arguments(insns, param_count, jump_targets):
    """Whether the stack is shown to hold fewer than *param_count* + 1 dwords at the call."""
    walk = _walk_stack(insns, param_count + 1, jump_targets)
    return walk.bounded and not all(slot in walk.slots for slot in range(param_count + 1))


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
    site = next(_decoder.disasm(text_data[site_va - text_va:site_va - text_va + _MAX_INSN], site_va))
    [method_slot] = [op for op in site.operands if op.type == x86.X86_OP_MEM]
    site_index = next((k for k, insn in enumerate(insns) if insn.address == site_va), len(insns))
    load_index = _last_write(insns, site_index, method_slot.mem.base, jump_targets)
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


def _is_register_copy(insn):
    return insn.id == x86.X86_INS_MOV and insn.operands[1].type == x86.X86_OP_REG


def _object_of_vtable_load(insn):
    """obj when *insn* is mov reg, [obj]; None for any other instruction."""
    if insn.id != x86.X86_INS_MOV or insn.operands[1].type != x86.X86_OP_MEM:
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
        if insn.address + insn.size in jump_targets or insn.group(CS_GRP_CALL):
            return k + 1, False
        if insn.id == x86.X86_INS_JMP or any(insn.group(group) for group in _FLOW_GROUPS
                                             if group not in (CS_GRP_JUMP, CS_GRP_CALL)):
            return k + 1, True
    return 0, False


def _writes(insn, reg):
    return reg in insn.regs_access()[1]


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

    A register copy is followed to its source. A load from memory not
    addressed through esp is that memory operand; any other write is the
    instruction that made it. A register the run does not write is its value
    on entry to the run, or _UNKNOWN when another path joins or a call
    intervenes before it.
    """
    first, entered = _straight_line_start(insns, index, jump_targets)
    for k in range(index - 1, first - 1, -1):
        insn = insns[k]
        if not _writes(insn, reg):
            continue
        if insn.id == x86.X86_INS_MOV:
            source = insn.operands[1]
            if source.type == x86.X86_OP_REG:
                return _register_value(insns, k, source.reg, jump_targets)
            if source.type == x86.X86_OP_MEM and source.mem.base != x86.X86_REG_ESP:
                return _memory_value(source)
        return ("written by", insn.address)
    return ("on entry", reg) if entered else _UNKNOWN


def _operand_value(insns, index, operand, jump_targets):
    """The value of *operand*, a register or memory, as insns[index] reads it."""
    if operand.type == x86.X86_OP_REG:
        return _register_value(insns, index, operand.reg, jump_targets)
    if operand.mem.base == x86.X86_REG_ESP:
        return ("written by", insns[index].address)
    return _memory_value(operand)


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


def method_immediates(text_data, text_va, site_va, method):
    """Like method_args, keeping only immediates.

    Returns:
        {"this": ..., <parameter name>: ...} with the immediate put on the
        stack for each argument, or None where the argument came from a
        register or memory, or was not recovered.
    """
    args = method_args(text_data, text_va, site_va, method)
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
# at least half as many different device methods at and above vtable+0x80 as
# the place with the most, and at least _MIN_DEVICE_METHODS. The device is the
# object a D3D9 game calls by far the most different methods of up there
# (render states, textures, transforms, draws, shaders: 25 or more in a full
# renderer); the other objects that reach those slots, an ID3DXEffect
# (SetFloatArray at +0x80, SetVector at +0x88, SetMatrix at +0x98) or the
# game's own large classes, are called through fewer than ten of them. The
# floor holds them out when the device itself lives where it cannot be
# learned, and the half keeps a busy effect out beside a device global.
_MIN_DEVICE_METHODS = 12

_PROVENANCE_REACH = 512         # bytes before a hit that the object's origin is followed back
_MAX_FIELD_HOPS = 2             # [[[g]+a]+b]: fields followed from the global to the object
_CALLEE_SAVED = frozenset((x86.X86_REG_EBX, x86.X86_REG_ESI, x86.X86_REG_EDI, x86.X86_REG_EBP))


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


def _global_load_chain(back, reg, jump_targets):
    """Follow *reg* back through register copies and loads from [base+disp] to the global it was read from.

    Passes a call when *reg* is one it preserves, and a conditional jump by
    its fall-through, like the argument walk.

    Args:
        back: Instructions before the point where *reg* is read, newest first.

    Returns:
        (global address, [displacement of each load, outermost first]), or
        None when the chain does not reach a global: it meets a join, a
        jump, a return, a call that clobbers the register, any write other
        than a mov, a load from the stack, or more than _MAX_FIELD_HOPS
        fields.
    """
    displacements = []
    for insn in back:
        if insn.address + insn.size in jump_targets:
            return None
        if insn.group(CS_GRP_CALL):
            if reg in _CALLEE_SAVED:
                continue
            return None
        if insn.group(CS_GRP_JUMP) and insn.id != x86.X86_INS_JMP:
            continue
        if any(insn.group(group) for group in _FLOW_GROUPS):
            return None
        if not _writes(insn, reg):
            continue
        if insn.id != x86.X86_INS_MOV:
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
        if mem.base in (x86.X86_REG_ESP, x86.X86_REG_EBP) or len(displacements) > _MAX_FIELD_HOPS:
            return None
        displacements.append(mem.disp)
        reg = mem.base
    return None


def object_origin(text_data, text_va, site_va):
    """The global the object a scan hit calls a method of was read from, and the fields in between.

    Follows the register the method pointer is read through back to the
    load of the vtable, mov vt, [obj], and obj back through register copies
    and loads, across calls for a register they preserve.

    Args:
        site_va: A hit of scan_vtable_calls or scan_vtable_mov.

    Returns:
        The object's location as text: "[0x009D915C]" for an object read
        from a global, "[[0x009D915C]+0x1C]" for one read from a field of
        such an object. None when the code before the hit does not lead
        back to a global, or the vtable is not read from the start of the
        object.
    """
    site = next(_decoder.disasm(text_data[site_va - text_va:site_va - text_va + _MAX_INSN], site_va))
    [method_slot] = [op for op in site.operands if op.type == x86.X86_OP_MEM]
    back = _instructions_back_from(text_data, text_va, site_va)
    chain = _global_load_chain(back, method_slot.mem.base, _jump_targets(text_data, text_va))
    if chain is None:
        return None
    address, displacements = chain
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
    call enough different methods of (see _MIN_DEVICE_METHODS).

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
    return frozenset(origin for origin, methods in methods_by_origin.items() if len(methods) >= needed)


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
# Standard CLI Setup
# ═══════════════════════════════════════════════════════════════════════

def load_binary(path):
    """Read binary + parse PE. Returns (data, image_base, sections).

    Exits with a message for a file these scanners cannot read: one that is
    not a PE, or a 64-bit one.
    """
    data = Path(path).read_bytes()
    try:
        image_base, sections = parse_pe(data)
    except ValueError as exc:
        sys.exit(f"ERROR: {path}: {exc}")
    return data, image_base, sections


def load_text_section(data, image_base, sections):
    """Load first executable section. Returns (text_data, text_va) or exits."""
    raw_start, raw_size, text_va = find_text_section(data, image_base, sections)
    if raw_start is None:
        print("ERROR: no executable section found")
        sys.exit(1)
    return data[raw_start:raw_start + raw_size], text_va


def print_header(data, image_base, sections):
    """Print standard binary info header."""
    _, _, text_va = find_text_section(data, image_base, sections)
    print(f"ImageBase: 0x{image_base:08X}")
    if text_va:
        print(f"Executable section VA: 0x{text_va:08X}")


# ═══════════════════════════════════════════════════════════════════════
# IDirect3DDevice9 Vtable (32-bit, offset = slot * 4)
# ═══════════════════════════════════════════════════════════════════════

D3D9_DEVICE_VTABLE = {
    0x00: "QueryInterface", 0x04: "AddRef", 0x08: "Release",
    0x0C: "TestCooperativeLevel", 0x10: "GetAvailableTextureMem",
    0x14: "EvictManagedResources", 0x18: "GetDirect3D", 0x1C: "GetDeviceCaps",
    0x20: "GetDisplayMode", 0x24: "GetCreationParameters",
    0x28: "SetCursorProperties", 0x2C: "SetCursorPosition", 0x30: "ShowCursor",
    0x34: "CreateAdditionalSwapChain", 0x38: "GetSwapChain",
    0x3C: "GetNumberOfSwapChains", 0x40: "Reset", 0x44: "Present",
    0x48: "GetBackBuffer", 0x4C: "GetRasterStatus", 0x50: "SetDialogBoxMode",
    0x54: "SetGammaRamp", 0x58: "GetGammaRamp", 0x5C: "CreateTexture",
    0x60: "CreateVolumeTexture", 0x64: "CreateCubeTexture",
    0x68: "CreateVertexBuffer", 0x6C: "CreateIndexBuffer",
    0x70: "CreateRenderTarget", 0x74: "CreateDepthStencilSurface",
    0x78: "UpdateSurface", 0x7C: "UpdateTexture", 0x80: "GetRenderTargetData",
    0x84: "GetFrontBufferData", 0x88: "StretchRect", 0x8C: "ColorFill",
    0x90: "CreateOffscreenPlainSurface", 0x94: "SetRenderTarget",
    0x98: "GetRenderTarget", 0x9C: "SetDepthStencilSurface",
    0xA0: "GetDepthStencilSurface", 0xA4: "BeginScene", 0xA8: "EndScene",
    0xAC: "Clear", 0xB0: "SetTransform", 0xB4: "GetTransform",
    0xB8: "MultiplyTransform", 0xBC: "SetViewport", 0xC0: "GetViewport",
    0xC4: "SetMaterial", 0xC8: "GetMaterial", 0xCC: "SetLight",
    0xD0: "GetLight", 0xD4: "LightEnable", 0xD8: "GetLightEnable",
    0xDC: "SetClipPlane", 0xE0: "GetClipPlane", 0xE4: "SetRenderState",
    0xE8: "GetRenderState", 0xEC: "CreateStateBlock", 0xF0: "BeginStateBlock",
    0xF4: "EndStateBlock", 0xF8: "SetClipStatus", 0xFC: "GetClipStatus",
    0x100: "GetTexture", 0x104: "SetTexture", 0x108: "GetTextureStageState",
    0x10C: "SetTextureStageState", 0x110: "GetSamplerState",
    0x114: "SetSamplerState", 0x118: "ValidateDevice",
    0x11C: "SetPaletteEntries", 0x120: "GetPaletteEntries",
    0x124: "SetCurrentTexturePalette", 0x128: "GetCurrentTexturePalette",
    0x12C: "SetScissorRect", 0x130: "GetScissorRect",
    0x134: "SetSoftwareVertexProcessing", 0x138: "GetSoftwareVertexProcessing",
    0x13C: "SetNPatchMode", 0x140: "GetNPatchMode",
    0x144: "DrawPrimitive", 0x148: "DrawIndexedPrimitive",
    0x14C: "DrawPrimitiveUP", 0x150: "DrawIndexedPrimitiveUP",
    0x154: "ProcessVertices", 0x158: "CreateVertexDeclaration",
    0x15C: "SetVertexDeclaration", 0x160: "GetVertexDeclaration",
    0x164: "SetFVF", 0x168: "GetFVF", 0x16C: "CreateVertexShader",
    0x170: "SetVertexShader", 0x174: "GetVertexShader",
    0x178: "SetVertexShaderConstantF", 0x17C: "GetVertexShaderConstantF",
    0x180: "SetVertexShaderConstantI", 0x184: "GetVertexShaderConstantI",
    0x188: "SetVertexShaderConstantB", 0x18C: "GetVertexShaderConstantB",
    0x190: "SetStreamSource", 0x194: "GetStreamSource",
    0x198: "SetStreamSourceFreq", 0x19C: "GetStreamSourceFreq",
    0x1A0: "SetIndices", 0x1A4: "GetIndices",
    0x1A8: "CreatePixelShader", 0x1AC: "SetPixelShader",
    0x1B0: "GetPixelShader", 0x1B4: "SetPixelShaderConstantF",
    0x1B8: "GetPixelShaderConstantF", 0x1BC: "SetPixelShaderConstantI",
    0x1C0: "GetPixelShaderConstantI", 0x1C4: "SetPixelShaderConstantB",
    0x1C8: "GetPixelShaderConstantB", 0x1CC: "DrawRectPatch",
    0x1D0: "DrawTriPatch", 0x1D4: "DeletePatch", 0x1D8: "CreateQuery",
}


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


# ═══════════════════════════════════════════════════════════════════════
# D3DRENDERSTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DRS = {
    7: "ZENABLE", 8: "FILLMODE", 9: "SHADEMODE",
    14: "ZWRITEENABLE", 15: "ALPHATESTENABLE", 16: "LASTPIXEL",
    19: "SRCBLEND", 20: "DESTBLEND",
    22: "CULLMODE", 23: "ZFUNC", 24: "ALPHAREF", 25: "ALPHAFUNC",
    26: "DITHERENABLE", 27: "ALPHABLENDENABLE",
    28: "FOGENABLE", 29: "SPECULARENABLE",
    34: "FOGCOLOR", 35: "FOGTABLEMODE",
    36: "FOGSTART", 37: "FOGEND", 38: "FOGDENSITY",
    48: "RANGEFOGENABLE",
    52: "STENCILENABLE", 53: "STENCILFAIL", 54: "STENCILZFAIL",
    55: "STENCILPASS", 56: "STENCILFUNC",
    57: "STENCILREF", 58: "STENCILMASK", 59: "STENCILWRITEMASK",
    60: "TEXTUREFACTOR",
    128: "WRAP0", 129: "WRAP1", 130: "WRAP2", 131: "WRAP3",
    132: "WRAP4", 133: "WRAP5", 134: "WRAP6", 135: "WRAP7",
    136: "CLIPPING", 137: "LIGHTING",
    139: "AMBIENT", 140: "FOGVERTEXMODE",
    141: "COLORVERTEX", 142: "LOCALVIEWER", 143: "NORMALIZENORMALS",
    145: "DIFFUSEMATERIALSOURCE", 146: "SPECULARMATERIALSOURCE",
    147: "AMBIENTMATERIALSOURCE", 148: "EMISSIVEMATERIALSOURCE",
    151: "VERTEXBLEND", 152: "CLIPPLANEENABLE",
    154: "POINTSIZE", 155: "POINTSIZE_MIN",
    156: "POINTSPRITEENABLE", 157: "POINTSCALEENABLE",
    158: "POINTSCALE_A", 159: "POINTSCALE_B", 160: "POINTSCALE_C",
    161: "MULTISAMPLEANTIALIAS", 162: "MULTISAMPLEMASK",
    163: "PATCHEDGESTYLE", 165: "DEBUGMONITORTOKEN",
    166: "POINTSIZE_MAX", 167: "INDEXEDVERTEXBLENDENABLE",
    168: "COLORWRITEENABLE",
    170: "TWEENFACTOR", 171: "BLENDOP",
    172: "POSITIONDEGREE", 173: "NORMALDEGREE",
    174: "SCISSORTESTENABLE", 175: "SLOPESCALEDEPTHBIAS",
    176: "ANTIALIASEDLINEENABLE",
    178: "MINTESSELLATIONLEVEL", 179: "MAXTESSELLATIONLEVEL",
    180: "ADAPTIVETESS_X", 181: "ADAPTIVETESS_Y",
    182: "ADAPTIVETESS_Z", 183: "ADAPTIVETESS_W",
    184: "ENABLEADAPTIVETESSELLATION",
    185: "TWOSIDEDSTENCILMODE",
    186: "CCW_STENCILFAIL", 187: "CCW_STENCILZFAIL",
    188: "CCW_STENCILPASS", 189: "CCW_STENCILFUNC",
    190: "COLORWRITEENABLE1", 191: "COLORWRITEENABLE2",
    192: "COLORWRITEENABLE3", 193: "BLENDFACTOR",
    194: "SRGBWRITEENABLE", 195: "DEPTHBIAS",
    198: "WRAP8", 199: "WRAP9", 200: "WRAP10", 201: "WRAP11",
    202: "WRAP12", 203: "WRAP13", 204: "WRAP14", 205: "WRAP15",
    206: "SEPARATEALPHABLENDENABLE",
    207: "SRCBLENDALPHA", 208: "DESTBLENDALPHA", 209: "BLENDOPALPHA",
}

# Render state value sub-enums (for decoding the Value argument)
D3DZBUFFERTYPE = {0: "D3DZB_FALSE", 1: "D3DZB_TRUE", 2: "D3DZB_USEW"}
D3DFILLMODE = {1: "POINT", 2: "WIREFRAME", 3: "SOLID"}
D3DSHADEMODE = {1: "FLAT", 2: "GOURAUD", 3: "PHONG"}
D3DBLEND = {
    1: "ZERO", 2: "ONE", 3: "SRCCOLOR", 4: "INVSRCCOLOR",
    5: "SRCALPHA", 6: "INVSRCALPHA", 7: "DESTALPHA", 8: "INVDESTALPHA",
    9: "DESTCOLOR", 10: "INVDESTCOLOR", 11: "SRCALPHASAT",
    12: "BOTHSRCALPHA", 13: "BOTHINVSRCALPHA",
    14: "BLENDFACTOR", 15: "INVBLENDFACTOR",
    16: "SRCCOLOR2", 17: "INVSRCCOLOR2",
}
D3DCMPFUNC = {
    1: "NEVER", 2: "LESS", 3: "EQUAL", 4: "LESSEQUAL",
    5: "GREATER", 6: "NOTEQUAL", 7: "GREATEREQUAL", 8: "ALWAYS",
}
D3DCULL = {1: "NONE", 2: "CW", 3: "CCW"}
D3DFOGMODE = {0: "NONE", 1: "EXP", 2: "EXP2", 3: "LINEAR"}
D3DSTENCILOP = {
    1: "KEEP", 2: "ZERO", 3: "REPLACE", 4: "INCRSAT",
    5: "DECRSAT", 6: "INVERT", 7: "INCR", 8: "DECR",
}
D3DBLENDOP = {1: "ADD", 2: "SUBTRACT", 3: "REVSUBTRACT", 4: "MIN", 5: "MAX"}
D3DMATERIALCOLORSOURCE = {0: "MATERIAL", 1: "COLOR1", 2: "COLOR2"}
D3DVERTEXBLENDFLAGS = {
    0: "DISABLE", 1: "1WEIGHTS", 2: "2WEIGHTS", 3: "3WEIGHTS", 255: "TWEENING",
}

# Tables that refer to render states name them and resolve the id here, so a
# state's id is written down in exactly one place.
D3DRS_ID = {name: state_id for state_id, name in D3DRS.items()}

_RS_VALUE_DECODERS_BY_NAME = {
    "ZENABLE": D3DZBUFFERTYPE,
    "FILLMODE": D3DFILLMODE,
    "SHADEMODE": D3DSHADEMODE,
    "SRCBLEND": D3DBLEND,
    "DESTBLEND": D3DBLEND,
    "CULLMODE": D3DCULL,
    "ZFUNC": D3DCMPFUNC,
    "ALPHAFUNC": D3DCMPFUNC,
    "FOGTABLEMODE": D3DFOGMODE,
    "STENCILFAIL": D3DSTENCILOP,
    "STENCILZFAIL": D3DSTENCILOP,
    "STENCILPASS": D3DSTENCILOP,
    "STENCILFUNC": D3DCMPFUNC,
    "FOGVERTEXMODE": D3DFOGMODE,
    "DIFFUSEMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "SPECULARMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "AMBIENTMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "EMISSIVEMATERIALSOURCE": D3DMATERIALCOLORSOURCE,
    "VERTEXBLEND": D3DVERTEXBLENDFLAGS,
    "BLENDOP": D3DBLENDOP,
    "CCW_STENCILFAIL": D3DSTENCILOP,
    "CCW_STENCILZFAIL": D3DSTENCILOP,
    "CCW_STENCILPASS": D3DSTENCILOP,
    "CCW_STENCILFUNC": D3DCMPFUNC,
    "SRCBLENDALPHA": D3DBLEND,
    "DESTBLENDALPHA": D3DBLEND,
    "BLENDOPALPHA": D3DBLENDOP,
}

# Map render state -> value decoder
RS_VALUE_DECODERS = {
    D3DRS_ID[name]: decoder for name, decoder in _RS_VALUE_DECODERS_BY_NAME.items()
}

# Boolean render states (value is 0/1 = FALSE/TRUE)
RS_BOOL_STATES = {D3DRS_ID[name] for name in (
    "ZWRITEENABLE", "ALPHATESTENABLE", "LASTPIXEL", "DITHERENABLE",
    "ALPHABLENDENABLE", "FOGENABLE", "SPECULARENABLE", "RANGEFOGENABLE",
    "STENCILENABLE", "CLIPPING", "LIGHTING", "COLORVERTEX", "LOCALVIEWER",
    "NORMALIZENORMALS", "POINTSPRITEENABLE", "POINTSCALEENABLE",
    "MULTISAMPLEANTIALIAS", "INDEXEDVERTEXBLENDENABLE", "SCISSORTESTENABLE",
    "ANTIALIASEDLINEENABLE", "ENABLEADAPTIVETESSELLATION",
    "TWOSIDEDSTENCILMODE", "SRGBWRITEENABLE", "SEPARATEALPHABLENDENABLE",
)}

# Render states whose value is a D3DCOLOR
RS_COLOR_STATES = {D3DRS_ID[name] for name in (
    "FOGCOLOR", "TEXTUREFACTOR", "AMBIENT", "BLENDFACTOR",
)}


def decode_rs_value(state_id, value):
    """Decode a render state value to a human-readable string."""
    if state_id in RS_VALUE_DECODERS:
        decoder = RS_VALUE_DECODERS[state_id]
        return decoder.get(value, f"0x{value:X}")
    if state_id in RS_BOOL_STATES:
        return "TRUE" if value else "FALSE"
    if state_id in RS_COLOR_STATES:
        return f"ARGB(0x{value:08X})"
    return str(value)


# ═══════════════════════════════════════════════════════════════════════
# D3DTEXTURESTAGESTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DTSS = {
    1: "COLOROP", 2: "COLORARG1", 3: "COLORARG2",
    4: "ALPHAOP", 5: "ALPHAARG1", 6: "ALPHAARG2",
    7: "BUMPENVMAT00", 8: "BUMPENVMAT01",
    9: "BUMPENVMAT10", 10: "BUMPENVMAT11",
    11: "TEXCOORDINDEX",
    22: "BUMPENVLSCALE", 23: "BUMPENVLOFFSET",
    24: "TEXTURETRANSFORMFLAGS",
    26: "COLORARG0", 27: "ALPHAARG0",
    28: "RESULTARG", 32: "CONSTANT",
}

D3DTEXTUREOP = {
    1: "DISABLE", 2: "SELECTARG1", 3: "SELECTARG2",
    4: "MODULATE", 5: "MODULATE2X", 6: "MODULATE4X",
    7: "ADD", 8: "ADDSIGNED", 9: "ADDSIGNED2X",
    10: "SUBTRACT", 11: "ADDSMOOTH",
    12: "BLENDDIFFUSEALPHA", 13: "BLENDTEXTUREALPHA",
    14: "BLENDFACTORALPHA", 15: "BLENDTEXTUREALPHAPM",
    16: "BLENDCURRENTALPHA", 17: "PREMODULATE",
    18: "MODULATEALPHA_ADDCOLOR", 19: "MODULATECOLOR_ADDALPHA",
    20: "MODULATEINVALPHA_ADDCOLOR", 21: "MODULATEINVCOLOR_ADDALPHA",
    22: "BUMPENVMAP", 23: "BUMPENVMAPLUMINANCE",
    24: "DOTPRODUCT3", 25: "MULTIPLYADD", 26: "LERP",
}

D3DTA = {
    0x00: "DIFFUSE", 0x01: "CURRENT", 0x02: "TEXTURE",
    0x03: "TFACTOR", 0x04: "SPECULAR", 0x05: "TEMP", 0x06: "CONSTANT",
}
D3DTA_COMPLEMENT = 0x10
D3DTA_ALPHAREPLICATE = 0x20


def decode_texture_arg(val):
    """Decode a D3DTA_* argument value to string."""
    base = val & 0x0F
    name = D3DTA.get(base, f"0x{base:X}")
    mods = []
    if val & D3DTA_COMPLEMENT:
        mods.append("COMPLEMENT")
    if val & D3DTA_ALPHAREPLICATE:
        mods.append("ALPHAREPLICATE")
    if mods:
        return f"{name} | {'|'.join(mods)}"
    return name


D3DTEXTURETRANSFORMFLAGS = {
    0: "DISABLE", 1: "COUNT1", 2: "COUNT2", 3: "COUNT3", 4: "COUNT4",
    256: "PROJECTED",
}

# Map TSS type -> value decoder
TSS_VALUE_DECODERS = {
    1: D3DTEXTUREOP,    # COLOROP
    4: D3DTEXTUREOP,    # ALPHAOP
}
TSS_ARG_STATES = {2, 3, 5, 6, 26, 27, 28}  # COLORARG1/2, ALPHAARG1/2, ARG0, RESULTARG


def decode_tss_value(state_id, value):
    """Decode a texture stage state value."""
    if state_id in TSS_VALUE_DECODERS:
        return TSS_VALUE_DECODERS[state_id].get(value, f"0x{value:X}")
    if state_id in TSS_ARG_STATES:
        return decode_texture_arg(value)
    if state_id == 11:  # TEXCOORDINDEX
        tci = value >> 16
        idx = value & 0xFFFF
        tci_names = {0: "PASSTHRU", 1: "CAMERASPACENORMAL",
                     2: "CAMERASPACEPOSITION", 3: "CAMERASPACEREFLECTIONVECTOR"}
        return f"{tci_names.get(tci, f'TCI(0x{tci:X})')}, index={idx}"
    if state_id == 24:  # TEXTURETRANSFORMFLAGS
        proj = " | PROJECTED" if value & 256 else ""
        count = value & 0xFF
        return D3DTEXTURETRANSFORMFLAGS.get(count, f"COUNT({count})") + proj
    return str(value)


# ═══════════════════════════════════════════════════════════════════════
# D3DSAMPLERSTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DSAMP = {
    1: "ADDRESSU", 2: "ADDRESSV", 3: "ADDRESSW",
    4: "BORDERCOLOR", 5: "MAGFILTER", 6: "MINFILTER", 7: "MIPFILTER",
    8: "MIPMAPLODBIAS", 9: "MAXMIPLEVEL", 10: "MAXANISOTROPY",
    11: "SRGBTEXTURE", 12: "ELEMENTINDEX", 13: "DMAPOFFSET",
}

D3DTEXF = {0: "NONE", 1: "POINT", 2: "LINEAR", 3: "ANISOTROPIC",
           4: "PYRAMIDALQUAD", 5: "GAUSSIANQUAD"}
D3DTADDRESS = {1: "WRAP", 2: "MIRROR", 3: "CLAMP", 4: "BORDER", 5: "MIRRORONCE"}

SAMP_VALUE_DECODERS = {
    1: D3DTADDRESS, 2: D3DTADDRESS, 3: D3DTADDRESS,  # ADDRESSU/V/W
    5: D3DTEXF, 6: D3DTEXF, 7: D3DTEXF,              # MAG/MIN/MIP FILTER
}
SAMP_BOOL_STATES = {11}  # SRGBTEXTURE


def decode_samp_value(state_id, value):
    """Decode a sampler state value."""
    if state_id in SAMP_VALUE_DECODERS:
        return SAMP_VALUE_DECODERS[state_id].get(value, f"0x{value:X}")
    if state_id in SAMP_BOOL_STATES:
        return "TRUE" if value else "FALSE"
    if state_id == 4:  # BORDERCOLOR
        return f"ARGB(0x{value:08X})"
    return str(value)


# ═══════════════════════════════════════════════════════════════════════
# D3DTRANSFORMSTATETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DTS = {
    2: "VIEW", 3: "PROJECTION",
    16: "TEXTURE0", 17: "TEXTURE1", 18: "TEXTURE2", 19: "TEXTURE3",
    20: "TEXTURE4", 21: "TEXTURE5", 22: "TEXTURE6", 23: "TEXTURE7",
    256: "WORLD",  # D3DTS_WORLDMATRIX(0)
}


def decode_transform_type(val):
    """Decode a D3DTRANSFORMSTATETYPE value."""
    if val in D3DTS:
        return D3DTS[val]
    if 256 <= val < 512:
        return f"WORLDMATRIX({val - 256})"
    return f"UNKNOWN(0x{val:X})"


# ═══════════════════════════════════════════════════════════════════════
# D3DFORMAT
# ═══════════════════════════════════════════════════════════════════════

D3DFMT = {
    0: "UNKNOWN",
    20: "R8G8B8", 21: "A8R8G8B8", 22: "X8R8G8B8",
    23: "R5G6B5", 24: "X1R5G5B5", 25: "A1R5G5B5",
    26: "A4R4G4B4", 27: "R3G3B2", 28: "A8",
    29: "A8R3G3B2", 30: "X4R4G4B4",
    31: "A2B10G10R10", 32: "A8B8G8R8", 33: "X8B8G8R8",
    34: "G16R16", 35: "A2R10G10B10", 36: "A16B16G16R16",
    40: "A8P8", 41: "P8",
    50: "L8", 51: "A8L8", 52: "A4L4",
    60: "V8U8", 61: "L6V5U5", 62: "X8L8V8U8",
    63: "Q8W8V8U8", 64: "V16U16", 67: "A2W10V10U10",
    70: "D16_LOCKABLE", 71: "D32", 73: "D15S1",
    75: "D24S8", 77: "D24X8", 79: "D24X4S4",
    80: "D16", 81: "L16",
    82: "D32F_LOCKABLE", 83: "D24FS8",
    84: "D32_LOCKABLE", 85: "S8_LOCKABLE",
    100: "VERTEXDATA", 101: "INDEX16", 102: "INDEX32",
    110: "Q16W16V16U16",
    111: "R16F", 112: "G16R16F", 113: "A16B16G16R16F",
    114: "R32F", 115: "G32R32F", 116: "A32B32G32R32F",
    117: "CxV8U8",
    # FourCC formats
    0x31545844: "DXT1", 0x32545844: "DXT2", 0x33545844: "DXT3",
    0x34545844: "DXT4", 0x35545844: "DXT5",
    0x59565955: "UYVY", 0x32595559: "YUY2",
    0x47424752: "R8G8_B8G8", 0x42475247: "G8R8_G8B8",
    0x3154454D: "MULTI2_ARGB8",
    # NVIDIA specific
    0x34324E49: "INTZ",  # shadow map depth
    0x46313152: "R1F",   # raw
}


def decode_format(val):
    """Decode D3DFORMAT value."""
    if val in D3DFMT:
        return D3DFMT[val]
    # Try as FourCC
    if val > 0xFF:
        try:
            cc = struct.pack('<I', val).decode('ascii', errors='replace')
            return f"FourCC('{cc}')"
        except Exception:
            pass
    return f"UNKNOWN(0x{val:X})"


# ═══════════════════════════════════════════════════════════════════════
# D3DFVF flags
# ═══════════════════════════════════════════════════════════════════════

D3DFVF_POSITION_MASK = 0x400E

D3DFVF_POSITIONS = {
    0x002: "XYZ", 0x004: "XYZRHW", 0x006: "XYZB1",
    0x008: "XYZB2", 0x00A: "XYZB3", 0x00C: "XYZB4",
    0x00E: "XYZB5", 0x4002: "XYZW",
}

D3DFVF_FLAGS = {
    0x010: "NORMAL", 0x020: "PSIZE",
    0x040: "DIFFUSE", 0x080: "SPECULAR",
}

D3DFVF_TEXCOUNT_SHIFT = 8
D3DFVF_TEXCOUNT_MASK = 0xF00
D3DFVF_LASTBETA_UBYTE4 = 0x1000
D3DFVF_LASTBETA_D3DCOLOR = 0x8000

# Per-texcoord size encoding (bits 16-31, 2 bits per coord)
D3DFVF_TEXCOORDSIZE = {0: "FLOAT2", 1: "FLOAT3", 2: "FLOAT4", 3: "FLOAT1"}

# Size in bytes for each position type
_FVF_POS_SIZES = {
    0x002: 12, 0x004: 16, 0x006: 16, 0x008: 20,
    0x00A: 24, 0x00C: 28, 0x00E: 32, 0x4002: 16,
}
_FVF_TEXCOORD_SIZES = {0: 8, 1: 12, 2: 16, 3: 4}


def decode_fvf(fvf):
    """Decode FVF flags into components and compute stride.

    Returns: (components: list[str], stride: int, tex_count: int)
    """
    components = []
    stride = 0

    # Position
    pos = fvf & D3DFVF_POSITION_MASK
    pos_name = D3DFVF_POSITIONS.get(pos)
    if pos_name:
        components.append(pos_name)
        stride += _FVF_POS_SIZES.get(pos, 0)

    if fvf & D3DFVF_LASTBETA_UBYTE4:
        components.append("LASTBETA_UBYTE4")
    if fvf & D3DFVF_LASTBETA_D3DCOLOR:
        components.append("LASTBETA_D3DCOLOR")

    # Fixed flags
    for bit, name in D3DFVF_FLAGS.items():
        if fvf & bit:
            components.append(name)
            if bit == 0x010:
                stride += 12  # NORMAL = 3 floats
            elif bit == 0x020:
                stride += 4   # PSIZE = 1 float
            elif bit in (0x040, 0x080):
                stride += 4   # DIFFUSE/SPECULAR = D3DCOLOR

    # Texture coordinates
    tex_count = (fvf & D3DFVF_TEXCOUNT_MASK) >> D3DFVF_TEXCOUNT_SHIFT
    if tex_count > 0:
        components.append(f"TEX{tex_count}")
        for i in range(tex_count):
            tc_bits = (fvf >> (16 + i * 2)) & 0x3
            tc_name = D3DFVF_TEXCOORDSIZE[tc_bits]
            if tc_bits != 0:  # Non-default (not FLOAT2)
                components.append(f"  TC{i}={tc_name}")
            stride += _FVF_TEXCOORD_SIZES[tc_bits]

    return components, stride, tex_count


# ═══════════════════════════════════════════════════════════════════════
# D3DSTATEBLOCKTYPE
# ═══════════════════════════════════════════════════════════════════════

D3DSTATEBLOCKTYPE = {1: "ALL", 2: "PIXELSTATE", 3: "VERTEXSTATE"}


# ═══════════════════════════════════════════════════════════════════════
# D3DPRIMITIVETYPE
# ═══════════════════════════════════════════════════════════════════════

D3DPRIMTYPE = {
    1: "POINTLIST", 2: "LINELIST", 3: "LINESTRIP",
    4: "TRIANGLELIST", 5: "TRIANGLESTRIP", 6: "TRIANGLEFAN",
}


# ═══════════════════════════════════════════════════════════════════════
# D3DPOOL
# ═══════════════════════════════════════════════════════════════════════

D3DPOOL = {0: "DEFAULT", 1: "MANAGED", 2: "SYSTEMMEM", 3: "SCRATCH"}


# ═══════════════════════════════════════════════════════════════════════
# Shader bytecode helpers
# ═══════════════════════════════════════════════════════════════════════

def validate_shader_token(data, offset):
    """Check if offset points to valid shader bytecode.

    Returns: (shader_type, major, minor) or None.
    shader_type is 'vs' or 'ps'.
    """
    if offset + 4 > len(data):
        return None
    token = struct.unpack_from('<I', data, offset)[0]
    shader_type_bits = (token >> 16) & 0xFFFF
    major = (token >> 8) & 0xFF
    minor = token & 0xFF
    if shader_type_bits == 0xFFFE and 1 <= major <= 3:
        return ('vs', major, minor)
    if shader_type_bits == 0xFFFF and 1 <= major <= 3:
        return ('ps', major, minor)
    return None


def find_shader_end(data, offset, max_scan=65536):
    """Find the END token (0x0000FFFF) in shader bytecode.

    Returns byte length including end token, or None.
    """
    end = min(offset + max_scan, len(data) - 3)
    pos = offset + 4  # skip version token
    while pos < end:
        token = struct.unpack_from('<I', data, pos)[0]
        if token == 0x0000FFFF:
            return (pos + 4) - offset
        pos += 4
    return None
