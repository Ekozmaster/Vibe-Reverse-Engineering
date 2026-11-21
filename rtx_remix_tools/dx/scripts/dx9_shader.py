"""D3D9 shader bytecode: version tokens, comment blocks and the end token."""
import struct


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


_END_TOKEN = 0x0000FFFF
_COMMENT_OPCODE = 0xFFFE
_DEF_OPCODE = 0x51
_DEF_OPERANDS = 5           # the register, then four floats
_OPERAND_TOKEN = 0x80000000  # set in every register operand, clear in opcode tokens


def _tokens(data, offset, end):
    """Walk the tokens after the version token at *offset*, up to the end token or *end*.

    A comment's payload and an instruction's operands are stepped over
    whole: a float constant or the text of a comment can hold any dword,
    the end token's value included. From shader model 2 on an opcode token
    counts its operands in bits 24-27. Shader model 1 opcodes carry no
    count; there every operand has bit 31 set, which no opcode has, except
    the floats of def.

    Yields:
        (position, token, position after its payload or operands) for each
        opcode, comment and end token.
    """
    counted_operands = data[offset + 1] >= 2
    pos = offset + 4
    while pos + 4 <= end:
        token = struct.unpack_from('<I', data, pos)[0]
        after = pos + 4
        if token & _OPERAND_TOKEN:
            pos = after
            continue
        opcode = token & 0xFFFF
        if opcode == _COMMENT_OPCODE:
            after += ((token >> 16) & 0x7FFF) * 4
        elif counted_operands:
            after += ((token >> 24) & 0xF) * 4
        elif opcode == _DEF_OPCODE:
            after += _DEF_OPERANDS * 4
        if after > end:
            return
        yield pos, token, after
        if token == _END_TOKEN:
            return
        pos = after


def find_shader_end(data, offset, max_scan=65536):
    """Find the END token (0x0000FFFF) of the shader bytecode at *offset*.

    Returns byte length including end token, or None.
    """
    end = min(offset + max_scan, len(data))
    for pos, token, _after in _tokens(data, offset, end):
        if token == _END_TOKEN:
            return (pos + 4) - offset
    return None


def comments(data, offset, byte_len):
    """The comment blocks of the shader bytecode at *offset*, *byte_len* bytes long.

    Yields:
        (start, end) of each comment's payload.
    """
    for pos, token, after in _tokens(data, offset, offset + byte_len):
        if token & 0xFFFF == _COMMENT_OPCODE:
            yield pos + 4, after
