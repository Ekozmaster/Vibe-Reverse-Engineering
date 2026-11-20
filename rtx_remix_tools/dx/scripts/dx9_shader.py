"""D3D9 shader bytecode: version tokens and the end token."""
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
