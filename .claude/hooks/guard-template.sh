#!/bin/bash
# PreToolUse — blocks writes to the read-only remix-comp-proxy template directory.

INPUT=$(cat)
FILE=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); inp=d.get('tool_input',{}); print(inp.get('file_path', inp.get('path','')))" 2>/dev/null)

if echo "$FILE" | grep -q "rtx_remix_tools/dx/remix-comp-proxy/"; then
    echo "BLOCKED: rtx_remix_tools/dx/remix-comp-proxy/ is a read-only template." >&2
    echo "Per-game changes go in patches/<GameName>/. Copy the template there first." >&2
    exit 2
fi
