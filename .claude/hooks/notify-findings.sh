#!/bin/bash
# PostToolUse — notifies when a subagent writes to findings.md, findings_r2.md, or addresses.json.

INPUT=$(cat)
TOOL=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name',''))" 2>/dev/null)

if [[ "$TOOL" != "Write" && "$TOOL" != "Edit" ]]; then
    exit 0
fi

FILE=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); inp=d.get('tool_input',{}); print(inp.get('file_path', inp.get('path','')))" 2>/dev/null)

if echo "$FILE" | grep -qE 'findings(_r2)?\.md$'; then
    GAME=$(echo "$FILE" | grep -oP 'patches/\K[^/]+')
    echo "findings updated: $GAME — $(tail -1 "$FILE" 2>/dev/null | cut -c1-120)"
fi

if echo "$FILE" | grep -qE 'addresses\.json$'; then
    GAME=$(echo "$FILE" | grep -oP 'patches/\K[^/]+')
    COUNT=$(python3 -c "import json; d=json.load(open('$FILE')); print(len(d.get('addresses',[])))" 2>/dev/null || echo "?")
    echo "addresses.json updated: $GAME — $COUNT entries"
fi
