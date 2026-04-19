#!/bin/bash
# PreToolUse — blocks pyghidra decompile calls when the Ghidra project doesn't exist yet.

INPUT=$(cat)
CMD=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null)

if ! echo "$CMD" | grep -qE 'pyghidra_backend (decompile|callgraph|xrefs|datarefs)|decompiler\.py.*(--backend (pyghidra|auto))'; then
    exit 0
fi

PROJECT=$(echo "$CMD" | grep -oP '(?<=--project )\S+')
if [ -z "$PROJECT" ]; then
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FULL_PROJECT="$REPO_ROOT/$PROJECT"
[ -d "$PROJECT" ] && FULL_PROJECT="$PROJECT"

GPR=$(find "$FULL_PROJECT" -name "*.gpr" 2>/dev/null | head -1)
if [ -z "$GPR" ]; then
    echo "ERROR: No Ghidra project found at '$PROJECT'." >&2
    echo "Run first: python -m retools.pyghidra_backend analyze <binary> --project $PROJECT" >&2
    exit 2
fi
