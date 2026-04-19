#!/bin/bash
# PreToolUse — validates retools commands have a reachable --project path.

INPUT=$(cat)
CMD=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null)

if ! echo "$CMD" | grep -qE 'python -m retools\.(decompiler|context|callgraph|xrefs|datarefs|structrefs|sigdb|bootstrap)'; then
    exit 0
fi

PROJECT=$(echo "$CMD" | grep -oP '(?<=--project )\S+')
if [ -z "$PROJECT" ]; then
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ ! -d "$REPO_ROOT/$PROJECT" ] && [ ! -d "$PROJECT" ]; then
    echo "ERROR: --project path '$PROJECT' does not exist. Check patches/<GameName> spelling." >&2
    exit 2
fi
