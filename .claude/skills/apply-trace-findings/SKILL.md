---
name: apply-trace-findings
description: Parse DX9 tracer JSONL --matrix-flow output and auto-patch ffp_state.hpp register defaults. Usage: /apply-trace-findings <GameName> <trace.jsonl>. Reads matrix flow analysis and updates vs_reg_*_start/end defaults in the game's ffp_state.hpp.
allowed-tools: Bash, Read, Edit
---

Apply tracer matrix findings to ffp_state.hpp for: $ARGUMENTS

Parse arguments: first token = GameName, second = path to JSONL trace file.

```bash
ARGS=($ARGUMENTS)
GAME="${ARGS[0]}"
JSONL="${ARGS[1]}"

PATCH="patches/$GAME"
FFP_HPP="$PATCH/src/shared/common/ffp_state.hpp"

if [ -z "$GAME" ] || [ -z "$JSONL" ]; then
    echo "Usage: /apply-trace-findings <GameName> <trace.jsonl>"
    exit 1
fi

if [ ! -f "$JSONL" ]; then
    echo "ERROR: trace file not found: $JSONL"
    exit 1
fi

if [ ! -f "$FFP_HPP" ]; then
    echo "ERROR: ffp_state.hpp not found at $FFP_HPP"
    echo "Has /new-game been run for $GAME?"
    exit 1
fi

echo "Running matrix flow analysis on $JSONL ..."
MATRIX_OUT=$(python -m graphics.directx.dx9.tracer analyze "$JSONL" --matrix-flow 2>&1)
echo "$MATRIX_OUT"
echo ""

VIEW_START=$(echo "$MATRIX_OUT" | grep -i 'view.*c[0-9]' | grep -oP 'c\K[0-9]+(?=-)' | head -1)
VIEW_END=$(echo "$MATRIX_OUT" | grep -i 'view.*c[0-9]' | grep -oP '-c\K[0-9]+' | head -1)
PROJ_START=$(echo "$MATRIX_OUT" | grep -i 'proj.*c[0-9]' | grep -oP 'c\K[0-9]+(?=-)' | head -1)
PROJ_END=$(echo "$MATRIX_OUT" | grep -i 'proj.*c[0-9]' | grep -oP '-c\K[0-9]+' | head -1)
WORLD_START=$(echo "$MATRIX_OUT" | grep -i 'world.*c[0-9]' | grep -oP 'c\K[0-9]+(?=-)' | head -1)
WORLD_END=$(echo "$MATRIX_OUT" | grep -i 'world.*c[0-9]' | grep -oP '-c\K[0-9]+' | head -1)

echo "=== Detected register ranges ==="
echo "View  : c${VIEW_START}-c${VIEW_END}"
echo "Proj  : c${PROJ_START}-c${PROJ_END}"
echo "World : c${WORLD_START}-c${WORLD_END}"
echo ""

if [ -z "$VIEW_START" ] || [ -z "$PROJ_START" ] || [ -z "$WORLD_START" ]; then
    echo "Could not parse all three matrix ranges from tracer output."
    echo "Review the matrix-flow output above and update ffp_state.hpp manually:"
    echo "  $FFP_HPP"
    exit 1
fi

VIEW_END=$((VIEW_END + 1))
PROJ_END=$((PROJ_END + 1))
WORLD_END=$((WORLD_END + 1))

echo "Patching $FFP_HPP ..."
python3 -c "
import re

with open('$FFP_HPP', 'r') as f:
    src = f.read()

replacements = [
    (r'(vs_reg_view_start_\s*=\s*)\d+', r'\g<1>$VIEW_START'),
    (r'(vs_reg_view_end_\s*=\s*)\d+',   r'\g<1>$VIEW_END'),
    (r'(vs_reg_proj_start_\s*=\s*)\d+', r'\g<1>$PROJ_START'),
    (r'(vs_reg_proj_end_\s*=\s*)\d+',   r'\g<1>$PROJ_END'),
    (r'(vs_reg_world_start_\s*=\s*)\d+',r'\g<1>$WORLD_START'),
    (r'(vs_reg_world_end_\s*=\s*)\d+',  r'\g<1>$WORLD_END'),
]

for pattern, repl in replacements:
    src = re.sub(pattern, repl, src)

with open('$FFP_HPP', 'w') as f:
    f.write(src)

print('Done.')
"

echo ""
echo "ffp_state.hpp updated. Rebuild to apply:"
echo "  cd $PATCH && build.bat release --name $GAME"
```
