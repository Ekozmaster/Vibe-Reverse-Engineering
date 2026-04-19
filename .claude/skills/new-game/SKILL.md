---
name: new-game
description: Set up a new game patch from the remix-comp-proxy template. Usage: /new-game <GameName>. Copies the template, creates kb.h and findings stubs, per-game CLAUDE.md, addresses.json, and prints the bootstrap commands to run next.
allowed-tools: Bash, Write
---

Set up a new game patch for: $ARGUMENTS

Run the following steps:

```bash
GAME="$ARGUMENTS"
PATCH="patches/$GAME"
TEMPLATE="rtx_remix_tools/dx/remix-comp-proxy"

if [ -z "$GAME" ]; then
  echo "Usage: /new-game <GameName>"
  exit 1
fi

if [ -d "$PATCH" ]; then
  echo "patches/$GAME already exists — aborting to avoid overwrite."
  exit 1
fi

rsync -a --exclude='build/' "$TEMPLATE/" "$PATCH/"
echo "Copied template to $PATCH/"

cat > "$PATCH/kb.h" << 'KBEOF'
// Game knowledge base — populated by bootstrap.py and manual analysis.
// Pass to all decompiler.py calls via --types patches/GAME/kb.h
KBEOF
echo "Created $PATCH/kb.h"

touch "$PATCH/findings.md"
touch "$PATCH/findings_r2.md"
echo "Created findings stubs"

cat > "$PATCH/addresses.json" << ADDREOF
{
  "game": "$GAME",
  "binary": "",
  "addresses": []
}
ADDREOF
echo "Created $PATCH/addresses.json"

mkdir -p "$PATCH/traces"
echo "Created $PATCH/traces/"

if [ -f ".claude/templates/game-CLAUDE.md" ]; then
  sed "s/<GameName>/$GAME/g" ".claude/templates/game-CLAUDE.md" > "$PATCH/CLAUDE.md"
  echo "Created $PATCH/CLAUDE.md"
fi

echo ""
echo "=== Next steps ==="
echo ""
echo "1. Set binary name in $PATCH/addresses.json and $PATCH/CLAUDE.md"
echo ""
echo "2. Run bootstrap (2-5 min):"
echo "   python -m retools.bootstrap <game.exe> --project $GAME"
echo ""
echo "3. In parallel, run full Ghidra analysis (5-15 min):"
echo "   python -m retools.pyghidra_backend analyze <game.exe> --project $PATCH"
echo ""
echo "4. Find VS constant layout:"
echo "   python rtx_remix_tools/dx/scripts/find_matrix_registers.py <game.exe>"
echo "   python rtx_remix_tools/dx/scripts/classify_draws.py <game.exe>"
echo ""
echo "5. Set WINDOW_CLASS_NAME in $PATCH/src/comp/main.cpp"
echo "6. Edit register layout defaults in $PATCH/src/shared/common/ffp_state.hpp"
echo "   (or use /apply-trace-findings $GAME <trace.jsonl> after a DX9 tracer capture)"
echo ""
echo "7. Build: cd $PATCH && build.bat release --name $GAME"
```
