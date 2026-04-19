#!/bin/bash
# Injected at SessionStart — primes context with game state and verifies tools.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

VERIFY_OUT=$(cd "$REPO_ROOT" && python verify_install.py 2>&1)
if echo "$VERIFY_OUT" | grep -q "WARN"; then
    echo "⚠ verify_install.py reports warnings — run 'python verify_install.py --setup' before static analysis"
    echo "$VERIFY_OUT" | grep "WARN"
fi

PATCHES_DIR="$REPO_ROOT/patches"
if [ ! -d "$PATCHES_DIR" ]; then
    exit 0
fi

GAMES=()
while IFS= read -r -d '' dir; do
    name="$(basename "$dir")"
    GAMES+=("$name")
done < <(find "$PATCHES_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)

if [ ${#GAMES[@]} -eq 0 ]; then
    echo "No game patches found in patches/ — ready for new game setup."
    exit 0
fi

echo "## Active game patches"
for game in "${GAMES[@]}"; do
    GAME_DIR="$PATCHES_DIR/$game"
    KB="$GAME_DIR/kb.h"
    FINDINGS="$GAME_DIR/findings.md"

    KB_COUNT=0
    [ -f "$KB" ] && KB_COUNT=$(grep -cE '^[@$]|^struct |^enum ' "$KB" 2>/dev/null || echo 0)

    LAST_FINDINGS="none"
    [ -f "$FINDINGS" ] && LAST_FINDINGS="$(tail -1 "$FINDINGS" 2>/dev/null)"

    GHIDRA_READY="no"
    [ -d "$GAME_DIR/ghidra" ] && GHIDRA_READY="yes"

    echo "  $game: kb.h=$KB_COUNT entries, ghidra=$GHIDRA_READY, last finding: $LAST_FINDINGS"
done
