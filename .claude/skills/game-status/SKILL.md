---
name: game-status
description: Show analysis status for a game patch. Usage: /game-status <GameName>. Shows KB entry count, Ghidra project status, findings summary, and build state.
allowed-tools: Bash
---

Show analysis status for: $ARGUMENTS

Run the following and present results clearly:

```bash
GAME="$ARGUMENTS"
PATCH="patches/$GAME"

if [ ! -d "$PATCH" ]; then
  echo "No patch found at $PATCH"
  exit 1
fi

KB="$PATCH/kb.h"
KB_COUNT=0
KB_BOOTSTRAPPED="no"
if [ -f "$KB" ]; then
  KB_COUNT=$(grep -cE '^[@$]|^struct |^enum ' "$KB" 2>/dev/null || echo 0)
  [ "$KB_COUNT" -gt 50 ] && KB_BOOTSTRAPPED="yes"
fi

GHIDRA_GPR=$(find "$PATCH/ghidra" -name "*.gpr" 2>/dev/null | head -1)
GHIDRA_STATUS="not analyzed"
[ -n "$GHIDRA_GPR" ] && GHIDRA_STATUS="ready ($(basename "$GHIDRA_GPR"))"

FINDINGS="$PATCH/findings.md"
FINDINGS_LINES=0
FINDINGS_TAIL="none"
if [ -f "$FINDINGS" ]; then
  FINDINGS_LINES=$(wc -l < "$FINDINGS")
  FINDINGS_TAIL=$(tail -3 "$FINDINGS")
fi

FINDINGS_R2="$PATCH/findings_r2.md"
FINDINGS_R2_LINES=0
[ -f "$FINDINGS_R2" ] && FINDINGS_R2_LINES=$(wc -l < "$FINDINGS_R2")

BUILD_DLL=$(find "$PATCH/build" -name "d3d9.dll" 2>/dev/null | head -1)
BUILD_STATUS="not built"
if [ -n "$BUILD_DLL" ]; then
  BUILD_DATE=$(stat -c "%y" "$BUILD_DLL" 2>/dev/null | cut -d' ' -f1)
  BUILD_STATUS="built ($BUILD_DATE)"
fi

echo "=== $GAME ==="
echo "KB entries    : $KB_COUNT  (bootstrapped: $KB_BOOTSTRAPPED)"
echo "Ghidra        : $GHIDRA_STATUS"
echo "findings.md   : $FINDINGS_LINES lines"
echo "findings_r2.md: $FINDINGS_R2_LINES lines"
echo "Build         : $BUILD_STATUS"
echo ""
echo "--- Latest findings ---"
echo "$FINDINGS_TAIL"
```
