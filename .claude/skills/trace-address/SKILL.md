---
name: trace-address
description: Generate a livetools trace command from a static analysis address. Usage: /trace-address <GameName> <addr> [read-specs]. Reads patches/<GameName>/addresses.json for known register/stack layout, outputs a ready-to-run livetools trace command.
allowed-tools: Bash, Read
---

Generate livetools trace for: $ARGUMENTS

Parse arguments: first token = GameName, second = address (hex), remainder = optional extra read specs.

```bash
ARGS=($ARGUMENTS)
GAME="${ARGS[0]}"
ADDR="${ARGS[1]}"
EXTRA_SPECS="${ARGS[@]:2}"

PATCH="patches/$GAME"
ADDRS_FILE="$PATCH/addresses.json"

if [ -z "$GAME" ] || [ -z "$ADDR" ]; then
    echo "Usage: /trace-address <GameName> <addr> [extra-read-specs]"
    exit 1
fi

ADDR_NORM=$(echo "$ADDR" | sed 's/^0x//i' | tr '[:lower:]' '[:upper:]')

LABEL=""
READS=""
NOTES=""
if [ -f "$ADDRS_FILE" ]; then
    ENTRY=$(python3 -c "
import json, sys
data = json.load(open('$ADDRS_FILE'))
addr = '$ADDR_NORM'.lower()
for e in data.get('addresses', []):
    if e.get('addr','').lower().lstrip('0') == addr.lstrip('0'):
        print(json.dumps(e))
        break
" 2>/dev/null)
    if [ -n "$ENTRY" ]; then
        LABEL=$(echo "$ENTRY" | python3 -c "import json,sys; e=json.load(sys.stdin); print(e.get('label',''))")
        READS=$(echo "$ENTRY" | python3 -c "import json,sys; e=json.load(sys.stdin); print(';'.join(e.get('read_specs',[])))")
        NOTES=$(echo "$ENTRY" | python3 -c "import json,sys; e=json.load(sys.stdin); print(e.get('notes',''))")
    fi
fi

ALL_READS="$READS"
[ -n "$EXTRA_SPECS" ] && ALL_READS="$ALL_READS;$EXTRA_SPECS"
ALL_READS=$(echo "$ALL_READS" | sed 's/^;//')

echo "=== livetools trace command ==="
echo ""
if [ -n "$LABEL" ]; then
    echo "# $LABEL"
    [ -n "$NOTES" ] && echo "# $NOTES"
fi
echo ""

if [ -n "$ALL_READS" ]; then
    echo "python -m livetools trace 0x$ADDR_NORM --count 50 --read \"$ALL_READS\""
else
    echo "python -m livetools trace 0x$ADDR_NORM --count 50"
fi

echo ""
echo "# To log to file:"
echo "python -m livetools collect --addr 0x$ADDR_NORM --duration 10 --out $PATCH/traces/${ADDR_NORM}.jsonl"
```

## addresses.json format

`patches/<GameName>/addresses.json` stores confirmed addresses from static analysis:

```json
{
  "game": "MyGame",
  "binary": "game.exe",
  "addresses": [
    {
      "addr": "0x5A3210",
      "label": "SetVertexShaderConstantF_callsite",
      "category": "vs_const",
      "read_specs": ["[esp+8]:4:uint32", "[esp+c]:4:uint32", "*[esp+10]:64:float32"],
      "notes": "startReg in esp+8, count in esp+c, data ptr in esp+10"
    }
  ]
}
```

Categories: `vs_const`, `ps_const`, `draw`, `matrix`, `texture`, `render_state`, `skinning`, `misc`
