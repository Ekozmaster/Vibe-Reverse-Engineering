#!/bin/bash
# Stop hook — detaches any live livetools daemon so stale .state.json doesn't accumulate.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
python -m livetools detach --force 2>/dev/null || true
