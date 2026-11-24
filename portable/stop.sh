#!/usr/bin/env bash
# Stop everything started by start.sh.
set -uo pipefail
RUN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run"

stopped=0
for name in buns zap juice-shop; do
  f="$RUN/$name.pid"
  [[ -s "$f" ]] || continue
  pid="$(cat "$f")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    echo "  stopped $name"
    stopped=1
  fi
  rm -f "$f"
done
[[ $stopped == 1 ]] || echo "  nothing was running"
