#!/usr/bin/env bash
# Start Juice Shop, ZAP and buns from portable/runtime (after setup.sh).
#   ./portable/start.sh             start everything and open the browser
#   ./portable/start.sh --no-open   do not open the browser
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
RT="$HERE/runtime"
DATA="$HERE/data"; LOGS="$HERE/logs"; RUN="$HERE/run"
# shellcheck disable=SC1091
source "$HERE/versions.env"
OPEN=1; [[ "${1:-}" == "--no-open" ]] && OPEN=0

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

[[ -x "$RT/python/bin/python3" && -d "$ROOT/backend/static" ]] || die "Run ./portable/setup.sh first."
mkdir -p "$DATA" "$LOGS" "$RUN"

# Rebuild the interface if its code changed since the last build (e.g. after git pull).
WEB="$ROOT/frontend"
INDEX="$ROOT/backend/static/index.html"
if [[ -x "$RT/node/bin/node" ]] && { [[ ! -f "$INDEX" ]] || \
     [[ -n "$(find "$WEB/src" "$WEB/index.html" "$WEB/package.json" "$WEB/package-lock.json" -newer "$INDEX" -print -quit 2>/dev/null)" ]]; }; then
  say "Interface code changed; rebuilding it (about a minute)"
  (
    export PATH="$RT/node/bin:$PATH"
    cd "$WEB"
    if [[ ! -d node_modules || package-lock.json -nt node_modules/.package-lock.json ]]; then
      npm install --no-audit --no-fund --loglevel=error
    fi
    npm run build
  ) > "$LOGS/frontend-build.log" 2>&1 || die "Rebuilding the interface failed; see portable/logs/frontend-build.log"
  rm -rf "$ROOT/backend/static" && cp -R "$WEB/dist" "$ROOT/backend/static"
  info "interface rebuilt"
fi

# Values from .env (KEY=VALUE lines), without overriding the environment.
if [[ -f "$ROOT/.env" ]]; then
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" == \#* ]] && continue
    value="${value%\"}"; value="${value#\"}"; value="${value%$'\r'}"
    [[ -z "${!key:-}" ]] && export "$key=$value"
  done < "$ROOT/.env"
fi
ZAP_KEY="${ZAP_API_KEY:-}"
if [[ -z "$ZAP_KEY" || "$ZAP_KEY" == change-me* ]]; then
  [[ -s "$DATA/zap-api-key" ]] || "$RT/python/bin/python3" -c "import secrets;print(secrets.token_hex(16))" > "$DATA/zap-api-key"
  ZAP_KEY="$(cat "$DATA/zap-api-key")"
fi

alive()     { [[ -s "$RUN/$1.pid" ]] && kill -0 "$(cat "$RUN/$1.pid")" 2>/dev/null; }
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
up()        { curl -fsS -o /dev/null --max-time 3 "$1" 2>/dev/null; }

launch() { # name port workdir cmd...
  local name="$1" port="$2" dir="$3"; shift 3
  if alive "$name"; then info "$name already running (pid $(cat "$RUN/$name.pid"))"; return 0; fi
  if port_busy "$port"; then
    info "$name: port $port is already in use by another program; stop it or change PORT_* in portable/versions.env"
    return 1
  fi
  ( cd "$dir" && exec nohup "$@" ) > "$LOGS/$name.log" 2>&1 &
  echo $! > "$RUN/$name.pid"
  info "$name started (pid $!, log portable/logs/$name.log)"
}

wait_for() { # name url seconds
  local i
  for ((i = 0; i < $3; i++)); do
    up "$2" && { info "$1 ready"; return 0; }
    alive "$1" || { info "$1 exited; last lines of its log:"; tail -n 15 "$LOGS/$1.log" | sed 's/^/    /'; return 1; }
    sleep 1
  done
  info "$1 is still starting; it will be picked up when ready"
}

say "Starting the buns lab"

if [[ -d "$RT/juice-shop" ]]; then
  launch juice-shop "$PORT_JUICE_SHOP" "$RT/juice-shop" env PORT="$PORT_JUICE_SHOP" "$RT/node/bin/node" build/app.js
else
  info "Juice Shop not installed; expecting it on http://localhost:$PORT_JUICE_SHOP"
fi

ZAP_JAR="$(ls "$RT"/zap/zap-*.jar 2>/dev/null | head -1)"
JAVA="$RT/jre/bin/java"; [[ -x "$RT/jre/Contents/Home/bin/java" ]] && JAVA="$RT/jre/Contents/Home/bin/java"
if [[ -n "$ZAP_JAR" && -x "$JAVA" ]]; then
  launch zap "$PORT_ZAP" "$RT/zap" "$JAVA" -Xmx1024m -jar "$ZAP_JAR" -daemon -silent \
    -host 127.0.0.1 -port "$PORT_ZAP" -dir "$DATA/zap-home" -config api.key="$ZAP_KEY"
else
  info "ZAP not installed; scans will run the cURL probes only"
fi

export BUNS_DATABASE_URL="sqlite:///$DATA/buns.db"
export BUNS_DATA_DIR="$DATA"
export BUNS_SEED_TARGET="${BUNS_SEED_TARGET:-http://localhost:$PORT_JUICE_SHOP}"
export ZAP_URL="http://127.0.0.1:$PORT_ZAP"
export ZAP_API_KEY="$ZAP_KEY"
export PYTHONUNBUFFERED=1
launch buns "$PORT_BUNS" "$ROOT/backend" "$RT/python/bin/python3" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT_BUNS" \
  || die "buns could not start."

wait_for buns "http://127.0.0.1:$PORT_BUNS/api/health" 40 || die "buns did not start."
[[ -d "$RT/juice-shop" ]] && wait_for juice-shop "http://127.0.0.1:$PORT_JUICE_SHOP/rest/admin/application-version" 90
[[ -n "$ZAP_JAR" ]] && wait_for zap "http://127.0.0.1:$PORT_ZAP/JSON/core/view/version/?apikey=$ZAP_KEY" 90

URL="http://localhost:$PORT_BUNS"
say "buns is running at $URL"
info "Juice Shop: http://localhost:$PORT_JUICE_SHOP"
info "Stop everything with ./portable/stop.sh"
if [[ $OPEN == 1 ]]; then
  if command -v open >/dev/null && [[ "$(uname -s)" == Darwin ]]; then open "$URL"
  elif command -v xdg-open >/dev/null; then xdg-open "$URL" >/dev/null 2>&1 || true; fi
fi
