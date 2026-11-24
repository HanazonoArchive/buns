#!/usr/bin/env bash
# Portable setup for Linux and macOS: downloads Python, Node.js, a Java
# runtime, OWASP ZAP and OWASP Juice Shop into portable/runtime, installs the
# back-end packages and builds the front end. Nothing is installed system-wide.
#
#   ./portable/setup.sh              everything
#   ./portable/setup.sh --no-zap     skip ZAP and Java (scans use cURL probes only)
#   ./portable/setup.sh --force      re-extract everything
#
# Downloads are cached in portable/cache. To prepare a machine with no
# internet, run setup on a connected machine of the same OS, then copy the
# whole project folder.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
RT="$HERE/runtime"
CACHE="$HERE/cache"
# shellcheck disable=SC1091
source "$HERE/versions.env"

WITH_ZAP=1
WITH_JUICE=1
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --no-zap) WITH_ZAP=0 ;;
    --no-juice-shop) WITH_JUICE=0 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die()  { printf '\n\033[31mSetup stopped:\033[0m %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required. Install it with your package manager (it is preinstalled on macOS)."
command -v tar  >/dev/null || die "tar is required."

# -- platform -----------------------------------------------------------------
case "$(uname -s)" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) die "Unsupported OS $(uname -s). On Windows use setup-portable.cmd." ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=x64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) die "Unsupported CPU $(uname -m)." ;;
esac

if [[ $OS == linux ]]; then
  PY_TRIPLE=$([[ $ARCH == x64 ]] && echo x86_64-unknown-linux-gnu || echo aarch64-unknown-linux-gnu)
  NODE_PLAT="linux-$ARCH"; JAVA_OS=linux; JUICE_PKG="linux_${ARCH}.tgz"
else
  PY_TRIPLE=$([[ $ARCH == x64 ]] && echo x86_64-apple-darwin || echo aarch64-apple-darwin)
  NODE_PLAT="darwin-$ARCH"; JAVA_OS=mac
  # Juice Shop publishes macOS packages for Apple silicon only.
  JUICE_PKG=$([[ $ARCH == arm64 ]] && echo "darwin_arm64.zip" || echo "")
fi
JAVA_ARCH=$([[ $ARCH == x64 ]] && echo x64 || echo aarch64)

mkdir -p "$RT" "$CACHE" "$HERE/data" "$HERE/logs" "$HERE/run"

fetch() { # url file
  local url="$1" out="$CACHE/$2"
  if [[ -s "$out" ]]; then info "cached   $2"; return; fi
  info "download $2"
  curl -fL --retry 3 --connect-timeout 20 --progress-bar -o "$out.part" "$url" || die "could not download $url"
  mv "$out.part" "$out"
}

# Extract an archive and move its single top-level folder to $RT/<name>.
unpack() { # file name
  local file="$CACHE/$1" name="$2" tmp="$RT/.tmp-$2"
  if [[ -d "$RT/$name" && $FORCE == 0 ]]; then info "present  runtime/$name"; return; fi
  rm -rf "$tmp" "$RT/$name"; mkdir -p "$tmp"
  case "$file" in
    *.zip) command -v unzip >/dev/null && unzip -q "$file" -d "$tmp" || tar -xf "$file" -C "$tmp" ;;
    *)     tar -xf "$file" -C "$tmp" ;;
  esac
  local top; top="$(find "$tmp" -mindepth 1 -maxdepth 1)"
  if [[ $(printf '%s\n' "$top" | wc -l) -eq 1 && -d "$top" ]]; then mv "$top" "$RT/$name"; else mv "$tmp" "$RT/$name"; fi
  rm -rf "$tmp"
  info "unpacked runtime/$name"
}

# -- Python ---------------------------------------------------------------------
say "Python $PYTHON_VERSION"
PY_FILE="cpython-${PYTHON_VERSION}+${PYTHON_BUILD}-${PY_TRIPLE}-install_only.tar.gz"
fetch "https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_BUILD}/${PY_FILE/+/%2B}" "$PY_FILE"
unpack "$PY_FILE" python
PY="$RT/python/bin/python3"
"$PY" -m pip install --disable-pip-version-check --no-warn-script-location -q -r "$ROOT/backend/requirements.txt"
info "back-end packages installed"

# -- Node.js ----------------------------------------------------------------------
say "Node.js $NODE_MAJOR"
if [[ -z "${NODE_VERSION:-}" ]]; then
  NODE_VERSION="$(curl -fsSL "https://nodejs.org/dist/latest-v${NODE_MAJOR}.x/SHASUMS256.txt" \
    | grep -o "node-v${NODE_MAJOR}\.[0-9]*\.[0-9]*-${NODE_PLAT}\.tar\.gz" | head -1 \
    | sed -E 's/^node-v([0-9.]+)-.*/\1/')" || true
  [[ -n "$NODE_VERSION" ]] || die "could not look up the latest Node.js $NODE_MAJOR release. Set NODE_VERSION=22.x.y and retry."
fi
NODE_FILE="node-v${NODE_VERSION}-${NODE_PLAT}.tar.gz"
fetch "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_FILE}" "$NODE_FILE"
unpack "$NODE_FILE" node
export PATH="$RT/node/bin:$PATH"

say "Front end"
( cd "$ROOT/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent ) > "$HERE/logs/frontend-build.log" 2>&1 \
  || die "front-end build failed; see portable/logs/frontend-build.log"
rm -rf "$ROOT/backend/static" && cp -R "$ROOT/frontend/dist" "$ROOT/backend/static"
info "built and copied to backend/static"

# -- Java + ZAP --------------------------------------------------------------------
if [[ $WITH_ZAP == 1 ]]; then
  say "Java runtime $JAVA_MAJOR"
  JAVA_FILE="temurin-jre-${JAVA_MAJOR}-${JAVA_OS}-${JAVA_ARCH}.tar.gz"
  fetch "https://api.adoptium.net/v3/binary/latest/${JAVA_MAJOR}/ga/${JAVA_OS}/${JAVA_ARCH}/jre/hotspot/normal/eclipse" "$JAVA_FILE"
  unpack "$JAVA_FILE" jre

  say "OWASP ZAP $ZAP_VERSION"
  ZAP_FILE="ZAP_${ZAP_VERSION}_Crossplatform.zip"
  fetch "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/${ZAP_FILE}" "$ZAP_FILE"
  unpack "$ZAP_FILE" zap
else
  say "Skipping ZAP (--no-zap): scans will run the cURL probes only."
fi

# -- Juice Shop ----------------------------------------------------------------------
if [[ $WITH_JUICE == 1 ]]; then
  say "OWASP Juice Shop $JUICE_SHOP_VERSION"
  if [[ -z "$JUICE_PKG" ]]; then
    info "Juice Shop has no prebuilt package for Intel Macs. Run it another way and keep it on http://localhost:${PORT_JUICE_SHOP}."
  else
    JS_FILE="juice-shop-${JUICE_SHOP_VERSION}_node${NODE_MAJOR}_${JUICE_PKG}"
    fetch "https://github.com/juice-shop/juice-shop/releases/download/v${JUICE_SHOP_VERSION}/${JS_FILE}" "$JS_FILE"
    unpack "$JS_FILE" juice-shop
  fi
fi

cat > "$RT/manifest.txt" <<EOF
os=$OS
arch=$ARCH
python=$PYTHON_VERSION
node=$NODE_VERSION
java=$([[ $WITH_ZAP == 1 ]] && echo "$JAVA_MAJOR" || echo none)
zap=$([[ $WITH_ZAP == 1 ]] && echo "$ZAP_VERSION" || echo none)
juice_shop=$([[ $WITH_JUICE == 1 && -n "$JUICE_PKG" ]] && echo "$JUICE_SHOP_VERSION" || echo none)
EOF

say "Done. Start everything with:  ./portable/start.sh"
du -sh "$RT" 2>/dev/null | awk '{print "  runtime size: " $1}'
