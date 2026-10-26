#!/usr/bin/env bash
# Crapplet DDoS Shield - one-command install and upgrade.
#
#   curl -fsSL https://raw.githubusercontent.com/singhhemant80/DDOs-Sheild/main/install.sh | sudo bash
#
# Run the same command again to upgrade. Optional settings go before `bash`, e.g.
#
#   curl -fsSL .../install.sh | sudo SHIELD_ADMIN_USER=hemant SHIELD_MGMT_NETS="10.255.0.0/24" bash
#
#   SHIELD_ADMIN_USER          first administrator (default: admin; first install only)
#   SHIELD_ADMIN_PASSWORD      their password (default: generated and printed once)
#   SHIELD_MGMT_NETS           networks allowed to open the dashboard
#                              (default: "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16")
#   SHIELD_VERSION             release tag to install, e.g. v0.3.0 (default: latest release)
#   SHIELD_BUILD_FROM_SOURCE=1 build from the main branch instead of using a release
#   SHIELD_SEED_EXAMPLE=1      load the example AS154950 inventory on first install
#   SHIELD_DOWNLOAD_ONLY=DIR   prepare the installable tree in DIR and stop (for offline servers:
#                              copy DIR across and run DIR/deploy/scripts/install.sh there)
#
# What it does: downloads a verified release bundle (or builds from source with temporary
# toolchains that are deleted afterwards), then runs deploy/scripts/install.sh, which installs
# PostgreSQL, Redis, ClickHouse and nginx, creates the administrator and serves the dashboard
# over HTTPS to your management networks only. It never changes your firewall.

set -euo pipefail

REPO=${SHIELD_REPO:-singhhemant80/DDOs-Sheild}

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

# Newest-first semantic comparison: is $1 >= $2 ?
version_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }

fetch() { curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 20 "$@"; }

verify_sha256() {  # file expected-hash
  local got
  got=$(sha256sum "$1" | awk '{print $1}')
  [ "$got" = "$2" ] || die "checksum mismatch for $(basename "$1") (expected $2, got $got)"
}

install_prereqs() {
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl tar xz-utils openssl >/dev/null
  elif command -v dnf >/dev/null; then
    dnf install -y -q ca-certificates curl tar xz openssl
  else
    die "unsupported distribution: need Ubuntu/Debian (apt) or AlmaLinux/Rocky (dnf)"
  fi
}

# ---------------------------------------------------------------- release bundle
latest_tag() {
  fetch "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
    | sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' | head -n1
}

get_release() {  # tag arch dest -> 0 on success
  local tag=$1 arch=$2 dest=$3 name base
  name="crapplet-shield-${tag}-linux-${arch}.tar.gz"
  base="https://github.com/$REPO/releases/download/$tag"
  note "downloading $name"
  fetch -o "$WORK/$name" "$base/$name" || return 1
  fetch -o "$WORK/$name.sha256" "$base/$name.sha256" || return 1
  verify_sha256 "$WORK/$name" "$(awk '{print $1}' "$WORK/$name.sha256")"
  note "checksum verified"
  mkdir -p "$dest"
  tar -xzf "$WORK/$name" -C "$dest"
}

# ---------------------------------------------------------------- source build
ensure_go() {  # sets PATH so a Go >= 1.22 is first
  if command -v go >/dev/null && version_ge "$(go env GOVERSION | sed 's/^go//')" 1.22; then
    note "using installed $(go version | awk '{print $3}')"; return
  fi
  local v file
  v=$(fetch "https://go.dev/VERSION?m=text" | head -n1)
  file="$v.linux-$GOARCH_NAME.tar.gz"
  note "downloading $v (temporary, removed after the build)"
  fetch -o "$WORK/$file" "https://dl.google.com/go/$file"
  verify_sha256 "$WORK/$file" "$(fetch "https://dl.google.com/go/$file.sha256")"
  tar -xzf "$WORK/$file" -C "$WORK/toolchain"
  export PATH="$WORK/toolchain/go/bin:$PATH" GOPATH="$WORK/gopath" GOCACHE="$WORK/gocache"
}

ensure_node() {  # sets PATH so a Node >= 20.19 is first
  if command -v node >/dev/null && version_ge "$(node --version | sed 's/^v//')" 20.19.0; then
    note "using installed node $(node --version)"; return
  fi
  local sums line sha file
  sums=$(fetch "https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt")
  line=$(printf '%s\n' "$sums" | grep "linux-$NODEARCH_NAME.tar.xz\$" | head -n1)
  [ -n "$line" ] || die "could not find a Node.js 22 build for linux-$NODEARCH_NAME"
  sha=${line%% *}; file=${line##* }
  note "downloading $file (temporary, removed after the build)"
  fetch -o "$WORK/$file" "https://nodejs.org/dist/latest-v22.x/$file"
  verify_sha256 "$WORK/$file" "$sha"
  tar -xJf "$WORK/$file" -C "$WORK/toolchain"
  export PATH="$WORK/toolchain/${file%.tar.xz}/bin:$PATH" npm_config_cache="$WORK/npm-cache"
}

build_from_source() {  # ref dest
  local ref=$1 dest=$2
  note "fetching source ($ref)"
  mkdir -p "$dest" "$WORK/toolchain"
  fetch "https://codeload.github.com/$REPO/tar.gz/$ref" | tar -xz --strip-components=1 -C "$dest"
  ensure_go
  ensure_node
  say "Building the flow collector"
  (cd "$dest/collector" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/ ./cmd/...)
  say "Building the dashboard"
  (cd "$dest/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent)
  echo "${ref##*/}" > "$dest/VERSION"
}

main() {
  [ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL .../install.sh | sudo bash"
  case "$(uname -m)" in
    x86_64|amd64)  GOARCH_NAME=amd64; NODEARCH_NAME=x64 ;;
    aarch64|arm64) GOARCH_NAME=arm64; NODEARCH_NAME=arm64 ;;
    *) die "unsupported CPU architecture $(uname -m) (need x86_64 or arm64)" ;;
  esac

  say "Crapplet DDoS Shield installer"
  install_prereqs

  WORK=$(mktemp -d /var/tmp/crapplet-shield.XXXXXX)
  trap 'rm -rf "$WORK"' EXIT
  local tree="$WORK/tree"

  if [ "${SHIELD_BUILD_FROM_SOURCE:-0}" != 1 ]; then
    local tag=${SHIELD_VERSION:-}
    [ -n "$tag" ] || tag=$(latest_tag || true)
    if [ -n "$tag" ] && get_release "$tag" "$GOARCH_NAME" "$tree"; then
      note "release $tag ready"
    else
      [ -z "${SHIELD_VERSION:-}" ] || die "release $SHIELD_VERSION not found for linux-$GOARCH_NAME"
      note "no published release found; building from source instead"
      rm -rf "$tree"
      build_from_source "refs/heads/main" "$tree"
    fi
  else
    build_from_source "refs/heads/${SHIELD_BRANCH:-main}" "$tree"
  fi

  if [ -n "${SHIELD_DOWNLOAD_ONLY:-}" ]; then
    mkdir -p "$SHIELD_DOWNLOAD_ONLY"
    cp -a "$tree/." "$SHIELD_DOWNLOAD_ONLY/"
    say "Prepared in $SHIELD_DOWNLOAD_ONLY"
    echo "    Copy it to the server and run: sudo $SHIELD_DOWNLOAD_ONLY/deploy/scripts/install.sh"
    return
  fi

  bash "$tree/deploy/scripts/install.sh" </dev/null
}

# Everything runs inside main so a partially downloaded script never executes.
main "$@"
