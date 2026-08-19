#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="vps-bootstrap"
CHECKOUT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${VPS_BOOTSTRAP_INSTALL_DIR:-/opt/vps-bootstrap}"
BIN_PATH="${VPS_BOOTSTRAP_BIN:-/usr/local/bin/vps-bootstrap}"
CURRENT_LINK="$INSTALL_DIR/current"
RELEASES_DIR="$INSTALL_DIR/releases"
STAGE="init"

log() {
  printf '[%s] %s\n' "$STAGE" "$*"
}

fail() {
  printf '\n[ERROR] bootstrap failed at stage: %s\n' "$STAGE" >&2
  printf '%s\n' "$*" >&2
  printf '\nAfter fixing the problem, run:\n\n  sudo bash bootstrap.sh\n\n' >&2
  exit 1
}

on_error() {
  local exit_code=$?
  printf '\n[ERROR] bootstrap failed at stage: %s (exit code %s)\n' "$STAGE" "$exit_code" >&2
  printf 'Diagnostic commands:\n\n' >&2
  printf '  cat /etc/os-release\n' >&2
  printf '  sudo dpkg --audit\n' >&2
  printf '  sudo apt-get check\n' >&2
  printf '\nAfter fixing the problem, run:\n\n  sudo bash bootstrap.sh\n\n' >&2
}
trap on_error ERR

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

validate_install_dir() {
  if [ -z "$INSTALL_DIR" ] || [ "$INSTALL_DIR" = "/" ]; then
    fail "Refusing unsafe install directory: $INSTALL_DIR"
  fi
  case "$INSTALL_DIR" in
    */vps-bootstrap|vps-bootstrap)
      ;;
    *)
      fail "Refusing install directory that is not named vps-bootstrap: $INSTALL_DIR"
      ;;
  esac
}

supported_ubuntu_versions() {
  sed -n '/^[[:space:]]*supported:[[:space:]]*$/,/^[^[:space:]]/s/^[[:space:]]*-[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CHECKOUT_ROOT/versions.yml"
}

project_version() {
  sed -n '/^project:[[:space:]]*$/,/^[^[:space:]]/s/^[[:space:]]*version:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$CHECKOUT_ROOT/versions.yml" | head -n 1
}

STAGE="os-check"
if [ ! -r /etc/os-release ]; then
  fail "Cannot read /etc/os-release. This bootstrap supports Ubuntu only."
fi

# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "ubuntu" ]; then
  fail "Unsupported OS: ${PRETTY_NAME:-unknown}. This release targets Ubuntu 24.04."
fi

SUPPORTED_UBUNTU="$(supported_ubuntu_versions | tr '\n' ' ')"
case " ${SUPPORTED_UBUNTU:-24.04} " in
  *" ${VERSION_ID:-unknown} "*)
    log "Ubuntu ${VERSION_ID} detected"
    ;;
  *)
    fail "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Supported Ubuntu versions: ${SUPPORTED_UBUNTU:-24.04}."
    ;;
esac

STAGE="privileges"
if [ "$(id -u)" -ne 0 ]; then
  fail "Run this script with sudo or as root: sudo bash bootstrap.sh"
fi
log "root privileges available"

STAGE="apt-precheck"
require_command apt-get
require_command dpkg

if command -v fuser >/dev/null 2>&1; then
  if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
    fail "apt/dpkg lock is currently held. Wait for unattended upgrades or another apt process to finish."
  fi
fi

dpkg --audit
apt-get check
log "apt/dpkg pre-checks passed"

STAGE="apt-update"
export DEBIAN_FRONTEND=noninteractive
apt-get update
log "package index updated"

STAGE="bootstrap-packages"
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  git \
  python3 \
  python3-venv \
  iproute2
log "bootstrap dependencies installed"

STAGE="install-layout"
validate_install_dir
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0755 "$RELEASES_DIR"
VERSION="$(project_version)"
RELEASE_ID="${VERSION:-unknown}-$(date -u +%Y%m%dT%H%M%SZ)-$$"
RELEASE_DIR="$RELEASES_DIR/$RELEASE_ID"
RELEASE_VENV_DIR="$RELEASE_DIR/venv"
NEXT_LINK="$INSTALL_DIR/current.next"

if [ -e "$CURRENT_LINK" ] && [ ! -L "$CURRENT_LINK" ]; then
  fail "$CURRENT_LINK exists but is not a symlink. Refusing to overwrite unmanaged install layout."
fi
if [ -e "$NEXT_LINK" ] && [ ! -L "$NEXT_LINK" ]; then
  fail "$NEXT_LINK exists but is not a symlink. Remove it manually after inspection."
fi

install -d -m 0755 "$RELEASE_DIR"
cp -R "$CHECKOUT_ROOT/app" "$RELEASE_DIR/app"
cp -R "$CHECKOUT_ROOT/ansible" "$RELEASE_DIR/ansible"
cp -R "$CHECKOUT_ROOT/templates" "$RELEASE_DIR/templates"
cp "$CHECKOUT_ROOT/requirements.txt" "$RELEASE_DIR/requirements.txt"
cp "$CHECKOUT_ROOT/versions.yml" "$RELEASE_DIR/versions.yml"
chmod -R go-w "$RELEASE_DIR"
chmod 0644 "$RELEASE_DIR/requirements.txt" "$RELEASE_DIR/versions.yml"
log "project release staged: $RELEASE_DIR"

STAGE="python-venv"
python3 -m venv "$RELEASE_VENV_DIR"
"$RELEASE_VENV_DIR/bin/python" -m pip install --requirement "$RELEASE_DIR/requirements.txt"
chmod -R go-w "$RELEASE_DIR"
log "virtual environment ready: $RELEASE_VENV_DIR"

STAGE="install-switch"
rm -f "$NEXT_LINK"
ln -s "$RELEASE_DIR" "$NEXT_LINK"
mv -Tf "$NEXT_LINK" "$CURRENT_LINK"
log "active release switched: $CURRENT_LINK -> $RELEASE_DIR"

STAGE="command-wrapper"
cat > "$BIN_PATH" <<EOF
#!/usr/bin/env bash
export VPS_BOOTSTRAP_PROJECT_ROOT="$CURRENT_LINK"
export PYTHONPATH="$CURRENT_LINK\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$CURRENT_LINK/venv/bin/python" -m app.cli "\$@"
EOF
chmod 0755 "$BIN_PATH"
log "command installed: $BIN_PATH"

STAGE="cli"
export VPS_BOOTSTRAP_PROJECT_ROOT="$CURRENT_LINK"
export PYTHONPATH="$CURRENT_LINK${PYTHONPATH:+:$PYTHONPATH}"
exec "$CURRENT_LINK/venv/bin/python" -m app.cli "$@"
