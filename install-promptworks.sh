#!/usr/bin/env bash
# Prompt-Works-Sudo-Auth v3.9.1 — side-by-side protected-upgrade installer
#
# Safe order:
#   1) Host dependencies
#   2) Local HTTPS PromptWorks server on this Manjaro/Ubuntu machine
#   3) Linux host identity + one-time pairing master + enrollment token
#   4) Android command-line SDK (no Android Studio)
#   5) ADB connect Pixel, build APK with local server trust + bootstrap values
#   6) Install/launch APK and wait for phone enrollment
#   7) Seal the 1:1 host↔APK binding, destroy pairing server/master, then install offline sudo PAM
#
# Run as a NORMAL desktop user, not root.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ANDROID_DIR="$SCRIPT_DIR/android"
readonly LINUX_DIR="$SCRIPT_DIR/linux"
readonly SERVER_DIR="$SCRIPT_DIR/server"
readonly APP_ID="com.promptworks.sudoauth.secure.v37"
readonly MAIN_ACTIVITY="com.promptworks.authenticator.MainActivity"
readonly COMPILE_SDK="36"
readonly BUILD_TOOLS="36.0.0"
SERVER_PORT="8787"
readonly DEFAULT_SDK_ROOT="${XDG_DATA_HOME:-$HOME/.local/share}/android-sdk"
SERVER_ETC="/etc/promptworks-server"
SERVER_STATE="/var/lib/promptworks-server"
SERVER_INSTALL="/opt/promptworks-auth-server"
readonly ACTIVE_AUTH_DIR="/etc/promptworks-auth"
SERVER_SERVICE="promptworks-auth-server.service"
readonly CANDIDATE_AUTH_DIR="/etc/promptworks-auth-v37-candidate"

APK_ONLY=0
LINUX_ONLY=0
ASSUME_YES=0
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$DEFAULT_SDK_ROOT}}"
LAN_IP=""
TLS_STAGE_DIR="${SCRIPT_DIR}/.promptworks-v391-tls"
SERVER_URL=""
ADMIN_TOKEN=""
PAIRING_MASTER_HEX=""
OFFLINE_SECRET_HEX=""
HOST_ID=""
PAIRING_ID=""
HOST_KEY_FINGERPRINT=""
PAIRED_DEVICE_ID=""
PAIRED_DEVICE_FINGERPRINT=""
ENROLL_TOKEN=""
ENROLL_START_ISO=""
PW_USER_ID="${PW_USER_ID:-$USER}"
MIGRATION_MODE=0
PROVISION_AUTH_DIR="$ACTIVE_AUTH_DIR"
LEGACY_BACKEND_PRESENT=0

usage() {
  cat <<'USAGE'
Prompt-Works-Sudo-Auth v3.9.1 protected-upgrade installer

Usage:
  ./install-promptworks.sh [options]

Options:
  --apk-only     Provision/build/install APK, verify enrollment, then disable the provisioning server; do not touch sudo PAM.
  --linux-only   Install offline Linux PAM using an already-provisioned bound runtime key; no server is started.
  --yes          Auto-accept ordinary confirmations. PAM safety confirmation still remains.
  --help         Show this help.

The v3.9.1 APK uses a NEW Android application ID, so it installs alongside v3.5 and earlier.
If an active PromptWorks backend already exists, it stays active while v3.9.1 is provisioned into
a separate candidate binding. The CURRENT/OLD APK must explicitly approve the backend switch.
After activation, managed PromptWorks component changes require both sudo/root and offline approval from the enrolled APK.
USAGE
}

log()  { printf '\n\033[1;36m[PromptWorks]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

ERROR_REPORTED=0
on_error() {
  local rc=$?
  trap - ERR
  if (( ERROR_REPORTED == 0 )); then
    ERROR_REPORTED=1
    printf '\n\033[1;31mInstallation stopped (exit %d).\033[0m\n' "$rc" >&2
    printf 'The sudo PAM integration is performed only after phone enrollment is verified.\n' >&2
    printf 'Fix the error above and rerun this installer; completed setup stages are designed to be repeatable.\n' >&2
  fi
  return "$rc"
}
trap on_error ERR

for arg in "$@"; do
  case "$arg" in
    --apk-only) APK_ONLY=1 ;;
    --linux-only) LINUX_ONLY=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h) usage; exit 0 ;;
    *) die "Unknown option: $arg (use --help)" ;;
  esac
done
(( APK_ONLY == 1 && LINUX_ONLY == 1 )) && die "--apk-only and --linux-only cannot be used together."
[[ $EUID -ne 0 ]] || die "Run as your normal user, not root: ./install-promptworks.sh"
[[ -r /etc/os-release ]] || die "/etc/os-release is missing."
[[ -d "$SERVER_DIR" && -d "$ANDROID_DIR" && -d "$LINUX_DIR" ]] || die "Run the installer from the complete PromptWorks source tree."
# shellcheck disable=SC1091
. /etc/os-release

confirm() {
  local prompt="$1"
  (( ASSUME_YES == 1 )) && return 0
  local reply
  read -r -p "$prompt [y/N]: " reply
  [[ "$reply" =~ ^[Yy]([Ee][Ss])?$ ]]
}

install_apk_prerequisites() {
  log "Stage 1/12 — Preflight for NEW side-by-side APK (no sudo unless a prerequisite is missing)"

  # Build/install the new APK BEFORE deliberately invoking the existing sudo/PAM stack.
  # This is critical during upgrades: the current/old APK remains the authenticator for
  # every privileged operation until the v3.9.1 candidate is completely provisioned.
  local missing=()
  command -v curl  >/dev/null 2>&1 || missing+=(curl)
  command -v unzip >/dev/null 2>&1 || missing+=(unzip)
  command -v zip   >/dev/null 2>&1 || missing+=(zip)
  command -v adb   >/dev/null 2>&1 || missing+=(adb)

  local java_ok=0
  if command -v java >/dev/null 2>&1 && java -version 2>&1 | head -n1 | grep -Eq '17[.]'; then
    java_ok=1
  elif [[ -x /usr/lib/jvm/java-17-openjdk/bin/java || -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]]; then
    java_ok=1
  fi
  (( java_ok == 1 )) || missing+=(java17)

  if (( ${#missing[@]} == 0 )); then
    ok "APK prerequisites already present. No sudo/PAM request was made before building the new APK."
    return 0
  fi

  warn "Missing APK prerequisites: ${missing[*]}"
  cat <<'AUTH'
These prerequisites are required before the NEW APK can be built.
Because this host already may be protected by PromptWorks, installing missing
packages can require the CURRENT/OLD sudo PAM flow. Use the OLD enrolled APK
for this prerequisite authorization. The backend is NOT switched here.
AUTH
  sudo -K || true
  sudo -v

  case "${ID:-}" in
    manjaro|arch)
      sudo pacman -S --needed --noconfirm curl unzip zip android-tools jdk17-openjdk
      ;;
    ubuntu|debian|linuxmint|pop)
      sudo apt-get update
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl unzip zip adb openjdk-17-jdk
      ;;
    *)
      if [[ " ${ID_LIKE:-} " == *" arch "* ]]; then
        sudo pacman -S --needed --noconfirm curl unzip zip android-tools jdk17-openjdk
      elif [[ " ${ID_LIKE:-} " == *" debian "* ]]; then
        sudo apt-get update
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl unzip zip adb openjdk-17-jdk
      else
        die "Unsupported distro: ${PRETTY_NAME:-${ID:-unknown}}."
      fi
      ;;
  esac
  ok "APK prerequisites ready."
}

install_backend_dependencies() {
  log "Stage 6/12 — Installing/checking Linux backend dependencies"
  cat <<'AUTH'
The NEW v3.9.1 APK is already installed side-by-side.
Privileged setup from this point still uses the CURRENT/OLD PromptWorks PAM
stack. If sudo asks for a PromptWorks challenge, use the OLD enrolled APK.
No trust switch happens until the protected migration stage later.
AUTH
  sudo -K || true
  sudo -v

  case "${ID:-}" in
    manjaro|arch)
      sudo pacman -S --needed --noconfirm \
        base-devel go pam ca-certificates curl unzip zip android-tools jdk17-openjdk \
        python openssl iproute2
      if ! command -v node >/dev/null 2>&1; then sudo pacman -S --needed --noconfirm nodejs; fi
      if ! command -v npm  >/dev/null 2>&1; then sudo pacman -S --needed --noconfirm npm; fi
      ;;
    ubuntu|debian|linuxmint|pop)
      sudo apt-get update
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential golang-go libpam0g-dev libpam-modules libssl-dev ca-certificates curl \
        unzip zip adb openjdk-17-jdk python3 nodejs npm openssl iproute2
      ;;
    *)
      if [[ " ${ID_LIKE:-} " == *" arch "* ]]; then
        sudo pacman -S --needed --noconfirm base-devel go pam ca-certificates curl unzip zip android-tools jdk17-openjdk python openssl iproute2
        if ! command -v node >/dev/null 2>&1; then sudo pacman -S --needed --noconfirm nodejs; fi
        if ! command -v npm  >/dev/null 2>&1; then sudo pacman -S --needed --noconfirm npm; fi
      elif [[ " ${ID_LIKE:-} " == *" debian "* ]]; then
        sudo apt-get update
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential golang-go libpam0g-dev libpam-modules libssl-dev ca-certificates curl unzip zip adb openjdk-17-jdk python3 nodejs npm openssl iproute2
      else
        die "Unsupported distro: ${PRETTY_NAME:-${ID:-unknown}}. Supported: Manjaro/Arch and Ubuntu/Debian families."
      fi
      ;;
  esac
  for cmd in adb java curl unzip node npm openssl ip cc; do command -v "$cmd" >/dev/null || die "Required command missing after package install: $cmd"; done
  ok "Backend dependencies ready."
}

configure_java17() {
  local candidate=""
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]] && "${JAVA_HOME}/bin/java" -version 2>&1 | head -n1 | grep -Eq '17[.]'; then
    candidate="$JAVA_HOME"
  elif [[ -d /usr/lib/jvm/java-17-openjdk ]]; then
    candidate=/usr/lib/jvm/java-17-openjdk
  elif [[ -d /usr/lib/jvm/java-17-openjdk-amd64 ]]; then
    candidate=/usr/lib/jvm/java-17-openjdk-amd64
  else
    local java_bin
    java_bin="$(readlink -f "$(command -v java)")"
    "$java_bin" -version 2>&1 | head -n1 | grep -Eq '17[.]' && candidate="$(dirname "$(dirname "$java_bin")")"
  fi
  [[ -n "$candidate" ]] || die "Java 17 is required but could not be located."
  export JAVA_HOME="$candidate"
  export PATH="$JAVA_HOME/bin:$PATH"
  ok "Using Java 17: $JAVA_HOME"
}

detect_lan_ip() {
  LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  if [[ -z "$LAN_IP" ]]; then
    LAN_IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+\./ && $0 !~ /^127\./ {print; exit}')"
  fi
  if [[ -z "$LAN_IP" ]]; then
    read -r -p "Could not detect this PC's LAN IPv4 address. Enter it manually: " LAN_IP
  fi
  python3 - "$LAN_IP" <<'PY' >/dev/null
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
assert ip.version == 4 and not ip.is_loopback
PY
  SERVER_URL="https://${LAN_IP}:${SERVER_PORT}"
  ok "Local PromptWorks URL will be: $SERVER_URL"
}


choose_candidate_port() {
  # The HTTPS listener exists only for one-time enrollment. Do not make upgrades
  # depend on a hard-coded candidate port that may be held by a stale older
  # candidate process. Pick the first actually bindable high port in our narrow
  # reserved range before the APK bootstrap URL is generated. Runtime approval
  # remains fully offline and does not use this port.
  local chosen
  chosen="$(python3 - <<'PYPORT'
import socket
for port in range(8788, 8899 + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('0.0.0.0', port))
    except OSError:
        s.close()
        continue
    s.close()
    print(port)
    break
PYPORT
)"
  [[ -n "$chosen" ]] || die "No free temporary enrollment port found in 8788-8899."
  if [[ "$chosen" != "8788" ]]; then
    warn "Temporary enrollment port 8788 is occupied; using ${chosen} instead. Runtime sudo approval is still fully offline."
  fi
  SERVER_PORT="$chosen"
}

prepare_candidate_tls_before_apk() {
  log "Stage 4/12 — Creating the NEW APK provisioning trust anchor before APK build"
  detect_lan_ip

  # This is intentionally done BEFORE the APK is built and without sudo. The exact
  # CA embedded in the APK is later installed for the temporary HTTPS server.
  # This prevents a stale/mismatched CA from producing CertPathValidatorException.
  rm -rf "$TLS_STAGE_DIR"
  install -d -m 0700 "$TLS_STAGE_DIR"
  cat >"$TLS_STAGE_DIR/server-ext.cnf" <<CFG
subjectAltName=IP:${LAN_IP}
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
basicConstraints=critical,CA:FALSE
CFG
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 1825 \
    -subj '/CN=PromptWorks v3.9.1 Local Root CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$TLS_STAGE_DIR/ca.key" -out "$TLS_STAGE_DIR/ca.crt" >/dev/null 2>&1
  openssl req -new -newkey rsa:3072 -sha256 -nodes \
    -subj '/CN=PromptWorks Local Auth Server' \
    -keyout "$TLS_STAGE_DIR/server.key" -out "$TLS_STAGE_DIR/server.csr" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 825 -in "$TLS_STAGE_DIR/server.csr" \
    -CA "$TLS_STAGE_DIR/ca.crt" -CAkey "$TLS_STAGE_DIR/ca.key" -CAcreateserial \
    -extfile "$TLS_STAGE_DIR/server-ext.cnf" -out "$TLS_STAGE_DIR/server.crt" >/dev/null 2>&1

  openssl verify -CAfile "$TLS_STAGE_DIR/ca.crt" "$TLS_STAGE_DIR/server.crt" >/dev/null || \
    die "Generated provisioning certificate failed local chain verification."
  openssl x509 -in "$TLS_STAGE_DIR/server.crt" -noout -checkip "$LAN_IP" >/dev/null || \
    die "Generated provisioning certificate does not cover LAN IP $LAN_IP."

  install -m 0644 "$TLS_STAGE_DIR/ca.crt" "$ANDROID_DIR/app/src/main/res/raw/promptworks_server_ca.pem"
  local ca_fp
  ca_fp="$(openssl x509 -in "$TLS_STAGE_DIR/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
  ok "NEW APK CA prepared before build (SHA-256 fingerprint: $ca_fp)."
}

install_local_server() {
  log "Stage 7/12 — Starting isolated NEW-candidate HTTPS backend"
  [[ -n "$LAN_IP" ]] || detect_lan_ip

  # Build TypeScript + native dependency before copying into /opt.
  (
    cd "$SERVER_DIR"
    # npm 12 blocks dependency install scripts unless they are explicitly approved.
    # package.json allowScripts intentionally permits only the two reviewed build dependencies
    # that actually need lifecycle scripts: better-sqlite3 and esbuild.
    npm install --no-audit --no-fund
    npm run build
    # Fail early with a useful error if better-sqlite3's native binding was not built.
    node --input-type=module -e "import Database from 'better-sqlite3'; const db=new Database(':memory:'); db.close();"
  )

  local nologin_shell
  nologin_shell="$(command -v nologin || true)"
  [[ -n "$nologin_shell" ]] || nologin_shell=/usr/sbin/nologin
  sudo id -u promptworks-server >/dev/null 2>&1 || sudo useradd --system --home-dir "$SERVER_STATE" --create-home --shell "$nologin_shell" promptworks-server
  # Public CA certificates must be readable by the normal installer user for curl/ADB bootstrap.
  # Secrets inside these directories keep their own restrictive file modes.
  sudo install -d -o root -g promptworks-server -m 0755 "$SERVER_ETC" "$SERVER_ETC/tls"
  sudo install -d -o promptworks-server -g promptworks-server -m 0750 "$SERVER_STATE"
  sudo install -d -o root -g root -m 0755 "$SERVER_INSTALL"

  # Keep an existing admin token on reruns; otherwise generate a fresh 48-byte secret.
  if sudo test -r "$SERVER_ETC/server.env"; then
    ADMIN_TOKEN="$(sudo awk -F= '$1=="PW_ADMIN_TOKEN"{sub(/^[^=]*=/,"");print;exit}' "$SERVER_ETC/server.env")"
  fi
  [[ ${#ADMIN_TOKEN} -ge 32 ]] || ADMIN_TOKEN="$(openssl rand -base64 48 | tr -d '\n')"

  # Create the permanent Linux host identity and a one-time pairing master. The runtime time-match
  # key is NOT generated yet: it is derived only after the single Pixel public key is enrolled.
  sudo install -d -o root -g root -m 0700 "$PROVISION_AUTH_DIR"
  if sudo test -r "$PROVISION_AUTH_DIR/binding.json"; then
    local already_device
    already_device="$(sudo python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("deviceId","unknown"))' "$PROVISION_AUTH_DIR/binding.json" 2>/dev/null || echo unknown)"
    die "The v3.9.1 provisioning candidate is already bound to $already_device. Remove $PROVISION_AUTH_DIR only if you intentionally want to restart v3.9.1 provisioning."
  fi
  if ! sudo test -r "$PROVISION_AUTH_DIR/host-identity.key.pem"; then
    local hosttmp
    hosttmp="$(mktemp -d)"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$hosttmp/host.key.pem" >/dev/null 2>&1
    openssl pkey -in "$hosttmp/host.key.pem" -pubout -out "$hosttmp/host.pub.pem" >/dev/null 2>&1
    sudo install -o root -g root -m 0400 "$hosttmp/host.key.pem" "$PROVISION_AUTH_DIR/host-identity.key.pem"
    sudo install -o root -g root -m 0444 "$hosttmp/host.pub.pem" "$PROVISION_AUTH_DIR/host-identity.pub.pem"
    rm -rf "$hosttmp"
  fi
  HOST_KEY_FINGERPRINT="$(sudo openssl pkey -pubin -in "$PROVISION_AUTH_DIR/host-identity.pub.pem" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  [[ "$HOST_KEY_FINGERPRINT" =~ ^[0-9a-f]{64}$ ]] || die "Could not fingerprint the Linux host identity key."
  if sudo test -r "$PROVISION_AUTH_DIR/pairing-id"; then
    PAIRING_ID="$(sudo cat "$PROVISION_AUTH_DIR/pairing-id" | tr -d '\r\n')"
  else
    PAIRING_ID="pwbind_$(openssl rand -hex 16)"
    printf '%s\n' "$PAIRING_ID" | sudo tee "$PROVISION_AUTH_DIR/pairing-id" >/dev/null
    sudo chown root:root "$PROVISION_AUTH_DIR/pairing-id"; sudo chmod 0444 "$PROVISION_AUTH_DIR/pairing-id"
  fi
  if sudo test -r "$PROVISION_AUTH_DIR/pairing-master.key"; then
    PAIRING_MASTER_HEX="$(sudo cat "$PROVISION_AUTH_DIR/pairing-master.key" | tr -d '[:space:]')"
  else
    PAIRING_MASTER_HEX="$(openssl rand -hex 32)"
    printf '%s\n' "$PAIRING_MASTER_HEX" | sudo tee "$PROVISION_AUTH_DIR/pairing-master.key" >/dev/null
    sudo chown root:root "$PROVISION_AUTH_DIR/pairing-master.key"; sudo chmod 0400 "$PROVISION_AUTH_DIR/pairing-master.key"
  fi
  [[ "$PAIRING_MASTER_HEX" =~ ^[0-9a-fA-F]{64}$ ]] || die "Pairing master is invalid."
  if sudo test -r "$PROVISION_AUTH_DIR/host-id"; then
    HOST_ID="$(sudo cat "$PROVISION_AUTH_DIR/host-id" | tr -d '\r\n')"
  else
    local mid short
    mid="$(cat /etc/machine-id 2>/dev/null || hostname)"
    short="$(printf '%s' "$mid" | sha256sum | cut -c1-10)"
    HOST_ID="$(hostname)-$short"
    printf '%s\n' "$HOST_ID" | sudo tee "$PROVISION_AUTH_DIR/host-id" >/dev/null
    sudo chown root:root "$PROVISION_AUTH_DIR/host-id"
    sudo chmod 0444 "$PROVISION_AUTH_DIR/host-id"
  fi

  # Install the exact TLS material that was generated BEFORE the APK build.
  # The APK and server therefore share one deterministic trust anchor for this run.
  [[ -r "$TLS_STAGE_DIR/ca.crt" && -r "$TLS_STAGE_DIR/ca.key" && \
     -r "$TLS_STAGE_DIR/server.crt" && -r "$TLS_STAGE_DIR/server.key" ]] || \
    die "Candidate TLS material is missing. Restart the v3.9.1 installer from the beginning."
  openssl verify -CAfile "$TLS_STAGE_DIR/ca.crt" "$TLS_STAGE_DIR/server.crt" >/dev/null || \
    die "Staged server certificate no longer verifies against the APK CA."
  openssl x509 -in "$TLS_STAGE_DIR/server.crt" -noout -checkip "$LAN_IP" >/dev/null || \
    die "Staged server certificate no longer matches LAN IP $LAN_IP."

  sudo install -o root -g root -m 0600 "$TLS_STAGE_DIR/ca.key" "$SERVER_ETC/tls/ca.key"
  sudo install -o root -g root -m 0644 "$TLS_STAGE_DIR/ca.crt" "$SERVER_ETC/tls/ca.crt"
  sudo install -o promptworks-server -g promptworks-server -m 0640 "$TLS_STAGE_DIR/server.key" "$SERVER_ETC/tls/server.key"
  sudo install -o root -g root -m 0644 "$TLS_STAGE_DIR/server.crt" "$SERVER_ETC/tls/server.crt"

  # Refuse to start if the installed server CA differs from what was embedded in the APK.
  local staged_fp installed_fp bundled_fp
  staged_fp="$(openssl x509 -in "$TLS_STAGE_DIR/ca.crt" -outform DER | sha256sum | awk '{print $1}')"
  installed_fp="$(sudo openssl x509 -in "$SERVER_ETC/tls/ca.crt" -outform DER | sha256sum | awk '{print $1}')"
  bundled_fp="$(openssl x509 -in "$ANDROID_DIR/app/src/main/res/raw/promptworks_server_ca.pem" -outform DER | sha256sum | awk '{print $1}')"
  [[ "$staged_fp" == "$installed_fp" && "$staged_fp" == "$bundled_fp" ]] || \
    die "Provisioning CA mismatch detected; refusing to start the server."

  sudo install -o root -g promptworks-server -m 0644 "$PROVISION_AUTH_DIR/host-identity.pub.pem" "$SERVER_ETC/host-identity.pub.pem"
  sudo rm -rf "$SERVER_INSTALL"/*
  sudo cp -a "$SERVER_DIR/dist" "$SERVER_DIR/node_modules" "$SERVER_DIR/package.json" "$SERVER_INSTALL/"
  sudo chown -R root:root "$SERVER_INSTALL"
  local service_tmp
  service_tmp="$(mktemp)"
  cat >"$service_tmp" <<SERVICE
[Unit]
Description=PromptWorks Auth Server v3.9.1 candidate/runtime
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=promptworks-server
Group=promptworks-server
WorkingDirectory=${SERVER_INSTALL}
EnvironmentFile=${SERVER_ETC}/server.env
ExecStart=/usr/bin/node ${SERVER_INSTALL}/dist/index.js
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SERVER_STATE}

[Install]
WantedBy=multi-user.target
SERVICE
  sudo install -Dm644 "$service_tmp" "/etc/systemd/system/$SERVER_SERVICE"
  rm -f "$service_tmp"

  sudo tee "$SERVER_ETC/server.env" >/dev/null <<ENV
PW_HOST=0.0.0.0
PW_PORT=${SERVER_PORT}
PW_DB_PATH=${SERVER_STATE}/promptworks-auth.sqlite
PW_ADMIN_TOKEN=${ADMIN_TOKEN}
PW_PAIRING_MASTER_HEX=${PAIRING_MASTER_HEX}
PW_OFFLINE_HOST_ID=${HOST_ID}
PW_PAIRING_ID=${PAIRING_ID}
PW_HOST_PUBLIC_KEY_PATH=${SERVER_ETC}/host-identity.pub.pem
PW_TLS_CERT=${SERVER_ETC}/tls/server.crt
PW_TLS_KEY=${SERVER_ETC}/tls/server.key
ENV
  sudo chown root:promptworks-server "$SERVER_ETC/server.env"
  sudo chmod 0640 "$SERVER_ETC/server.env"

  sudo systemctl daemon-reload
  sudo systemctl enable "$SERVER_SERVICE" >/dev/null
  sudo systemctl restart "$SERVER_SERVICE"

  # Verify that the public CA really is readable by the normal user before health checks.
  [[ -r "$SERVER_ETC/tls/ca.crt" ]] || {
    sudo ls -ld "$SERVER_ETC" "$SERVER_ETC/tls" || true
    sudo ls -l "$SERVER_ETC/tls" || true
    die "Generated CA certificate exists but is not readable by the installer user."
  }

  local n
  for n in {1..20}; do
    if curl --silent --show-error --fail --cacert "$SERVER_ETC/tls/ca.crt" "$SERVER_URL/healthz" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  curl --silent --show-error --fail --cacert "$SERVER_ETC/tls/ca.crt" "$SERVER_URL/healthz" >/dev/null || {
    sudo systemctl --no-pager --full status "$SERVER_SERVICE" || true
    echo
    echo "---- PromptWorks server journal (last 80 lines) ----" >&2
    sudo journalctl -u "$SERVER_SERVICE" -n 80 --no-pager >&2 || true
    echo "---------------------------------------------------" >&2
    die "Local PromptWorks server did not become healthy at $SERVER_URL"
  }
  ok "Local HTTPS server is healthy."

  if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q '^Status: active'; then
    warn "UFW is active. If the Pixel cannot connect, allow TCP port $SERVER_PORT from your trusted LAN."
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --state >/dev/null 2>&1; then
    warn "firewalld is active. If the Pixel cannot connect, allow TCP port $SERVER_PORT on your trusted LAN zone."
  fi
}

api_admin() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl --silent --show-error --fail --cacert "$SERVER_ETC/tls/ca.crt" \
      -X "$method" -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      --data "$body" "$SERVER_URL$path"
  else
    curl --silent --show-error --fail --cacert "$SERVER_ETC/tls/ca.crt" \
      -X "$method" -H "Authorization: Bearer $ADMIN_TOKEN" "$SERVER_URL$path"
  fi
}

prepare_credentials() {
  log "Stage 8/12 — Creating one-time NEW-candidate enrollment token"
  local response
  ENROLL_START_ISO="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  response="$(api_admin POST /v1/admin/enrollment-tokens "{\"userId\":\"$PW_USER_ID\",\"ttlSeconds\":1800}")"
  ENROLL_TOKEN="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<<"$response")"
  [[ "$ENROLL_TOKEN" == pwe_* ]] || die "Could not create a phone enrollment token."
  ok "One-time provisioning token generated. The bound runtime key itself is never printed."
}

install_android_cli_sdk() {
  log "Stage 2/12 — Preparing Android command-line SDK (Android Studio is not used)"
  mkdir -p "$ANDROID_SDK_ROOT"
  export ANDROID_SDK_ROOT ANDROID_HOME="$ANDROID_SDK_ROOT"
  local sdkmanager="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
  if [[ ! -x "$sdkmanager" ]]; then
    local tmpdir repo_xml archive_url archive
    tmpdir="$(mktemp -d)"; repo_xml="$tmpdir/repository2-1.xml"; archive="$tmpdir/cmdline-tools.zip"
    curl --fail --location --retry 3 'https://dl.google.com/android/repository/repository2-1.xml' -o "$repo_xml"
    archive_url="$(python3 - "$repo_xml" <<'PY'
import sys,xml.etree.ElementTree as ET
root=ET.parse(sys.argv[1]).getroot(); items=[]
for pkg in root.iter():
    if not pkg.tag.endswith('remotePackage') or not pkg.attrib.get('path','').startswith('cmdline-tools;'): continue
    ver=(0,0,0)
    for c in pkg.iter():
        if c.tag.endswith('revision'):
            d={n.tag.split('}')[-1]:int((n.text or '0').strip() or 0) for n in c}; ver=(d.get('major',0),d.get('minor',0),d.get('micro',0)); break
    for a in pkg.iter():
        if not a.tag.endswith('archive'): continue
        osname=url=None
        for n in a.iter():
            t=n.tag.split('}')[-1]
            if t=='host-os': osname=(n.text or '').strip()
            elif t=='url': url=(n.text or '').strip()
        if osname=='linux' and url: items.append((ver,url))
if not items: raise SystemExit('No Linux cmdline-tools archive found')
items.sort(reverse=True); print('https://dl.google.com/android/repository/'+items[0][1])
PY
)"
    curl --fail --location --retry 3 "$archive_url" -o "$archive"
    rm -rf "$ANDROID_SDK_ROOT/cmdline-tools/latest"; mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
    unzip -q "$archive" -d "$tmpdir/unpacked"
    mv "$tmpdir/unpacked/cmdline-tools" "$ANDROID_SDK_ROOT/cmdline-tools/latest"
    rm -rf "$tmpdir"
  fi
  export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"
  set +o pipefail; yes | "$sdkmanager" --licenses >/dev/null 2>&1 || true; set -o pipefail
  "$sdkmanager" --install 'platform-tools' "platforms;android-$COMPILE_SDK" "build-tools;$BUILD_TOOLS"
  printf 'sdk.dir=%s\n' "${ANDROID_SDK_ROOT//\\/\\\\}" > "$ANDROID_DIR/local.properties"
  ok "Android SDK ready."
}

wait_for_android_device() {
  log "Stage 3/12 — Connecting to Pixel/GrapheneOS over ADB"
  cat <<'PHONE'
On the Pixel:
  • Enable Developer options and USB debugging.
  • Connect a data-capable USB cable.
  • Unlock the phone and accept the RSA debugging authorization prompt.
PHONE
  adb start-server >/dev/null
  local serial unauthorized answer
  while true; do
    serial="$(adb devices | awk 'NR>1 && $2=="device" {print $1; exit}')"
    unauthorized="$(adb devices | awk 'NR>1 && $2=="unauthorized" {print $1; exit}')"
    if [[ -n "$serial" ]]; then export ANDROID_SERIAL="$serial"; ok "ADB device authorized: $serial"; return; fi
    [[ -z "$unauthorized" ]] || warn "Pixel detected but not authorized; accept the prompt on the unlocked phone."
    read -r -p "Press ENTER to check again, or q to quit: " answer
    [[ "$answer" != q && "$answer" != Q ]] || die "ADB setup cancelled."
  done
}

build_install_apk_unprovisioned() {
  log "Stage 5/12 — Building and installing the NEW side-by-side v3.9.1 APK FIRST"
  cd "$ANDROID_DIR"
  chmod +x ./gradlew
  ./gradlew --no-daemon clean assembleDebug
  local apk="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
  [[ -s "$apk" ]] || die "APK not found after Gradle build: $apk"
  adb -s "$ANDROID_SERIAL" install -r "$apk"
  adb -s "$ANDROID_SERIAL" shell am start -S -W -n "$APP_ID/$MAIN_ACTIVITY" >/dev/null 2>&1 || true
  ok "NEW v3.9.1 APK installed side-by-side BEFORE privileged backend migration."
  ok "The CURRENT/OLD APK remains the only trusted sudo authenticator at this point."
}

deliver_provisioning_bootstrap() {
  log "Stage 9/12 — Delivering candidate bootstrap to the NEW APK"
  # Deliver one-time bootstrap material over the explicitly-authorized ADB session.
  # The token is never compiled into the APK and is deleted by the app after enrollment.
  adb -s "$ANDROID_SERIAL" logcat -c >/dev/null 2>&1 || true
  adb -s "$ANDROID_SERIAL" shell am start -S -W -n "$APP_ID/$MAIN_ACTIVITY" \
    --es pw_url "$SERVER_URL" --es pw_token "$ENROLL_TOKEN" --es pw_activation_state "candidate" >/dev/null

  local ack=""
  for _ in {1..10}; do
    ack="$(adb -s "$ANDROID_SERIAL" logcat -d -s PromptWorksBootstrap:I '*:S' 2>/dev/null | tail -n 20 || true)"
    if grep -q 'received_url=true received_token=true' <<<"$ack"; then
      ok "NEW APK confirmed receipt of provisioning URL and one-time token."
      return 0
    fi
    sleep 1
  done

  warn "The NEW APK did not acknowledge both provisioning values. Retrying once."
  adb -s "$ANDROID_SERIAL" shell am force-stop "$APP_ID" >/dev/null 2>&1 || true
  adb -s "$ANDROID_SERIAL" shell am start -S -W -n "$APP_ID/$MAIN_ACTIVITY" \
    --es pw_url "$SERVER_URL" --es pw_token "$ENROLL_TOKEN" --es pw_activation_state "candidate" >/dev/null
  sleep 2
  ack="$(adb -s "$ANDROID_SERIAL" logcat -d -s PromptWorksBootstrap:I '*:S' 2>/dev/null | tail -n 30 || true)"
  grep -q 'received_url=true received_token=true' <<<"$ack" || \
    die "The NEW APK did not receive its enrollment bootstrap. Existing PAM/backend remains unchanged."
  ok "NEW APK confirmed bootstrap receipt after retry."
}

wait_for_phone_enrollment() {
  log "Stage 10/12 — Enrolling NEW APK as CANDIDATE (sudo remains on OLD PromptWorks)"
  cat <<ENROLL
On the Pixel, open the NEW PromptWorks Secure v3.7 APK. It is a CANDIDATE only.
  Candidate server: $SERVER_URL
  Enrollment token: prefilled

Tap “Enroll as candidate” in the NEW APK. This does NOT change sudo.
The OLD PromptWorks APK/PAM remains the active sudo protector throughout enrollment.
The installer waits for the NEW APK's cryptographic enrollment proof before continuing.
ENROLL
  local deadline=$((SECONDS + 900)) audit_json found
  while (( SECONDS < deadline )); do
    audit_json="$(api_admin GET /v1/admin/audit 2>/dev/null || true)"
    found="$(AUDIT_JSON="$audit_json" python3 -c '
import json, os, sys
uid, start = sys.argv[1], sys.argv[2]
try:
    rows = json.loads(os.environ.get("AUDIT_JSON", "[]"))
except Exception:
    raise SystemExit
for r in rows:
    if r.get("event") != "device.offline_ready" or r.get("created_at", "") < start:
        continue
    try:
        d = json.loads(r.get("data", "{}"))
    except Exception:
        continue
    if d.get("userId") == uid:
        print(d.get("id", ""))
        break
' "$PW_USER_ID" "$ENROLL_START_ISO" 2>/dev/null || true)"
    if [[ "$found" == dev_* ]]; then ok "NEW APK enrollment/binding proof verified: $found"; return; fi
    sleep 3
  done
  die "NEW APK enrollment/binding proof was not verified within 15 minutes. PAM has NOT been modified. Check the phone biometric/provisioning screen, Wi-Fi/firewall, and retry."
}

finalize_single_device_binding() {
  log "Binding — sealing this Linux installation to the enrolled APK"
  local pairing_json tmpdir
  pairing_json="$(api_admin GET /v1/admin/pairing)"
  PAIRED_DEVICE_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["deviceId"])' <<<"$pairing_json")"
  PAIRED_DEVICE_FINGERPRINT="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["approvalKeyFingerprint"])' <<<"$pairing_json")"
  local returned_pair returned_hostfp ready_at
  returned_pair="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["pairingId"])' <<<"$pairing_json")"
  returned_hostfp="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["hostKeyFingerprint"])' <<<"$pairing_json")"
  ready_at="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("readyAt") or "")' <<<"$pairing_json")"
  [[ "$returned_pair" == "$PAIRING_ID" && "$returned_hostfp" == "$HOST_KEY_FINGERPRINT" && -n "$ready_at" ]] || die "Provisioning binding proof did not match this Linux host."
  [[ "$PAIRED_DEVICE_FINGERPRINT" =~ ^[0-9a-fA-F]{64}$ ]] || die "Invalid paired phone public-key fingerprint."

  OFFLINE_SECRET_HEX="$(PAIRING_MASTER_HEX="$PAIRING_MASTER_HEX" PAIRING_ID="$PAIRING_ID" HOST_ID="$HOST_ID" DEVICE_ID="$PAIRED_DEVICE_ID" PHONE_FP="$PAIRED_DEVICE_FINGERPRINT" HOST_FP="$HOST_KEY_FINGERPRINT" python3 - <<'PY2'
import os,hmac,hashlib
master=bytes.fromhex(os.environ['PAIRING_MASTER_HEX'])
payload='\n'.join(['promptworks-offline-pair-v1',os.environ['PAIRING_ID'],os.environ['HOST_ID'],os.environ['DEVICE_ID'],os.environ['PHONE_FP'],os.environ['HOST_FP']]).encode()
print(hmac.new(master,payload,hashlib.sha256).hexdigest())
PY2
)"
  [[ "$OFFLINE_SECRET_HEX" =~ ^[0-9a-f]{64}$ ]] || die "Could not derive the bound offline key."

  printf '%s\n' "$OFFLINE_SECRET_HEX" | sudo tee "$PROVISION_AUTH_DIR/offline.key" >/dev/null
  sudo chown root:root "$PROVISION_AUTH_DIR/offline.key"; sudo chmod 0400 "$PROVISION_AUTH_DIR/offline.key"
  tmpdir="$(mktemp -d)"
  PAIRING_JSON="$pairing_json" python3 - "$tmpdir/binding.json" <<'PY2'
import json,os,sys
p=json.loads(os.environ['PAIRING_JSON'])
out={
  'version': 2,
  'backendVersion': '3.9.1',
  'androidAppId': 'com.promptworks.sudoauth.secure.v37',
  'pairingId': p['pairingId'],
  'hostId': p['hostId'],
  'hostKeyFingerprint': p['hostKeyFingerprint'],
  'deviceId': p['deviceId'],
  'userId': p['userId'],
  'deviceName': p['deviceName'],
  'approvalKeyFingerprint': p['approvalKeyFingerprint'],
  'readyAt': p['readyAt'],
}
open(sys.argv[1],'w').write(json.dumps(out,indent=2,sort_keys=True)+'\n')
open(sys.argv[1]+'.pub','w').write(p['approvalPublicKeyPem'])
PY2
  sudo install -o root -g root -m 0444 "$tmpdir/binding.json" "$PROVISION_AUTH_DIR/binding.json"
  sudo install -o root -g root -m 0444 "$tmpdir/binding.json.pub" "$PROVISION_AUTH_DIR/paired-phone-approval.pub.pem"
  rm -rf "$tmpdir"
  ok "Candidate 1:1 binding sealed: host $HOST_ID ↔ new v3.9.1 APK device $PAIRED_DEVICE_ID"
  if (( MIGRATION_MODE == 1 )); then
    ok "Existing backend remains active; no PAM/service files have been changed yet."
  fi
}

retire_provisioning_server() {
  log "Hardening — removing the first-time provisioning server"
  # TLS staging secrets are no longer needed after enrollment.
  rm -rf "$TLS_STAGE_DIR" 2>/dev/null || true
  sudo systemctl disable --now "$SERVER_SERVICE" >/dev/null 2>&1 || true
  sudo rm -f "/etc/systemd/system/$SERVER_SERVICE"
  sudo systemctl daemon-reload >/dev/null 2>&1 || true

  # Runtime authentication does not need the server, its database, TLS private keys,
  # admin token, Node modules, or service account. Remove that attack surface entirely.
  if sudo test -f "$SERVER_ETC/server.env"; then sudo shred -u "$SERVER_ETC/server.env" 2>/dev/null || sudo rm -f "$SERVER_ETC/server.env"; fi
  if sudo test -f "$SERVER_ETC/tls/ca.key"; then sudo shred -u "$SERVER_ETC/tls/ca.key" 2>/dev/null || true; fi
  if sudo test -f "$SERVER_ETC/tls/server.key"; then sudo shred -u "$SERVER_ETC/tls/server.key" 2>/dev/null || true; fi
  if sudo test -f "$PROVISION_AUTH_DIR/pairing-master.key"; then sudo shred -u "$PROVISION_AUTH_DIR/pairing-master.key" 2>/dev/null || sudo rm -f "$PROVISION_AUTH_DIR/pairing-master.key"; fi
  sudo rm -rf "$SERVER_ETC" "$SERVER_STATE" "$SERVER_INSTALL"
  sudo userdel promptworks-server >/dev/null 2>&1 || true
  ok "Provisioning server and pairing master removed. Runtime sudo authentication is network-independent and locked to the enrolled APK identity."
}


detect_upgrade_mode_early() {
  # /etc/pam.d/sudo is normally world-readable. This lets us decide whether this
  # is an upgrade BEFORE invoking sudo, which prevents the installer from throwing
  # the old PromptWorks challenge at the user before the NEW APK has even been built.
  if grep -q 'pam_promptworks\.so' /etc/pam.d/sudo 2>/dev/null; then
    LEGACY_BACKEND_PRESENT=1
    MIGRATION_MODE=1
    PROVISION_AUTH_DIR="$CANDIDATE_AUTH_DIR"
    choose_candidate_port
    SERVER_ETC="/etc/promptworks-server-v391-candidate"
    SERVER_STATE="/var/lib/promptworks-server-v391-candidate"
    SERVER_INSTALL="/opt/promptworks-auth-server-v391-candidate"
    SERVER_SERVICE="promptworks-auth-server-v391.service"
    warn "Existing PromptWorks PAM detected. OLD PromptWorks stays ACTIVE and protects every sudo request until final handover."
    return 0
  fi
  LEGACY_BACKEND_PRESENT=0
  MIGRATION_MODE=0
  PROVISION_AUTH_DIR="$ACTIVE_AUTH_DIR"
  return 0
}

validate_upgrade_mode_privileged() {
  if (( MIGRATION_MODE == 0 )); then return 0; fi
  sudo test -r "$ACTIVE_AUTH_DIR/binding.json" || die "PromptWorks PAM is present but active binding.json is missing. Refusing migration."
  sudo test -r "$ACTIVE_AUTH_DIR/offline.key" || die "PromptWorks PAM is present but active offline.key is missing. Refusing migration."
  local ver app_id
  ver="$(sudo python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("backendVersion","legacy"))' "$ACTIVE_AUTH_DIR/binding.json" 2>/dev/null || echo legacy)"
  app_id="$(sudo python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("androidAppId","legacy"))' "$ACTIVE_AUTH_DIR/binding.json" 2>/dev/null || echo legacy)"

  # Only treat the ACTIVE binding as an already-completed v3.7+ migration when
  # both markers identify the side-by-side v37 Android package. v3.6.1 is the
  # PREVIOUS backend and must continue through candidate provisioning/migration.
  # The old v3.7.0 installer incorrectly returned 2 for v3.6.1, which caused it
  # to exit at Stage 5 before provisioning or switching trust.
  if [[ "$app_id" == "com.promptworks.sudoauth.secure.v37" && "$ver" == "3.9.1" ]]; then
    return 2
  fi

  warn "Validated CURRENT PromptWorks backend: version=$ver appId=$app_id"
  warn "It remains ACTIVE while v3.9.1 is provisioned side-by-side."
  return 0
}

reset_incomplete_candidate() {
  (( MIGRATION_MODE == 1 )) || return 0

  # A candidate is disposable until the atomic handover commits. Never attempt to
  # "resume" a sealed-but-uncommissioned candidate because its systemd unit, TLS
  # material, runtime client, APK trust anchor, or database may be only partially
  # present from the failed run. Recreate the candidate from a clean slate while
  # the known-good OLD PromptWorks stack continues to protect sudo.
  local found=0 svc path
  if sudo test -e "$CANDIDATE_AUTH_DIR"; then found=1; fi
  for svc in promptworks-auth-server-v375.service promptworks-auth-server-v376.service promptworks-auth-server-v377.service promptworks-auth-server-v378.service promptworks-auth-server-v379.service promptworks-auth-server-v380.service promptworks-auth-server-v381.service promptworks-auth-server-v382.service promptworks-auth-server-v383.service promptworks-auth-server-v390.service promptworks-auth-server-v391.service; do
    if sudo systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q "$svc"; then found=1; fi
  done
  for path in /etc/promptworks-server-v375-candidate /etc/promptworks-server-v376-candidate /etc/promptworks-server-v377-candidate /etc/promptworks-server-v378-candidate /etc/promptworks-server-v379-candidate /etc/promptworks-server-v380-candidate /etc/promptworks-server-v381-candidate /etc/promptworks-server-v382-candidate /etc/promptworks-server-v383-candidate /etc/promptworks-server-v390-candidate /etc/promptworks-server-v391-candidate \
              /var/lib/promptworks-server-v375-candidate /var/lib/promptworks-server-v376-candidate /var/lib/promptworks-server-v377-candidate /var/lib/promptworks-server-v378-candidate /var/lib/promptworks-server-v379-candidate /var/lib/promptworks-server-v380-candidate /var/lib/promptworks-server-v381-candidate /var/lib/promptworks-server-v382-candidate /var/lib/promptworks-server-v383-candidate /var/lib/promptworks-server-v390-candidate /var/lib/promptworks-server-v391-candidate \
              /opt/promptworks-auth-server-v375-candidate /opt/promptworks-auth-server-v376-candidate /opt/promptworks-auth-server-v377-candidate /opt/promptworks-auth-server-v378-candidate /opt/promptworks-auth-server-v379-candidate /opt/promptworks-auth-server-v380-candidate /opt/promptworks-auth-server-v381-candidate /opt/promptworks-auth-server-v382-candidate /opt/promptworks-auth-server-v383-candidate /opt/promptworks-auth-server-v390-candidate /opt/promptworks-auth-server-v391-candidate; do
    if sudo test -e "$path"; then found=1; fi
  done

  if (( found == 1 )); then
    warn "Found an incomplete prior NEW-candidate state. It will be discarded and provisioned again from scratch."
    warn "The ACTIVE/OLD PromptWorks PAM, backend, binding, and sudo protection are not touched."
  fi

  for svc in promptworks-auth-server-v375.service promptworks-auth-server-v376.service promptworks-auth-server-v377.service promptworks-auth-server-v378.service promptworks-auth-server-v379.service promptworks-auth-server-v380.service promptworks-auth-server-v381.service promptworks-auth-server-v382.service promptworks-auth-server-v383.service promptworks-auth-server-v390.service promptworks-auth-server-v391.service; do
    sudo systemctl disable --now "$svc" >/dev/null 2>&1 || true
    sudo rm -f "/etc/systemd/system/$svc"
  done
  sudo systemctl daemon-reload >/dev/null 2>&1 || true

  # Stop/remove every known historical candidate service, including v3.8.3 and
  # v3.9.0. The current run has already selected a free temporary enrollment port,
  # so an orphan on an older port cannot block provisioning. We still fail closed
  # if the selected port becomes occupied before server startup. The active/OLD
  # PromptWorks backend is never targeted here.
  local port_owner
  port_owner="$(sudo ss -ltnp 2>/dev/null | awk -v p=":${SERVER_PORT}" '$4 ~ (p "$" ) {print}' || true)"
  if [[ -n "$port_owner" ]]; then
    echo "$port_owner" >&2
    die "Selected temporary enrollment port ${SERVER_PORT} became occupied before startup. Refusing to kill an unknown listener; rerun to select another free port."
  fi

  sudo rm -rf "$CANDIDATE_AUTH_DIR" \
    /etc/promptworks-server-v375-candidate /etc/promptworks-server-v376-candidate /etc/promptworks-server-v377-candidate /etc/promptworks-server-v378-candidate /etc/promptworks-server-v379-candidate /etc/promptworks-server-v380-candidate /etc/promptworks-server-v381-candidate /etc/promptworks-server-v382-candidate /etc/promptworks-server-v383-candidate /etc/promptworks-server-v390-candidate /etc/promptworks-server-v391-candidate \
    /var/lib/promptworks-server-v375-candidate /var/lib/promptworks-server-v376-candidate /var/lib/promptworks-server-v377-candidate /var/lib/promptworks-server-v378-candidate /var/lib/promptworks-server-v379-candidate /var/lib/promptworks-server-v380-candidate /var/lib/promptworks-server-v381-candidate /var/lib/promptworks-server-v382-candidate /var/lib/promptworks-server-v383-candidate /var/lib/promptworks-server-v390-candidate /var/lib/promptworks-server-v391-candidate \
    /opt/promptworks-auth-server-v375-candidate /opt/promptworks-auth-server-v376-candidate /opt/promptworks-auth-server-v377-candidate /opt/promptworks-auth-server-v378-candidate /opt/promptworks-auth-server-v379-candidate /opt/promptworks-auth-server-v380-candidate /opt/promptworks-auth-server-v381-candidate /opt/promptworks-auth-server-v382-candidate /opt/promptworks-auth-server-v383-candidate /opt/promptworks-auth-server-v390-candidate /opt/promptworks-auth-server-v391-candidate

  # Clear only the side-by-side NEW package's candidate data. The OLD enrolled APK
  # has a different application ID and remains untouched/usable for sudo.
  adb -s "$ANDROID_SERIAL" shell pm clear "$APP_ID" >/dev/null 2>&1 || true

  if (( found == 1 )); then
    ok "Incomplete NEW candidate removed safely. OLD PromptWorks is still the active sudo protector."
  fi
}

compile_update_gate_temp() {
  local out="$1"
  cc -O2 -Wall -Wextra -Werror=format-security -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now -o "$out" "$LINUX_DIR/promptworks-update-gate.c" -lcrypto
}

create_previous_promptworks_fallback() {
  (( MIGRATION_MODE == 1 )) || return 0
  log "Creating transaction-safe previous PromptWorks PAM/backend fallback BEFORE trust switch"

  # This marker means rollback is an upgrade rollback. In this mode we must NEVER
  # fall through to the distro/original sudo PAM configuration.
  sudo install -d -o root -g root -m 0700 /var/lib
  sudo touch /var/lib/promptworks-upgrade-mode
  sudo chown root:root /var/lib/promptworks-upgrade-mode
  sudo chmod 0600 /var/lib/promptworks-upgrade-mode

  # Recreate the fallback only after the CURRENT PromptWorks stack has just
  # authenticated this migration successfully. That makes this snapshot the
  # last-known-good PromptWorks PAM/backend pair.
  sudo rm -rf /var/lib/promptworks-backend-fallback
  sudo install -d -o root -g root -m 0700 /var/lib/promptworks-backend-fallback
  sudo cp -a /etc/pam.d/sudo /var/lib/promptworks-backend-fallback/sudo.pam
  sudo cp -a "$ACTIVE_AUTH_DIR" /var/lib/promptworks-backend-fallback/auth-dir
  sudo cp -a /var/lib/promptworks-auth-guard/state /var/lib/promptworks-backend-fallback/guard-state 2>/dev/null || true
  if sudo systemctl is-active --quiet promptworks-auth-server.service 2>/dev/null; then
    sudo touch /var/lib/promptworks-backend-fallback/server-was-active
  fi
  local oldpam
  oldpam="$(find /usr/lib /lib -type f -path '*/security/pam_promptworks.so' -print -quit 2>/dev/null || true)"
  if [[ -n "$oldpam" ]]; then
    printf '%s\n' "$oldpam" | sudo tee /var/lib/promptworks-backend-fallback/pam-path >/dev/null
    sudo cp -a "$oldpam" /var/lib/promptworks-backend-fallback/pam_promptworks.so
  fi
  sudo touch /var/lib/promptworks-backend-fallback/SNAPSHOT_COMPLETE
  sudo chmod 0600 /var/lib/promptworks-backend-fallback/SNAPSHOT_COMPLETE
  ok "Last-known-good PromptWorks PAM/backend snapshot captured before activation."
}

candidate_end_to_end_proof() {
  (( MIGRATION_MODE == 1 )) || return 0
  log "Candidate proof — testing NEW APK fully OFFLINE WITHOUT changing sudo"
  sudo test -r "$CANDIDATE_AUTH_DIR/offline.key" || die "Candidate offline key is missing. OLD PromptWorks remains active."
  sudo test -r "$CANDIDATE_AUTH_DIR/host-id" || die "Candidate host binding is missing. OLD PromptWorks remains active."
  sudo test -r "$CANDIDATE_AUTH_DIR/binding.json" || die "Candidate device binding is missing. OLD PromptWorks remains active."

  cat <<'PROOF'
SUDO IS STILL PROTECTED BY THE OLD PROMPTWORKS STACK.
Nothing in /etc/pam.d/sudo is changed by this test.

THIS PROOF IS OFFLINE.
The candidate provisioning HTTPS service has already been removed and is NOT used.
No phone notification, LAN callback, polling request, cloud service, or backend response is involved.

Flow:
  1. Linux prints a fresh 3-digit NUMBER MATCH.
  2. Enter those 3 digits in the NEW PromptWorks Secure APK.
  3. Tap APPROVE (or DENY) and unlock with BIOMETRIC_STRONG.
  4. The phone computes an 8-digit decision code locally.
  5. Type that 8-digit code back into this terminal.

The code is bound to this host, this enrolled APK, the current 60-second time window,
the displayed 3-digit match, and the explicit APPROVE/DENY decision.
If the proof fails, OLD PromptWorks remains active.
PROOF

  local gate
  gate="$(mktemp)"
  rm -f "$gate"
  compile_update_gate_temp "$gate" || die "Could not compile the offline candidate verifier. OLD PromptWorks remains active."
  chmod 0755 "$gate"

  # Foreground the NEW app only as UI convenience. ADB carries no approval material;
  # the decision itself is computed on the phone and transferred manually as 8 digits.
  adb -s "$ANDROID_SERIAL" shell am start -W -n "$APP_ID/$MAIN_ACTIVITY" >/dev/null 2>&1 || true

  local rc=0
  sudo "$gate" \
    --key "$CANDIDATE_AUTH_DIR/offline.key" \
    --host "$CANDIDATE_AUTH_DIR/host-id" \
    --purpose "v3.9.1 offline candidate proof before PAM handover" || rc=$?
  rm -f "$gate"
  if [[ $rc -ne 0 ]]; then
    die "NEW v3.9.1 offline candidate proof failed. OLD PromptWorks remains the active sudo protector."
  fi
  ok "NEW APK produced a valid offline biometric decision code. No runtime backend was used."
}

authorize_existing_backend_change() {
  (( MIGRATION_MODE == 1 )) || return 0
  log "Stage 11/12 — OLD PromptWorks authorizes atomic handover"
  cat <<'UPGRADE'
The NEW v3.9.1 APK is now installed and cryptographically provisioned as a
candidate, but the CURRENT/OLD backend is still active.

The backend switch itself is authorized by the CURRENT/OLD sudo PAM stack:
  1) the installer invalidates every cached sudo credential;
  2) sudo starts the OLD PromptWorks PAM flow;
  3) use the OLD enrolled APK to satisfy that challenge;
  4) only after that succeeds does this installer activate the new binding.

This intentionally uses whatever protocol the currently-installed PAM/APK pair
already uses (legacy 12-digit OCRA or number-match). It does NOT require the old
APK to understand the new v3.9.1 protocol.
UPGRADE
  sudo -K || true
  if ! sudo -v; then
    die "CURRENT/OLD PromptWorks PAM authorization failed. New APK remains only a candidate; existing backend is unchanged."
  fi
  ok "CURRENT/OLD sudo PAM + enrolled OLD APK approved this privileged migration session."
}

activate_candidate_binding() {
  (( MIGRATION_MODE == 1 )) || return 0
  sudo test -r "$CANDIDATE_AUTH_DIR/binding.json" || die "v3.9.1 candidate binding missing."
  sudo test -r "$CANDIDATE_AUTH_DIR/offline.key" || die "v3.9.1 candidate runtime key missing."
  local stamp backup staging
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup="/var/lib/promptworks-backend-backups/pre-v370-$stamp"
  staging="/etc/.promptworks-auth-v370-new-$stamp"
  sudo install -d -o root -g root -m 0700 /var/lib/promptworks-backend-backups

  # Approval has already been obtained from the old APK. Remove defense-in-depth
  # immutable flags only inside this approved maintenance transaction.
  if command -v chattr >/dev/null 2>&1; then
    sudo chattr -i "$ACTIVE_AUTH_DIR/backend.manifest" /usr/local/sbin/promptworksctl \
      /usr/local/libexec/promptworks-update-gate /usr/local/sbin/promptworks-backend-manifest 2>/dev/null || true
  fi

  sudo cp -a "$ACTIVE_AUTH_DIR" "$backup"
  sudo rm -rf "$staging"
  sudo cp -a "$CANDIDATE_AUTH_DIR" "$staging"
  sudo chown -R root:root "$staging"
  sudo chmod 0700 "$staging"

  # Keep the previous active directory as a local rollback snapshot until the
  # new backend is commissioned. Directory renames stay on the same filesystem.
  sudo rm -rf "${ACTIVE_AUTH_DIR}.pre-v370"
  sudo mv "$ACTIVE_AUTH_DIR" "${ACTIVE_AUTH_DIR}.pre-v370"
  if ! sudo mv "$staging" "$ACTIVE_AUTH_DIR"; then
    sudo mv "${ACTIVE_AUTH_DIR}.pre-v370" "$ACTIVE_AUTH_DIR" || true
    die "Could not activate the v3.9.1 candidate binding; old binding restored."
  fi
  sudo rm -rf "$CANDIDATE_AUTH_DIR"
  HOST_ID="$(sudo cat "$ACTIVE_AUTH_DIR/host-id")"
  ok "v3.9.1 candidate binding activated. Previous active binding preserved at ${ACTIVE_AUTH_DIR}.pre-v370 until commissioning."
  ok "Additional root-only rollback copy: $backup"
}

protect_backend_files() {
  # Best-effort defense in depth. This is not a security boundary against root;
  # root can always remove immutable flags. Cryptographic APK approval is enforced
  # by PromptWorks managed update/reset workflows.
  if command -v chattr >/dev/null 2>&1; then
    sudo chattr +i "$ACTIVE_AUTH_DIR/backend.manifest" /usr/local/sbin/promptworksctl \
      /usr/local/libexec/promptworks-update-gate /usr/local/sbin/promptworks-backend-manifest 2>/dev/null || true
  fi
}


install_linux_integration() {
  log "Stage 12/12 — Atomic PAM handover to NEW PromptWorks"
  sudo test -r "$ACTIVE_AUTH_DIR/offline.key" || die "Bound offline key is missing; complete phone provisioning first."
  sudo test -r "$ACTIVE_AUTH_DIR/binding.json" || die "Single-device binding record is missing; refusing to install PAM."
  [[ -n "$HOST_ID" ]] || HOST_ID="$(sudo cat "$ACTIVE_AUTH_DIR/host-id" 2>/dev/null || hostname)"
  cat <<PAMWARN
The phone has been provisioned. The next step modifies /etc/pam.d/sudo.
Keep this terminal open and preferably keep a separate root shell open during commissioning.

Runtime mode: OFFLINE NUMBER MATCH + BIOMETRIC DECISION CODE
  Host ID: $HOST_ID
  Network: NONE required at runtime (LAN/Internet/backend not used)
  Binding: exactly one APK installation ↔ this Linux host
  Secret:  per-binding 256-bit key; root-only on Linux + biometric Keystore-wrapped on phone
PAMWARN
  if ! confirm "Proceed with offline sudo/PAM installation now?"; then
    warn "PAM installation skipped. Phone provisioning remains complete."
    return 0
  fi
  # The upgrade fallback was captured BEFORE the trust switch in Stage 9.
  # Every new PAM/backend activation is a new commissioning transaction.
  # Never inherit a previous version's "passed" guard state.
  sudo install -d -o root -g root -m 0700 /var/lib/promptworks-auth-guard
  printf 'armed 0\n' | sudo tee /var/lib/promptworks-auth-guard/state >/dev/null
  sudo chown root:root /var/lib/promptworks-auth-guard/state
  sudo chmod 0600 /var/lib/promptworks-auth-guard/state

  sudo env \
    PW_OFFLINE_SECRET_FILE="$ACTIVE_AUTH_DIR/offline.key" \
    PW_HOST_ID="$HOST_ID" \
    "$LINUX_DIR/install.sh"
  protect_backend_files
  ok "Offline Linux sudo integration installed and backend integrity lock enabled."
  cat <<'DONE'

COMMISSIONING TEST — use a SECOND terminal:

    sudo -K
    sudo id

Expected flow:
  1. Complete the normal sudo password/authentication policy.
  2. Linux prints a fresh 3-digit NUMBER MATCH and waits for an 8-digit decision code.
  3. Open PromptWorks Secure and enter the same 3 digits.
  4. Tap APPROVE or DENY and unlock with BIOMETRIC_STRONG.
  5. Type the phone-generated 8-digit decision code into the waiting sudo prompt.

No LAN, Internet, notification delivery, polling, or local HTTPS backend is used at runtime.
The commissioning guard is re-armed for every upgrade. The installer performs a real NEW-stack authentication before declaring success.
If that commissioning attempt fails or times out, the root watchdog restores the previous PromptWorks PAM/backend snapshot captured before activation.
DONE
}

commission_new_promptworks_stack() {
  log "Commissioning — proving the NEW offline PromptWorks PAM before declaring success"

  # Start a root-owned dead-man switch while the current sudo session still works.
  # If the new PromptWorks PAM never records a successful authentication, this
  # process restores the previous PromptWorks snapshot without needing sudo again.
  sudo sh -c 'nohup bash -c '\''sleep 75; if ! grep -q "^passed " /var/lib/promptworks-auth-guard/state 2>/dev/null; then /usr/local/sbin/promptworks-auth-rollback --auto; fi'\'' >/var/log/promptworks-commission-watchdog.log 2>&1 </dev/null &'

  cat <<'COMMISSION'
The installer will now invalidate the cached sudo credential and perform ONE
real authentication through the NEW PromptWorks stack.

If the NEW offline biometric decision code succeeds, commissioning completes.
If it fails or expires, a root-owned
watchdog restores the previous PromptWorks PAM/backend automatically. It does
NOT enable original/distro-only sudo mode.
COMMISSION

  sudo -K || true
  if sudo -v; then
    ok "NEW offline PromptWorks PAM commissioning succeeded."
    # The PAM module writes "passed" before sudo returns success. Keep the fallback
    # snapshot for future protected upgrades, but clear the in-progress marker.
    sudo rm -f /var/lib/promptworks-upgrade-mode
    return 0
  fi

  warn "NEW PromptWorks commissioning FAILED. Automatic rollback to the previous PromptWorks stack is armed."
  warn "Waiting for the root rollback watchdog to restore the last-known-good PromptWorks PAM/backend…"
  sleep 20
  printf '\nRollback is handled by the root watchdog. Do NOT keep retrying the failed NEW stack.\n' >&2
  return 1
}

main() {
  clear 2>/dev/null || true
  cat <<'BANNER'
============================================================
 Prompt-Works-Sudo-Auth v3.9.1 — Protected Side-by-Side Upgrade
 OLD PromptWorks protects sudo continuously; NEW OFFLINE stack is proven before atomic handover
============================================================
BANNER
  log "Detected host: ${PRETTY_NAME:-${ID:-unknown}}"

  detect_upgrade_mode_early

  # CRITICAL ORDERING:
  # Build + install the new package before intentionally invoking sudo on an
  # already-protected host. This guarantees both APKs exist during migration.
  install_apk_prerequisites
  configure_java17
  install_android_cli_sdk
  wait_for_android_device
  prepare_candidate_tls_before_apk
  build_install_apk_unprovisioned

  if (( APK_ONLY == 1 )); then
    warn "--apk-only installs the new side-by-side APK but cannot provision it without privileged local-server setup."
    ok "NEW APK installed; OLD APK/backend remains trusted and unchanged."
    exit 0
  fi

  # From this point, if this is an upgrade, every sudo request is intentionally
  # answered with the CURRENT/OLD APK until the final atomic handover performs the trust switch.
  install_backend_dependencies

  local rc=0
  validate_upgrade_mode_privileged || rc=$?
  if [[ $rc -eq 2 ]]; then
    HOST_ID="$(sudo cat "$ACTIVE_AUTH_DIR/host-id" 2>/dev/null || hostname)"
    if ! sudo grep -q 'pam_promptworks\.so' /etc/pam.d/sudo 2>/dev/null; then
      warn "v3.9.1 binding is already active, but PAM integration is missing."
      install_linux_integration
      sudo -K || true
      exit 0
    fi
    ok "PromptWorks v3.9.1 binding is already active on this host."
    sudo -K || true
    exit 0
  elif [[ $rc -ne 0 ]]; then
    return "$rc"
  fi

  if (( LINUX_ONLY == 1 )); then
    if (( MIGRATION_MODE == 1 )); then
      die "--linux-only cannot replace an active older backend. Run the normal installer so the NEW side-by-side APK is present first."
    fi
    sudo test -r "$ACTIVE_AUTH_DIR/offline.key" || die "No existing bound offline key found."
    sudo test -r "$ACTIVE_AUTH_DIR/binding.json" || die "No single-device binding record found."
    install_linux_integration
    sudo -K || true
    exit 0
  fi

  # Never reuse an uncommissioned candidate from an earlier failed run. A sealed
  # binding alone does not prove that its service unit, database, TLS material,
  # and the APK's embedded CA are still coherent. Recreate only the
  # NEW candidate; the OLD PromptWorks stack remains active throughout.
  reset_incomplete_candidate
  install_local_server
  prepare_credentials
  deliver_provisioning_bootstrap
  wait_for_phone_enrollment
  finalize_single_device_binding

  # Enrollment is complete. Runtime authentication is deliberately air-gapped:
  # remove the candidate HTTPS service and all of its TLS/database/admin secrets
  # BEFORE proving the candidate and BEFORE any PAM handover.
  retire_provisioning_server

  if (( MIGRATION_MODE == 1 )); then
    candidate_end_to_end_proof
    authorize_existing_backend_change
    create_previous_promptworks_fallback
    activate_candidate_binding
  fi

  install_linux_integration
  if ! commission_new_promptworks_stack; then
    die "v3.9.1 commissioning failed; previous PromptWorks rollback was armed and the migration is NOT complete."
  fi
  adb -s "$ANDROID_SERIAL" shell am start -W -n "$APP_ID/$MAIN_ACTIVITY" \
    --es pw_activation_state "active" >/dev/null 2>&1 || true
  if (( MIGRATION_MODE == 1 )) && [[ "$SERVER_SERVICE" != "promptworks-auth-server.service" ]]; then
    sudo systemctl disable --now promptworks-auth-server.service >/dev/null 2>&1 || true
  fi
  sudo -K || true
  printf '\n\033[1;32mPrompt-Works-Sudo-Auth v3.9.1 protected migration complete.\033[0m\n'
  echo "Both APKs may remain installed, but only PromptWorks Secure v3.9.1 is trusted after activation."
  echo "The old APK/PAM pair authorized the trust exchange; runtime approval is now fully offline."
}

main "$@"
