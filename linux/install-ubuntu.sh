#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run with sudo"; exit 1; }
ROOT="$(cd "$(dirname "$0")" && pwd)"
. /etc/os-release
case "${ID:-}" in ubuntu|debian|linuxmint|pop) ;; *) [[ " ${ID_LIKE:-} " == *" debian "* ]] || { echo "Ubuntu/Debian-family only"; exit 1; };; esac
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential libpam0g-dev libpam-modules libssl-dev ca-certificates
[[ -f /etc/pam.d/sudo ]] || { echo "/etc/pam.d/sudo not found"; exit 1; }
SECRET_FILE="${PW_OFFLINE_SECRET_FILE:-/etc/promptworks-auth/offline.key}"
HOST_ID="${PW_HOST_ID:-$(hostname)}"
[[ -r "$SECRET_FILE" ]] || { echo "Offline provisioning key missing: $SECRET_FILE"; exit 1; }
[[ -r /etc/promptworks-auth/binding.json ]] || { echo "Single-device binding missing: /etc/promptworks-auth/binding.json"; exit 1; }
[[ -r /etc/promptworks-auth/paired-phone-approval.pub.pem ]] || { echo "Paired phone public key missing"; exit 1; }
SECRET="$(tr -d '[:space:]' < "$SECRET_FILE")"
[[ "$SECRET" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Offline key must be 64 hex chars"; exit 1; }
make -C "$ROOT/pam" clean all
cc -O2 -Wall -Wextra -Werror=format-security -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -o "$ROOT/promptworks-update-gate" "$ROOT/promptworks-update-gate.c" -lcrypto
PAM_UNIX="$(dpkg -L libpam-modules | awk '/\/security\/pam_unix\.so$/{print; exit}')"
[[ -n "$PAM_UNIX" && -f "$PAM_UNIX" ]] || { echo "Could not locate PAM security module directory"; exit 1; }
PAM_SECURITY_DIR="$(dirname "$PAM_UNIX")"
install -Dm755 "$ROOT/pam/pam_promptworks.so" "$PAM_SECURITY_DIR/pam_promptworks.so"
install -Dm700 "$ROOT/promptworks-auth-rollback" /usr/local/sbin/promptworks-auth-rollback
install -Dm700 "$ROOT/promptworksctl" /usr/local/sbin/promptworksctl
install -Dm700 "$ROOT/promptworks-update-gate" /usr/local/libexec/promptworks-update-gate
install -Dm700 "$ROOT/promptworks-backend-manifest" /usr/local/sbin/promptworks-backend-manifest
install -Dm644 "$ROOT/promptworks-binding-guard.service" /etc/systemd/system/promptworks-binding-guard.service
install -d -o root -g root -m 0700 /etc/promptworks-auth /var/lib/promptworks-auth-guard
printf '%s\n' "$SECRET" > /etc/promptworks-auth/offline.key
printf '%s\n' "$HOST_ID" > /etc/promptworks-auth/host-id
chown root:root /etc/promptworks-auth/offline.key /etc/promptworks-auth/host-id
chmod 0400 /etc/promptworks-auth/offline.key
chmod 0444 /etc/promptworks-auth/host-id
chown root:root /etc/promptworks-auth/binding.json /etc/promptworks-auth/paired-phone-approval.pub.pem /etc/promptworks-auth/host-identity.pub.pem /etc/promptworks-auth/host-identity.key.pem /etc/promptworks-auth/pairing-id
chmod 0444 /etc/promptworks-auth/binding.json /etc/promptworks-auth/paired-phone-approval.pub.pem /etc/promptworks-auth/host-identity.pub.pem /etc/promptworks-auth/pairing-id
chmod 0400 /etc/promptworks-auth/host-identity.key.pem
if [[ ! -f /var/lib/promptworks-auth-guard/state ]]; then
  printf 'armed 0\n' >/var/lib/promptworks-auth-guard/state
fi
touch /var/lib/promptworks-auth-guard/time-match-history
chown root:root /var/lib/promptworks-auth-guard/state /var/lib/promptworks-auth-guard/time-match-history
chmod 0600 /var/lib/promptworks-auth-guard/state /var/lib/promptworks-auth-guard/time-match-history
# Upgrade safely from the earlier online-daemon architecture if present.
systemctl disable --now promptworksd.service >/dev/null 2>&1 || true
rm -f /usr/local/sbin/promptworksd /etc/systemd/system/promptworksd.service
systemctl daemon-reload >/dev/null 2>&1 || true
# Install PAM using a validated primary-factor -> PromptWorks second-factor order.
"$ROOT/install-pam-order.sh" common-auth
/usr/local/sbin/promptworks-backend-manifest create
systemctl enable --now promptworks-binding-guard.service >/dev/null
# Defense-in-depth: make update-control files immutable after the integrity manifest is sealed.
# Root can remove these flags, so this is not a substitute for the APK approval gate.
if command -v chattr >/dev/null 2>&1; then
  chattr +i /etc/promptworks-auth/backend.manifest /usr/local/sbin/promptworksctl \
    /usr/local/libexec/promptworks-update-gate /usr/local/sbin/promptworks-backend-manifest 2>/dev/null || true
fi
echo "PromptWorks single-device-bound OFFLINE time-match PAM installed at $PAM_SECURITY_DIR/pam_promptworks.so. No runtime server, LAN, Internet, polling, or notification delivery is required."
echo "Test in a SECOND terminal: sudo -K && sudo id"
echo "The terminal shows a single-use 3-digit number; the phone produces a time-bound 8-digit APPROVE/DENY code locally."
echo "Commissioning guard: first 3 PromptWorks failures before any success trigger automatic rollback."
