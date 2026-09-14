#!/usr/bin/env bash
set -euo pipefail

FALLBACK=/var/lib/promptworks-backend-fallback
LOG=/var/log/promptworks-manual-recovery.log

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$0" "$@"
  fi
  echo "This recovery must run as root. Use an already-open root shell; do NOT use sudo if PromptWorks sudo auth is broken." >&2
  exit 1
fi

exec > >(tee -a "$LOG") 2>&1
printf '[%s] PromptWorks previous-version recovery started\n' "$(date -Is)"

# Upgrade recovery is intentionally fail-closed: restore only a complete previous
# PromptWorks snapshot. Never use the distro/original sudo PAM backup here.
[[ -d "$FALLBACK" ]] || { echo "ERROR: $FALLBACK does not exist. Refusing original-mode fallback." >&2; exit 2; }
[[ -f "$FALLBACK/sudo.pam" ]] || { echo "ERROR: previous PromptWorks sudo PAM snapshot is missing." >&2; exit 2; }
[[ -d "$FALLBACK/auth-dir" ]] || { echo "ERROR: previous PromptWorks backend snapshot is missing." >&2; exit 2; }
[[ -f "$FALLBACK/auth-dir/binding.json" ]] || { echo "ERROR: previous PromptWorks binding.json is missing." >&2; exit 2; }
[[ -f "$FALLBACK/pam_promptworks.so" && -f "$FALLBACK/pam-path" ]] || { echo "ERROR: previous PromptWorks PAM module snapshot is missing." >&2; exit 2; }

pam_path="$(cat "$FALLBACK/pam-path")"
[[ "$pam_path" == */security/pam_promptworks.so ]] || { echo "ERROR: unsafe PAM module path in fallback snapshot." >&2; exit 2; }

# Remove immutable flags that a newer candidate may have applied.
if command -v chattr >/dev/null 2>&1; then
  chattr -i /etc/promptworks-auth/backend.manifest /usr/local/sbin/promptworksctl \
    /usr/local/libexec/promptworks-update-gate /usr/local/sbin/promptworks-backend-manifest 2>/dev/null || true
fi

cp -a "$FALLBACK/sudo.pam" /etc/pam.d/sudo
rm -rf /etc/promptworks-auth
cp -a "$FALLBACK/auth-dir" /etc/promptworks-auth
install -Dm755 "$FALLBACK/pam_promptworks.so" "$pam_path"

if [[ -f "$FALLBACK/guard-state" ]]; then
  install -d -o root -g root -m 0700 /var/lib/promptworks-auth-guard
  install -Dm600 "$FALLBACK/guard-state" /var/lib/promptworks-auth-guard/state
fi

# Legacy v3.7.2 snapshots do not record service state. Infer it conservatively:
# v3.7.x uses the bound HTTPS backend; older PromptWorks releases do not.
backend_version="$(python3 - <<'PY' 2>/dev/null || true
import json
try:
    print(json.load(open('/etc/promptworks-auth/binding.json')).get('backendVersion',''))
except Exception:
    pass
PY
)"
if [[ -f "$FALLBACK/server-was-active" || "$backend_version" == 3.7.* ]]; then
  systemctl restart promptworks-auth-server.service 2>/dev/null || true
else
  systemctl stop promptworks-auth-server.service 2>/dev/null || true
fi

rm -f /var/lib/promptworks-upgrade-mode
systemctl daemon-reload 2>/dev/null || true

printf '[%s] Restored previous PromptWorks PAM/backend version=%s. Original/distro-only sudo mode was NOT enabled.\n' \
  "$(date -Is)" "${backend_version:-unknown}"
echo "Recovery complete. Test from a NEW terminal with: sudo -K && sudo id"
