#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }
if [[ -f /etc/pam.d/sudo.promptworks-backup ]]; then cp -a /etc/pam.d/sudo.promptworks-backup /etc/pam.d/sudo; fi
rm -f /usr/lib/security/pam_promptworks.so /usr/local/sbin/promptworks-auth-rollback /usr/local/sbin/promptworksctl
if [[ -f /etc/promptworks-auth/offline.key ]]; then shred -u /etc/promptworks-auth/offline.key 2>/dev/null || rm -f /etc/promptworks-auth/offline.key; fi
rm -rf /etc/promptworks-auth /var/lib/promptworks-auth-guard
systemctl disable --now promptworks-binding-guard.service 2>/dev/null || true
rm -f /etc/systemd/system/promptworks-binding-guard.service
# Also clean legacy pre-v3.3 online-daemon artifacts if present.
systemctl disable --now promptworksd.service 2>/dev/null || true
rm -f /usr/local/sbin/promptworksd /etc/systemd/system/promptworksd.service
systemctl daemon-reload 2>/dev/null || true
userdel promptworks-auth 2>/dev/null || true
echo "PromptWorks offline sudo integration removed."
