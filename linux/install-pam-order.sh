#!/usr/bin/env bash
set -euo pipefail

# Install PromptWorks as a true second factor in /etc/pam.d/sudo.
# Usage: install-pam-order.sh <primary-stack-name>
#   Arch/Manjaro: system-auth
#   Debian/Ubuntu: common-auth
#
# The normal distro authentication stack is changed from "include" to "substack".
# This contains any "sufficient" controls inside that stack so they cannot return
# past the PromptWorks factor. PromptWorks is inserted immediately AFTER that
# primary stack, never appended blindly to the end of the file.

[[ ${EUID} -eq 0 ]] || { echo "install-pam-order.sh must run as root" >&2; exit 1; }
[[ $# -eq 1 ]] || { echo "Usage: $0 <primary-stack-name>" >&2; exit 2; }

PRIMARY="$1"
PAM_FILE="${PW_PAM_FILE:-/etc/pam.d/sudo}"
BACKUP="${PW_PAM_BACKUP:-/etc/pam.d/sudo.promptworks-backup}"
PW_LINE='auth required pam_promptworks.so keyfile=/etc/promptworks-auth/offline.key hostfile=/etc/promptworks-auth/host-id bindingfile=/etc/promptworks-auth/binding.json'

[[ -f "$PAM_FILE" ]] || { echo "$PAM_FILE not found" >&2; exit 1; }

# Preserve the first pre-PromptWorks sudo PAM file for rollback/uninstall.
if [[ ! -f "$BACKUP" ]]; then
  cp -a "$PAM_FILE" "$BACKUP"
  sed -i '/pam_promptworks\.so/d;/# PromptWorks offline OCRA second factor/d;/# PromptWorks second factor/d' "$BACKUP"
fi

TMP="$(mktemp "$(dirname "$PAM_FILE")/.sudo.promptworks.XXXXXX")"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

# Rewrite only the primary authentication include. Existing non-authentication
# account/session directives are preserved. Existing PromptWorks lines/comments
# are removed so reruns are idempotent.
awk -v primary="$PRIMARY" -v pw="$PW_LINE" '
BEGIN { inserted=0; found=0 }
/pam_promptworks\.so/ { next }
/^#[[:space:]]*PromptWorks (offline OCRA )?second factor/ { next }
{
  line=$0

  # Debian/Ubuntu shorthand: @include common-auth
  if (line ~ "^[[:space:]]*@include[[:space:]]+" primary "([[:space:]]|$)") {
    if (!inserted) {
      print "auth    substack    " primary
      print ""
      print "# PromptWorks second factor — MUST remain after the normal OS authentication stack."
      print pw
      inserted=1
    }
    found=1
    next
  }

  # Standard PAM syntax: auth include|substack <primary>
  if (line ~ "^[[:space:]]*auth[[:space:]]+(include|substack)[[:space:]]+" primary "([[:space:]]|$)") {
    if (!inserted) {
      print "auth    substack    " primary
      print ""
      print "# PromptWorks second factor — MUST remain after the normal OS authentication stack."
      print pw
      inserted=1
    }
    found=1
    next
  }

  print line
}
END {
  if (!found) exit 42
}
' "$PAM_FILE" > "$TMP" || rc=$?
rc=${rc:-0}
if [[ $rc -eq 42 ]]; then
  echo "ERROR: Could not find the expected '$PRIMARY' authentication stack in $PAM_FILE." >&2
  echo "Refusing to guess PAM ordering. Original file was not changed." >&2
  exit 1
elif [[ $rc -ne 0 ]]; then
  echo "ERROR: Failed to construct the PromptWorks PAM configuration." >&2
  exit "$rc"
fi

# Security validation: no top-level 'sufficient' auth module may appear before
# PromptWorks, because it could terminate sudo authentication before factor 2.
pw_no="$(grep -n 'pam_promptworks\.so' "$TMP" | cut -d: -f1)"
primary_no="$(grep -nE "^[[:space:]]*auth[[:space:]]+substack[[:space:]]+$PRIMARY([[:space:]]|$)" "$TMP" | head -n1 | cut -d: -f1)"
[[ -n "$pw_no" && -n "$primary_no" ]] || { echo "ERROR: PAM ordering validation failed." >&2; exit 1; }
[[ "$primary_no" -lt "$pw_no" ]] || { echo "ERROR: PromptWorks would run before primary authentication; refusing install." >&2; exit 1; }
[[ "$(grep -c 'pam_promptworks\.so' "$TMP")" -eq 1 ]] || { echo "ERROR: PromptWorks PAM module must appear exactly once." >&2; exit 1; }

if awk -v stop="$pw_no" 'NR < stop && /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+/ { bad=1 } END { exit bad ? 0 : 1 }' "$TMP"; then
  echo "ERROR: Found a top-level 'auth sufficient' rule before PromptWorks." >&2
  echo "That rule could bypass the second factor, so installation is intentionally stopped." >&2
  echo "Review $PAM_FILE manually; it has NOT been replaced." >&2
  exit 1
fi

# Keep PAM file ownership/mode consistent with the original and replace atomically.
chmod --reference="$PAM_FILE" "$TMP"
chown --reference="$PAM_FILE" "$TMP"
mv -f "$TMP" "$PAM_FILE"
trap - EXIT

# Final on-disk verification.
primary_no="$(grep -nE "^[[:space:]]*auth[[:space:]]+substack[[:space:]]+$PRIMARY([[:space:]]|$)" "$PAM_FILE" | head -n1 | cut -d: -f1)"
pw_no="$(grep -n 'pam_promptworks\.so' "$PAM_FILE" | cut -d: -f1)"
[[ "$primary_no" -lt "$pw_no" ]] || { echo "ERROR: Final PAM ordering check failed." >&2; exit 1; }

echo "PromptWorks PAM ordering verified: primary authentication (line $primary_no) -> PromptWorks second factor (line $pw_no)."
