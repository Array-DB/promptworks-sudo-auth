from pathlib import Path
import re

root=Path(__file__).resolve().parents[1]
gradle=(root/'android/app/build.gradle.kts').read_text()
manifest=(root/'android/app/src/main/AndroidManifest.xml').read_text()
installer=(root/'install-promptworks.sh').read_text()
ctl=(root/'linux/promptworksctl').read_text()

assert 'applicationId = "com.promptworks.sudoauth.secure.v37"' in gradle
assert 'PromptWorks Secure v3.9.1' in manifest
assert 'readonly APP_ID="com.promptworks.sudoauth.secure.v37"' in installer
assert 'CANDIDATE_AUTH_DIR="/etc/promptworks-auth-v37-candidate"' in installer
assert 'authorize_existing_backend_change' in installer
assert 'sudo -K || true' in installer and 'if ! sudo -v; then' in installer
assert 'promptworks-update-gate' in ctl
assert 'authorize-change' in ctl
assert 'reset_pairing' in ctl and 'authorize_change "RESET the PromptWorks pairing' in ctl
print('v3.7 side-by-side/protected-upgrade layout: OK')

# Regression: v3.6.1 is the old backend and must NOT be classified as already-v3.7.
assert 'if [[ "$app_id" == "com.promptworks.sudoauth.secure.v37" && "$ver" == "3.9.1" ]]' in installer
assert "'backendVersion': '3.9.1'" in installer
assert "'androidAppId': 'com.promptworks.sudoauth.secure.v37'" in installer
assert 'versionName = "3.9.1"' in gradle

# Regression: every upgrade is transactional and must prove the NEW PAM before success.
assert 'create_previous_promptworks_fallback' in installer
main_idx=installer.index('main()')
migration_idx=installer.index('if (( MIGRATION_MODE == 1 )); then', main_idx)
assert installer.index('create_previous_promptworks_fallback', migration_idx) < installer.index('activate_candidate_binding', migration_idx)
assert "printf 'armed 0\\n' | sudo tee /var/lib/promptworks-auth-guard/state" in installer
assert 'commission_new_promptworks_stack' in installer
assert 'promptworks-commission-watchdog.log' in installer
assert 'previous PromptWorks PAM/backend automatically' in installer

rollback=(root/'linux/promptworks-auth-rollback').read_text()
assert 'promptworks-upgrade-mode' in rollback
assert 'refusing original-mode rollback' in rollback
assert 'SNAPSHOT_COMPLETE' in rollback

# Protected-upgrade invariant: old PromptWorks remains untouched while the NEW candidate is proven.
assert 'choose_candidate_port' in installer
assert 'promptworks-auth-server-v391.service' in installer
assert 'candidate_end_to_end_proof' in installer
assert 'WITHOUT changing sudo' in installer
assert installer.index('candidate_end_to_end_proof', migration_idx) < installer.index('authorize_existing_backend_change', migration_idx)
assert '--es pw_activation_state "candidate"' in installer
assert '--es pw_activation_state "active"' in installer
assert 'disable --now promptworks-auth-server.service' in installer
assert 'promptworks-auth-server-v391.service' in rollback

# v3.9.1 invariant: runtime approval is fully offline. Candidate provisioning
# server is destroyed before candidate proof and before PAM handover.
assert 'THIS PROOF IS OFFLINE.' in installer
assert 'retire_provisioning_server' in installer
main_seq=installer.index('finalize_single_device_binding', migration_idx)
assert installer.index('retire_provisioning_server', main_seq) < installer.index('candidate_end_to_end_proof', main_seq)
assert '--key "$CANDIDATE_AUTH_DIR/offline.key"' in installer
assert '--host "$CANDIDATE_AUTH_DIR/host-id"' in installer
assert 'promptworks-runtime-client' not in installer[main_idx:]
assert not (root/'linux/promptworks-runtime-client').exists()

# v3.7.8 regression: an uncommissioned candidate must never be "resumed" by
# assuming its systemd unit/TLS state still exists. It is rebuilt cleanly while
# the active old PromptWorks stack remains untouched.
assert 'reset_incomplete_candidate' in installer
assert 'Skipping re-provisioning' not in installer
assert 'Incomplete NEW candidate removed safely. OLD PromptWorks is still the active sudo protector.' in installer
assert 'promptworks-auth-server-v377.service' in installer
assert 'adb -s "$ANDROID_SERIAL" shell pm clear "$APP_ID"' in installer

# v3.9.1 Android runtime must not contain/start the former network poller.
main=(root/'android/app/src/main/java/com/promptworks/authenticator/MainActivity.kt').read_text()
assert not (root/'android/app/src/main/java/com/promptworks/authenticator/RequestPollingService.kt').exists()
assert 'startForegroundService' not in main
assert 'OFFLINE SUDO APPROVAL' in main
assert 'biometricOfflineResponse(challenge, "approve")' in main
assert 'Type this 8-digit code into the waiting sudo prompt' in main
assert 'android.permission.POST_NOTIFICATIONS' not in manifest
assert '.RequestPollingService' not in manifest

# PAM must perform local HMAC verification and manual decision-code entry.
pam=(root/'linux/pam/pam_promptworks.c').read_text()
assert 'PromptWorks decision code: ' in pam
assert 'decision_code(key,host,epoch,number,"approve"' in pam
assert 'decision_code(key,host,epoch,number,"deny"' in pam
assert 'constant_time_digits_eq' in pam
assert 'promptworks-runtime-client' not in pam

# Failed historical candidates must be stopped, and a stale fixed 8788 listener must not block enrollment.
for stale in (
    'promptworks-auth-server-v380.service',
    'promptworks-auth-server-v381.service',
    'promptworks-auth-server-v382.service',
    'promptworks-auth-server-v383.service',
    'promptworks-auth-server-v390.service',
):
    assert stale in installer
assert 'Selected temporary enrollment port ${SERVER_PORT} became occupied before startup.' in installer
assert 'sudo ss -ltnp' in installer

# v3.9.1 regression: stale v3.8.3 must be cleaned and fixed port 8788 must not block upgrades.
assert 'promptworks-auth-server-v383.service' in installer
assert '/opt/promptworks-auth-server-v383-candidate' in installer
assert 'choose_candidate_port' in installer
assert 'range(8788, 8899 + 1)' in installer
assert 'Runtime sudo approval is still fully offline' in installer
