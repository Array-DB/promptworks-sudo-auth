# PromptWorks v3.7.8 recovery-safe candidate provisioning

This release fixes the failed-rerun path exposed when v3.7.7 found a sealed candidate but its candidate systemd unit no longer existed.

## Root cause

A sealed `binding.json` + `offline.key` was incorrectly treated as proof that the entire candidate runtime was resumable. That assumption was false: the systemd unit, runtime client, server database, TLS files or APK trust anchor can be incomplete after a failed/aborted run. The installer then called `systemctl enable --now promptworks-auth-server-v377.service` and failed if the unit had disappeared. A rerun could also rebuild the APK with a new embedded CA while trying to reuse an older candidate server CA.

## v3.7.8 behavior

While the active v3.6.x PromptWorks stack continues to protect sudo, any uncommissioned v3.7.5-v3.7.8 candidate artifacts are treated as disposable. The installer stops/removes only candidate services/directories, clears only the side-by-side `com.promptworks.sudoauth.secure.v37` app data, and provisions a fresh candidate whose server TLS matches the CA embedded in the just-built APK. The active `/etc/promptworks-auth`, active PAM configuration, old APK and active backend are not touched.

There is no plain-sudo fallback. Candidate cleanup happens before any handover.
