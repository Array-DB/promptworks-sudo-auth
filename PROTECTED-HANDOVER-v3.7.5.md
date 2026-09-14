# PromptWorks v3.7.7 — continuously protected handover

Hard invariant for upgrades: **sudo is never intentionally left without a PromptWorks second factor.**

Upgrade order:

1. Detect the currently working PromptWorks PAM and leave it active.
2. Build/install the new Android package side-by-side.
3. Start the NEW candidate backend on an isolated port/service (`8788`, `promptworks-auth-server-v377.service`). The current backend is not replaced or restarted.
4. Enroll the NEW APK in **CANDIDATE** state. The APK explicitly shows that it is not active in PAM yet.
5. Run an end-to-end candidate request (notification → 3-digit match → BIOMETRIC_STRONG → signed APPROVE) without modifying `/etc/pam.d/sudo`.
6. If and only if candidate proof succeeds, force a fresh authorization through the CURRENT/OLD PromptWorks sudo stack.
7. Capture the last-known-good PromptWorks PAM/backend snapshot.
8. Perform the PromptWorks-to-PromptWorks handover. PAM replacement remains atomic and always contains a PromptWorks module; there is no password-only/original-sudo transition.
9. Run a real `sudo -v` through the NEW stack under a root rollback watchdog.
10. On success, mark the NEW APK ACTIVE and retire the previous online backend. On failure, restore the previous PromptWorks PAM/backend; original/distro-only sudo is forbidden as an upgrade rollback target.

The old APK/backend should not be removed until the NEW stack has passed the real sudo commissioning test.
