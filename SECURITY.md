# Security Architecture — Prompt-Works-Sudo-Auth v3.6

PromptWorks v3.6 is an offline sudo second factor for Manjaro/Arch and Ubuntu/Debian-family Linux with a Pixel/GrapheneOS authenticator.

## Authentication controls

- Existing Linux password/fingerprint policy remains the first factor.
- PromptWorks is installed afterward as `auth required` in PAM.
- Runtime uses a fresh 3-digit number match inside a 60-second epoch.
- APPROVE and DENY produce distinct HMAC-SHA-256-derived 8-digit decision codes.
- Runtime number reuse is bounded by root-owned history.
- Android requires `BIOMETRIC_STRONG` for decision generation.
- Android wrapping material uses AES-256-GCM with Android Keystore; StrongBox is requested where supported.
- Pairing binds one Linux P-256 identity to one Android Keystore P-256 identity.
- The one-time pairing master is destroyed after provisioning.
- The temporary HTTPS provisioning service and private TLS/server state are removed after enrollment.

## Side-by-side upgrade protection

v3.6 uses Android package ID `com.promptworks.sudoauth.secure`, so an existing `com.promptworks.sudoauth` app remains installed and usable during migration.

If an older backend is active, the v3.6 installer provisions the new APK into `/etc/promptworks-auth-v36-candidate` while `/etc/promptworks-auth` remains active. Before candidate activation, a root-run update gate generates a fresh 3-digit number using the **old active runtime key**. The old/current enrolled APK must return an APPROVE decision within that time window. DENY, expiry, or an invalid response aborts the migration.

## Backend integrity controls

The installed backend includes:

- root-only update gate;
- root-only management CLI;
- SHA-256 integrity manifest for the PAM module, sudo PAM file, update gate, management CLI, and binding-guard unit;
- systemd sandboxing for boot-time binding/integrity verification;
- restrictive ownership/modes;
- best-effort immutable flags on update-control files after installation.

`sudo promptworksctl authorize-change` requires enrolled-APK approval and creates only a short root-only maintenance window. `reset-pairing` is also protected by APK approval.

## Important root boundary

PromptWorks cannot make its backend unchangeable to a malicious actor who already has unrestricted Linux root. Root controls the kernel, filesystem, PAM configuration, systemd, binaries, boot chain, and can remove immutable flags. Claims otherwise would be misleading.

The backend-change gate protects the intended administrative workflow and raises resistance to accidental/non-root modification. If resistance to privileged tampering is required, combine PromptWorks with platform controls such as UEFI Secure Boot, TPM-backed measured boot, IMA appraisal, read-only/verified system partitions, and tightly scoped sudo policy.

## Manual-code limitation

An 8-digit manual decision code is not a full P-256 signature. P-256 is used for device identity/binding; the compact runtime decision is HMAC-based because it must be human-enterable without a runtime transport channel. A future transport-based mode can carry complete asymmetric signatures over QR/USB/Bluetooth.

## Recovery

Keep a separate root shell open during PAM commissioning. The three-failure commissioning rollback remains enabled until the first successful PromptWorks verification. Physical Linux recovery remains the final recovery path if the enrolled phone is lost and no authenticated administration path remains.
