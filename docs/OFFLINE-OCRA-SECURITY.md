# PromptWorks v3.4 Offline OCRA Security Design

## Goals

The v3.4 sudo path is designed so that the phone and Linux computer require network connectivity only during initial provisioning. Runtime authentication is deterministic cryptography performed independently on each device.

## Provisioning trust boundary

The installer creates a temporary install-specific CA and HTTPS server on the Linux host. It generates a 256-bit per-host OCRA key and a one-time enrollment token. The APK is built without the token. After ADB authorization, the installer starts the app with the provisioning URL/token as intent extras. The enrollment token is single-use and the app removes the bootstrap values after success.

The server returns the OCRA key only as part of a valid one-time enrollment response over TLS. Android immediately wraps the key with AES-256-GCM using an Android Keystore key requiring per-use `BIOMETRIC_STRONG` authorization. The plaintext key is not persisted in ordinary app preferences.

After enrollment is observed, the installer removes the provisioning service, database, environment file/admin token, server TLS private keys, installed Node server tree, and system service account.

## Runtime authentication

1. Existing sudo/PAM authentication remains required.
2. `pam_promptworks.so` reads the host OCRA key from a root-owned, non-symlink regular file.
3. The module uses OpenSSL `RAND_bytes` to generate a fresh 12-digit numeric challenge.
4. The challenge is persisted in a root-owned bounded history to avoid reuse.
5. The user types the challenge into the enrolled phone.
6. The phone requires `BIOMETRIC_STRONG` to decrypt the OCRA key for that operation.
7. The phone computes `PW-TIME-MATCH-HMAC-SHA256-8:v1` and displays an 8-digit response.
8. PAM verifies the response locally in constant-time style and returns success/failure.

No server, daemon, socket, TCP port, cloud account, LAN, or Internet connection participates in runtime verification.

## Linux key handling

`/etc/promptworks-auth/offline.key` is owned by root and mode `0400`. The PAM module rejects key files that are symlinks, are not regular files, are not owned by root, or are group/other-writable. The challenge history and commissioning state are root-owned mode `0600` under `/var/lib/promptworks-auth-guard`.

## Android key handling

The OCRA credential is not itself an Android Keystore HMAC key because the Linux verifier must possess the same symmetric OCRA key. Instead, Android Keystore holds a non-exportable AES-256 wrapping key. The wrapping key is configured for per-use strong-biometric authorization and biometric-enrollment invalidation. StrongBox is requested where available and falls back to the hardware-backed Android Keystore implementation if StrongBox key creation is unavailable.

If the biometric set invalidates the wrapping key, the authenticator must be re-provisioned. This is intentional fail-closed behavior.

## Replay and guessing resistance

A response is tied to a random 12-digit verifier challenge and a 256-bit key uniquely derived from the sealed host↔APK pairing. Previously observed responses do not authenticate a fresh challenge. The verifier accepts one response per PAM invocation; the existing sudo factor remains required before the PromptWorks factor in the supported installer layout.

The user-visible response is deliberately short enough to enter manually, so it does not carry the full entropy of the HMAC output. This is normal for OCRA/HOTP-style authenticators and is why online attempt controls and the independent sudo factor remain important.

## Commissioning rollback

Until one PromptWorks authentication succeeds, three PromptWorks failures trigger the root-owned rollback helper. It restores `/etc/pam.d/sudo.promptworks-backup`, removes the PromptWorks PAM module and offline key, and leaves a diagnostic log. This protects against a broken first-time installation without creating a permanent runtime bypass.

## What this design does not claim

There is no meaningful universal “10/10” security score. Security depends on the Linux host, phone, user behavior, supply chain, physical access, kernel integrity, sudo configuration, and recovery process.

Manual-entry OTP/challenge-response is not the same thing as a channel-bound FIDO2/WebAuthn assertion. This design is strong against network unavailability and replay of old responses, but it does not cryptographically bind the exact authoritative sudo command/argv because PAM does not reliably receive that data. Command-level transaction authorization needs a supported sudo policy/I/O plugin or a purpose-built privileged command broker.


## Single-device binding

The v3.4 runtime key is derived only after the APK presents its hardware-backed approval public key. The derivation binds the pairing ID, host ID, Linux host public-key fingerprint, APK device ID, and APK approval-key fingerprint. The one-time pairing master is destroyed after the binding is sealed. Linux refuses a second APK identity until an explicit `sudo promptworksctl reset-pairing`. See `SINGLE-DEVICE-BINDING.md`.
