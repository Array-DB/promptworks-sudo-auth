# PromptWorks v3.4 — strict one-host / one-APK binding

PromptWorks v3.4 permits exactly one active Android APK installation to be paired with one Linux installation.

## Provisioning identity

During the one-time TLS provisioning session:

1. Linux creates a persistent P-256 host identity keypair and random pairing ID.
2. The APK creates a P-256 approval key in Android Keystore, requesting StrongBox when available and requiring `BIOMETRIC_STRONG` for approval-key use.
3. The provisioning service records the APK approval public-key fingerprint as the only accepted device identity.
4. The runtime OCRA key is derived with HMAC-SHA-256 from a one-time 256-bit pairing master plus the pairing ID, host ID, Linux host public-key fingerprint, APK device ID, and APK approval-key fingerprint.
5. The phone proves possession of the derived runtime credential before Linux seals `/etc/promptworks-auth/binding.json`.
6. Linux stores the paired phone public key and binding metadata root-owned, destroys the pairing master, and removes the provisioning service.

A second APK/public key is rejected with `host_already_bound`. Updating the same APK with `adb install -r` keeps Android app data/Keystore material and therefore keeps the same pairing.

## Runtime

Runtime sudo remains network-independent OCRA challenge/response. PAM requires both the root-only derived OCRA key and the root-owned binding record. A boot-time `promptworks-binding-guard.service` verifies the binding material is present and protected.

## Replacing a phone

Pairing replacement is intentionally explicit. On Linux:

```bash
sudo promptworksctl reset-pairing
```

The command requires the exact confirmation phrase `RESET PROMPTWORKS PAIRING`, restores the pre-PromptWorks sudo PAM configuration, destroys the old runtime/host private material, and removes the binding. Rerun `./install-promptworks.sh` to bind one new APK installation.

On Android, **Securely reset this phone pairing** requires a strong biometric and destroys the app's approval, transport, and offline wrapping keys. Resetting only the phone does not unlock the Linux host for another device; Linux must be reset separately.
