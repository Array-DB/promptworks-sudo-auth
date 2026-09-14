# Protected Backend Upgrades — v3.6

## Goal

Allow a new APK and backend to be installed without destroying the currently working authenticator first, and require the currently trusted APK to authorize the backend transition.

## Android coexistence

v3.6 intentionally changes the Android application ID from:

```text
com.promptworks.sudoauth
```

to:

```text
com.promptworks.sudoauth.secure
```

Android therefore treats v3.6 as a separate application with a separate sandbox and Android Keystore namespace. Installing v3.6 does not overwrite or clear the old authenticator.

## Candidate binding

During migration:

```text
/etc/promptworks-auth                 active old binding
/etc/promptworks-auth-v36-candidate   new candidate binding
```

The installer provisions and verifies the new phone identity against the candidate directory only. PAM continues using the active old directory until approval is obtained.

## Old-APK approval gate

Immediately before activating the candidate, the root-run `promptworks-update-gate` reads the old root-only runtime key and host ID. It generates a fresh 3-digit number and verifies the old app's time-bound APPROVE or DENY code using the same constant-time comparison rules as runtime PAM.

Only APPROVE allows the installer to continue.

## Commit

After approval, the old active binding is copied to a root-only rollback directory, the candidate becomes `/etc/promptworks-auth`, and the new PAM/backend files are installed. The old APK remains installed but is no longer the trusted runtime peer.

## Future maintenance

The management flow is:

```bash
sudo promptworksctl authorize-change "maintenance reason"
```

The currently enrolled app must approve. The resulting maintenance ticket lives only under `/run`, is root-only, and expires after 120 seconds.

`sudo promptworksctl reset-pairing` invokes the same APK approval mechanism before destructive reset.

## Integrity manifest

`promptworks-backend-manifest` hashes the active PAM module, `/etc/pam.d/sudo`, PromptWorks management binaries, update gate, and binding-guard unit. The binding guard verifies both the 1:1 binding and this manifest at boot.

## Threat boundary

This mechanism cannot cryptographically defeat unrestricted root. Root can replace the verifier itself or boot another environment. For privileged-tamper resistance, use an external root of trust such as Secure Boot/TPM/IMA or a verified immutable OS image.
