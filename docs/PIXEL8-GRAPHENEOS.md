# Pixel 8 / GrapheneOS installation

The Android client is branded **Prompt-Works-Sudo-Auth** and uses the supplied PromptWorks artwork as the launcher and in-app icon.

The recommended path is the repository's terminal installer:

```bash
chmod +x ./install-promptworks.sh
./install-promptworks.sh
```

Android Studio is not required. The installer prepares the Android command-line SDK, waits for an authorized ADB connection, builds the APK, installs it, and passes the one-time provisioning URL/token over ADB rather than compiling the token into the APK.

On the Pixel:

1. Enable Developer options and USB debugging for installation.
2. Connect the Pixel with a data-capable cable and authorize the computer.
3. When Prompt-Works-Sudo-Auth opens, review the prefilled local provisioning URL.
4. Tap **Provision offline authenticator**.
5. Complete the `BIOMETRIC_STRONG` prompt so Android Keystore can wrap the per-host OCRA credential.
6. Wait for the Linux installer to report that the cryptographic offline-ready proof was verified.
7. Disable USB debugging when you no longer need it.

After provisioning, the phone does **not** need to remain on the same LAN and does not need Internet access for sudo authentication. Runtime use is manual OCRA challenge-response: enter the 12-digit challenge shown by sudo, unlock the app with the strong biometric, then type the generated 8-digit response into the terminal.

The left-side settings drawer pushes the main content to the right rather than overlaying it. Settings expose offline mode, host ID, OCRA suite, provisioning values, local reset/re-provision controls, commissioning rollback information, and phone security state.
