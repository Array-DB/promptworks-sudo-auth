# PromptWorks Secure v3.7.2 UI pixel pass

This release rebuilds the Android Compose UI around the three supplied phone references.

- Home: glowing PromptWorks mark + inline `PromptWorks Secure` wordmark, paired-device pill, large approval card, biometric CTA, three security tiles, and fixed bottom navigation.
- Sudo request: compact no-scroll request card, host + command rows, three oversized number-match tiles, expiry countdown, deny/approve controls, and biometric footer.
- Drawer: fixed-width push drawer with PromptWorks branding, Devices/Security/Offline Mode/Upgrade Gate/History/About rows and security footer.
- Responsive fit: no `verticalScroll` is used by the production home/request/drawer/settings/history/about screens. Compact measurements are selected on short displays.
- Existing signing, strong-biometric approval, request polling, automatic backend decision return, and side-by-side Android package ID are preserved.
- Installer compatibility: server dependency is moved to `better-sqlite3 ^13.0.3` to avoid the Node 26 / V8 API build failure seen with 11.x.

The Android build is versionCode 13 / versionName 3.7.2 and keeps applicationId `com.promptworks.sudoauth.secure.v37`, so it updates the v3.7 candidate while remaining installed alongside the original PromptWorks package.
