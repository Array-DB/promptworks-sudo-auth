# PromptWorks Secure v3.7.7 — UI and hardening pass

- Applies system status/navigation insets to stop the app bar, drawer, and content colliding with GrapheneOS system UI.
- Removes the legacy `PromptWorks Sudo Auth` bitmap from candidate provisioning and uses the same vector mark/PromptWorks Secure wordmark as the reference UI.
- Adds an explicit CANDIDATE state pill so the user cannot confuse the new APK with the currently active sudo authenticator.
- Keeps the one-time enrollment token masked and makes TLS failures actionable without exposing secrets.
- Uses a dedicated OkHttp trust store containing only the installer-generated PromptWorks CA, rather than accepting the general Android/user CA set for backend calls.
- Keeps cleartext disabled, backups disabled, and adds full-backup opt-out.
- Version 3.7.7 / versionCode 17. The v37 application ID remains unchanged so this upgrades the side-by-side candidate package without replacing the legacy PromptWorks package.
- Upgrade invariant remains: the previous known-good PromptWorks stack protects sudo until the candidate is proven and the protected handover succeeds.
