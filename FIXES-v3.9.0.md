# PromptWorks v3.9.1 — Offline runtime response

v3.9.1 removes the runtime HTTPS request/response path from sudo authentication. The local HTTPS server exists only during one-time candidate enrollment, is destroyed before candidate proof, and is not required after provisioning.

Runtime sudo flow:

1. PAM generates a random single-use 3-digit number inside a 60-second epoch.
2. The user enters those three digits in the enrolled APK.
3. `BIOMETRIC_STRONG` unlocks the Keystore-wrapped per-binding secret for that operation.
4. The APK computes an 8-digit HMAC-SHA-256 decision code over the protocol label, bound host ID, epoch, three-digit match, and explicit `approve`/`deny` decision.
5. The user types the 8-digit code into sudo. PAM verifies both APPROVE and DENY candidates locally in constant time.

No runtime notification, polling service, LAN callback, cloud service, or local HTTPS backend is used. The Android INTERNET permission remains only for the temporary first-time HTTPS enrollment step.
