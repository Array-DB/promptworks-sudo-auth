# PromptWorks v3.8.0 — signed response reliability

This release refactors the phone-to-Linux decision path so an APPROVE/DENY is not treated as complete until the backend acknowledges the exact signed request and returns the final 8-digit receipt.

## Response path

1. Linux creates one request and prints the three-digit number match.
2. The enrolled APK fetches that request using the device transport key.
3. BIOMETRIC_STRONG unlocks the approval signing key for that exact request.
4. The APK signs request ID, challenge, verification digits, user, service, host/action, expiry, decision and device ID.
5. The decision endpoint verifies the signature and atomically commits APPROVED or DENIED.
6. The endpoint returns an authenticated-over-TLS acknowledgement containing the request ID, final state and receipt.
7. The APK validates the acknowledgement and only then marks the action confirmed.
8. Linux independently polls the request using its scoped client credential and returns the same final receipt to PAM.

The decision endpoint is idempotent for an identical already-committed signed decision. This makes retry safe when the server committed the decision but the HTTP response was lost.

Pending requests no longer expose their receipt code. The Linux runtime tolerates short transient polling failures but fails closed for authentication/protocol errors.

Notification deep links now preserve the request ID so the app focuses the exact request that generated the notification.

Sudo remains protected by the previous PromptWorks stack during candidate proof and is not switched until this entire response path succeeds.
