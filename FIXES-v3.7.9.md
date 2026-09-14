# PromptWorks v3.8.0 candidate proof / notification fix

## Root cause

The foreground `RequestPollingService` used OkHttp's default Android trust store. The candidate server uses a private per-install PromptWorks CA embedded in the APK, so enrollment worked through `MainActivity` (which used the embedded CA) while the background poller silently failed TLS. Linux successfully created the request and printed `MATCH NNN`, then appeared frozen because the phone never fetched that pending request.

## Fixes

- Background polling uses the exact same APK-embedded PromptWorks CA as `MainActivity`.
- Polling failures are logged under `PromptWorksRuntime` instead of being silently swallowed.
- Candidate proof checks Android notification permission before creating a test request.
- Linux prints progress every ~10 seconds while waiting and is hard-capped by a 75-second outer timeout.
- A failed proof never switches `/etc/pam.d/sudo`; the old PromptWorks stack remains active.
