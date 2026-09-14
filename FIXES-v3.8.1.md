# PromptWorks v3.9.1 — deterministic request delivery

- Replaces 1.8-second Android polling with authenticated 25-second long-polling.
- Keeps the foreground runtime service and private per-install CA trust.
- Candidate commissioning no longer depends solely on notification timing: once Linux creates the request, the installer opens the NEW APK on that exact request ID over the already-authorized ADB session.
- The signed approval still travels phone -> candidate HTTPS backend -> Linux runtime; ADB is not used to approve or carry the decision.
- Normal post-handover sudo continues to use the foreground runtime notification path, with long-polling and bounded retry/backoff.
- Old PromptWorks remains the active sudo protector until the candidate proof succeeds.
