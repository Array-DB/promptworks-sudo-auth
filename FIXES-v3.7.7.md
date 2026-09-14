# PromptWorks v3.7.7 targeted fixes

- Uses the exact PromptWorks emblem artwork from the supplied reference UI for the in-app mark.
- Fixes candidate end-to-end proof HTTP 403 caused by a client scoped to `sudo` while the proof incorrectly sent service=`candidate-test`.
- Candidate proof now exercises the same `sudo` service scope as the eventual PAM runtime without changing `/etc/pam.d/sudo`.
- Runtime bridge now reports safe backend error identifiers (for example `service_scope_violation`) with HTTP failures.
- Enrollment output now says `enrollment/binding proof` instead of the misleading `offline credential` wording.
- Keeps the old PromptWorks PAM/backend active throughout candidate proof and only hands over after proof succeeds.
