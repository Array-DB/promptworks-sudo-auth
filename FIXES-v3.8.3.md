# PromptWorks v3.9.1 — stale candidate port cleanup

This release fixes a protected-upgrade failure where an older v3.8.0/v3.8.1/v3.8.2
candidate service could remain active on TCP 8788. The next candidate then entered a
systemd restart loop with `EADDRINUSE`.

The installer now stops and removes every known side-by-side candidate service from
v3.7.5 through v3.9.1 before provisioning a new candidate, removes their candidate-only
state directories, and verifies that the isolated candidate port is actually free. If an
unrelated process owns the port, installation fails closed and prints the listener rather
than killing an unknown process. The active/old PromptWorks sudo backend is not touched.
