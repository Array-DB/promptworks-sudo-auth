# v3.7.4 transactional commissioning and recovery

v3.7.3 and earlier could switch the candidate binding/PAM and then merely print instructions for a later commissioning test. That meant an installer could report migration complete even though the new PromptWorks stack had never successfully authenticated.

v3.7.4 changes the migration to a transaction:

1. The currently-working PromptWorks PAM must authorize the migration.
2. Its PAM file, PAM module, backend binding and guard state are snapshotted **before** trust is switched.
3. The new guard state is forcibly re-armed; a prior version's `passed` state is never inherited.
4. A root-owned dead-man watchdog is started before the cached sudo credential is invalidated.
5. The installer performs one real authentication through the new PromptWorks stack.
6. Only a successful new PromptWorks authentication allows the installer to print migration complete.
7. Failure/timeout leaves the watchdog to restore the previous PromptWorks PAM/backend. Upgrade rollback refuses to fall through to original/distro-only sudo mode.

For a host already left on an uncommissioned v3.7.2/v3.7.3 stack, use `restore-previous-promptworks.sh` with `pkexec`, or from an already-open root shell. The rescue script restores only `/var/lib/promptworks-backend-fallback` and fails closed if that previous PromptWorks snapshot is incomplete.
