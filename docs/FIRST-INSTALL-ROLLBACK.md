# First-install rollback guard

The Manjaro/Arch and Ubuntu/Debian installers arm a root-owned commissioning guard at `/var/lib/promptworks-auth-guard/state`.

Initial state is `armed 0`. While armed, PromptWorks PAM failures increment the counter. The first successful offline OCRA response changes the state to `passed 0`, permanently disabling automatic uninstall for that installation.

If the first three PromptWorks checks fail before any success, `/usr/local/sbin/promptworks-auth-rollback` restores `/etc/pam.d/sudo.promptworks-backup`, removes the PromptWorks PAM module and offline credential, and writes `/var/log/promptworks-auth-rollback.log`.

v3.4 does not depend on a runtime daemon or network server, so rollback focuses on restoring the PAM stack and deleting the local second-factor material. It also removes legacy `promptworksd` artifacts if upgrading from an older version.
