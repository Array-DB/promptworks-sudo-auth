# PromptWorks PAM ordering

PromptWorks must be a second factor, not merely another PAM module appended at the end of `/etc/pam.d/sudo`.

For Manjaro/Arch, the installer produces the equivalent of:

```text
auth    substack    system-auth
auth    required    pam_promptworks.so keyfile=/etc/promptworks-auth/offline.key hostfile=/etc/promptworks-auth/host-id bindingfile=/etc/promptworks-auth/binding.json
```

For Ubuntu/Debian, it uses `common-auth` as the contained substack.

`substack` is intentional: controls such as `sufficient` inside the distro authentication stack cannot return past the PromptWorks factor. The installer inserts PromptWorks directly after the primary stack, checks that it appears exactly once, checks ordering, and refuses installation if a top-level `auth sufficient` rule appears before PromptWorks.

The first commissioning test should be run from a second terminal with a separate root shell kept open:

```bash
sudo -K
sudo -v
```

The expected logical sequence is the operating-system authentication policy first, followed by the PromptWorks challenge and 8-digit response.
