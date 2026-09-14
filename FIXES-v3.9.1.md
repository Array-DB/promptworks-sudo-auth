# PromptWorks v3.9.1 — stale candidate port fix

v3.9.0 could refuse an otherwise safe protected upgrade when TCP 8788 was still held by the v3.8.3 candidate service. Its stale-candidate cleanup accidentally skipped v3.8.3, and the provisioning server was still tied to fixed port 8788.

v3.9.1 fixes both failure modes:

- cleanup now includes v3.8.3, v3.9.0, and v3.9.1 candidate services and candidate-only directories;
- before the APK bootstrap URL is generated, upgrades choose the first actually bindable temporary enrollment port in 8788–8899;
- if 8788 is occupied, the installer uses the next free port instead of killing an unknown listener;
- the selected port is used consistently by the TLS URL, systemd service, Android bootstrap, health check, and enrollment;
- the temporary HTTPS server is still destroyed after binding; sudo approval remains fully offline.

The ACTIVE/OLD PromptWorks PAM/backend is not targeted by candidate cleanup.
