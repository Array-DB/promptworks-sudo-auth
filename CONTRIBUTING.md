# Contributing

PromptWorks touches Linux PAM and Android authentication. Keep changes small, reviewed, and testable.

Before opening a pull request:

1. Run shell syntax checks on changed scripts.
2. Build the Android project locally when Android files change.
3. Keep PAM ordering explicit: normal OS auth first, PromptWorks second.
4. Never commit generated keys, pairing state, enrollment tokens, keystores, or local TLS material.
