# PromptWorks Secure v3.7.4 — screen-by-screen UI refactor

This pass replaces the v3.7.2 approximation with a reference-driven layout for the three supplied Pixel screens.

## What changed

- Home screen now has fixed, non-scrolling regions: top action, PromptWorks mark, inline wordmark, pairing pill, hero approval card, three security cards, and a full-width bottom navigation bar.
- The PromptWorks mark is no longer a Unicode asterisk. It is rendered as a scalable six-lobed vector with cyan outline/glow and outer ring.
- The primary action uses the cyan-to-blue pill gradient from the reference instead of a flat Material button.
- Sudo Request is rebuilt as a single-viewport screen with one-line host/command rows, large three-digit match tiles, expiry row, symmetric DENY/APPROVE buttons, and the biometric footer pinned inside the request card.
- The drawer no longer shrinks the active page. It overlays from the left while the active page shifts right and is clipped by the phone viewport, matching the supplied drawer composition.
- Drawer spacing, selected-row cyan rail, footer card, card radii, muted text, borders, and dark gradient surfaces were retuned.
- Home/Request layouts use short-screen breakpoints instead of ScrollColumn/vertical scrolling.
- Android version is now 3.7.4 / versionCode 14 while retaining applicationId `com.promptworks.sudoauth.secure.v37`, so it updates the side-by-side v3.7 candidate.

## Installer cleanup included

The installer output had stale v3.7.0/v3.7.2 labels and two misleading recovery/runtime messages. v3.7.4 updates the visible version labels, states that commissioning rollback restores the previous PromptWorks PAM/backend snapshot, and no longer claims that no runtime backend is required while the bound approval backend is active.

## Verification in this build tree

- `bash -n install-promptworks.sh`
- `bash -n linux/install-manjaro.sh`
- `bash -n linux/install-ubuntu.sh`
- `python tests/test_v37_upgrade_layout.py`
- `python tests/test_binding.py`
- `python tests/test_time_match.py`
- `python tests/test_ocra.py`

The container cannot download Gradle 8.11.1, so the APK itself cannot be compiled in this environment. The v3.7.2 installer log supplied by the user confirms that the same Android project compiled successfully before this UI-only Kotlin refactor.
