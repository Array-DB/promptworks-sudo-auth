# PromptWorks v3.5 Time-Match + ECC Security Design

## Goal

PromptWorks v3.5 keeps the one-time provisioning model and strict one-Linux-host ↔ one-APK binding, while changing runtime sudo authentication to a GitHub-style **number match** with a hard time window. Runtime authentication does not require LAN, Internet, cloud, or a permanent server.

## Runtime flow

1. Normal Linux sudo authentication runs first.
2. PAM starts a fresh 60-second epoch. If fewer than 20 seconds remain, it waits for the next epoch before displaying a request.
3. PAM generates a cryptographically random, single-use 3-digit number and records `(epoch, number)` in a root-only replay ledger.
4. The terminal displays the number and the remaining lifetime.
5. The user opens the one enrolled APK, enters/selects the same 3-digit number, and taps **APPROVE** or **DENY**.
6. Android requires `BIOMETRIC_STRONG` before unwrapping the bound runtime key.
7. The APK generates an 8-digit decision code over the host binding, epoch, number, and explicit decision.
8. The user types that code into the terminal. PAM rejects wrong, expired, or replayed decisions. A valid DENY code fails authentication immediately; a valid APPROVE code succeeds.

## Cryptography

The device binding uses P-256 elliptic-curve key pairs. The APK approval private key is generated in Android Keystore with StrongBox requested where available, biometric authorization required for use, and invalidation on biometric re-enrollment. Linux keeps the paired APK public key and its own P-256 host identity as part of the sealed 1:1 binding.

For the short human-entered runtime decision code, v3.5 uses HMAC-SHA-256 with dynamic truncation over:

```
PromptWorks-TimeMatch-v1
<host-id>
<60-second epoch>
<3-digit match number>
<approve|deny>
```

The 256-bit runtime key is derived during the one-time pairing from high-entropy pairing material plus both host and phone binding identities. It is then stored root-only on Linux and wrapped by a biometric-gated AES-256-GCM Android Keystore key on the Pixel.

### Why not make the 8-digit code an ECDSA signature?

A P-256 ECDSA signature is roughly 64 bytes before encoding. It cannot be reduced to eight decimal digits and still remain publicly verifiable. A system that is simultaneously **air-gapped at runtime**, **asymmetric-only**, and **short-code/manual-entry** cannot provide all three properties at once. PromptWorks therefore uses ECC for non-exportable device identity/binding and a symmetric MAC for the compact offline decision code.

If full asymmetric per-request authorization is desired later, the response must be transported in full (for example over Bluetooth, USB, QR, or a network channel) so Linux can verify the phone's ECDSA signature.

## Replay and timeout controls

- Match numbers are generated with OpenSSL `RAND_bytes`.
- A number is never reused in the same time epoch.
- The code binds the explicit `approve` or `deny` decision.
- The verifier rejects the code after the epoch deadline.
- Old codes cannot authenticate a different epoch or a different match number.
- The commissioning rollback remains active until the first successful PromptWorks approval.

## Seed phrase comparison

Bitcoin-style mnemonic seed phrases are a human backup representation of secret entropy; they are not a number-matching authentication protocol. PromptWorks intentionally does **not** expose its phone private key as a seed phrase because that would make a hardware-bound, non-exportable authenticator exportable. A future recovery design should use a separately scoped recovery credential, not the live approval key.

## Security boundary

No design can guarantee that a fully compromised Linux root account or a compromised phone OS cannot subvert authentication. In particular, the Linux verifier necessarily possesses the symmetric runtime verifier key for the short manual code. v3.5 is designed to resist replay, accidental duplication, remote network spoofing, second-device enrollment, and unauthorized use of the legitimate APK key, but it is not a substitute for a trusted operating system, secure boot, timely updates, and physical device security.
