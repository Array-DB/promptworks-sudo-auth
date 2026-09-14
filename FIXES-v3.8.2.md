# PromptWorks v3.9.1 — candidate backend compile fix

## Fixed

- Repairs the long-poll device-auth payload in `server/src/index.ts`. v3.8.1 accidentally emitted a literal newline inside a single-quoted TypeScript string at the `/v1/devices/:id/requests/wait` endpoint, causing `TS1002: Unterminated string literal` and preventing the isolated candidate backend from building.
- The payload is now serialized exactly as the other authenticated device endpoint: `['promptworks-device-auth-v1', deviceId, nonce].join('\\n')` in source generation, which produces a newline-delimited signature payload at runtime without breaking TypeScript syntax.
- Bumps candidate service/config namespace to v3.9.1 so an incomplete v3.8.1 candidate cannot be mistaken for the current candidate.
- Keeps the previous PromptWorks stack active until candidate proof and commissioning succeed.

## Validation

- `bash -n install-promptworks.sh`
- `bash -n linux/promptworks-auth-rollback`
- binding vectors
- OCRA vectors
- time-match vectors
- protected-upgrade layout regression test
- TypeScript parser check confirms the v3.8.1 TS1002/TS1005 parse failure is gone (dependency type-checking requires installed server dependencies).
