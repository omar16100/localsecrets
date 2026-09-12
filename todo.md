# todo

## M0 — workspace scaffold
- [x] Cargo workspace, edition 2024, shared dependency versions
- [x] Four crates: ls-core, ls-store, ls-server, ls-cli (stubs)
- [x] Workspace lints: forbid unsafe, warn on unwrap/expect/panic
- [x] `cargo check --workspace` green
- [x] docs/index.md, docs/c4model.md
- [x] docs/12092026_localsecrets_plan.md
- [x] docs/security.md (threat model)
- [x] Dependency policy: audited crypto only, 326 crates down to 44

## M1 — ls-core crypto (TDD)
- [x] Encoding: URL-safe base64 and hex, RFC 4648 vectors
- [x] Entropy as a Result, never a panic
- [x] AEAD seal/open with canonical length-prefixed associated data
- [x] Shamir split/combine over GF(2^8), FIPS-197 field vectors
- [x] Printed shares with index and checksum
- [x] argon2id password hashing
- [x] Opaque token generation and hashing
- [ ] Apply findings from the codex crypto review

## M2 — ls-json and ls-http
- [ ] JSON parse, build, serialise; reject malformed input without panicking
- [ ] HTTP/1.1 request and response parsing, with body size limits
- [ ] Blocking server on std::net with a bounded thread pool
- [ ] Blocking client for the CLI
- [ ] Structured logging to stderr, level from the environment

## M3 — ls-store append-only log
- [ ] Record format with a version byte, length prefix and authentication
- [ ] Append with fsync, replay on startup, in-memory index
- [ ] Compaction
- [ ] Data file and directory created mode 0600
- [ ] Crash-safety tests: truncated tail, corrupted record

## M4 — seal/unseal and sessions
- [ ] init, unseal, seal, health
- [ ] Unseal progress behind a mutex, with an attempt identity and reset
- [ ] Init is single-shot even under concurrent calls
- [ ] Root token kind, and creating the first user
- [ ] Login, logout, rate limiting, dummy verify on unknown accounts

## M5 — projects, environments, secrets
- [ ] Projects and environments
- [ ] Secrets: get one, list, put, delete, bulk upsert
- [ ] Machine tokens: issue, list, revoke, expiry, scope
- [ ] Audit record on every operation

## M6 — CLI
- [ ] Config, project pin, token file
- [ ] All commands including `run --`, import, export

## M7 — verification
- [ ] End-to-end live run
- [ ] Ciphertext-at-rest check, audit check, log redaction check
- [ ] Docs updated
