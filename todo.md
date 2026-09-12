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
- [x] Apply findings from the codex crypto review

## M2 — ls-json and ls-http
- [x] JSON parse, build, serialise; reject malformed input without panicking
- [x] HTTP/1.1 request and response parsing, with body size limits
- [x] Blocking server on std::net with a bounded thread pool
- [x] Blocking client for the CLI
- [x] Structured logging to stderr, level from the environment (ls-log)
- [x] UTC timestamps and RFC 3339 (ls-core::time)

## M3 — ls-store append-only log
- [x] Record format with a version byte, length prefix and authentication
- [x] Records bound to their position, so a reorder or replay fails
- [x] Append with fsync, replay on open, torn-tail repair
- [x] Compaction through a temporary file and a rename
- [x] Log file created mode 0600
- [x] Crash-safety tests: truncated tail, edited record, wrong key
- [ ] Domain events and the state they fold into

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
