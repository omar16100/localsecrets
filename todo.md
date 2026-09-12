# todo

## M0 — workspace scaffold
- [x] Cargo workspace, edition 2024, shared dependency versions
- [x] Four crates: ls-core, ls-store, ls-server, ls-cli (stubs)
- [x] Workspace lints: forbid unsafe, warn on unwrap/expect/panic
- [x] `cargo check --workspace` green
- [x] docs/index.md, docs/c4model.md
- [ ] docs/12092026_localsecrets_plan.md
- [ ] docs/security.md (threat model)

## M1 — ls-core crypto (TDD)
- [ ] AEAD seal/open with associated data
- [ ] Shamir split/combine for the master key
- [ ] argon2id password hashing
- [ ] Opaque token generation and hashing
- [ ] Review findings from the crypto review applied

## M2 — ls-store
- [ ] Schema and migrations
- [ ] Repositories over SqlitePool
- [ ] In-memory SQLite tests

## M3 — seal/unseal
- [ ] init, unseal, seal, health endpoints
- [ ] Seal middleware

## M4 — auth
- [ ] Users, login, logout
- [ ] Machine tokens: issue, revoke, expiry, scope

## M5 — secrets
- [ ] Projects, environments
- [ ] Secrets CRUD and batch
- [ ] Audit log on every operation

## M6 — CLI
- [ ] Config, project pin, token file
- [ ] All commands including `run --`, import, export

## M7 — verification
- [ ] End-to-end live run
- [ ] Ciphertext-at-rest check, audit check, log redaction check
- [ ] Docs updated
