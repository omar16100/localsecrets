# localsecrets build plan

## Goal

A minimal self-hosted secrets manager in Rust: a single-binary server plus a CLI, covering store a secret encrypted, fetch it from a machine, inject it into a process. Inspired by Infisical (addressing model, machine identities) and OpenBao (seal/unseal barrier, revocable tokens).

## Status

| Milestone | State |
|---|---|
| M0 workspace scaffold | done |
| M1 ls-core crypto | done (72 tests, clippy clean) |
| M2 ls-json, ls-http, ls-log | done (187 tests, clippy clean) |
| M3 ls-store append-only log | done (227 tests, clippy clean) |
| M4 seal/unseal and sessions | done |
| M5 projects, environments, secrets, machine tokens, audit | done (288 tests, clippy clean) |
| M6 CLI | done (309 tests, clippy clean) |
| M7 verification and docs | done; both review rounds applied |

## Milestones

- **M0** Cargo workspace, four crates, shared dependency versions, lints, docs skeleton.
- **M1** `ls-core`: AEAD with associated data, Shamir split/combine, argon2id, opaque tokens. Fully unit tested, no I/O.
- **M2** `ls-store`: schema, migrations, repositories, in-memory SQLite tests.
- **M3** `/v1/sys/init`, `/unseal`, `/seal`, `/health`, plus the seal middleware.
- **M4** Users, login, machine tokens with scope, TTL and revocation.
- **M5** Projects, environments, secrets CRUD and batch, audit log on every operation.
- **M6** CLI: config, project pin, all commands including `run --`, import and export.
- **M7** End-to-end live run, ciphertext-at-rest and redaction checks, docs.

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-09-12 | Server + CLI core only, no web UI in v1 | Smallest thing that is a real secrets manager |
| 2026-09-12 | Server-side envelope encryption, not E2EE | Keeps a future UI, rotation and integrations possible |
| 2026-09-12 | SQLite via sqlx, Postgres deferred | Single binary, no external dependency, fast tests |
| 2026-09-12 | Binary named `lsec`, not `ls` | `ls` collides with coreutils |
| 2026-09-12 | Edition 2024, resolver 3, rustc 1.95 | Matches the toolchain on this machine |
| 2026-09-12 | No dependencies except audited crypto | 326 crates in the lockfile was too large a supply chain for a tool that guards credentials. HTTP, storage, JSON, logging, argument parsing and time are written on std. Hand-written ciphers and KDFs are not, because they fail quietly on side channels. |
| 2026-09-12 | Shamir implemented in ls-core, not taken from a crate | `vsss-rs` works over prime fields, which cannot represent every 32-byte key without bias; `sharks` is byte-wise but unmaintained since 2021 and is now excluded by the dependency policy anyway. The primitive is small and verifiable against FIPS-197 worked examples. |
| 2026-09-12 | Entropy failure is an error, not a panic | A secrets manager that silently produces predictable keys is worse than one that refuses to start. `DataKey::generate` and `token::generate` return `Result`. |
| 2026-09-12 | Printed shares carry a checksum | Without it, a mistyped share surfaces as an unexplained decryption failure during a recovery, which is the worst possible moment for a confusing error. |

## Deviations

| Date | Deviation from the approved plan | Reason |
|---|---|---|
| 2026-09-12 | Dropped tokio, axum, sqlx, reqwest, clap, serde, chrono, uuid, thiserror, tracing | Requested constraint: no dependencies beyond audited crypto. Lockfile went from 326 crates to 44. |
| 2026-09-12 | SQLite replaced by an append-only encrypted log | Follows from the dependency constraint; sqlx alone pulled about 90 crates. Also gives secret history for free later. |
| 2026-09-12 | Two new crates, `ls-json` and `ls-http` | JSON and HTTP/1.1 now have to be written; they are pure and shared by the server and the CLI, so they belong in their own crates rather than inside either binary. |
| 2026-09-12 | Associated data is length-prefixed and versioned | The approved plan said `project_id \|\| environment_id \|\| key`. Plain concatenation is ambiguous across field boundaries, which defeats the point of binding. |
| 2026-09-12 | Crypto crates moved to the current generation | aes-gcm 0.11, argon2 0.6. Mixing generations does not compile, and a security tool should not ship a generation behind. |

## Open findings from review, not yet applied

Raised in the M1 design review, to be handled in the milestone named:

- **M3** Data file and directory created mode 0600. Every stored ciphertext gets a format version byte so rotation is possible later.
- **M4** Bootstrap: the init response returns a root token, which needs its own token kind and a root-authorised endpoint to create the first user. Unseal progress needs a mutex, an attempt identity and a reset operation. Login needs rate limiting and a dummy verification on unknown accounts so timing does not enumerate users.
- **M5** Single-secret read endpoint, token listing, and a documented rule for who may revoke a token. Bulk upsert is `POST .../secrets`, avoiding a colon in the path.
- **M6** `lsec set KEY` reading the value from stdin is the primary documented form; passing a value as an argument warns, because argv is visible in shell history and `ps`.

## Published

2026-09-12: github.com/omar16100/localsecrets, MIT, public. CI runs build,
clippy with warnings denied, the test suite, and a check that the lockfile
still holds only audited cryptography. Green on Linux and macOS.

## Untested paths

Stated rather than glossed over:

- The store marks itself unusable after a failed append. Reaching that needs a
  real write or fsync error, which the suite cannot induce, so the guard is
  implemented and reasoned about but not exercised.
- Long-running token expiry is tested by issuing already-expired tokens, not
  by waiting.
- Multi-user concurrency is exercised only by the parallel test suite, not by
  a deliberate contention test.

## Out of scope for v1

RBAC, folders, versioning, secret references, dynamic secrets, rotation, integrations, PKI, PAM, web UI, HA, Postgres, Kubernetes operator, SDKs.
