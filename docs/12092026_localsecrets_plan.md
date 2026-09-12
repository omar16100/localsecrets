# localsecrets build plan

## Goal

A minimal self-hosted secrets manager in Rust: a single-binary server plus a CLI, covering store a secret encrypted, fetch it from a machine, inject it into a process. Inspired by Infisical (addressing model, machine identities) and OpenBao (seal/unseal barrier, revocable tokens).

## Status

| Milestone | State |
|---|---|
| M0 workspace scaffold | done |
| M1 ls-core crypto | in progress |
| M2 ls-store | not started |
| M3 seal/unseal | not started |
| M4 auth | not started |
| M5 secrets and audit | not started |
| M6 CLI | not started |
| M7 verification and docs | not started |

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

## Deviations

None yet. Record every departure from the approved plan here with its reason.

## Out of scope for v1

RBAC, folders, versioning, secret references, dynamic secrets, rotation, integrations, PKI, PAM, web UI, HA, Postgres, Kubernetes operator, SDKs.
