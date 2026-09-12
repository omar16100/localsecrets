# Architecture (C4)

Source of truth for the architecture of localsecrets. Update this file for every architectural change: containers, components, services, dependencies, data flows.

## Context

localsecrets is a minimal self-hosted secrets manager. It stores key/value secrets encrypted at rest, scoped by project and environment, and hands them to humans (CLI) and machines (scoped tokens).

Actors:

- **Operator** runs the server, initialises it, holds unseal shares.
- **Developer** logs in with email and password, reads and writes secrets for a project.
- **Machine** (CI job, service, script) holds a scoped token and reads secrets, typically through `lsec run --`.

Inspiration: Infisical (project / environment / secret addressing, machine identities), OpenBao (seal/unseal barrier with Shamir shares, opaque revocable tokens).

## Containers

| Container | Technology | Responsibility |
|---|---|---|
| `localsecretsd` | Rust, std::net, thread per connection | HTTP API, authentication, authorisation, seal state, audit |
| `lsec` | Rust, std only | Command line client, local config, process env injection |
| Data file | append-only encrypted log on disk | Persistence of wrapped keys, users, tokens, ciphertext, audit records |

Single node. No clustering, no external services, no database engine.

The only third-party code in the whole system is audited cryptography
(`aes-gcm`, `argon2`, `sha2`, `zeroize`, `subtle`) plus `getrandom`. HTTP,
storage, JSON, logging, argument parsing and time are written on the standard
library. See [security.md](security.md) for the reasoning.

## Components

### `ls-core` (library, no I/O)

- `crypto::aead` — AES-256-GCM seal/open with canonical associated data.
- `crypto::shamir` — split and recombine the master key over GF(2^8).
- `crypto::password` — argon2id hashing and verification.
- `crypto::token` — opaque token generation and hashing.
- `encoding` — URL-safe base64 and hex.
- `time` — UTC timestamps and RFC 3339, exact before 1970 and across leap years.
- `random` — the single entropy source; failure is an error, not a panic.
- `model` — domain types shared across crates.

No database, no network, no filesystem. This is what makes it exhaustively unit-testable.

### `ls-json` (library, no I/O)

Minimal JSON: a `Value` type, a parser that rejects malformed input without
panicking, and a serialiser. Shared by the server and the CLI.

### `ls-http` (library)

HTTP/1.1 request and response parsing with body size limits, a blocking server
on `std::net::TcpListener` with a bounded thread pool, and a blocking client for
the CLI.

### `ls-log` (library)

One line per event on standard error: timestamp, level, message, then
`key=value` fields. Values are escaped, so nothing that reaches a field can
forge a second record. Level comes from `LS_LOG`.

### `ls-store` (library)

- `record` — the on-disk format: version byte, length prefix, authenticated payload.
- `log` — append with fsync, replay on startup, compaction.
- `index` — the in-memory view rebuilt from the log: users, tokens, projects, environments, secrets.

State is reconstructed by replaying the log at startup. Every write appends and
fsyncs, so a crash truncates at a record boundary rather than corrupting state.

### `ls-server` (binary `localsecretsd`)

- `state` — shared state behind a lock, including the in-memory root key when unsealed.
- `auth` — resolves a bearer token into a `Caller`.
- `seal` — rejects secret operations while sealed, and guards unseal progress.
- `routes::sys` — init, unseal, seal, health.
- `routes::auth` — login, logout, tokens.
- `routes::projects`, `routes::environments`, `routes::secrets`.
- `audit` — recording of every secret operation.
- `log` — structured lines to stderr, level from the environment, values never included.

### `ls-cli` (binary `lsec`)

- `config` — `~/.config/localsecrets/config` plus a `0600` token file, and the `.localsecrets` project pin.
- `client` — thin HTTP client over the API.
- `commands` — one module per command group.

## Key hierarchy and data flow

```
unseal shares (t of n)  --recombine-->  master key (memory only, never stored)
master key              --AES-GCM-->    root key      (stored wrapped in `barrier`)
root key                --AES-GCM-->    project DEK   (stored wrapped on `projects`)
project DEK             --AES-GCM-->    secret value  (stored as nonce + ciphertext)
```

Write path: client `PUT /v1/projects/{slug}/envs/{env}/secrets/{key}` → auth middleware resolves the caller → seal middleware confirms unsealed → project DEK unwrapped with the in-memory root key → value encrypted with a fresh nonce and associated data binding it to project, environment and key → row upserted → audit row appended.

Read path: the reverse. Decryption fails closed if the ciphertext was moved to a different project, environment or key, because the associated data no longer matches.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Server-side envelope encryption, not end-to-end | Required for a future web UI, rotation and integrations. Same trade-off Infisical made. |
| 2 | Seal/unseal barrier with Shamir shares | Protects secrets when the process is not running, and forces multi-party recovery after a restart. |
| 3 | Opaque revocable tokens, not JWTs | Immediate revocation matters more than statelessness on a single node. |
| 4 | Append-only encrypted log, no database engine | Follows from the dependency policy. Crash-safe by construction, and it makes secret history cheap to add later. |
| 5 | Associated data binds ciphertext to its slot | Prevents a ciphertext being copied between environments to leak a production value into dev. |

## Deferred

RBAC, folders, versioning, secret references, dynamic secrets, rotation, integrations, PKI, PAM, web UI, HA, Postgres, Kubernetes operator, SDKs.
