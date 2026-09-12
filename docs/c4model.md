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
| `localsecretsd` | Rust, axum 0.8 | HTTP API, authentication, authorisation, seal state, audit |
| `lsec` | Rust, clap 4 | Command line client, local config, process env injection |
| SQLite database | file on disk, sqlx 0.8 | Persistence of wrapped keys, users, tokens, ciphertext, audit log |

Single node. No clustering, no external services.

## Components

### `ls-core` (library, no I/O)

- `crypto::aead` — AES-256-GCM seal/open with associated data.
- `crypto::shamir` — split and recombine the master key.
- `crypto::password` — argon2id hashing and verification.
- `crypto::token` — opaque token generation and hashing.
- `model` — domain types shared across crates.

No database, no network, no filesystem. This is what makes it exhaustively unit-testable.

### `ls-store` (library)

- `migrations` — schema, applied at startup.
- Repository structs over a `SqlitePool`: `BarrierRepo`, `UserRepo`, `TokenRepo`, `ProjectRepo`, `EnvironmentRepo`, `SecretRepo`, `AuditRepo`.

### `ls-server` (binary `localsecretsd`)

- `state` — shared app state, including the in-memory root key when unsealed.
- `middleware::auth` — resolves a bearer token into a `Caller`.
- `middleware::seal` — rejects secret operations while sealed.
- `routes::sys` — init, unseal, seal, health.
- `routes::auth` — login, logout, tokens.
- `routes::projects`, `routes::environments`, `routes::secrets`.
- `audit` — append-only recording of every secret operation.

### `ls-cli` (binary `lsec`)

- `config` — `~/.config/localsecrets/config.toml` plus a `0600` token file, and the `.localsecrets` project pin.
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
| 4 | SQLite first | Single binary, no external dependency, fast tests. Queries stay portable for a later Postgres backend. |
| 5 | Associated data binds ciphertext to its slot | Prevents a ciphertext being copied between environments to leak a production value into dev. |

## Deferred

RBAC, folders, versioning, secret references, dynamic secrets, rotation, integrations, PKI, PAM, web UI, HA, Postgres, Kubernetes operator, SDKs.
