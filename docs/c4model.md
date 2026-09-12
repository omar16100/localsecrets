# Architecture (C4)

Source of truth for the architecture of localsecrets. Update this file for every architectural change: containers, components, services, dependencies, data flows.

## Context

localsecrets is a minimal self-hosted secrets manager. It stores key/value secrets encrypted at rest, scoped by project and environment, and hands them to people (the CLI) and to machines (scoped tokens).

Actors:

- **Operator** runs the server, initialises it, holds unseal shares, re-splits them when a custodian changes.
- **Developer** logs in with an email and a password, reads and writes secrets for a project.
- **Machine** (CI job, service, script) holds a token confined to one environment and reads secrets, usually through `lsec run --`.

Inspiration: Infisical (project / environment / secret addressing, machine identities), OpenBao (seal barrier with Shamir shares, opaque revocable tokens).

## Containers

| Container | Technology | Responsibility |
|---|---|---|
| `localsecretsd` | Rust, `std::net`, fixed worker pool | HTTP API, authentication, capabilities, seal state, audit |
| `lsec` | Rust, std only | Command line client, local config, process environment injection |
| Store | one append-only encrypted file | Wrapped keys, users, tokens, ciphertext, audit records |

Single node. No clustering, no external services, no database engine.

The only third-party code in the whole system is audited cryptography (`aes-gcm`, `argon2`, `sha2`, `zeroize`, `subtle`) plus `getrandom`. HTTP, storage, JSON, logging, argument parsing and calendar arithmetic are written on the standard library. CI fails the build if the lockfile grows anything else. See [security.md](security.md) for the reasoning.

## Components

### `ls-core` — crypto, encodings, time. No I/O.

| Module | Holds |
|---|---|
| `crypto::aead` | AES-256-GCM seal/open, key wrapping, canonical associated data |
| `crypto::shamir` | Split and recombine the master key over GF(2^8); printed shares with a checksum |
| `crypto::password` | argon2id hashing, and a cap on the work a stored hash may demand |
| `crypto::token` | Opaque token generation, SHA-256 storage form, constant-time comparison |
| `encoding` | URL-safe base64 (canonical only) and hex |
| `time` | UTC timestamps and RFC 3339, held inside the range that can be read back |
| `random` | The single entropy source; failure is an error, never a fallback |

No database, no network, no filesystem. That is what makes it exhaustively unit-testable.

### `ls-json` — a strict JSON parser and renderer. No I/O.

`value` holds the type and the renderer; `parser` is recursive descent, bounded at 64 deep, and refuses duplicate keys, trailing commas, leading zeros, raw control characters, lone surrogates and trailing content.

### `ls-http` — HTTP/1.1 on `std::net`.

| Module | Holds |
|---|---|
| `request` | Parsing, with the ambiguities refused rather than guessed |
| `response` | Building and writing; header values that contain a line break are dropped |
| `server` | Listener, bounded accept queue, fixed worker pool, one request per connection |
| `client` | Blocking client for the CLI |

Bounds live in `Limits`: head size, header count, body size, and a deadline for the whole request that is checked on every arrival of bytes.

### `ls-log` — one line per event on standard error.

Timestamp, level, message, then `key=value`. Values are escaped, so nothing that reaches a field can forge a second record. Level from `LS_LOG`.

### `ls-store` — the append-only log and the state folded from it.

| Module | Holds |
|---|---|
| `log` | Frames, appending with fsync, replay, torn-tail repair, compaction |
| `event` | What can happen, as JSON with a type tag and a format marker |
| `state` | The fold: users, tokens, projects, environments, current secret values |

### `ls-server` — the rules, and the HTTP layer over them.

| Module | Holds |
|---|---|
| `vault` | Seal state, the key hierarchy, capabilities, every operation on secrets |
| `barrier` | The one record stored in the clear: the root key, wrapped by the master key |
| `validate` | What a slug, a secret key and an email may contain |
| `rate_limit` | Fixed-window counting for logins and for the ceremony endpoints |
| `api` | Routing, request bodies, status codes, and the checks that keep a browser out |
| `main` | Arguments, a 0700 data directory, and the listener |

The HTTP layer holds no rules of its own. Every decision about what is allowed belongs to `vault`.

### `ls-cli` — the client.

| Module | Holds |
|---|---|
| `commands` | One function per command |
| `api` | The API calls, and turning an error status into a message |
| `config` | The 0600 token file and the `.localsecrets` project pin |
| `input` | Reading values and shares without echoing them |

## Key hierarchy

```
unseal shares (t of n)  --recombine-->  master key   (memory only, never written)
master key              --AES-256-GCM-> root key     (stored wrapped, in the barrier)
root key                --AES-256-GCM-> project key  (stored wrapped, one per project)
project key             --AES-256-GCM-> secret value (stored as nonce and ciphertext)
```

Every ciphertext is bound to its slot through canonical associated data: a domain tag, a field count, and each field length-prefixed. A stored row moved to another project, environment or key name fails to decrypt rather than reveal its value.

## Capabilities

There are no roles. There is a fixed answer to "what is this token for", checked inside `vault` on every operation.

| Token | May |
|---|---|
| Root, from `init` | Create the first account. Spent the moment an account exists. |
| Session, from `login` | Everything. |
| Machine, from `token create` | Read secrets in the one environment it was issued for. |

Any token may revoke itself, which is what logging out is.

## Data flow

**Write.** `PUT /v1/projects/{slug}/envs/{env}/secrets/{key}` → the request is refused unless it is addressed to this machine and carries a JSON content type → the bearer token resolves to a caller → the vault confirms it is unsealed → the slugs resolve to identifiers, recording the attempt if they do not → the capability is checked → the project key is unwrapped with the in-memory root key → the value is sealed with a fresh nonce and associated data naming its slot → the event is appended and flushed → the state is updated → an audit record follows.

A change reaches the log before it reaches memory, so memory never runs ahead of what survived a crash.

**Read.** The reverse, and decryption fails closed if the ciphertext is not where it was sealed.

**Replay.** At unseal, the file is read from the start: the barrier gives the root key, every other record is opened with it and folded into the state. A sealed server has no state at all rather than state it declines to serve.

## Storage format

```
header:  "LSLOG1" 0x00 <format version>          8 bytes
record:  <length: u32 be> <kind: u8> <payload>   length counts kind and payload
```

`kind` is 0 for a plain record and 1 for a sealed one. A sealed payload is a nonce followed by ciphertext, with associated data naming the file format and the record's position, so a record cannot be edited, replayed or reordered without the replay failing. The barrier is the only plain record, because it must be readable before there is a key to read with.

An interrupted write leaves a prefix of a frame, which the next open truncates away. A frame that is complete and impossible cannot have come from an interrupted write, so it is refused rather than mistaken for one.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Server-side envelope encryption, not end-to-end | Keeps a future UI, rotation and integrations possible. The trade-off Infisical made. |
| 2 | Seal barrier with Shamir shares | Files are inert while the process is not running, and a restart needs a quorum. |
| 3 | Opaque revocable tokens, not JWTs | On one node, immediate revocation is worth more than statelessness. |
| 4 | Append-only log, no database engine | Follows from the dependency policy. Crash-safe by construction. |
| 5 | Associated data binds ciphertext to its slot | Stops a production value being read by moving its row into dev. |
| 6 | Capabilities by token kind, not roles | A leaked deploy token stays a leaked deploy token. Roles can come later; this cannot be added later. |
| 7 | Re-splitting rotates the root key and rewrites the file | Appending a new barrier leaves the old one readable, so the old shares would still work and truncation would undo the re-split. |
| 8 | A format marker on every sealed value | The day the wrapping changes there has to be something to branch on. |
| 9 | The HTTP layer holds no rules | One place to look for what is allowed, and one place to get it wrong. |

## Deferred

RBAC, folders, secret versioning and rollback, secret references, dynamic secrets, integrations, PKI, PAM, web UI, HA, Postgres, a Kubernetes operator, SDKs. Compaction exists and is used by a re-split, but has no command of its own.
