# localsecrets

A small self-hosted secrets manager in Rust: a single-binary server and a command line client. Store a secret encrypted, fetch it from a machine, inject it into a process.

Inspired by [Infisical](https://github.com/infisical/infisical) for its addressing model and machine identities, and by [OpenBao](https://github.com/openbao/openbao) for its seal barrier and revocable tokens. It is far smaller than either, on purpose.

```sh
lsec init --threshold 2 --shares 3   # prints the unseal shares, once
lsec user create you@example.com     # asks for the root token, then a password
lsec login you@example.com
lsec use demo dev

lsec set DB_URL                      # typed or piped, never echoed
lsec run -- npm start                # the child gets the secrets in its environment
```

## What it does

- **Secrets scoped by project and environment**, read and written over a small HTTP API or the CLI.
- **A seal barrier.** A master key is split into unseal shares with Shamir's scheme and never stored. A restarted server comes back sealed and can read nothing until a quorum of share holders is present.
- **Machine tokens** confined to one environment, read-only, revocable, with an optional lifetime.
- **An audit trail** of every read, write and delete, including refusals. Key names appear; values never do.
- **An append-only store.** One file. Every change is appended and flushed; a crash leaves a partial tail that the next start discards.

## Dependencies

45 entries in the lockfile, of which seven are this project's own crates. The only third-party code is audited cryptography (`aes-gcm`, `argon2`, `sha2`, `zeroize`, `subtle`), `getrandom`, and the proc-macro crates those build with.

The HTTP server and client, the JSON parser, the storage layer, the logger, the argument parsing and the calendar arithmetic are written on the standard library. That is a deliberate trade for a tool whose whole job is guarding credentials: a smaller supply chain is worth the extra code, while hand-written ciphers and key derivation are not, because they fail quietly on side channels.

## How the keys fit together

```
unseal shares (t of n)  --recombine-->  master key   (memory only, never written)
master key              --AES-256-GCM-> root key     (stored wrapped)
root key                --AES-256-GCM-> project key  (stored wrapped, one per project)
project key             --AES-256-GCM-> secret value (stored as nonce + ciphertext)
```

Every ciphertext is bound to its slot through canonical associated data, so a stored row moved to another project, environment or key name fails to decrypt instead of revealing its value.

## Build and run

```sh
cargo build --release
target/release/localsecretsd --data-dir ~/.local/share/localsecrets
```

The server binds loopback. Serving it to a network means putting a reverse proxy in front to terminate TLS.

## Read before you trust it

[docs/security.md](docs/security.md) sets out what this protects against and, at more length, what it does not: an attacker with code execution on an unsealed host, a compromised client, swap and core dumps, someone who can write to the store file. It also explains why a 3-of-5 split held by one person is a passphrase with extra steps.

This is a personal project with no security guarantees and no audit. Do not use it to hold credentials whose loss you could not absorb.

## Documentation

| Document | What it covers |
|---|---|
| [docs/usage.md](docs/usage.md) | Running the server, every command, configuration |
| [docs/security.md](docs/security.md) | Threat model, key hierarchy, capabilities, known limits |
| [docs/c4model.md](docs/c4model.md) | Architecture: containers, components, data flow |

## Tests

```sh
cargo test --workspace     # 347 tests, no external services, a few seconds
cargo clippy --workspace --all-targets
```

The suite covers the cryptography against published vectors (FIPS-197 for the field arithmetic, RFC 4648 for base64), the HTTP parser against the ambiguities that cause request smuggling, the store against crashes and tampering, and the whole flow end to end through the real binaries.

## Licence

MIT.
