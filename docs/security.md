# Security

## Purpose

What localsecrets protects, what it does not, and why the design is shaped the way it is. This document is deliberately blunt. A secrets manager that oversells itself is worse than no secrets manager, because people put real credentials in it on the strength of the claim.

## Key hierarchy

```
unseal shares (t of n)  --recombine-->  master key   (memory only, never written)
master key              --AES-256-GCM-> root key     (stored wrapped)
root key                --AES-256-GCM-> project DEK  (stored wrapped, one per project)
project DEK             --AES-256-GCM-> secret value (stored as nonce + ciphertext)
```

Every ciphertext is bound to its slot through canonical associated data: a domain tag, a field count, and each field length-prefixed. Moving a stored row to another project, environment or key name makes it fail to decrypt rather than reveal its value.

## Who may do what

There are no roles. What there is, is a fixed answer to "what is this token for":

| Token | May |
|---|---|
| Root, from `init` | Create the first account, once. Using it spends it. Nothing else. |
| Session, from `login` | Everything. |
| Machine, from `token create` | Read the one environment it was issued for. Not write, not delete, not list projects, not mint tokens, not read the audit trail, not seal. |

Any token may revoke itself, which is what logging out is.

The point of the machine row is that a leaked deploy token stays a leaked deploy token. Without it, a token that could create an account would be a token that owns the vault, because an account is unconfined.

## What this protects against

- **Theft of the data file or a backup.** Values are AES-256-GCM ciphertext. The file contains no plaintext secrets and no key able to decrypt them on its own.
- **A stolen disk image of a powered-off or sealed server.** The root key exists only in memory while unsealed, so a stopped server's files are inert without a quorum of unseal shares.
- **Casual exposure.** No secret value is ever written to a log or an audit record. Only key names and outcomes are recorded.
- **Row tampering.** A moved or edited ciphertext fails authentication instead of decrypting to something unexpected.
- **Credential leakage from the store.** Tokens are stored as SHA-256 hashes and passwords as argon2id, so reading the file yields nothing directly usable.
- **Transcription mistakes during a recovery.** Printed shares carry a checksum, so a typo is reported as a typo.
- **A lost share, or a change of custodians.** `lsec rekey` splits the master key again and hands out a fresh set. The root key is untouched, so every stored value stays readable and the old shares stop working immediately.
- **Edits to a record frame.** A length field that is complete and impossible cannot have come from an interrupted write, so the store refuses to open rather than treating the last record as a torn tail and discarding it.

## What this does NOT protect against

State these to anyone deciding whether to trust it.

- **An attacker with code execution or root on the host while the server is unsealed.** They can read the root key out of process memory, or simply present a stolen token to the API. Sealing is the only defence, and it requires a quorum to undo.
- **A compromised client machine.** The CLI caches its token in a file readable by the same user. Anything running as that user can use it.
- **Swap files and core dumps.** Keys are zeroized when dropped, but zeroizing does not stop the kernel paging a copy to disk first, and no memory is locked. A crash dump of an unsealed server may contain the root key.
- **A modified server binary.** The server sees every value in plaintext by design. If you do not trust the binary, encryption at rest is irrelevant.
- **Network eavesdropping without TLS.** The server binds `127.0.0.1` and expects a reverse proxy to terminate TLS. Rebinding to a public address without TLS sends tokens and secret values in the clear.
- **A malicious or careless operator.** Any account can read any project: the only confinement is on machine tokens.
- **Someone who can delete bytes from the end of the store file.** Editing a record makes the replay fail, and editing a record's length field is now refused rather than mistaken for a crash, because an interrupted write can only ever leave a valid prefix of a frame. What remains is plain truncation: cutting the last record off entirely is indistinguishable from a write that never finished, and would, for instance, undo a revocation. Detecting that needs state kept somewhere the attacker cannot reach, which a single file cannot provide.
- **Denial of service by an authenticated caller.** Requests are bounded in size and time and the accept queue is capped, but anyone who can log in can fill the store.

## On the seal barrier

The honest description of seal/unseal is narrow: it means that restarting the server requires a quorum of share holders, and that a stolen copy of the files is useless on its own. It does not protect a running server.

For a single operator, a 3-of-5 split usually ends up entirely in one password manager. That is a passphrase with extra steps, not a quorum. If you are the only custodian, use `--shares 1 --threshold 1` and store the single share deliberately, rather than pretending to a control you do not have. The multi-share configuration earns its keep only when the shares genuinely live with different people.

## Cryptographic choices

| Choice | Reasoning |
|---|---|
| AES-256-GCM | Standard AEAD with hardware acceleration. Fresh 96-bit random nonce per operation. |
| Random nonces | With 96-bit random nonces the chance of a repeat after q encryptions under one key is about q(q-1)/2^97: roughly 2^-33 at 2^32 writes. A project data key at human write rates stays many orders of magnitude below that. Rotation is the answer if that ever changes. |
| Length-prefixed associated data | Plain concatenation is ambiguous: `("ab","c")` and `("a","bc")` would collide and defeat slot binding. |
| argon2id, m=19 MiB, t=2, p=1 | The OWASP floor, stated explicitly rather than inherited from a library default that may change between versions. |
| Opaque tokens hashed with SHA-256 | 32 bytes of entropy means no stretching is needed, and storing the hash makes a stolen file useless. Looking a token up walks the list comparing hashes, which is not a constant-time operation; it does not need to be, because an attacker cannot choose the hash their guess produces. |
| Capped argon2 parameters on verification | Work parameters come out of the stored hash, so a tampered store could otherwise demand gigabytes and many passes on every login. Anything above 256 MiB, 10 passes or 4 lanes is refused before any hashing happens. |
| Canonical base64 only | `Zg` and `Zh` would otherwise both decode to the same byte. One value, one spelling, so a checksum over decoded bytes detects an edited share. |
| Shamir over GF(2^8) | Byte-wise sharing splits an arbitrary 32-byte key exactly. Prime-field and elliptic-curve schemes cannot represent every 32-byte value without bias. |
| A format marker on every sealed value | The day the wrapping changes there has to be something to branch on. A value written in a format this build does not know is refused rather than read hopefully. |

Shamir sharing carries no integrity of its own. A wrong recombination is caught because the recovered master key then fails to authenticate the wrapped root key, so a bad unseal reports failure rather than installing a wrong key.

## Dependency policy

The lockfile holds 45 entries, of which seven are this project's own crates. The only third-party code is audited cryptography (`aes-gcm`, `argon2`, `sha2`, `zeroize`, `subtle`) plus `getrandom`, and the proc-macro crates those pull in to build. HTTP, storage, JSON, logging, argument parsing and time are written on the standard library.

This is a deliberate trade. Hand-written ciphers and key derivation functions fail quietly on side channels, so those stay with the specialists. Everything else is ordinary code where a smaller supply chain is worth more than a saved afternoon.

Adding any dependency requires a reason recorded in `12092026_localsecrets_plan.md`.

## Re-splitting the shares

`lsec rekey --threshold 2 --shares 4` generates a new master key, splits it, and wraps the same root key with it. A new barrier record is appended; the newest one is the one that counts, because the log is append-only and nothing is ever edited in place.

The consequence worth stating: the old barrier record is still in the file. Anyone holding a quorum of the *old* shares and a copy of the file taken before the re-split can still reach the root key from that copy. Re-splitting replaces who can unseal this server from now on; it does not reach backwards into copies already made. If shares were exposed rather than merely lost, the honest response is a new vault and new secret values.

## Limits worth knowing before you rely on this

- The store holds every version of every secret ever written, because the log is append-only. Compaction exists but is not wired to a command yet, so deleting a secret stops it being served without removing its earlier ciphertext from the file.
- The rate limit on logins is per address and lives in memory, so it resets on restart.
- There is no TLS in the binary. Loopback plus a reverse proxy is the supported arrangement.

## Reporting

This is a personal project with no security guarantees and no audit. Do not use it to hold credentials whose loss you could not absorb.
