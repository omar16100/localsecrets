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
- [x] Domain events and the state they fold into

## M4 — seal/unseal and sessions
- [x] init, unseal, seal, health
- [x] Unseal progress guarded, duplicate shares ignored, failed attempt resets
- [x] Init refuses a second time
- [x] Root token kind, and creating the first user
- [x] Login, logout, rate limiting, dummy verify on unknown accounts

## M5 — projects, environments, secrets
- [x] Projects and environments
- [x] Secrets: get one, list, put, delete, bulk write
- [x] Machine tokens: issue, revoke, expiry, scope
- [x] Audit record on every operation, including refusals
- [x] localsecretsd binary with arguments and a 0700 data directory

## M6 — CLI
- [x] Config, project pin, token file at 0600
- [x] init, unseal, seal, status
- [x] user create, login, logout
- [x] project/env create and list, `use` to pin a directory
- [x] set (stdin by default, warns on argv), get, list, delete
- [x] export dotenv and json, import .env
- [x] `run -- command` with the child's exit code passed through
- [x] token create and revoke, audit

## M7 — verification
- [x] End-to-end live run with the release binaries
- [x] Ciphertext at rest: no value, key name, email or password readable in the store
- [x] Log redaction at LS_LOG=debug: no value, password or token in the server log
- [x] Permissions: store 0600, data dir 0700, token file 0600
- [x] Restart and unseal with a different pair of shares, state intact
- [x] Machine token refused on another environment, refusal recorded as denied
- [x] docs/usage.md written and registered in the index
- [x] Apply the findings of the final review:
  - [x] blocker: machine tokens were unconfined outside secret routes
  - [x] machine tokens are read-only; root is bootstrap-only and spent on use
  - [x] token lifetimes range checked, so an expiry cannot break the replay
  - [x] whole-request deadline and a bounded accept queue (slowloris)
  - [x] login rate limit normalises its key and caps the map
  - [x] a failed append makes the log unusable until it is reopened
  - [x] init does everything fallible before the first write
  - [x] a repaired tail is reported to the operator
  - [x] the root token is prompted for, never suggested on a command line
  - [x] security.md corrected: token comparison, dependency count, tail rollback

## M8 — published
- [x] MIT LICENSE and README
- [x] CI on Linux and macOS: build, clippy -D warnings, tests
- [x] CI gate on the dependency policy, so it fails the build rather than
      living only in a document
- [x] cargo fmt across the workspace
- [x] github.com/omar16100/localsecrets, public, CI green on the first run

## M9 — second defect hunt applied
- [x] blocker: a failed audit write during a re-split could destroy the vault
      (new shares dropped, new barrier already on disk). Re-split is now one
      rewrite, and the last thing that can fail
- [x] a re-split rotates the root key and rewrites the file, so the old
      barrier stops existing rather than merely being superseded
- [x] the read path fails closed on an impossible frame, as the open path does
- [x] a barrier that cannot be read stops the vault opening, instead of
      reporting "not initialised" and inviting a second init over sealed data
- [x] a store holding records but no barrier is refused
- [x] identifiers never fall back to a clock reading, which could repeat
- [x] timestamps are held inside the range that can be read back, so a wrong
      clock cannot write an event that breaks every later replay
- [x] state-changing requests need a JSON content type, so a page on another
      site cannot reach init or unseal
- [x] the unauthenticated ceremony endpoints share a rate limit
- [x] a confined token gets the same answer for an absent and a present name
- [x] a poisoned login limiter no longer disables the limit
- [x] a panic mid-operation seals the vault rather than serving state that may
      disagree with the file
- [x] the request deadline is checked on every arrival of bytes, not between
      lines, so a client that never completes one is still cut off
- [x] share parameters that are present but unusable are refused, not defaulted
- [x] a bulk write validates everything before writing anything
- [x] an oversized value is a client error, not a server error
- [x] the root token is spent by the first account existing, with no second
      write and so no window
- [x] a read or delete that finds nothing is recorded too
- [x] lsec unseal --reset, which the API supported and the client could not reach

## M10 — verification pass on the fixes
- [x] compaction keeps the handle it already has rather than reopening the
      path, so nothing after the rename can fail and lose a re-split
- [x] the directory is flushed after the rename, so a power loss cannot bring
      the old file back after the old shares have been destroyed
- [x] a temporary file left by an interrupted compaction no longer blocks
      every later one
- [x] Host is checked, so DNS rebinding cannot walk around the content-type
      rule; an Origin header is refused outright
- [x] two Host headers are refused, as two Content-Lengths already were
- [x] the drain after a refusal is bounded in total time, not only per read
      and per byte, so a dribbling client cannot hold a worker for hours
- [x] token lookup uses the constant-time comparison that was written for it
- [x] an entropy failure while hashing a password is no longer reported as
      the caller's password being invalid
- [x] a request for a name that does not exist is recorded, so walking the
      name space is visible in the trail
- [x] the bulk-write comment says what it actually guarantees

## Next, if it is picked up again
- [ ] Wire compaction to a command, so deleting a secret can also remove its
      earlier ciphertext from the file
- [ ] Secret versioning and rollback (the log already holds the history)
- [ ] A read-only web view, or Postgres, both deliberately deferred in v1
- [ ] Wire compaction to a command of its own; re-splitting uses it, so the
      machinery is exercised, but there is no way to ask for it directly
