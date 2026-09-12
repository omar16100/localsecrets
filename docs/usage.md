# Usage

## Purpose

How to run localsecrets and use it day to day. For what it does and does not protect, read [security.md](security.md) first.

## Build

```sh
cargo build --release
# target/release/localsecretsd  the server
# target/release/lsec           the client
```

## Start the server

```sh
localsecretsd --data-dir ~/.local/share/localsecrets --listen 127.0.0.1:8787
```

It binds loopback. Serving it to a network means putting a reverse proxy in front to terminate TLS; without that, tokens and secret values travel in the clear.

Logging goes to standard error. `LS_LOG` takes `error`, `warn`, `info` or `debug`.

## First run

```sh
lsec init --threshold 2 --shares 3
```

This prints the unseal shares and a root token, once. They are not stored anywhere and cannot be printed again. Write the shares down and keep them apart from each other and from the server. If you are the only custodian, `--threshold 1 --shares 1` is the honest configuration; see the note in [security.md](security.md).

Use the root token once, to create the first account:

```sh
lsec user create you@example.com --token <root token>
lsec login you@example.com
```

## Every day

```sh
lsec project create demo
lsec env create dev --project demo
lsec use demo dev            # pins this directory, so later commands need no flags

lsec set DB_URL              # type or pipe the value; it is not echoed
lsec get DB_URL
lsec list                    # keys only, never values
lsec delete DB_URL

lsec run -- npm start        # runs with the secrets in its environment
```

Passing a value as an argument (`lsec set KEY value`) works but warns: argv lands in shell history and is visible to anyone who can list processes.

## Moving secrets around

```sh
lsec export                       # .env format, quoting what needs it
lsec export --format json
lsec import .env                  # comments, blank lines and `export ` are handled
cat .env | lsec import -
```

## Machines

```sh
lsec token create --label ci --ttl 2592000
```

The token can read the project and environment it was issued for, and nothing else. Use it with `--token`, or set `LS_TOKEN` in the job:

```sh
LS_TOKEN=lsec_... lsec run -- ./deploy.sh
```

Revoke it with `lsec token revoke <id>`. Revocation takes effect immediately: the token is checked against the store on every request.

## Sealing

```sh
lsec seal                    # drops the root key; the server can read nothing
lsec unseal                  # offer one share, repeat until the threshold is met
lsec unseal --reset          # throw away a part-finished attempt and start over
lsec status
```

A restarted server comes back sealed. This is the point: the files on disk are inert until a quorum of share holders is present.

Offer the share at the prompt rather than as an argument. Passing it as an argument works and warns, because it lands in your shell history and is visible to anyone who can list processes.

Mixing shares from two different splits, or mistyping one, leaves a part-finished attempt. `lsec unseal --reset` clears it. An attempt that reaches the threshold and fails clears itself.

## Changing who holds the shares

```sh
lsec rekey --threshold 2 --shares 4
```

Generates a new master key and a new root key, re-wraps each project's data key, and rewrites the store so the old barrier stops existing. The old shares stop working straight away and the secrets are untouched. Use this when a share is lost, or when a custodian leaves.

It does not help if a share was *exposed* rather than lost: anyone with a copy of the store file from before the re-split, and a quorum of the old shares, can still open that copy. See [security.md](security.md).

## Configuration

| What | Where |
|---|---|
| Session token | `~/.config/localsecrets/token`, mode 0600 |
| Project and environment for a directory | `./.localsecrets` |
| Server address | `LS_SERVER`, default `127.0.0.1:8787` |
| Token override | `LS_TOKEN`, or `--token` |
| Store | `<data-dir>/store.log`, mode 0600, directory 0700 |
| Log level | `LS_LOG`: `error`, `warn`, `info` (default) or `debug` |

## When something refuses

Every status the server sends:

| Status | Means |
|---|---|
| 400 | The request or the body does not make sense, or a share will not parse. |
| 401 | No token, or one that is expired, revoked or spent. |
| 403 | A real token that may not do this, or may not reach that environment. |
| 404 | No such project, environment or secret. |
| 405 | That method on that path. |
| 409 | It already exists, or the vault is already initialised. |
| 412 | The vault has not been initialised. |
| 413 | The value is larger than a secret may be. |
| 415 | A state-changing request without `content-type: application/json`. |
| 421 | Addressed to a name that is not this machine, or carrying a browser `Origin`. |
| 429 | Too many login attempts, or too many init and unseal attempts. |
| 500 | Something failed on this side. The reason is in the log. |
| 503 | The vault is sealed. |

415 and 421 exist to keep a web page out; see [security.md](security.md). If you are writing a client, send the content type on everything except `GET`, address the server as `127.0.0.1` or `localhost`, and send no `Origin`.

## Auditing

```sh
lsec audit
```

Every read, write and delete is recorded with who, what and the outcome. Key names appear; values never do.

| Outcome | Means |
|---|---|
| `ok` | It happened. |
| `denied` | The caller was not allowed. |
| `missing` | The key is not there. |
| `unknown` | The project or environment is not there, so someone may be hunting for names. |

The trail lives in the store, so reading it needs an unsealed server and a session token.

## Examples

Read a secret in a script, failing loudly if it is missing:

```sh
set -e
DB_URL=$(lsec get DB_URL)
```

Copy an environment from one project to another:

```sh
lsec export --project demo --env dev | lsec import - --project other --env dev
```
