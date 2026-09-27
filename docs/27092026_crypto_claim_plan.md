# Dependency audit claim: plan and record (27 Sep 2026)

## Goal

The README, security.md, c4model.md, Cargo.toml and the GitHub description said the only third-party code was "audited cryptography", with no citation. Replace that with what the lockfile actually holds and what has, and has not, been reviewed, so no reader takes it to mean localsecrets or its locked dependencies were audited.

## Status

| Item | State |
|---|---|
| Identify crypto crates and versions from Cargo.lock | done |
| Find and verify any public audit covering them | done |
| Reword README, security.md, c4model.md, Cargo.toml comment, CI comment, todo.md | done |
| GitHub description and topics | done |

## Milestones

1. Lockfile: `aes-gcm` 0.11.1, `argon2` 0.6.0, `sha2` 0.10.9, `zeroize` 1.9.0 (RustCrypto), `subtle` 2.6.1 (dalek-cryptography), `getrandom` 0.3.4 (rust-random), plus 32 transitive package entries (28 distinct crate names, four of them at two versions). 45 entries in all, 7 of them this project's own.
2. Audit search: grep of every locked crate's README and CHANGELOG. This shows only what those files reference; it cannot prove no audit exists elsewhere. Only `aes-gcm`, `aes`, `ghash` and `polyval` reference an audit, all the same NCC Group 2020 report. `ctutils` and `cmov` say they have never been independently audited.
3. Report scope: the report (v1.0, 13 Feb 2020) lists commits; their manifests give `aes-gcm` 0.3.0, `aes` 0.3.2, `ghash` 0.2.3, `polyval` 0.3.2. The locked versions are 0.11.1, 0.9.2, 0.6.0 and 0.7.3, so the report does not cover them.
4. Link: the original `research.nccgroup.com` PDF URL now redirects to a general NCC Group page. The web.archive.org copy that the crates' own READMEs link to returns HTTP 200 with `application/pdf`, so that is the one cited.

## Decisions

| Date | Decision | Rationale |
|---|---|---|
| 2026-09-27 | Drop "audited" as a description of the dependencies | No public audit covering the locked versions was found in their READMEs and changelogs. |
| 2026-09-27 | Keep the NCC Group report as a precise, scoped citation in security.md | It is real and relevant history for the `aes-gcm` stack, as long as the versions are stated. |
| 2026-09-27 | Reword the 2026-09-12 decision and deviation rows in place, marking the original "audited crypto" wording as withdrawn | Leaving them unqualified would keep the claim published; a new dated decision row records the correction. |

## Deviations

None. No code or dependency changes; the CI allowlist is unchanged, only its comment.
