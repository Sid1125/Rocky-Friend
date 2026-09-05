# Dependency review (2026-09-05)

Method: `cargo tree` + manifest inspection. No new code. Re-run when any
dependency is added or quarterly, whichever comes first.

## Direct dependencies (the entire trust surface)

| Crate | Version | Used by | Purpose | Why this one |
| ----- | ------- | ------- | ------- | ------------ |
| `rusqlite` (+`bundled`) | 0.40.2 | `rocky-storage` | SQLite persistence | Only embedded-DB option that needs no service, no daemon, no network. `bundled` compiles SQLite from source so there is no system-library lottery on user machines. |
| `sysinfo` | 0.36.1 (pinned `=`) | `rocky-resources` | CPU/RAM counters | The stdlib exposes no counters on any desktop OS. Narrowest crate that does (no runtime, no services, single-shot use only). Pinned because 0.39+ requires a newer rustc than this project's toolchain. |

That's it: two direct dependencies for the whole workspace.

## Transitive dependencies (audited for shape, not line-by-line)

- Via `rusqlite`: `libsqlite3-sys` (builds the C amalgamation), `bitflags`,
  `smallvec`, `hashlink`/`hashbrown`/`foldhash`, `fallible-*`,
  build-time `cc`, `pkg-config`, `vcpkg`, `shlex`, `find-msvc-tools`.
- Via `sysinfo` 0.36.1: `libc`, `memchr`, `ntapi` + `windows` 0.61.3
  (Windows only), all narrow OS-binding crates.
- No async runtimes, no HTTP clients, no serialization frameworks, no
  crypto, no proc-macro sprawl beyond what `windows` pulls for its own
  bindings. Nothing phones home: every transitive crate is computation
  or OS bindings.

## Policy going forward

1. Prefer stdlib; a new dependency needs a weighed justification comment
   in the dependent crate's manifest (see `rocky-resources/Cargo.toml`
   for the template).
2. Pin exactly (`=`) when newer releases demand a newer toolchain than
   the project's stable, with the reason recorded.
3. `Cargo.lock` is committed; review the lockfile diff on every
   dependency change, not just `Cargo.toml`.
4. Vulnerability scanning: `cargo audit` is wired into CI (see
   `.github/workflows/ci.yml`). No audit tool is installed on dev
   machines by default; CI is the enforcement point.

## Open items (not done in this review)

- SBOM generation (`cargo sbom` or equivalent) — tooling not evaluated yet.
- License inventory automation — current set is MIT/Apache-2.0 only by
  inspection; re-verify when the set changes.
