# Dependency review

Method: `cargo tree` + manifest inspection + `cargo deny list --layout
license` against the committed `Cargo.lock`. No new code. Re-run when any
dependency is added or quarterly, whichever comes first.

- First review: 2026-09-05 (pre-Tauri).
- Revised 2026-09-06: the desktop shell landed between the two, which
  invalidated three claims in the first version. Corrections are called out
  inline rather than quietly overwritten, because the point of this document
  is to be trusted.

## Direct dependencies (the entire trust surface)

| Crate | Version | Used by | Purpose | Why this one |
| ----- | ------- | ------- | ------- | ------------ |
| `rusqlite` (+`bundled`) | 0.40.2 | `rocky-storage` | SQLite persistence | Only embedded-DB option that needs no service, no daemon, no network. `bundled` compiles SQLite from source so there is no system-library lottery on user machines. |
| `sysinfo` | 0.36.1 (pinned `=`) | `rocky-resources` | CPU/RAM counters | The stdlib exposes no counters on any desktop OS. Narrowest crate that does (no runtime, no services, single-shot use only). Pinned because 0.39+ requires a newer rustc than this project's toolchain. |
| `keyring` | 3.6.3 | `rocky-models` | OS credential storage | Secret values must live in Credential Manager / Keychain / Secret Service, which no stdlib API reaches. Only `KeyringSecretStore` touches it. Backend features are per-target; see the note below. |
| `ureq` (+`json`) | 2.12.1 | `rocky-models` | Loopback HTTP for the local model provider | The provider trait is synchronous by design, so Tokio/reqwest would drag a reactor across a sync boundary. Narrowest blocking client with a long-stable API. |
| `serde_json` | 1 | `rocky-models`, `rocky-desktop` | Chat-reply parsing, command DTOs | Parses replies without derive macros or schema codegen. |
| `serde` (+`derive`) | 1 | `rocky-desktop` | Typed command DTOs | Required shape for `#[tauri::command]` return types. |
| `tauri` (+`tray-icon`) | 2.11.5 | `rocky-desktop` | Desktop shell | This crate *is* the shell, so the framework is the product rather than incidental weight. |
| `tauri-build` | 2.6.3 | `rocky-desktop` (build) | Config/ACL codegen | Required by `tauri`. |

**Correction to the 2026-09-05 review**, which read "That's it: two direct
dependencies for the whole workspace." That was true when written and is not
true now: there are eight, six of them introduced or first recorded by the
desktop shell. The eight are still confined to four crates — `rocky-storage`,
`rocky-resources`, `rocky-models`, `rocky-desktop` — and the eight pure crates
(`domain`, `policy`, `tools`, `agents`, `audit`, `ipc`, `config`, `runtime`)
remain dependency-free. That property, not the count, is the one worth
defending.

## Transitive dependencies (audited for shape, not line-by-line)

453 packages in the SPDX inventory (see *SBOM* below).

- Via `rusqlite`: `libsqlite3-sys` (builds the C amalgamation), `bitflags`,
  `smallvec`, `hashlink`/`hashbrown`/`foldhash`, `fallible-*`,
  build-time `cc`, `pkg-config`, `vcpkg`, `shlex`, `find-msvc-tools`.
- Via `sysinfo` 0.36.1: `libc`, `memchr`, `ntapi` + `windows` 0.61.3
  (Windows only), all narrow OS-binding crates.
- Via `keyring` 3.6.3: `log`, `zeroize`, plus `windows-sys` on Windows and
  `security-framework` on macOS.
- Via `ureq` 2.x: `url`, `idna` and the `icu_*` set, `rustls`,
  `webpki-roots`, `base64`, `flate2`.
- Via `tauri` 2.11.5: the large one. `tokio`, `wry`/`tao`, `webview2-com` +
  `windows` on Windows, `gtk`/`webkit2gtk`/`soup3`/`x11`/`dbus` on Linux,
  `objc2-*` on macOS, `html5ever`/`selectors`/`cssparser`, `serde_with`,
  `schemars`, `json-patch`, `brotli`, `png`/`ico`/`plist`, and via
  `tauri-build` the `cargo_metadata`/`toml_edit` build-time set.

**Correction to the 2026-09-05 review**, which read "No async runtimes, no
HTTP clients, no serialization frameworks, no crypto, no proc-macro sprawl."
Tauri brings all four: `tokio` 1.53.1, `hyper` 1.11.1 and `reqwest` 0.13.4,
`serde`/`serde_with`/`schemars`, and `rustls` 0.23.43 + `ring` 0.17.14. The
defensible statement is narrower and still worth making: **no ROCKY crate
calls any of them.** The async runtime belongs to the framework's event loop,
the HTTP clients to its updater and asset paths, and the authorization core
(`policy`, `runtime`, `tools`, `domain`) links none of it. The earlier
"nothing phones home" claim now needs the same qualification: nothing ROCKY
writes phones home, and the shell's network-capable paths are framework
surface that the threat model should treat as such.

## Licences

Inventory taken 2026-09-06 with `cargo deny list --layout license`. The
allowlist and the reasoning for each entry live in `deny.toml`; this section
records only what the inventory found.

Present: `MIT` (400 crates), `Apache-2.0` (294),
`Apache-2.0 WITH LLVM-exception` (4), `BSD-3-Clause` (7), `0BSD` (1),
`ISC` (5), `Unlicense` (6), `Zlib` (20), `CC0-1.0` (1), `MIT-0` (1),
`Unicode-3.0` (19), `CDLA-Permissive-2.0` (2), `MPL-2.0` (5),
`LGPL-2.1-or-later` (2). Counts overlap because most crates are dual or
triple licensed.

**Correction to the 2026-09-05 review**, which read "current set is
MIT/Apache-2.0 only by inspection." Two entries need a decision rather than a
glance:

- `MPL-2.0` — `cssparser`, `cssparser-macros`, `selectors`, `dtoa-short`
  (Tauri's WebView stack) and `option-ext` (via `dirs-sys`). Single-licensed,
  so it cannot be dodged by picking another option. Allowed: MPL-2.0
  obligations attach per file and ROCKY modifies none of these files.
  Revisit if that changes.
- `LGPL-2.1-or-later` — `r-efi` only, which is
  `MIT OR Apache-2.0 OR LGPL-2.1-or-later`, so the permissive option is
  taken. **Not** in the allowlist, deliberately, so that a future
  single-licensed LGPL crate fails CI instead of arriving unnoticed.

## SBOM

`cargo sbom`, installed and run against this workspace on 2026-09-06.

Chosen on three properties confirmed from its own `--help` and output rather
than from its README: it is a single Rust binary installable with
`cargo install --locked`, it reads `Cargo.lock` without building the project,
and it emits SPDX 2.3 *and* CycloneDX 1.4/1.5/1.6 from one tool. The third
point is what settles the comparison — `cargo-cyclonedx` would add a second
tool to cover a format this one already emits, and `syft` is a general-purpose
scanner that would bring a non-Rust binary (and, in its usual CI form, a
container) for the same `Cargo.lock` parse. Neither alternative was installed;
the argument against them is redundancy and footprint, not measured behaviour,
and is recorded here as such.

Wired into `.github/workflows/ci.yml` as the `sbom` job: it emits SPDX 2.3
JSON, asserts the document is well formed, and uploads it as a build artifact.

Verified locally 2026-09-06: `SPDX-2.3`, 453 packages, 1336 relationships,
`pkg:cargo/...` purls and per-package licence fields.

Not committed to the repository on purpose. The document is derived entirely
from `Cargo.lock`, so committing it would double every dependency diff and
create conflicts that carry no information.

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
5. Licence, ban, and source policy: `cargo deny check licenses bans sources`
   in CI, configured by `deny.toml`. Advisories are deliberately left to the
   `audit` job so each control has exactly one enforcement point.
6. Every workspace crate sets `publish = false`. ROCKY ships as an
   application, and the flag is also what lets the licence gate report
   third-party obligations only.

## Open items

- **`keyring` has no Linux backend.** Windows requests `windows-native` and
  macOS `apple-native`; Linux requests nothing, so `keyring` falls back to
  its mock store, which accepts a write and then reports no entry.
  `KeyringSecretStore` must not be used on Linux until
  `sync-secret-service` (which pulls `dbus-secret-service` plus a crypto
  stack) is evaluated as its own dependency decision. Root cause and evidence
  are in the test comment on `keyring_backend_round_trips_against_the_os`.
- **The project has no licence of its own.** No `LICENSE` file, and no
  `license` field on any of the 13 workspace crates. `publish = false` keeps
  the CI gate meaningful, but it does not answer the question, and choosing
  one is the owner's call, not an agent's.

Closed 2026-09-06: SBOM generation (`cargo sbom`, wired into CI) and licence
inventory automation (`cargo deny`, wired into CI) — the two items the
2026-09-05 review left open.
