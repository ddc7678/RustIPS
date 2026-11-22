# Third-party notices

RustIPS itself is MIT licensed (see `Cargo.toml`).

## Reference material

`repos/` contains reference projects that were **studied, not copied**:

* **Suricata** — GPLv2. Used as a semantics reference only: detector
  behaviour, rule-file shape, protocol edge cases. No code, data or rule
  files from Suricata are linked, vendored or distributed with RustIPS
  (REF-03). Snort rules are never shipped; any future rule acquisition
  downloads them at runtime under the administrator's own licence
  (FR-433/FR-434).
* **`ip-location-db/`** — the `user-country` dataset is PDDL licensed. The
  dataset is not vendored in this repository; it is fetched at runtime by the
  installation that opts in (FR-160).

No source file in `src/`, `tests/` or `scripts/` is derived from either
project. Constants that match the public wire formats (Ethernet types, IP
protocol numbers, TCP flag bits) come from the relevant RFCs and the Linux
UAPI headers exposed by `libc`.

## Rust crates

All dependencies are permissively licensed and are linked statically into the
release binary, except `libc`/`libm`/`libgcc`, which are provided by the
system.

| Crate | Version | Licence |
|---|---|---|
| `chrono` | 0.4 | MIT OR Apache-2.0 |
| `clap` | 4.6 | MIT OR Apache-2.0 |
| `libc` | 0.2 | MIT OR Apache-2.0 |
| `rusqlite` | 0.43 | MIT |
| `serde` | 1.0 | MIT OR Apache-2.0 |
| `serde_json` | 1.0 | MIT OR Apache-2.0 |
| `signal-hook` | 0.4 | MIT OR Apache-2.0 |
| `thiserror` | 2.0 | MIT OR Apache-2.0 |
| `toml` | 1.2 | MIT OR Apache-2.0 |
| `tracing` | 0.1 | MIT |
| `tracing-subscriber` | 0.3 | MIT |

Transitive dependencies are enumerated in `Cargo.lock`. `rusqlite` is built
with the `bundled` feature, so the binary contains **SQLite**, which is in the
public domain.

## System libraries loaded at runtime

The web UI authenticates through the host's PAM stack. `libpam.so.0` is loaded
with `dlopen` when a login is attempted; it is **not** linked into or
distributed with RustIPS. PAM, its modules and the underlying NSS/SSSD stack
are part of the operating system and carry their own licences
(Linux-PAM is BSD-3-Clause; individual modules and NSS providers vary). No PAM
source code or module is vendored here.

## Generating a full report

The authoritative licence text for every crate in the dependency graph can be
produced with:

```sh
cargo install cargo-license
cargo license
```

or, for a file-per-crate bundle suitable for distribution:

```sh
cargo about generate about.hbs > THIRD_PARTY.html
```
