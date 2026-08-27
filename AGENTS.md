# AGENTS.md

## What this crate is

`frnsc-liveregistry-rs` implements forensic-rs's `Registry` trait (`forensic_rs::traits::registry::raw::Registry`) using raw Win32 registry APIs (`advapi32.dll`, via the `windows` crate) to read the registry of the live machine `cargo test`/the consuming program runs on.

The whole crate is one file: `src/lib.rs`. There is no other module structure — keep it that way unless it genuinely outgrows a single file.

## Build / test

- `cargo check` / `cargo build` — Windows-only (`windows` is a `cfg(target_os = "windows")` dependency); this crate cannot be meaningfully built or tested on Linux/macOS.
- `cargo test --verbose` — runs real integration tests against the live registry (`HKEY_CURRENT_USER`, `Volatile Environment\USERNAME`, etc.) plus a doctest. No mocking. A failure may mean the dev machine's registry genuinely lacks the expected keys, not necessarily a code bug — check that first.
- CI (`.github/workflows/rust.yml`) just runs `cargo test --verbose` on `windows-latest`.

## Dependency on forensic-rs

- This crate's own `version` in `Cargo.toml` tracks the **minor version** of the `forensic-rs` it targets (e.g. this crate at `0.14.0` targets `forensic-rs` `0.14.x`). Keep them in lockstep when bumping either.
- `forensic-rs` lives in a sibling checkout at `../forensic-rs` and is developed in tandem with this crate. When bumping to a forensic-rs minor version that hasn't been published to crates.io yet (check its `CHANGELOG.md` for an "Unreleased" heading), point `Cargo.toml` at a direct path dependency (`forensic-rs = { path = "../forensic-rs" }`) instead of a version string — a version-string requirement can't resolve against a version that doesn't exist on crates.io yet, and `.cargo/config.toml` path overrides can't fix that either (they only patch an already-resolvable registry dependency). Switch back to a version string once that version is published.
- If forensic-rs's `Registry` trait changes in a future version (see its CHANGELOG's RFC entries), this crate needs a matching rewrite, not just a version bump. Read forensic-rs's `src/traits/registry/{mod.rs,raw.rs}` and its own README's "Registry Example"/"Registry Handle Example" sections first; they're the authoritative source for the current trait shape, not this file.

## windows-rs specifics worth knowing before touching src/lib.rs

- `HKEY` is `pub struct HKEY(pub *mut core::ffi::c_void)` (pointer-backed, not integer-backed) as of windows-rs 0.62. This crate's `RawKey <-> HKEY` conversion (`raw_to_hkey`/`hkey_to_raw`) routes through `usize` as a pivot type specifically so it keeps working regardless of whether a future windows-rs version changes this representation again — don't "simplify" that cast without checking the currently pinned version's actual field type first (`cargo check` will tell you immediately if it's wrong).
- The `RegOpenKeyW`/`RegCloseKey`/`RegEnumValueW`/`RegEnumKeyExW`/`RegQueryInfoKeyW`/`RegQueryValueExW` functions return `WIN32_ERROR` directly (a `PartialEq`-comparable newtype over `u32`), **not** `windows::core::Result<()>`. Compare against named constants (`ERROR_NO_MORE_ITEMS`, etc.) or check `.is_err()`/`.0`; don't wrap calls in `if let Err(...)`.
- `RegEnumValueW`'s `lptype` out-param is typed `Option<*mut u32>` (not `Option<*mut REG_VALUE_TYPE>`) — wrap the raw `u32` in `REG_VALUE_TYPE(...)` yourself before matching on it. `RegQueryValueExW`'s `lptype` *is* `Option<*mut REG_VALUE_TYPE>` — the two functions are inconsistent in this crate version, don't assume they match.
- Verify exact Win32 function signatures against the actual pinned version's source (`cargo metadata` to find the resolved `windows` version, then its source under `~/.cargo/registry/src/.../windows-<version>/src/Windows/Win32/...`) rather than assuming they're unchanged from a prior version — several of these details changed between windows-rs 0.53 and 0.62.

## Conventions

- `RegValue`/`RegHiveKey`/`PredefinedHive`-style enums in forensic-rs are `#[non_exhaustive]`; any `match` against them needs a wildcard arm.
- `close_raw`/`close_key`-style methods on this trait are infallible by design (called from RAII `Drop`) — swallow the underlying Win32 close error rather than propagating it, matching forensic-rs's own documented contract.
- Update `CHANGELOG.md` with a version-numbered entry for behavior/API changes, matching the terse one-line-per-change style already there.
