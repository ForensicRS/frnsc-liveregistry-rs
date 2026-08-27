# CHANGELOG

## 0.14.0

* Migrate to forensic-rs 0.14's redesigned `Registry` trait (replaces the removed `RegistryReader`/`RegHiveKey`/`RegistryKeyInfo`). Positional `key_at`/`value_at` and the `from_file`/`from_fs` VFS hooks are gone, since the new trait has no equivalents; `values_raw`/`keys_raw` now return full `(name, value)` pairs and `KeyEntry` lists directly.
* Implement `values_iter_raw`/`keys_iter_raw`, the `Registry` trait's lazy one-at-a-time enumeration methods: each pulls entries directly from `RegEnumValueW`/`RegEnumKeyExW` by index instead of building on top of `values_raw`/`keys_raw`, so a caller that only needs the first few entries (or bails early) doesn't pay for enumerating the rest.
* Bump `windows` (windows-rs) from 0.53 to 0.62.
* `keys_raw` now captures each subkey's last-write time directly from `RegEnumKeyExW` instead of discarding it.

## 0.12.1

* Fix a bug when accessing MULTI_SZ registry values.