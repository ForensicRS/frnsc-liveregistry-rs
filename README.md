# Windows Registry Reader
[![crates.io](https://img.shields.io/crates/v/frnsc-liveregistry-rs.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-liveregistry-rs) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-liveregistry-rs) [![MIT License](https://img.shields.io/crates/l/frnsc-liveregistry-rs?style=for-the-badge)](https://github.com/ForensicRS/frnsc-liveregistry-rs/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-liveregistry-rs/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-liveregistry-rs/workflows/Rust/badge.svg?branch=main)


Implements [*Registry*](https://github.com/ForensicRS/forensic-rs/blob/main/src/traits/registry/raw.rs) using the Windows API to access the registry of a live system.

### Usage
```rust
fn test_reg(reg: &dyn Registry) {
    let keys = reg.keys_at("HKCU").unwrap();
    let names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    assert!(names.contains(&"SOFTWARE"));
    assert!(names.contains(&"Microsoft"));
}

let registry = LiveRegistryReader::new();
let key = registry.key(r"HKCU\Volatile Environment").unwrap();
let value: String = key.value("USERNAME").unwrap().try_into().unwrap();
assert!(value.len() > 1);
let values = key.values().unwrap();

test_reg(&registry);
```
