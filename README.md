# Windows Registry Reader
[![crates.io](https://img.shields.io/crates/v/frnsc-liveregistry-rs.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-liveregistry-rs) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-liveregistry-rs) [![MIT License](https://img.shields.io/crates/l/frnsc-liveregistry-rs?style=for-the-badge)](https://github.com/ForensicRS/frnsc-liveregistry-rs/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-liveregistry-rs/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-liveregistry-rs/workflows/Rust/badge.svg?branch=main)


Implements [*RegistryReader*](https://github.com/ForensicRS/forensic-rs/blob/main/src/traits/registry.rs#L200) using the Windows API to access the registry of a live system.

### Usage
```rust
fn test_reg(reg : &mut Box<dyn RegistryReader>) {
    let keys = reg.enumerate_keys(HkeyCurrentUser).unwrap();
    assert!(keys.contains("SOFTWARE"));
    assert!(keys.contains("Microsoft"));
}

let registry = Box::new(LiveRegistryReader::new());
let key = registry.open_key(HkeyCurrentUser, "Volatile Environment").unwrap();
let value : String = registry.read_value(key, "USERNAME").unwrap().try_into().unwrap();
assert!(value.len() > 1);
let values : Vec<String> = registry.enumerate_values(key).unwrap();

test_reg(&mut registry);
```