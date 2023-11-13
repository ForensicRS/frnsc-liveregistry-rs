# frnsc-liveregistry-rs
[![crates.io](https://img.shields.io/crates/v/frnsc-liveregistry-rs)](https://crates.io/crates/frnsc-liveregistry-rs) [![documentation](https://docs.rs/frnsc-liveregistry-rs/badge.svg)](https://docs.rs/frnsc-liveregistry-rs) ![MIT License](https://img.shields.io/crates/l/frnsc-liveregistry-rs) ![Rust](https://github.com/secsamdev/frnsc-liveregistry-rs/workflows/Rust/badge.svg?branch=main)

Implements *RegistryReader* using the Windows API to access the registry of a live system.

### Usage
```rust

fn test_reg(reg : &mut Box<dyn RegistryReader>) {
    let keys = reg.enumerate_keys(HkeyCurrentUser).unwrap();
    assert!(keys.contains("SOFTWARE"));
    assert!(keys.contains("Microsoft"));
}

let registry = LiveRegistryReader::new();
let mut registry : Box<dyn RegistryReader> = Box::new(registry);

test_reg(&mut registry);
```