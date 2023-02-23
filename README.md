# frnsc-liveregistry-rs

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