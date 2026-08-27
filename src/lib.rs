extern crate forensic_rs;
extern crate windows;

use forensic_rs::prelude::{
    ForensicError, ForensicResult, ForensicTimestamp, KeyEntry, KeyInfo, PredefinedHive, RawKey,
    RegValue, Registry,
};
use std::convert::TryInto;

use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA, ERROR_INVALID_HANDLE,
            ERROR_MORE_DATA, ERROR_NO_MORE_FILES, ERROR_NO_MORE_ITEMS, FILETIME, WIN32_ERROR,
        },
        System::Registry::{
            RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyW, RegQueryInfoKeyW,
            RegQueryValueExW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER,
            HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_PERFORMANCE_NLSTEXT,
            HKEY_PERFORMANCE_TEXT, HKEY_USERS, REG_BINARY, REG_DWORD, REG_EXPAND_SZ,
            REG_MULTI_SZ, REG_QWORD, REG_SZ, REG_VALUE_TYPE,
        },
    },
};

/// Access windows registry. To be used in a running windows machine.
///
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_liveregistry_rs::LiveRegistryReader;
/// let reader = LiveRegistryReader::new();
/// let key = reader.key(r"HKCU\Volatile Environment").unwrap();
/// let value: String = key.value("USERNAME").unwrap().try_into().unwrap();
/// assert!(value.len() > 1);
/// // `key` closes the underlying registry handle automatically when dropped.
/// ```
#[derive(Clone, Default)]
pub struct LiveRegistryReader {}

impl LiveRegistryReader {
    pub fn new() -> Self {
        Self {}
    }
}

impl Registry for LiveRegistryReader {
    fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey> {
        Ok(hkey_to_raw(hive_to_hkey(hive)?))
    }

    fn open_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey> {
        let hkey = raw_to_hkey(parent);
        unsafe {
            let mut new_key = HKEY(std::ptr::null_mut());
            let new_key_str = to_pwstr(name);
            let status = RegOpenKeyW(hkey, PCWSTR(new_key_str.as_ptr()), &mut new_key);
            if status.is_err() {
                return Err(map_windows_error(status));
            }
            Ok(hkey_to_raw(new_key))
        }
    }

    fn read_raw(&self, key: &RawKey, value: &str) -> ForensicResult<RegValue> {
        read_reg_value(raw_to_hkey(key), value)
    }

    fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>> {
        let hkey = raw_to_hkey(key);
        unsafe {
            let mut count: u32 = 0;
            let mut max_name_len: u32 = 0;
            let mut max_data_len: u32 = 0;
            let status = RegQueryInfoKeyW(
                hkey,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut max_name_len),
                Some(&mut max_data_len),
                None,
                None,
            );
            if status.is_err() {
                return Err(map_windows_error(status));
            }

            let mut out = Vec::with_capacity(count as usize);
            let mut name_buff = vec![0u16; max_name_len as usize + 1];
            let mut data_buff = vec![0u8; max_data_len as usize];

            for pos in 0..count {
                let mut name_len = name_buff.len() as u32;
                let mut data_len = data_buff.len() as u32;
                let mut data_type_raw: u32 = 0;
                let status = RegEnumValueW(
                    hkey,
                    pos,
                    Some(PWSTR(name_buff.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut data_type_raw),
                    Some(data_buff.as_mut_ptr()),
                    Some(&mut data_len),
                );
                if status == ERROR_NO_MORE_ITEMS || status == ERROR_NO_MORE_FILES {
                    break;
                }
                if status == ERROR_MORE_DATA {
                    // A value's data grew since the sizing pass above; grow the
                    // shared buffer to the size the API just reported and retry
                    // this same index once, since the name/data returned on the
                    // failing call aren't guaranteed to be usable.
                    data_buff.resize(data_len.max(data_buff.len() as u32) as usize, 0);
                    name_len = name_buff.len() as u32;
                    data_len = data_buff.len() as u32;
                    let retry_status = RegEnumValueW(
                        hkey,
                        pos,
                        Some(PWSTR(name_buff.as_mut_ptr())),
                        &mut name_len,
                        None,
                        Some(&mut data_type_raw),
                        Some(data_buff.as_mut_ptr()),
                        Some(&mut data_len),
                    );
                    if retry_status.is_err() {
                        return Err(map_windows_error(retry_status));
                    }
                    let name = from_pwstr(&name_buff[..name_len as usize]);
                    let value =
                        decode_reg_value(REG_VALUE_TYPE(data_type_raw), &data_buff[..data_len as usize])?;
                    out.push((name, value));
                    continue;
                }
                if status.is_err() {
                    return Err(map_windows_error(status));
                }
                let name = from_pwstr(&name_buff[..name_len as usize]);
                let value =
                    decode_reg_value(REG_VALUE_TYPE(data_type_raw), &data_buff[..data_len as usize])?;
                out.push((name, value));
            }
            Ok(out)
        }
    }

    fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>> {
        let hkey = raw_to_hkey(key);
        unsafe {
            let mut count: u32 = 0;
            let mut max_subkey_len: u32 = 0;
            let status = RegQueryInfoKeyW(
                hkey,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut max_subkey_len),
                None,
                None,
                None,
                None,
                None,
                None,
            );
            if status.is_err() {
                return Err(map_windows_error(status));
            }

            let mut out = Vec::with_capacity(count as usize);
            let mut name_buff = vec![0u16; max_subkey_len as usize + 1];

            for pos in 0..count {
                let mut name_len = name_buff.len() as u32;
                let mut last_write = FILETIME::default();
                let status = RegEnumKeyExW(
                    hkey,
                    pos,
                    Some(PWSTR(name_buff.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None,
                    None,
                    Some(&mut last_write),
                );
                if status == ERROR_NO_MORE_ITEMS || status == ERROR_NO_MORE_FILES {
                    break;
                }
                if status.is_err() {
                    return Err(map_windows_error(status));
                }
                let filetime_bits = ((last_write.dwHighDateTime as u64) << 32)
                    | last_write.dwLowDateTime as u64;
                out.push(KeyEntry {
                    name: from_pwstr(&name_buff[..name_len as usize]),
                    last_write: if filetime_bits == 0 {
                        None
                    } else {
                        Some(ForensicTimestamp::from_win_filetime(filetime_bits))
                    },
                    allocated: true,
                });
            }
            Ok(out)
        }
    }

    fn close_raw(&self, key: &RawKey) {
        let hkey = raw_to_hkey(key);
        if !is_predefined(hkey) {
            let _ = unsafe { RegCloseKey(hkey) };
        }
    }

    fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo> {
        let hkey = raw_to_hkey(key);
        unsafe {
            let mut max_value_name_length = 0;
            let mut values = 0;
            let mut max_value_length = 0;
            let mut subkeys = 0;
            let mut max_subkey_name_length = 0;
            let mut last_write_time = FILETIME::default();
            let status = RegQueryInfoKeyW(
                hkey,
                None,
                None,
                None,
                Some(&mut subkeys),
                Some(&mut max_subkey_name_length),
                None,
                Some(&mut values),
                Some(&mut max_value_name_length),
                Some(&mut max_value_length),
                None,
                Some(&mut last_write_time),
            );
            if status.is_err() {
                return Err(map_windows_error(status));
            }
            let filetime_bits =
                ((last_write_time.dwHighDateTime as u64) << 32) | last_write_time.dwLowDateTime as u64;
            Ok(KeyInfo {
                last_write_time: if filetime_bits == 0 {
                    None
                } else {
                    Some(ForensicTimestamp::from_win_filetime(filetime_bits))
                },
                max_subkey_name_length,
                max_value_length,
                max_value_name_length,
                subkeys,
                values,
            })
        }
    }

    fn values_iter_raw<'a>(
        &'a self,
        key: &RawKey,
    ) -> ForensicResult<Box<dyn Iterator<Item = (String, RegValue)> + 'a>> {
        let hkey = raw_to_hkey(key);
        unsafe {
            let mut count: u32 = 0;
            let mut max_name_len: u32 = 0;
            let mut max_data_len: u32 = 0;
            let status = RegQueryInfoKeyW(
                hkey,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut max_name_len),
                Some(&mut max_data_len),
                None,
                None,
            );
            if status.is_err() {
                return Err(map_windows_error(status));
            }
            Ok(Box::new(ValuesIter {
                hkey,
                pos: 0,
                count,
                name_buff: vec![0u16; max_name_len as usize + 1],
                data_buff: vec![0u8; max_data_len as usize],
            }))
        }
    }

    fn keys_iter_raw<'a>(&'a self, key: &RawKey) -> ForensicResult<Box<dyn Iterator<Item = KeyEntry> + 'a>> {
        let hkey = raw_to_hkey(key);
        unsafe {
            let mut count: u32 = 0;
            let mut max_subkey_len: u32 = 0;
            let status = RegQueryInfoKeyW(
                hkey,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut max_subkey_len),
                None,
                None,
                None,
                None,
                None,
                None,
            );
            if status.is_err() {
                return Err(map_windows_error(status));
            }
            Ok(Box::new(KeysIter {
                hkey,
                pos: 0,
                count,
                name_buff: vec![0u16; max_subkey_len as usize + 1],
            }))
        }
    }
}

/// Lazily pulls one value at a time via `RegEnumValueW`, called by index
/// instead of `values_raw`'s eager loop-and-collect. `RegEnumValueW`'s
/// `Item` is `(String, RegValue)`, not a `Result`, so unlike `values_raw`
/// this can't propagate a mid-enumeration Win32 error to the caller — it
/// just ends iteration early (`next` returns `None`) the same way it does
/// for `ERROR_NO_MORE_ITEMS`. That mirrors `values_raw`'s existing
/// `ERROR_MORE_DATA` retry-and-grow behavior for the one recoverable case
/// (a value's data grew since the sizing pass), but any other failure is
/// silently treated as "no more items" rather than surfaced.
struct ValuesIter {
    hkey: HKEY,
    pos: u32,
    count: u32,
    name_buff: Vec<u16>,
    data_buff: Vec<u8>,
}

impl Iterator for ValuesIter {
    type Item = (String, RegValue);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.count {
            let pos = self.pos;
            self.pos += 1;
            let mut name_len = self.name_buff.len() as u32;
            let mut data_len = self.data_buff.len() as u32;
            let mut data_type_raw: u32 = 0;
            let status = unsafe {
                RegEnumValueW(
                    self.hkey,
                    pos,
                    Some(PWSTR(self.name_buff.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut data_type_raw),
                    Some(self.data_buff.as_mut_ptr()),
                    Some(&mut data_len),
                )
            };
            if status == ERROR_NO_MORE_ITEMS || status == ERROR_NO_MORE_FILES {
                return None;
            }
            if status == ERROR_MORE_DATA {
                self.data_buff
                    .resize(data_len.max(self.data_buff.len() as u32) as usize, 0);
                name_len = self.name_buff.len() as u32;
                data_len = self.data_buff.len() as u32;
                let retry_status = unsafe {
                    RegEnumValueW(
                        self.hkey,
                        pos,
                        Some(PWSTR(self.name_buff.as_mut_ptr())),
                        &mut name_len,
                        None,
                        Some(&mut data_type_raw),
                        Some(self.data_buff.as_mut_ptr()),
                        Some(&mut data_len),
                    )
                };
                if retry_status.is_err() {
                    return None;
                }
                let name = from_pwstr(&self.name_buff[..name_len as usize]);
                let value =
                    decode_reg_value(REG_VALUE_TYPE(data_type_raw), &self.data_buff[..data_len as usize]).ok()?;
                return Some((name, value));
            }
            if status.is_err() {
                return None;
            }
            let name = from_pwstr(&self.name_buff[..name_len as usize]);
            let value =
                decode_reg_value(REG_VALUE_TYPE(data_type_raw), &self.data_buff[..data_len as usize]).ok()?;
            return Some((name, value));
        }
        None
    }
}

/// Lazily pulls one subkey at a time via `RegEnumKeyExW`; see
/// [`ValuesIter`] for why a Win32 error mid-enumeration ends iteration
/// early instead of being surfaced.
struct KeysIter {
    hkey: HKEY,
    pos: u32,
    count: u32,
    name_buff: Vec<u16>,
}

impl Iterator for KeysIter {
    type Item = KeyEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.count {
            let pos = self.pos;
            self.pos += 1;
            let mut name_len = self.name_buff.len() as u32;
            let mut last_write = FILETIME::default();
            let status = unsafe {
                RegEnumKeyExW(
                    self.hkey,
                    pos,
                    Some(PWSTR(self.name_buff.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None,
                    None,
                    Some(&mut last_write),
                )
            };
            if status == ERROR_NO_MORE_ITEMS || status == ERROR_NO_MORE_FILES {
                return None;
            }
            if status.is_err() {
                return None;
            }
            let filetime_bits =
                ((last_write.dwHighDateTime as u64) << 32) | last_write.dwLowDateTime as u64;
            return Some(KeyEntry {
                name: from_pwstr(&self.name_buff[..name_len as usize]),
                last_write: if filetime_bits == 0 {
                    None
                } else {
                    Some(ForensicTimestamp::from_win_filetime(filetime_bits))
                },
                allocated: true,
            });
        }
        None
    }
}

fn read_reg_value(hkey: HKEY, name: &str) -> ForensicResult<RegValue> {
    unsafe {
        let value_name = to_pwstr(name);
        let mut capacity: u32 = 0;
        let _ = RegQueryValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            None,
            None,
            Some(&mut capacity),
        );
        let mut readed_data = vec_with_capacity(capacity as usize);
        let mut data_type: REG_VALUE_TYPE = REG_VALUE_TYPE::default();
        let status = RegQueryValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            None,
            Some(&mut data_type),
            Some(readed_data.as_mut_ptr()),
            Some(&mut capacity),
        );
        if status.is_err() {
            return Err(map_windows_error(status));
        }
        readed_data.resize(capacity as usize, 0);
        decode_reg_value(data_type, &readed_data)
    }
}

fn decode_reg_value(data_type: REG_VALUE_TYPE, readed_data: &[u8]) -> ForensicResult<RegValue> {
    let capacity = readed_data.len();
    Ok(match data_type {
        //https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
        REG_DWORD => {
            if capacity != 4 {
                return Err(ForensicError::invalid_format(
                    "registry",
                    "Returned data size is distinct than 4 bytes",
                ));
            }
            RegValue::DWord(u32::from_ne_bytes(
                readed_data[0..4].try_into().unwrap_or_default(),
            ))
        }
        REG_QWORD => {
            if capacity != 8 {
                return Err(ForensicError::invalid_format(
                    "registry",
                    "Returned data size is distinct than 8 bytes",
                ));
            }
            RegValue::QWord(u64::from_ne_bytes(
                readed_data[0..8].try_into().unwrap_or_default(),
            ))
        }
        REG_SZ => {
            let mut u16_vec: Vec<u16> = readed_data[0..capacity]
                .chunks(2)
                .map(|v| (v[1] as u16) << 8 | v[0] as u16)
                .collect();
            let _ = u16_vec.pop(); //Ends with 00
            RegValue::SZ(String::from_utf16_lossy(&u16_vec))
        }
        REG_MULTI_SZ => {
            let mut returned_strs = Vec::with_capacity(16);
            let mut txt = vec![0; capacity];
            let mut txt_lngt = 0;
            for chr in readed_data[0..capacity]
                .chunks(2)
                .map(|v| (v[1] as u16) << 8 | v[0] as u16)
            {
                if chr == 0 {
                    if txt_lngt > 0 {
                        returned_strs.push(String::from_utf16_lossy(&txt[0..txt_lngt]));
                    } else {
                        returned_strs.push(String::new());
                    }
                    txt_lngt = 0;
                } else {
                    txt[txt_lngt] = chr;
                    txt_lngt += 1;
                }
            }
            RegValue::MultiSZ(returned_strs)
        }
        REG_BINARY => RegValue::Binary(readed_data.to_vec()),
        REG_EXPAND_SZ => {
            let mut u16_vec: Vec<u16> = readed_data[0..capacity]
                .chunks(2)
                .map(|v| (v[1] as u16) << 8 | v[0] as u16)
                .collect();
            let _ = u16_vec.pop(); //Ends with 00
            RegValue::ExpandSZ(String::from_utf16_lossy(&u16_vec))
        }
        _ => return Err(ForensicError::invalid_format("registry", "Reg type not implemented")),
    })
}

pub fn vec_with_capacity(capacity: usize) -> Vec<u8> {
    vec![0; capacity as usize]
}

pub fn to_pwstr(val: &str) -> Vec<u16> {
    let mut val = val.encode_utf16().collect::<Vec<u16>>();
    val.push(0);
    val
}

pub fn from_pwstr(val: &[u16]) -> String {
    String::from_utf16_lossy(val)
}

fn hive_to_hkey(hive: PredefinedHive) -> ForensicResult<HKEY> {
    Ok(match hive {
        PredefinedHive::ClassesRoot => HKEY_CLASSES_ROOT,
        PredefinedHive::CurrentConfig => HKEY_CURRENT_CONFIG,
        PredefinedHive::CurrentUser => HKEY_CURRENT_USER,
        PredefinedHive::DynData => HKEY_DYN_DATA,
        PredefinedHive::LocalMachine => HKEY_LOCAL_MACHINE,
        PredefinedHive::PerformanceData => HKEY_PERFORMANCE_DATA,
        PredefinedHive::PerformanceNlsText => HKEY_PERFORMANCE_NLSTEXT,
        PredefinedHive::PerformanceText => HKEY_PERFORMANCE_TEXT,
        PredefinedHive::Users => HKEY_USERS,
        // PredefinedHive is #[non_exhaustive]: forensic-rs may add hives this
        // crate doesn't know about yet.
        _ => {
            return Err(ForensicError::other(
                "registry",
                format!("unsupported predefined hive: {hive}"),
            ))
        }
    })
}

fn raw_to_hkey(key: &RawKey) -> HKEY {
    HKEY(key.raw() as usize as *mut core::ffi::c_void)
}

fn hkey_to_raw(hkey: HKEY) -> RawKey {
    RawKey::from_raw(hkey.0 as usize as u64)
}

fn is_predefined(hkey: HKEY) -> bool {
    matches!(
        hkey,
        HKEY_CLASSES_ROOT
            | HKEY_CURRENT_CONFIG
            | HKEY_CURRENT_USER
            | HKEY_DYN_DATA
            | HKEY_LOCAL_MACHINE
            | HKEY_PERFORMANCE_DATA
            | HKEY_PERFORMANCE_NLSTEXT
            | HKEY_PERFORMANCE_TEXT
            | HKEY_USERS
    )
}

fn map_windows_error(err: WIN32_ERROR) -> ForensicError {
    match err {
        ERROR_FILE_NOT_FOUND => {
            ForensicError::missing_data("registry_key", "key or value not found".into())
        }
        ERROR_ACCESS_DENIED => ForensicError::access_denied(
            "registry",
            "access denied opening/reading registry key",
        ),
        ERROR_INVALID_HANDLE => {
            ForensicError::invalid_format("registry", "the key handle is invalid")
        }
        ERROR_INVALID_DATA => {
            ForensicError::invalid_format("registry", "the supplied data is invalid")
        }
        ERROR_NO_MORE_ITEMS | ERROR_NO_MORE_FILES => ForensicError::no_more_data(),
        ERROR_MORE_DATA => ForensicError::other("registry", "more data is available".into()),
        _ => ForensicError::other("registry", format!("unknown Win32 error: {}", err.0)),
    }
}

#[cfg(test)]
mod test_live_registry {
    use crate::LiveRegistryReader;
    use forensic_rs::prelude::*;

    #[test]
    fn should_list_keys() {
        let registry = LiveRegistryReader::new();
        let keys = registry.keys_at(r"HKCU").unwrap();
        let names: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
        println!("{:?}", names);
        assert!(names.contains(&"Software"));
        assert!(names.contains(&"Environment"));

        let root = registry.root(PredefinedHive::CurrentUser).unwrap();
        let _info = registry.info_raw(&root).unwrap();
        registry.close_raw(&root);
    }

    #[test]
    fn should_read_volatile_environment() {
        let registry = LiveRegistryReader::new();
        let root = registry.root(PredefinedHive::CurrentUser).unwrap();
        let key = registry.open_raw(&root, "Volatile Environment").unwrap();

        let value: String = registry
            .read_raw(&key, "USERNAME")
            .unwrap()
            .try_into()
            .unwrap();
        assert!(value.len() > 1);

        let values = registry.values_raw(&key).unwrap();
        assert!(values.len() > 2);

        registry.close_raw(&key);
        registry.close_raw(&root);
    }

    #[test]
    fn should_use_registry_ext() {
        let registry = LiveRegistryReader::new();
        let key = registry.key(r"HKCU\Volatile Environment").unwrap();
        let value: String = key.value("USERNAME").unwrap().try_into().unwrap();
        assert!(value.len() > 1);
    }

    #[test]
    fn values_iter_matches_values_raw() {
        let registry = LiveRegistryReader::new();
        let root = registry.root(PredefinedHive::CurrentUser).unwrap();
        let key = registry.open_raw(&root, "Volatile Environment").unwrap();

        let mut expected = registry.values_raw(&key).unwrap();
        expected.sort_by(|a, b| a.0.cmp(&b.0));

        let mut via_iter: Vec<_> = registry.values_iter_raw(&key).unwrap().collect();
        via_iter.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(via_iter, expected);

        registry.close_raw(&key);
        registry.close_raw(&root);
    }

    #[test]
    fn keys_iter_matches_keys_raw() {
        let registry = LiveRegistryReader::new();
        let root = registry.root(PredefinedHive::CurrentUser).unwrap();

        let mut expected: Vec<String> = registry
            .keys_raw(&root)
            .unwrap()
            .into_iter()
            .map(|k| k.name)
            .collect();
        expected.sort();

        let mut via_iter: Vec<String> = registry
            .keys_iter_raw(&root)
            .unwrap()
            .map(|k| k.name)
            .collect();
        via_iter.sort();

        assert_eq!(via_iter, expected);

        registry.close_raw(&root);
    }

    #[test]
    fn values_iter_supports_partial_consumption() {
        let registry = LiveRegistryReader::new();
        let root = registry.root(PredefinedHive::CurrentUser).unwrap();
        let key = registry.open_raw(&root, "Volatile Environment").unwrap();

        // A real `Iterator`, not a pre-collected `Vec` wearing an `Iterator`
        // interface — a caller can pull just the first entry.
        let mut iter = registry.values_iter_raw(&key).unwrap();
        assert!(iter.next().is_some());

        registry.close_raw(&key);
        registry.close_raw(&root);
    }
}
