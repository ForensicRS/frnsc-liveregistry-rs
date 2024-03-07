extern crate forensic_rs;
extern crate windows;

use forensic_rs::{prelude::{ForensicError, ForensicResult, RegHiveKey, RegValue, RegistryReader}, traits::registry::RegistryKeyInfo, utils::time::Filetime};
use std::convert::TryInto;

use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::ERROR_NO_MORE_ITEMS,
        System::Registry::{
            RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyW, RegQueryInfoKeyW, RegQueryValueExW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_PERFORMANCE_NLSTEXT, HKEY_PERFORMANCE_TEXT, HKEY_USERS, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ, REG_VALUE_TYPE
        },
    },
};

/// Access windows registry. To be used in a running windows machine.
/// 
/// ```rust
/// use forensic_rs::prelude::*;
/// use frnsc_liveregistry_rs::LiveRegistryReader;
/// let reader = LiveRegistryReader::new();
/// let key = reader.open_key(RegHiveKey::HkeyCurrentUser, "Volatile Environment").unwrap();
/// // auto_close_key() closes a registry key if an error occurs, this makes the code more readable.
/// auto_close_key(&reader, key, || {
///     let value : String = reader.read_value(key, "USERNAME")?.try_into()?;
///     Ok(())
/// });
/// 
/// ```
#[derive(Clone, Default)]
pub struct LiveRegistryReader {}

impl LiveRegistryReader {
    pub fn new() -> Self {
        Self {}
    }
}

impl RegistryReader for LiveRegistryReader {
    fn open_key(&self, hkey: RegHiveKey, name: &str) -> ForensicResult<RegHiveKey> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut new_key = HKEY(0);
            let new_key_str = to_pwstr(name);
            if let Err(err) = RegOpenKeyW(hkey, PCWSTR(new_key_str.as_ptr()), &mut new_key) {
                return Err(map_windows_error(err));
            }
            Ok(from_hkey(new_key))
        }
    }

    fn read_value(&self, hkey: RegHiveKey, name: &str) -> ForensicResult<RegValue> {
        let hkey = to_hkey(hkey);
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
            match RegQueryValueExW(
                hkey,
                PCWSTR(value_name.as_ptr()),
                None,
                Some(&mut data_type),
                Some(readed_data.as_mut_ptr()),
                Some(&mut capacity),
            ) {
                Ok(_) => {}
                Err(err) => return Err(map_windows_error(err)),
            };
            readed_data.resize(capacity as usize, 0);
            return Ok(match data_type {
                //https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
                REG_DWORD => {
                    if capacity != 4 {
                        return Err(ForensicError::bad_format_str(
                            "Returned data size is distinct than 4 bytes",
                        ));
                    }
                    RegValue::DWord(u32::from_ne_bytes(
                        readed_data[0..4].try_into().unwrap_or_default(),
                    ))
                }
                REG_QWORD => {
                    if capacity != 8 {
                        return Err(ForensicError::bad_format_str(
                            "Returned data size is distinct than 8 bytes",
                        ));
                    }
                    RegValue::QWord(u64::from_ne_bytes(
                        readed_data[0..8].try_into().unwrap_or_default(),
                    ))
                }
                REG_SZ => {
                    let mut u16_vec: Vec<u16> = readed_data[0..capacity as usize]
                        .chunks(2)
                        .map(|v| (v[1] as u16) << 8 | v[0] as u16)
                        .collect();
                    let _ = u16_vec.pop(); //Ends with 00
                    RegValue::SZ(String::from_utf16_lossy(&u16_vec))
                }
                REG_MULTI_SZ => {
                    let mut returned_strs = Vec::with_capacity(16);
                    let mut txt = Vec::with_capacity(capacity as usize);
                    let mut txt_lngt = 0;
                    for chr in readed_data[0..capacity as usize]
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
                REG_BINARY => RegValue::Binary(readed_data),
                REG_EXPAND_SZ => {
                    let mut u16_vec: Vec<u16> = readed_data[0..capacity as usize]
                        .chunks(2)
                        .map(|v| (v[1] as u16) << 8 | v[0] as u16)
                        .collect();
                    let _ = u16_vec.pop(); //Ends with 00
                    RegValue::ExpandSZ(String::from_utf16_lossy(&u16_vec))
                }
                _ => return Err(ForensicError::bad_format_str("Reg type not implemented")),
            });
        }
    }

    fn enumerate_values(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut max_value_length = 0;
            let mut count = 0;
            let _ = RegQueryInfoKeyW(
                hkey,
                PWSTR::null(),
                None,
                None,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut max_value_length),
                None,
                None,
                None,
            );
            let mut key_value_capacity: u32 = max_value_length + 1;
            let mut to_ret = Vec::with_capacity(count as usize);
            let mut key_value_buff = vec![0; key_value_capacity as usize];
            
            for pos in 0..count {
                key_value_capacity = max_value_length + 1;
                match RegEnumValueW(
                    hkey,
                    pos,
                    PWSTR(key_value_buff.as_mut_ptr()),
                    &mut key_value_capacity,
                    None,
                    None,
                    None,
                    None,
                ) {
                    Ok(_) => {}
                    Err(err) => {
                        if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                            break;
                        }
                        return Err(map_windows_error(err));
                    }
                };
                to_ret.push(from_pwstr(&key_value_buff[0..key_value_capacity as usize]));
            }
            Ok(to_ret)
        }
    }

    fn enumerate_keys(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut max_subkey_length = 0;
            let mut count = 0;
            let _ = RegQueryInfoKeyW(
                hkey,
                PWSTR::null(),
                None,
                None,
                Some(&mut count),
                Some(&mut max_subkey_length),
                None,
                None,
                None,
                None,
                None,
                None,
            );
            let mut key_name_capacity: u32 = max_subkey_length + 1;
            let mut to_ret = Vec::with_capacity(count as usize);
            let mut key_name_buff = vec![0; key_name_capacity as usize];
            
            for pos in 0..count {
                key_name_capacity = max_subkey_length + 1;
                match RegEnumKeyExW(
                    hkey,
                    pos,
                    PWSTR(key_name_buff.as_mut_ptr()),
                    &mut key_name_capacity,
                    None,
                    PWSTR::null(),
                    None,
                    None
                ) {
                    Ok(_) => {}
                    Err(err) => {
                        if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                            break;
                        }
                        return Err(map_windows_error(err));
                    }
                }
                to_ret.push(from_pwstr(&key_name_buff[0..key_name_capacity as usize]));
            }
            Ok(to_ret)
        }
    }

    fn key_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut max_subkey_length = 0;
            let mut subkey_count = 0;
            let _ = RegQueryInfoKeyW(
                hkey,
                PWSTR::null(),
                None,
                None,
                Some(&mut subkey_count),
                Some(&mut max_subkey_length),
                None,
                None,
                None,
                None,
                None,
                None,
            );
            if pos >= subkey_count {
                return Err(ForensicError::NoMoreData)
            }
            let mut key_name_capacity: u32 = max_subkey_length + 1;
            let mut key_name_buff = [0; 256];
            match RegEnumKeyExW(
                hkey,
                pos,
                PWSTR(key_name_buff.as_mut_ptr()),
                &mut key_name_capacity,
                None,
                PWSTR::null(),
                None,
                None,
            ) {
                Ok(_) => {}
                Err(err) => return Err(map_windows_error(err)),
            };
            Ok(from_pwstr(&key_name_buff[0..key_name_capacity as usize]))
        }
    }

    fn value_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut max_value_length = 0;
            let mut value_count = 0;
            let _ = RegQueryInfoKeyW(
                hkey,
                PWSTR::null(),
                None,
                None,
                None,
                None,
                None,
                Some(&mut value_count),
                Some(&mut max_value_length),
                None,
                None,
                None,
            );
            if pos >= value_count {
                return Err(ForensicError::NoMoreData)
            }
            let mut key_value_capacity: u32 = max_value_length;
            let mut key_value_buff = vec![0; key_value_capacity as usize];
            match RegEnumValueW(
                hkey,
                pos,
                PWSTR(key_value_buff.as_mut_ptr()),
                &mut key_value_capacity,
                None,
                None,
                None,
                None,
            ) {
                Ok(_) => {}
                Err(err) => return Err(map_windows_error(err)),
            }
            Ok(from_pwstr(&key_value_buff[0..key_value_capacity as usize]))
        }
    }

    fn from_file(
        &self,
        _file: Box<dyn forensic_rs::traits::vfs::VirtualFile>,
    ) -> ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(LiveRegistryReader {}))
    }

    fn from_fs(
        &self,
        _fs: Box<dyn forensic_rs::traits::vfs::VirtualFileSystem>,
    ) -> ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(LiveRegistryReader {}))
    }
    fn close_key(&self, key : RegHiveKey) {
        match key {
            RegHiveKey::Hkey(key) => {
                match unsafe { RegCloseKey(HKEY(key)) } {
                    Ok(_) => {},
                    Err(_) => {},
                }
            },
            _ => {},
        }
    }
    fn key_info(&self, hkey: RegHiveKey) -> ForensicResult<RegistryKeyInfo> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut max_value_name_length = 0;
            let mut values = 0;
            let mut max_value_length = 0;
            let mut subkeys = 0;
            let mut max_subkey_name_length = 0;
            let mut last_write_time = windows::Win32::Foundation::FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let _ = RegQueryInfoKeyW(
                hkey,
                PWSTR::null(),
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
            Ok(RegistryKeyInfo {
                last_write_time : Filetime::new(((last_write_time.dwHighDateTime as u64) << 32) + last_write_time.dwLowDateTime as u64),
                max_subkey_name_length,
                max_value_length,
                max_value_name_length,
                subkeys,
                values
            })
        }
    }
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
fn to_hkey(hkey: RegHiveKey) -> HKEY {
    match hkey {
        RegHiveKey::HkeyClassesRoot => HKEY_CLASSES_ROOT,
        RegHiveKey::HkeyCurrentConfig => HKEY_CURRENT_CONFIG,
        RegHiveKey::HkeyCurrentUser => HKEY_CURRENT_USER,
        RegHiveKey::HkeyDynData => HKEY_DYN_DATA,
        RegHiveKey::HkeyLocalMachine => HKEY_LOCAL_MACHINE,
        RegHiveKey::KkeyPerformanceData => HKEY_PERFORMANCE_DATA,
        RegHiveKey::HkeyPerformanceNlstext => HKEY_PERFORMANCE_NLSTEXT,
        RegHiveKey::HkeyPerformanceText => HKEY_PERFORMANCE_TEXT,
        RegHiveKey::HkeyUsers => HKEY_USERS,
        RegHiveKey::Hkey(v) => HKEY(v),
    }
}

fn from_hkey(hkey: HKEY) -> RegHiveKey {
    match hkey {
        HKEY_CLASSES_ROOT => RegHiveKey::HkeyClassesRoot,
        HKEY_CURRENT_CONFIG => RegHiveKey::HkeyCurrentConfig,
        HKEY_CURRENT_USER => RegHiveKey::HkeyCurrentUser,
        HKEY_DYN_DATA => RegHiveKey::HkeyDynData,
        HKEY_LOCAL_MACHINE => RegHiveKey::HkeyLocalMachine,
        HKEY_PERFORMANCE_DATA => RegHiveKey::KkeyPerformanceData,
        HKEY_PERFORMANCE_NLSTEXT => RegHiveKey::HkeyPerformanceNlstext,
        HKEY_PERFORMANCE_TEXT => RegHiveKey::HkeyPerformanceText,
        HKEY_USERS => RegHiveKey::HkeyUsers,
        HKEY(v) => RegHiveKey::Hkey(v),
    }
}

fn map_windows_error(err: windows::core::Error) -> ForensicError {
    let code = err.code().0 as u32;
    match code {
        2 => ForensicError::missing_str("File not found"),
        5 => ForensicError::PermissionError,
        6 => ForensicError::bad_format_str("The key handle is invalid"),
        13 => ForensicError::bad_format_str("The supplied data is invalid"),
        18 => ForensicError::NoMoreData,
        259 => ForensicError::NoMoreData,
        234 => ForensicError::Other("More data is available".into()),
        _ => ForensicError::Other(format!("Unknown Win32 Error: {}", code)),
    }
}

#[cfg(test)]
mod test_live_registry {
    use crate::LiveRegistryReader;
    use forensic_rs::prelude::{RegHiveKey::*, RegistryReader};

    #[test]
    fn should_list_keys() {
        let registry = LiveRegistryReader::new();
        let mut registry: Box<dyn RegistryReader> = Box::new(registry);

        fn test_reg(reg: &mut Box<dyn RegistryReader>) {
            let keys = reg.enumerate_keys(HkeyCurrentUser).unwrap();
            println!("{:?}", keys);
            assert!(keys.contains(&format!("Software")));
            assert!(keys.contains(&format!("Environment")));
            let _info = reg.key_info(HkeyCurrentUser).unwrap();
        }
        test_reg(&mut registry);
    }

    #[test]
    fn should_read_volatile_environment() {
        let registry = LiveRegistryReader::new();
        let key = registry.open_key(HkeyCurrentUser, "Volatile Environment").unwrap();
        let value : String = registry.read_value(key, "USERNAME").unwrap().try_into().unwrap();
        assert!(value.len() > 1);
        let values : Vec<String> = registry.enumerate_values(key).unwrap();
        assert!(values.len() > 2);
        let value_name  = registry.value_at(key, 2).unwrap();
        assert!(value_name.len() > 2);
        let key_name = registry.key_at(HkeyCurrentUser, 1).unwrap();
        assert!(key_name.len() > 2);
    }
}