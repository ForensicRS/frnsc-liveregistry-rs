extern crate windows;
extern crate forensic_rs;

use forensic_rs::prelude::{RegHiveKey, ForensicResult, ForensicError, RegValue, RegistryReader};
use std::convert::TryInto;

use windows::{Win32::{
    System::Registry::{HKEY, REG_DWORD, REG_VALUE_TYPE, RegQueryValueExW, REG_SZ, RegEnumKeyExW, HKEY_USERS, REG_MULTI_SZ, REG_QWORD, REG_BINARY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_DYN_DATA, HKEY_LOCAL_MACHINE, HKEY_PERFORMANCE_DATA, HKEY_PERFORMANCE_NLSTEXT, HKEY_PERFORMANCE_TEXT, REG_EXPAND_SZ, RegOpenKeyW, RegEnumValueW}, Foundation::{FILETIME, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS},
}, core::{PCWSTR, PWSTR}};

#[derive(Clone, Default)]
pub struct LiveRegistryReader{

}

impl LiveRegistryReader {
    pub fn new() -> Self {
        Self {  }
    }
}

impl RegistryReader for LiveRegistryReader {
    fn open_key(&self, hkey : RegHiveKey, name : &str) -> ForensicResult<RegHiveKey> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut new_key = HKEY(0);
            let new_key_str = to_pwstr(name);
            let opened = RegOpenKeyW(hkey, PCWSTR(new_key_str.as_ptr()), &mut new_key);
            if opened.is_err() {
                return Err(ForensicError::BadFormat);
            }
            Ok(from_hkey(new_key))
        }
    }

    fn read_value(&self, hkey : RegHiveKey, name : &str) -> ForensicResult<RegValue> {
        let hkey = to_hkey(hkey);
        unsafe {
            let value_name = to_pwstr(name);
            let mut capacity : u32 = 10_000;
            loop {
                let mut readed_data = vec_with_capacity(capacity as usize);
                let mut data_type : REG_VALUE_TYPE = REG_VALUE_TYPE::default();
                match RegQueryValueExW(hkey, PCWSTR(value_name.as_ptr()),None, Some(&mut data_type),Some(readed_data.as_mut_ptr()), Some(&mut capacity)) {
                    Ok(_) => {},
                    Err(err) => {
                        if err.code() == ERROR_MORE_DATA.to_hresult() {
                            continue;
                        }
                        return Err(ForensicError::Other(format!("read_value({}) Win32 error: {}",name, err.code().0)));
                    }
                };
                readed_data.resize(capacity as usize, 0);
                return Ok(match data_type {
                    //https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
                    REG_DWORD => {
                        if capacity != 4 {
                            return Err(ForensicError::BadFormat);
                        }
                        let data : [u8; 4] = match readed_data[0..4].try_into() {
                            Ok(v) => v,
                            Err(_) => return Err(ForensicError::BadFormat)
                        };
                        RegValue::DWord(u32::from_ne_bytes(data))
                    },
                    REG_QWORD => {
                        if capacity != 8 {
                            return Err(ForensicError::BadFormat);
                        }
                        let data : [u8; 8] = match readed_data[0..8].try_into() {
                            Ok(v) => v,
                            Err(_) => return Err(ForensicError::BadFormat)
                        };
                        RegValue::QWord(u64::from_ne_bytes(data))
                    },
                    REG_SZ => {
                        let mut u16_vec : Vec<u16> = readed_data[0..capacity as usize].chunks(2).map(|v| (v[1] as u16) << 8 | v[0] as u16).collect();
                        let _ = u16_vec.pop();//Ends with 00
                        RegValue::SZ(String::from_utf16_lossy(&u16_vec))
                    },
                    REG_MULTI_SZ => {
                        let mut returned_strs = Vec::with_capacity(16);
                        let mut txt = Vec::with_capacity(capacity as usize);
                        let mut txt_lngt = 0;
                        for chr in readed_data[0..capacity as usize].chunks(2).map(|v| (v[1] as u16) << 8 | v[0] as u16) {
                            if chr == 0 {
                                if txt_lngt > 0 {
                                    returned_strs.push(String::from_utf16_lossy(&txt[0..txt_lngt]));
                                }else{
                                    returned_strs.push(String::new());
                                }
                                txt_lngt = 0;
                            }else{
                                txt[txt_lngt] = chr;
                                txt_lngt += 1;
                            }
                        }
                        RegValue::MultiSZ(returned_strs)
                    },
                    REG_BINARY => {
                        RegValue::Binary(readed_data)
                    },
                    REG_EXPAND_SZ => {
                        let mut u16_vec : Vec<u16> = readed_data[0..capacity as usize].chunks(2).map(|v| (v[1] as u16) << 8 | v[0] as u16).collect();
                        let _ = u16_vec.pop();//Ends with 00
                        RegValue::ExpandSZ(String::from_utf16_lossy(&u16_vec))
                    },
                    _ => return Err(ForensicError::BadFormat)
                });
            }
        }
    }

    fn enumerate_values(&self, hkey : RegHiveKey) -> ForensicResult<Vec<String>> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut to_ret = Vec::with_capacity(512);
            let mut count = 0;
            loop {
                let mut key_name_capacity : u32 = 1024;
                let mut key_name_buff = [0; 1024];
            
                let mut value_type : u32 = 0;
                match RegEnumValueW(hkey, count, PWSTR(key_name_buff.as_mut_ptr()),&mut key_name_capacity, None, Some(&mut value_type) ,None, None){
                    Ok(_) => {},
                    Err(err) => {
                        if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                            break;
                        }
                        return Err(ForensicError::Other(format!("enumerate_values() Win32 error: {}", err.code().0)));
                    }
                };
                to_ret.push(from_pwstr(&key_name_buff[0..key_name_capacity as usize]));
                count += 1;
            }
            Ok(to_ret)
        }
    }

    fn enumerate_keys(&self, hkey : RegHiveKey) -> ForensicResult<Vec<String>> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut count = 0;
            let mut to_ret = Vec::with_capacity(128);
            loop {
                let mut key_name_capacity : u32 = 1024;
                let mut key_name_buff = [0; 1024];
            
                let mut key_class_capacity : u32 = 1024;
                let mut key_class_buff = [0; 1024];
            
                let mut last_written : FILETIME = FILETIME::default();
            
                match RegEnumKeyExW(hkey, count, PWSTR(key_name_buff.as_mut_ptr()),&mut key_name_capacity, None, PWSTR(key_class_buff.as_mut_ptr()),Some(&mut key_class_capacity), Some(&mut last_written)) {
                    Ok(_) => {},
                    Err(err) => {
                        if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                            break;
                        }
                        return Err(ForensicError::Other(format!("enumerate_keys() Win32 error: {}",err.code().0)));
                    }
                 }
                to_ret.push(from_pwstr(&key_name_buff[0..key_name_capacity as usize]));
                count += 1;
            }
            Ok(to_ret)
        }
    }

    fn key_at(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<String> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut key_name_capacity : u32 = 1024;
            let mut key_name_buff = [0; 1024];
        
            let mut key_class_capacity : u32 = 1024;
            let mut key_class_buff = [0; 1024];
        
            let mut last_written : FILETIME = FILETIME::default();
        
            match RegEnumKeyExW(hkey, pos, PWSTR(key_name_buff.as_mut_ptr()),&mut key_name_capacity, None, PWSTR(key_class_buff.as_mut_ptr()),Some(&mut key_class_capacity), Some(&mut last_written)) {
                Ok(_) => {},
                Err(err) => {
                    if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                        return Err(ForensicError::NoMoreData);
                    }
                    return Err(ForensicError::Other(format!("enumerate_keys() Win32 error: {}",err.code().0)));
                }
            };
            Ok(from_pwstr(&key_name_buff[0..key_name_capacity as usize]))
        }
    }

    fn value_at(&self, hkey : RegHiveKey, pos : u32) -> ForensicResult<String> {
        let hkey = to_hkey(hkey);
        unsafe {
            let mut key_name_capacity : u32 = 1024;
            let mut key_name_buff = [0; 1024];
        
            let mut value_type : u32 = 0;
            match RegEnumValueW(hkey, pos, PWSTR(key_name_buff.as_mut_ptr()),&mut key_name_capacity, None, Some(&mut value_type), None, None) {
                Ok(_) => {},
                Err(err) => {
                    if err.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                        return Err(ForensicError::NoMoreData);
                    }
                    return Err(ForensicError::Other(format!("enumerate_keys() Win32 error: {}",err.code().0)));
                }
            }
            Ok(from_pwstr(&key_name_buff[0..key_name_capacity as usize]))
        }
    }

    fn from_file(&self, _file : Box<dyn forensic_rs::traits::vfs::VirtualFile>) -> ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(LiveRegistryReader {  }))
    }

    fn from_fs(&self, _fs : Box<dyn forensic_rs::traits::vfs::VirtualFileSystem>) -> ForensicResult<Box<dyn RegistryReader>> {
        Ok(Box::new(LiveRegistryReader {  }))
    }
}

pub fn vec_with_capacity(capacity : usize) -> Vec<u8> {
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
fn to_hkey(hkey : RegHiveKey) -> HKEY {
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

fn from_hkey(hkey : HKEY) -> RegHiveKey {
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


#[cfg(test)]
mod test_live_registry {
    use forensic_rs::prelude::{RegistryReader, RegHiveKey::*};
    use crate::LiveRegistryReader;

    #[test]
    fn should_list_keys() {
        let registry = LiveRegistryReader::new();
        let mut registry : Box<dyn RegistryReader> = Box::new(registry);

        fn test_reg(reg : &mut Box<dyn RegistryReader>) {
            let keys = reg.enumerate_keys(HkeyCurrentUser).unwrap();
            println!("{:?}", keys);
            assert!(keys.contains(&format!("Software")));
            assert!(keys.contains(&format!("Environment")));
        }
        test_reg(&mut registry);
    }
}