use std::ffi::*;

use windows::Win32::{
    Foundation::*,
    System::{
        LibraryLoader::*,
        ProcessStatus::*,
        Threading::*
    }
};

use crate::{pattern::Signature, pcstr};

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Module {
    pub name: &'static str,
    handle: HMODULE,
    pub size: usize,
    pub base: *const u8
}

impl Module {
    /// Creates a module, fetching information from current process, to read other's applications modules and their information,
    /// you should use `Module::new_with_process` or any of `Process::find_by_name()`, `Process::find_by_pid()`
    pub fn new(name: &'static str) -> anyhow::Result<Module> {
        unsafe {
            let mut info = MODULEINFO::default();

            let process = GetCurrentProcess();
            let handle = GetModuleHandleA(pcstr!(name))?;

            GetModuleInformation(process, handle, &mut info, std::mem::size_of::<MODULEINFO>() as u32)?;

            Ok(Module {
                name,
                handle,
                size: info.SizeOfImage as usize,
                base: info.lpBaseOfDll as *const u8
            })
        }
    }

    /// Same as `Module::new` but uses custom process to get module from.
    pub fn new_with_process(name: &'static str, process: HANDLE) -> anyhow::Result<Module> {
        unsafe {
            let mut info = MODULEINFO::default();

            let handle = GetModuleHandleA(pcstr!(name))?;
            GetModuleInformation(process, handle, &mut info, std::mem::size_of::<MODULEINFO>() as u32)?;

            Ok(Module {
                name,
                handle,
                size: info.SizeOfImage as usize,
                base: info.lpBaseOfDll as *const u8
            })
        }
    }

    /// GetProcAddress binding that searches a function (or symbol) inside a module.
    ///
    /// ---
    /// ## Example
    /// ```rs
    /// type Fn = unsafe extern "system" fn(this: *mut c_void, message: *const c_char) -> bool;
    ///
    /// let module = Module::new("tier0.dll")?;
    ///
    /// let untyped_fn = module.get("Msg")?;
    /// let typed_fn: Fn = std::mem::transmute(untyped_fn);
    ///
    /// typed_fn("Hello, World\0".as_ptr() as _);
    /// ```
    pub fn get(&self, name: &str) -> Option<*mut c_void> {
        unsafe {
            let func = GetProcAddress(self.handle, pcstr!(name))?;
            Some(func as *mut c_void)
        }
    }

    /// Same as `Module::get` function, but allows to specify function type beforehand.
    pub fn get_typed<T>(&self, name: &str) -> Option<T>
    where
        T: Copy,
    {
        unsafe {
            let func = GetProcAddress(self.handle, pcstr!(name))?;
            Some(std::mem::transmute_copy(&func))
        }
    }

    /// Searches `Signature` inside a module and returns address to it.
    ///
    /// ---
    /// ## Example
    /// ```rs
    /// let module = Module::new("tier0.dll")?;
    ///
    /// let signature = ida("FF ?? 0A ?? CC CC CC 0A");
    /// let address = module.find(signature)?;
    ///
    /// println!("Address: {address:X}, Signature: {signature:#?}");
    /// ```
    pub fn find(&self, sig: &Signature) -> Option<*mut c_void> {
        unsafe {
            let data = std::slice::from_raw_parts(self.base, self.size);
            let sig_len = sig.bytes.len();

            if sig_len == 0 || sig_len > data.len() {
                return None;
            }

            'outer: for i in 0..=(data.len() - sig_len) {
                for j in 0..sig_len {
                    if sig.mask[j] && data[i + j] != sig.bytes[j] {
                        continue 'outer;
                    }
                }

                return Some(self.base.add(i) as *mut c_void);
            }

            None
        }
    }
}