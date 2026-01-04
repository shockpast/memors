use std::ffi::*;

use minhook::MinHook;
use windows::{
    Win32::{
        Foundation::*,
        System::{
            LibraryLoader::*,
            ProcessStatus::*,
            Threading::*
        }
    },
    core::*
};

use crate::pattern::*;

#[derive(Debug)]
pub struct Module {
    name: &'static str,
    handle: HMODULE,
    pub size: usize,
    pub base: *const u8
}

impl Module {
    unsafe fn new(name: &'static str) -> Result<Module> {
        unsafe {
            let mut info = MODULEINFO::default();

            let process = GetCurrentProcess();
            let module = GetModuleHandleA(PCSTR(format!("{name}\0").as_ptr()))?;

            GetModuleInformation(process, module, &mut info, std::mem::size_of::<MODULEINFO>() as u32)?;

            Ok(Module {
                name,
                handle: module,
                size: info.SizeOfImage as usize,
                base: info.lpBaseOfDll as *const u8
            })
        }
    }

    /// GetProcAddress binding that searches a function (or variable) inside a module
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
    unsafe fn get(&self, name: &str) -> Option<*mut c_void> {
        unsafe {
            let func = GetProcAddress(self.handle, PCSTR(format!("{}\0", name).as_ptr()))?;
            Some(func as *mut c_void)
        }
    }

    /// Same as `#get` function, but allows to specify function type beforehand
    unsafe fn get_typed<T>(&self, name: &str) -> Option<T>
    where
        T: Copy,
    {
        unsafe {
            let func = GetProcAddress(self.handle, PCSTR(format!("{}\0", name).as_ptr()))?;
            Some(std::mem::transmute_copy(&func))
        }
    }

    /// Searches `Signature` inside a module and returns address to it
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
    unsafe fn find(&self, sig: &Signature) -> Option<*mut c_void> {
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

#[derive(Debug)]
pub struct Hook {
    sig: Signature,
    name: &'static str,
    detour: *mut c_void,
    target: Option<*mut c_void>,
    original: Option<*mut c_void>,
}

impl Hook {
    fn new(sig: Signature, name: &'static str, detour: *mut c_void) -> Self {
        Self { sig, name, detour, target: None, original: None }
    }

    fn detour(&self) -> *mut c_void {
        self.detour
    }
    fn target(&self) -> Option<*mut c_void> {
        self.target
    }
    fn original(&self) -> Option<*mut c_void> {
        self.original
    }

    /// Installs a hook for specified function (that will be found by signature)
    /// but doesn't automatically enable it.
    ///
    /// ---
    /// ## Example
    /// ```rs
    /// let module = Module::new("tier0.dll")?;
    /// let sig = ida("FF ?? 0A ?? CC CC CC 0A");
    ///
    /// unsafe extern "system" fn detour(this: *mut c_void, msg: *const c_char) {
    ///     println!("hooked!");
    /// }
    ///
    /// let mut hook = Hook::new(sig, "Msg", detour as _);
    ///
    /// unsafe {
    ///     hook.install(&module);
    ///     hook.enable();
    /// }
    /// ```
    unsafe fn install(&mut self, module: Module) -> Option<bool> {
        unsafe {
            let address = module.find(&self.sig)?;
            let original = MinHook::create_hook(address, self.detour).ok()?;

            // @note: will these two values be the same?
            self.target = Some(address);
            self.original = Some(original);

            Some(true)
        }
    }

    unsafe fn enable(&self) -> Option<bool> {
        unsafe {
            MinHook::enable_hook(self.target?).ok()?;

            Some(true)
        }
    }

    unsafe fn disable(&self) -> Option<bool> {
        unsafe {
            MinHook::disable_hook(self.target?).ok()?;

            Some(true)
        }
    }
}