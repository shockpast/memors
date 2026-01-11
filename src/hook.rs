use std::ffi::*;

use minhook::MinHook;

use crate::{
    pattern::Signature,
    structures::module::Module
};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Default, Clone)]
pub struct Hook {
    sig: Signature,
    pub name: &'static str,
    pub detour: *mut c_void,
    pub target: Option<*mut c_void>,
    pub original: Option<*mut c_void>,
}

impl Hook {
    pub fn new(sig: Signature, name: &'static str, detour: *mut c_void) -> Self {
        Self { sig, name, detour, target: None, original: None }
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
    pub fn install(&mut self, module: Module, original: &mut *mut c_void) -> Option<bool> {
        unsafe {
            let function_ptr = module.find(&self.sig)?;
            let original_ptr = MinHook::create_hook(function_ptr, self.detour).ok()?;

            // @note: will these two values be the same?
            self.target = Some(function_ptr);
            self.original = Some(original_ptr);

            *original = original_ptr;

            Some(true)
        }
    }

    /// Enables hook.
    pub fn enable(&self) -> Option<bool> {
        unsafe {
            MinHook::enable_hook(self.target?).ok()?;

            Some(true)
        }
    }

    /// Disables hook.
    pub fn disable(&self) -> Option<bool> {
        unsafe {
            MinHook::disable_hook(self.target?).ok()?;

            Some(true)
        }
    }
}