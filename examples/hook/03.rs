// 03 - finding function using patterns and hooking them

use std::ffi::*;

use memors::hook::*;
use memors::pattern::*;

unsafe extern "system" fn detour(this: *mut c_void, message: *const c_char) {
    println!("hooked!");
}

fn main() -> Option<()> {
    unsafe {
        let module = Module::new("tier0.dll")?;
        let sig = ida("FF ?? 0A ?? CC CC CC 0A");

        let mut hook = Hook::new(sig, "Msg", detour as _);
        // it doesn't enable hook automatically after installing it
        hook.install(module)?;
        // so you will need to call "hook.enable()" atleast once
        hook.enable()?;
        // vice-versa you can disable hook whenever you want
        // hook.disable()?;

        Some(())
    }
}