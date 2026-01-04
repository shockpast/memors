// 02 - resolving exported functions from dll, and calling them

use std::ffi::{c_void, c_char};

use memors::hook::*;

type MsgFn = unsafe extern "system" fn(*mut c_void, *const c_char) -> bool;

// using default #get function that doesn't resolve to a specific type beforehand
// and must be manually converted to your own type, if you want to call it
fn untyped() -> Option<()> {
    unsafe {
        let module = Module::new("tier0.dll")?;

        let raw = module.get("Msg")
            .expect("symbol not found");

        let msg: MsgFn = std::mem::transmute(raw);

        msg(std::ptr::null_mut(), b"Hello, world!\0".as_ptr() as _);

        Some(())
    }
}

// automatically converts resolved export function to a type specified by user
// allowing to instantly call it
fn typed() -> Option<()> {
    unsafe {
        let module = Module::new("tier0.dll")?;

        let msg: MsgFn = module
            .get_typed("Msg")
            .expect("symbol not found");

        msg(std::ptr::null_mut(), b"Hello from get_typed!\0".as_ptr() as _);

        Some(())
    }
}