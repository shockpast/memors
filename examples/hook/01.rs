// 01 - loading module, and displaying some basic information about it

use memors::hook::*;

fn main() -> Option<()> {
    unsafe {
        // tries to load a module, returns Result<Module>
        let module = Module::new("tier0.dll")?;

        println!("module loaded: base={:p}, size=0x{:X}", module.base, module.size);

        Some(())
    }
}