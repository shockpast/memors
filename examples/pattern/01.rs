// 01 - using different variations of patterns to find addresses of functions/variables inside module

use memors::pattern::*;
use memors::hook::*;

fn find_ida() -> Option<()> {
    unsafe {
        let module = Module::new("tier0.dll");
        let sig = ida("FF ?? 0A ?? CC CC 0A");

        let address = module.find(&sig)?;

        println!("signature found at {:p}", address);

        Some(())
    }
}

fn find_code() -> Option<()> {
    unsafe {
        let module = Module::new("tier0.dll");
        let sig = code(r"\xFF\x00\x0A\x00\xCC\xCC\x0A");

        let address = module.find(&sig)?;

        println!("signature found at {:p}", address);

        Some(())
    }
}