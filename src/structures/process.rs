use std::ffi::*;

use windows::Win32::{
    Foundation::*,
    System::{
        Diagnostics::{
            Debug::*,
            ToolHelp::*
        },
        Threading::*
    },
};

use crate::structures::module::Module;

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct Process {
    pub id: u32,
    pub handle: Option<HANDLE>
}

impl Process {
    /// Creates a handle to specified process, by default with full access to it (that might cause some unexpected issues)
    pub fn new(id: u32, access: Option<PROCESS_ACCESS_RIGHTS>) -> Self {
        let access = access.unwrap_or(PROCESS_ALL_ACCESS);

        unsafe {
            let handle = OpenProcess(access, false, id).ok();

            Self { id, handle }
        }
    }

    /// Creates a handle to process that matches name.
    pub fn find_by_name(name: &str) -> anyhow::Result<Self> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            if snapshot.is_invalid() {
                anyhow::bail!("failed to create a snapshot");
            }

            let entry = &mut PROCESSENTRY32::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            Process32First(snapshot, entry)
                .map_err(|e| {
                    let _ = CloseHandle(snapshot);
                    anyhow::anyhow!("failed to get information about process: {e:#?}")
                })?;

            while Process32Next(snapshot, entry).is_ok() {
                let process_name = CStr::from_ptr(entry.szExeFile.as_ptr()).to_str().unwrap_or_default();
                if !process_name.eq_ignore_ascii_case(name) {
                    continue;
                }

                let handle = OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID)
                    .map_err(|e| anyhow::anyhow!("failed to open process from iteration: {e:#?}"))?;

                return Ok(Self {
                    id: entry.th32ProcessID,
                    handle: Some(handle)
                })
            }
        }

        anyhow::bail!("failed to find a process that matches your name ({name})")
    }

    /// Creates a handle to process that matches id.
    pub fn find_by_pid(id: u32) -> anyhow::Result<Self> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            if snapshot.is_invalid() {
                anyhow::bail!("failed to create a snapshot");
            }

            let entry = &mut PROCESSENTRY32::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            Process32First(snapshot, entry)
                .map_err(|e| {
                    let _ = CloseHandle(snapshot);
                    anyhow::anyhow!("failed to get information about process: {e:#?}")
                })?;

            while Process32Next(snapshot, entry).is_ok() {
                if entry.th32ProcessID != id {
                    continue;
                }

                let handle = OpenProcess(PROCESS_ALL_ACCESS, false, entry.th32ProcessID)
                    .map_err(|e| anyhow::anyhow!("failed to open process from iteration: {e:#?}"))?;

                return Ok(Self {
                    id,
                    handle: Some(handle)
                })
            }
        }

        unreachable!()
    }

    /// Returns all modules loaded in the process.
    pub fn modules(&self) -> anyhow::Result<Vec<Module>> {
        let mut items = Vec::new();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.id)?;
            if snapshot.is_invalid() {
                anyhow::bail!("failed to create a snapshot");
            }

            let entry = &mut MODULEENTRY32::default();
            entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

            Module32First(snapshot, entry)
                .map_err(|e| {
                    let _ = CloseHandle(snapshot);
                    anyhow::anyhow!("failed to get information about module: {e:#?}")
                })?;

            while Module32Next(snapshot, entry).is_ok() {
                if let Some(handle) = self.handle {
                    let name = CStr::from_ptr(entry.szModule.as_ptr()).to_str().unwrap_or_default();
                    let module = Module::new_with_process(name, handle)?;

                    items.push(module);
                } else {
                    anyhow::bail!("failed to get handle to structured process");
                }
            }
        }

        Ok(items)
    }

    /// Returns specific module matched by name.
    pub fn module(&self, name: &str) -> anyhow::Result<Module> {
        let module = self.modules()?
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.clone())
            .ok_or(anyhow::anyhow!("failed to get module matching name ({name})"))?;

        Ok(module)
    }

    /// Writes arbitrary data to specific address in process memory region, there are no safe-guards in place
    /// to prevent writing in memory that doesn't allow to be written into, therefore when using this function
    /// you must triple-check every input and address that you write into.
    pub fn write(&self, addr: i64, buffer: *const c_void, size: usize) -> anyhow::Result<bool> {
        unsafe {
            if let Some(handle) = self.handle {
                WriteProcessMemory(handle, addr as _, buffer, size, None)?;
            } else {
                anyhow::bail!("failed to get handle to structured process")
            }
        }

        Ok(true)
    }

    /// Reads arbitrary data from specific address in process memory region and writes it into buffer,
    /// there are no safe-guards in place to prevent reading frm memory that doesn't allow to be readed from,
    /// therefore when using this function, you must triple-check every input and address that you read into.
    pub fn read(&self, addr: i64, buffer: *mut c_void, size: usize) -> anyhow::Result<()> {
        unsafe {
            if let Some(handle) = self.handle {
                ReadProcessMemory(handle, addr as _, buffer, size, None)?;
            } else {
                anyhow::bail!("failed to get handle to structured process")
            }

            Ok(())
        }
    }

    /// Returns whether process's handle is still open and not invalid.
    pub fn is_valid(&self) -> bool {
        if let Some(handle) = self.handle {
            return handle.is_invalid()
        } else {
            false
        }
    }
}