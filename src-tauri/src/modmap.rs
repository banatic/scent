//! Per-process module map + stack→caller-DLL resolution (tier 3).
//!
//! Snapshots a live process's loaded modules (base/size/name) via PSAPI, then
//! resolves a stack's user-mode return addresses against those ranges. The first
//! frame that isn't a syscall/loader thunk (ntdll/kernelbase/kernel32/win32u) is
//! the responsible DLL — e.g. for a JS-driven file probe it resolves to node.dll.

use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_QUERY_INFORMATION,
};

use crate::model::basename;

// NtQueryInformationThread isn't surfaced by windows-rs; declare it. Used to read
// a thread's Win32 start address (ThreadQuerySetWin32StartAddress = 9).
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationThread(
        thread: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        ret_len: *mut u32,
    ) -> i32;
}
const THREAD_QUERY_SET_WIN32_START_ADDRESS: i32 = 9;

/// Where an attribution came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttrSource {
    /// Resolved from the call stack's first non-thunk user frame (tier 3).
    Stack,
    /// Fallback: the thread's Win32 start-address module (tier 2), used when the
    /// stack was dropped or unresolved.
    ThreadStart,
    None,
}

#[derive(Clone, Debug)]
pub struct Module {
    pub base: u64,
    pub end: u64,
    pub name: String,
}

/// Frames in these modules are syscall/loader thunks — skip them to find the
/// real caller above them.
const THUNKS: &[&str] = &[
    "ntdll.dll",
    "kernelbase.dll",
    "kernel32.dll",
    "win32u.dll",
    "wow64.dll",
    "wow64cpu.dll",
    "wow64win.dll",
];

/// Snapshot the loaded modules of a live process, sorted by base address.
pub fn snapshot(pid: u32) -> Vec<Module> {
    let mut out = Vec::new();
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
        else {
            return out;
        };
        let mut mods = vec![HMODULE::default(); 2048];
        let mut needed = 0u32;
        let cb = (mods.len() * std::mem::size_of::<HMODULE>()) as u32;
        if EnumProcessModulesEx(handle, mods.as_mut_ptr(), cb, &mut needed, LIST_MODULES_ALL)
            .is_ok()
        {
            let count = (needed as usize / std::mem::size_of::<HMODULE>()).min(mods.len());
            for &m in &mods[..count] {
                let mut info = MODULEINFO::default();
                if GetModuleInformation(handle, m, &mut info, std::mem::size_of::<MODULEINFO>() as u32)
                    .is_ok()
                {
                    let mut buf = [0u16; 260];
                    let n = GetModuleFileNameExW(Some(handle), Some(m), &mut buf);
                    let name = if n > 0 {
                        String::from_utf16_lossy(&buf[..n as usize])
                    } else {
                        String::new()
                    };
                    let base = info.lpBaseOfDll as u64;
                    out.push(Module {
                        base,
                        end: base + info.SizeOfImage as u64,
                        name,
                    });
                }
            }
        }
        let _ = CloseHandle(handle);
    }
    out.sort_by_key(|m| m.base);
    out
}

/// Resolve an address to the module whose range contains it.
pub fn resolve<'a>(addr: u64, mods: &'a [Module]) -> Option<&'a Module> {
    mods.iter().find(|m| addr >= m.base && addr < m.end)
}

/// One resolved stack frame, for the inspector's call-chain view.
#[derive(Clone, Serialize)]
pub struct Frame {
    pub addr: u64,
    /// Module basename (e.g. "node.dll"), or None if the address is unbacked.
    pub module: Option<String>,
    /// Offset of `addr` within the module (0 if unresolved).
    pub offset: u64,
    /// Syscall/loader thunk (ntdll/kernelbase/…) — collapsed by default in the UI.
    pub thunk: bool,
}

/// Resolve every user-mode return address to a module frame (top frame first).
pub fn resolve_frames(user_addrs: &[u64], mods: &[Module]) -> Vec<Frame> {
    user_addrs
        .iter()
        .map(|&addr| match resolve(addr, mods) {
            Some(m) => {
                let name = basename(&m.name);
                let thunk = THUNKS.contains(&name.to_lowercase().as_str());
                Frame {
                    addr,
                    offset: addr - m.base,
                    module: Some(name),
                    thunk,
                }
            }
            None => Frame {
                addr,
                module: None,
                offset: 0,
                thunk: false,
            },
        })
        .collect()
}

/// Known-benign caller DLLs → human description. Lets the tool auto-tag common
/// noise (driver/overlay app-detection) instead of re-investigating it every
/// capture. Keys are lowercased module basenames. Extend as new vendors appear.
const KNOWN_BENIGN_CALLERS: &[(&str, &str)] = &[
    ("nvwgf2umx.dll", "NVIDIA D3D driver app-detection"),
    ("nvwgf2um.dll", "NVIDIA D3D driver app-detection"),
    ("nvmemmapstoragex.dll", "NVIDIA driver app-detection"),
    ("nvspcap64.dll", "NVIDIA GeForce/ShadowPlay app-detection"),
    ("nvspcap.dll", "NVIDIA GeForce/ShadowPlay app-detection"),
    ("nvd3dumx.dll", "NVIDIA D3D driver app-detection"),
];

/// If `caller` is a known-benign source, return its description (for auto-tagging
/// probes as e.g. "[benign: NVIDIA app-detection]"). See memory
/// `nvidia-game-detection-probes`.
pub fn benign_caller(caller: &str) -> Option<&'static str> {
    let name = caller.to_lowercase();
    KNOWN_BENIGN_CALLERS
        .iter()
        .find(|(m, _)| *m == name)
        .map(|(_, desc)| *desc)
}

/// The responsible DLL for a stack: the first user frame outside the syscall/
/// loader thunks. Returns the module basename (e.g. "node.dll").
pub fn caller_dll(user_addrs: &[u64], mods: &[Module]) -> Option<String> {
    for &addr in user_addrs {
        let Some(m) = resolve(addr, mods) else {
            continue;
        };
        let base = basename(&m.name).to_lowercase();
        if THUNKS.contains(&base.as_str()) {
            continue;
        }
        return Some(basename(&m.name));
    }
    None
}

/// Tier-2 fallback: the module containing a thread's Win32 start address.
pub fn thread_start_module(tid: u32, mods: &[Module]) -> Option<String> {
    unsafe {
        let Ok(h) = OpenThread(THREAD_QUERY_INFORMATION, false, tid) else {
            return None;
        };
        let mut addr: u64 = 0;
        let status = NtQueryInformationThread(
            h,
            THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &mut addr as *mut u64 as *mut core::ffi::c_void,
            8,
            std::ptr::null_mut(),
        );
        let _ = CloseHandle(h);
        if status != 0 || addr == 0 {
            return None;
        }
        resolve(addr, mods).map(|m| basename(&m.name))
    }
}

/// Attribute a captured event to a responsible DLL: tier-3 (stack caller) first,
/// then tier-2 (thread start module) as a fallback when the stack is missing.
pub fn attribute(user_addrs: &[u64], tid: u32, mods: &[Module]) -> (Option<String>, AttrSource) {
    if let Some(c) = caller_dll(user_addrs, mods) {
        return (Some(c), AttrSource::Stack);
    }
    if let Some(c) = thread_start_module(tid, mods) {
        return (Some(c), AttrSource::ThreadStart);
    }
    (None, AttrSource::None)
}
