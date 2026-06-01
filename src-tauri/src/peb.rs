//! Best-effort command-line recovery for a child process by reading its PEB.
//!
//! ETW's Kernel-Process ProcessStart carries only `ImageName`, not the command
//! line. We recover it the way a debugger would: open the process, ask
//! `NtQueryInformationProcess` for the PEB base, then walk
//! `PEB -> ProcessParameters -> CommandLine` (a `UNICODE_STRING`) with
//! `ReadProcessMemory`.
//!
//! This is heavy (OpenProcess + cross-process reads), so the **single ingest
//! thread** calls it *outside* the store write lock; the ETW callbacks never do
//! (the capture invariant). Exited processes can't be opened, so they best-effort
//! to `None`.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

// NtQueryInformationProcess isn't surfaced by windows-rs; declare it. We only use
// ProcessBasicInformation (class 0) to obtain the PEB base address.
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        info_class: i32,
        info: *mut core::ffi::c_void,
        info_len: u32,
        ret_len: *mut u32,
    ) -> i32;
}
const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;

/// Subset of `PROCESS_BASIC_INFORMATION` we need (`repr(C)` matches the OS layout,
/// padding included). Only `peb_base_address` is read.
#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: *mut core::ffi::c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

// x64 PEB / RTL_USER_PROCESS_PARAMETERS offsets (stable across Win10/11 x64).
// The 64-bit PEB is also valid for WOW64 children read from a 64-bit reader.
const PEB_OFF_PROCESS_PARAMETERS: u64 = 0x20;
const RTL_OFF_COMMAND_LINE: u64 = 0x70;
// UNICODE_STRING { u16 Length; u16 MaximumLength; /*4 pad*/ u16* Buffer; }
const UNICODE_STRING_BUFFER_OFF: u64 = 8;

const MAX_CMDLINE_BYTES: usize = 64 * 1024;

/// Read a `Copy` value of `T`'s size from another process at `addr`. Returns
/// `None` on a partial or failed read.
unsafe fn read_pod<T: Copy>(h: HANDLE, addr: u64) -> Option<T> {
    let mut val: T = std::mem::zeroed();
    let mut got = 0usize;
    ReadProcessMemory(
        h,
        addr as *const core::ffi::c_void,
        &mut val as *mut T as *mut core::ffi::c_void,
        std::mem::size_of::<T>(),
        Some(&mut got),
    )
    .ok()?;
    (got == std::mem::size_of::<T>()).then_some(val)
}

/// Best-effort recovery of `pid`'s command line via its PEB. `None` if the
/// process is gone or its memory is unreadable.
pub fn read_command_line(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .ok()?;
        // Inner closure so we always CloseHandle on the way out.
        let result = (|| {
            let mut pbi: ProcessBasicInformation = std::mem::zeroed();
            let mut ret = 0u32;
            let status = NtQueryInformationProcess(
                handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                &mut pbi as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret,
            );
            if status != 0 {
                return None;
            }
            let peb = pbi.peb_base_address as u64;
            if peb == 0 {
                return None;
            }
            let params: u64 = read_pod(handle, peb + PEB_OFF_PROCESS_PARAMETERS)?;
            if params == 0 {
                return None;
            }
            let length: u16 = read_pod(handle, params + RTL_OFF_COMMAND_LINE)?;
            let buffer: u64 =
                read_pod(handle, params + RTL_OFF_COMMAND_LINE + UNICODE_STRING_BUFFER_OFF)?;
            if length == 0 || buffer == 0 {
                return None;
            }
            let len = (length as usize).min(MAX_CMDLINE_BYTES);
            let mut bytes = vec![0u8; len];
            let mut got = 0usize;
            ReadProcessMemory(
                handle,
                buffer as *const core::ffi::c_void,
                bytes.as_mut_ptr() as *mut core::ffi::c_void,
                len,
                Some(&mut got),
            )
            .ok()?;
            let u16s: Vec<u16> = bytes[..got]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&u16s);
            let s = s.trim_end_matches('\0').trim().to_string();
            (!s.is_empty()).then_some(s)
        })();
        let _ = CloseHandle(handle);
        result
    }
}
