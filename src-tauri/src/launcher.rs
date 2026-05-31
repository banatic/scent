//! Target launcher: create the root process suspended so the ETW session can be
//! attached *before* the target runs a single instruction, then resume it.
//!
//! The root is created before the ETW session exists, so its own ProcessStart
//! event is never captured. We therefore record the root's create-time here
//! (via `GetProcessTimes`) and seed the tree node from launcher-known data.

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, GetProcessTimes, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
    STARTUPINFOW,
};

/// A raw Windows HANDLE that we promise to use single-threaded-safely across
/// thread boundaries (only the wait thread touches the process handle).
#[derive(Clone, Copy)]
pub struct SendHandle(pub HANDLE);
unsafe impl Send for SendHandle {}

pub struct LaunchResult {
    pub pid: u32,
    /// Process creation time as a FILETIME packed into u64 (reuse-proof stamp).
    pub create_time: u64,
    pub process: SendHandle,
    pub thread: SendHandle,
    pub image: String,
    pub cmdline: String,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Build a Windows command line: quoted exe path followed by quoted-as-needed args.
fn build_command_line(path: &str, args: &[String]) -> String {
    let mut out = String::new();
    out.push('"');
    out.push_str(path);
    out.push('"');
    for a in args {
        out.push(' ');
        if a.is_empty() || a.contains([' ', '\t']) {
            out.push('"');
            out.push_str(a);
            out.push('"');
        } else {
            out.push_str(a);
        }
    }
    out
}

/// Launch the target in a suspended state. Returns handles + identity; the caller
/// must `resume` it once ETW is live, and eventually `close` the handles.
pub fn create_suspended(path: &str, args: &[String]) -> Result<LaunchResult, String> {
    let app_w = wide(path);
    let cmdline = build_command_line(path, args);
    let mut cmd_w = wide(&cmdline);

    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            PCWSTR(app_w.as_ptr()),
            Some(PWSTR(cmd_w.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            None,
            PCWSTR::null(),
            &startup,
            &mut pi,
        )
        .map_err(|e| format!("CreateProcessW failed for '{path}': {e}"))?;
    }

    // Capture the root's create-time; ETW won't give us its ProcessStart.
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let create_time = unsafe {
        match GetProcessTimes(
            pi.hProcess,
            &mut create,
            &mut exit,
            &mut kernel,
            &mut user,
        ) {
            Ok(()) => filetime_to_u64(create),
            Err(_) => 0,
        }
    };

    Ok(LaunchResult {
        pid: pi.dwProcessId,
        create_time,
        process: SendHandle(pi.hProcess),
        thread: SendHandle(pi.hThread),
        image: path.to_string(),
        cmdline,
    })
}

/// Resume the suspended main thread, starting the target running.
pub fn resume(thread: SendHandle) -> Result<(), String> {
    let prev = unsafe { ResumeThread(thread.0) };
    if prev == u32::MAX {
        Err("ResumeThread failed".to_string())
    } else {
        Ok(())
    }
}

/// Block until the given process exits and return its exit code.
pub fn wait_exit(process: SendHandle) -> Option<i64> {
    unsafe {
        // INFINITE = 0xFFFFFFFF
        WaitForSingleObject(process.0, 0xFFFF_FFFF);
        let mut code: u32 = 0;
        match GetExitCodeProcess(process.0, &mut code) {
            Ok(()) => Some(code as i64),
            Err(_) => None,
        }
    }
}

/// Map of NT device paths (`\Device\HarddiskVolumeN`) to DOS drive letters
/// (`C:`), for normalizing the NT paths ETW reports into readable form.
pub fn dos_device_map() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut buf = vec![0u16; 1024];
    for c in b'A'..=b'Z' {
        let drive = format!("{}:", c as char);
        let name = wide(&drive);
        let len = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(buf.as_mut_slice())) };
        if len == 0 {
            continue;
        }
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        if let Some(target) = s.split('\0').find(|t| t.starts_with("\\Device")) {
            out.push((target.to_string(), drive));
        }
    }
    out
}

/// Forcibly terminate the target (used to clean up a suspended process when
/// capture setup fails before resume).
pub fn terminate(process: SendHandle) {
    unsafe {
        let _ = TerminateProcess(process.0, 1);
    }
}

/// Close a process/thread handle.
pub fn close(handle: SendHandle) {
    unsafe {
        let _ = CloseHandle(handle.0);
    }
}
