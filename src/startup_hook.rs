use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject,
};

use crate::logger::log_line;

const INJECT_DELAY_MS: u64 = 200;
const INJECT_WAIT_MS: u32 = 5_000;

pub fn inject_after_resume(h_process: HANDLE, game_dir: &str) -> Result<()> {
    if std::env::var_os("LOGIN38_STARTUP_HOOK")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        log_line!("[StartupHook] disabled by LOGIN38_STARTUP_HOOK");
        return Ok(());
    }

    let dll_path = match locate_startup_hook_dll(game_dir) {
        Some(path) => path,
        None => {
            log_line!("[StartupHook] L38Hook.dll not found, skip");
            return Ok(());
        }
    };

    std::thread::sleep(Duration::from_millis(INJECT_DELAY_MS));
    inject_dll(h_process, &dll_path)
        .with_context(|| format!("startup hook inject failed: {}", dll_path.display()))
}

pub fn inject_required_now(h_process: HANDLE, game_dir: &str) -> Result<()> {
    if std::env::var_os("LOGIN38_STARTUP_HOOK")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        bail!("StartupHook is required but disabled by LOGIN38_STARTUP_HOOK");
    }

    let dll_path = locate_startup_hook_dll(game_dir).ok_or_else(|| {
        anyhow!("StartupHook is required but L38Hook.dll/startup_hook.dll was not found")
    })?;

    inject_dll(h_process, &dll_path).with_context(|| {
        format!(
            "required startup hook inject failed: {}",
            dll_path.display()
        )
    })
}

fn locate_startup_hook_dll(game_dir: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("L38Hook.dll"));
            candidates.push(dir.join("startup_hook_probe.dll"));
            candidates.push(dir.join("startup_hook.dll"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("L38Hook.dll"));
        candidates.push(cwd.join("startup_hook_probe.dll"));
        candidates.push(cwd.join("startup_hook.dll"));
    }
    candidates.push(PathBuf::from(game_dir).join("L38Hook.dll"));
    candidates.push(PathBuf::from(game_dir).join("startup_hook_probe.dll"));
    candidates.push(PathBuf::from(game_dir).join("startup_hook.dll"));

    candidates.into_iter().find(|p| p.exists())
}

fn inject_dll(h_process: HANDLE, dll_path: &Path) -> Result<()> {
    let start = Instant::now();
    let load_lib = load_library_w_addr()?;
    let path_w: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let path_bytes = path_w.len() * 2;

    let remote = unsafe {
        VirtualAllocEx(
            h_process,
            None,
            path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        bail!("VirtualAllocEx({path_bytes}) failed");
    }

    let result = (|| -> Result<()> {
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                h_process,
                remote,
                path_w.as_ptr().cast(),
                path_bytes,
                Some(&mut written),
            )?;
        }
        if written != path_bytes {
            bail!("WriteProcessMemory wrote {written}/{path_bytes}");
        }

        let mut tid = 0u32;
        let thread = unsafe {
            CreateRemoteThread(
                h_process,
                None,
                0,
                Some(std::mem::transmute(load_lib)),
                Some(remote),
                0,
                Some(&mut tid),
            )
        }?;

        let wait = unsafe { WaitForSingleObject(thread, INJECT_WAIT_MS) };
        let mut hmod = 0u32;
        let _ = unsafe { GetExitCodeThread(thread, &mut hmod) };
        unsafe {
            let _ = CloseHandle(thread);
        }

        if wait == WAIT_TIMEOUT {
            bail!("LoadLibraryW timeout {INJECT_WAIT_MS}ms tid={tid}");
        }
        if wait != WAIT_OBJECT_0 {
            bail!("LoadLibraryW wait failed: {wait:?} tid={tid}");
        }
        if hmod == 0 {
            bail!("LoadLibraryW returned NULL tid={tid}");
        }

        log_line!(
            "[StartupHook] injected {} tid={} hmod=0x{:08X} after {:.3}s",
            dll_path.display(),
            tid,
            hmod,
            start.elapsed().as_secs_f64()
        );
        Ok(())
    })();

    unsafe {
        let _ = VirtualFreeEx(h_process, remote, 0, MEM_RELEASE);
    }
    result
}

fn load_library_w_addr() -> Result<usize> {
    let kernel32 = wide_null("kernel32.dll");
    unsafe {
        let module = GetModuleHandleW(PCWSTR(kernel32.as_ptr()))
            .context("GetModuleHandleW(kernel32.dll)")?;
        let proc = GetProcAddress(module, PCSTR(b"LoadLibraryW\0".as_ptr()))
            .ok_or_else(|| anyhow!("GetProcAddress(LoadLibraryW) returned NULL"))?;
        Ok(proc as usize)
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
