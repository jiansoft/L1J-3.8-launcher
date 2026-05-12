//! 進程管理模組 — CreateProcess + 模組列舉 + PE export 解析 + 執行緒暫停/恢復 — v1.0.0 第一版

use crate::memory;
use anyhow::{bail, Result};
use std::mem;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, Thread32First, Thread32Next,
    MODULEENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, OpenThread, ResumeThread, SuspendThread, CREATE_SUSPENDED,
    PROCESS_ALL_ACCESS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    THREAD_SUSPEND_RESUME,
};

fn to_wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 啟動遊戲進程，回傳 (hProcess, hThread, pid)
///
/// suspended=true: CREATE_SUSPENDED（安裝 hook 用，呼叫方需自行 ResumeThread）
/// suspended=false: 正常啟動
pub fn create_game(
    exe_path: &str,
    work_dir: &str,
    suspended: bool,
) -> Result<(HANDLE, HANDLE, u32)> {
    create_game_with_args(exe_path, work_dir, suspended, None)
}

pub fn create_game_with_args(
    exe_path: &str,
    work_dir: &str,
    suspended: bool,
    extra_args: Option<&str>,
) -> Result<(HANDLE, HANDLE, u32)> {
    let cmdline = match extra_args {
        Some(args) if !args.trim().is_empty() => format!("\"{exe_path}\" {args}"),
        _ => exe_path.to_string(),
    };
    let mut cmd = to_wide_null(&cmdline);
    let dir = to_wide_null(work_dir);

    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let flags = if suspended {
        CREATE_SUSPENDED
    } else {
        PROCESS_CREATION_FLAGS(0)
    };

    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            None,
            PCWSTR(dir.as_ptr()),
            &si,
            &mut pi,
        )?;
    }

    Ok((pi.hProcess, pi.hThread, pi.dwProcessId))
}

pub fn open_game_process(pid: u32) -> Result<HANDLE> {
    let h = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
    Ok(h)
}

/// 恢復主執行緒（CREATE_SUSPENDED 後呼叫）
pub fn resume_main_thread(h_thread: HANDLE) {
    unsafe {
        ResumeThread(h_thread);
        let _ = CloseHandle(h_thread);
    }
}

const ERROR_BAD_LENGTH_HRESULT: i32 = 0x80070018u32 as i32;
const MODULE_SNAPSHOT_RETRIES: usize = 50;
const MODULE_SNAPSHOT_RETRY_DELAY_MS: u64 = 20;

fn should_retry_module_snapshot_error(code: i32) -> bool {
    code == ERROR_BAD_LENGTH_HRESULT
}

fn create_module_snapshot_with_retry(pid: u32) -> Result<HANDLE> {
    let mut last_retryable_error = None;

    for attempt in 0..MODULE_SNAPSHOT_RETRIES {
        match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) } {
            Ok(snapshot) => return Ok(snapshot),
            Err(err)
                if should_retry_module_snapshot_error(err.code().0)
                    && attempt + 1 < MODULE_SNAPSHOT_RETRIES =>
            {
                last_retryable_error = Some(err);
                std::thread::sleep(std::time::Duration::from_millis(
                    MODULE_SNAPSHOT_RETRY_DELAY_MS,
                ));
            }
            Err(err) => return Err(err.into()),
        }
    }

    Err(last_retryable_error
        .expect("retryable module snapshot error should be recorded")
        .into())
}

/// 在目標進程中尋找模組基址（CreateToolhelp32Snapshot + Module32First/Next）
pub fn find_module(pid: u32, name: &str) -> Result<Option<u32>> {
    let name_lower = name.to_lowercase();
    let snapshot = create_module_snapshot_with_retry(pid)?;

    let mut me: MODULEENTRY32 = unsafe { mem::zeroed() };
    me.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

    let mut result = None;

    unsafe {
        if Module32First(snapshot, &mut me).is_ok() {
            loop {
                // szModule 是 [i8; 256]，轉成字串比較
                let mod_name = std::ffi::CStr::from_ptr(me.szModule.as_ptr())
                    .to_string_lossy()
                    .to_lowercase();
                if mod_name == name_lower {
                    result = Some(me.modBaseAddr as u32);
                    break;
                }
                if Module32Next(snapshot, &mut me).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    Ok(result)
}

/// 從 PE export table 找函數地址（讀取目標進程記憶體中的 PE 結構）
pub fn find_export(h: HANDLE, dll_base: u32, func_name: &str) -> Result<Option<u32>> {
    // 讀取 DOS header
    let dos = memory::read_bytes(h, dll_base, 64)?;
    if &dos[0..2] != b"MZ" {
        bail!("無效的 DOS header @ 0x{dll_base:08X}");
    }
    let e_lfanew = u32::from_le_bytes(dos[60..64].try_into()?);

    // 讀取 PE header（PE32 = 248 bytes optional header）
    let pe = memory::read_bytes(h, dll_base + e_lfanew, 264)?;
    if &pe[0..4] != b"PE\x00\x00" {
        bail!("無效的 PE header @ 0x{:08X}", dll_base + e_lfanew);
    }

    // Export directory RVA（PE optional header offset 96 → PE header offset 120）
    let export_rva = u32::from_le_bytes(pe[120..124].try_into()?);
    if export_rva == 0 {
        return Ok(None);
    }

    // 讀取 IMAGE_EXPORT_DIRECTORY（40 bytes）
    let export_dir = memory::read_bytes(h, dll_base + export_rva, 40)?;
    let num_funcs = u32::from_le_bytes(export_dir[20..24].try_into()?);
    let num_names = u32::from_le_bytes(export_dir[24..28].try_into()?);
    let addr_table_rva = u32::from_le_bytes(export_dir[28..32].try_into()?);
    let name_table_rva = u32::from_le_bytes(export_dir[32..36].try_into()?);
    let ordinal_table_rva = u32::from_le_bytes(export_dir[36..40].try_into()?);

    // 讀取名稱指標表、序號表、地址表
    let name_ptrs = memory::read_bytes(h, dll_base + name_table_rva, num_names as usize * 4)?;
    let ordinals = memory::read_bytes(h, dll_base + ordinal_table_rva, num_names as usize * 2)?;
    let addr_table = memory::read_bytes(h, dll_base + addr_table_rva, num_funcs as usize * 4)?;

    let target = func_name.as_bytes();

    for i in 0..num_names as usize {
        let name_rva = u32::from_le_bytes(name_ptrs[i * 4..(i + 1) * 4].try_into()?);
        let name_data = memory::read_bytes(h, dll_base + name_rva, 64)?;

        // 比對函數名稱（null-terminated）
        let end = name_data.iter().position(|&b| b == 0).unwrap_or(64);
        if &name_data[..end] == target {
            let ordinal = u16::from_le_bytes(ordinals[i * 2..(i + 1) * 2].try_into()?) as usize;
            let func_rva =
                u32::from_le_bytes(addr_table[ordinal * 4..(ordinal + 1) * 4].try_into()?);
            return Ok(Some(dll_base + func_rva));
        }
    }
    Ok(None)
}

/// 暫停進程的所有執行緒（修補前呼叫）
pub fn suspend_threads(pid: u32) -> Result<Vec<HANDLE>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)? };

    let mut te: THREADENTRY32 = unsafe { mem::zeroed() };
    te.dwSize = mem::size_of::<THREADENTRY32>() as u32;

    let mut handles = Vec::new();

    unsafe {
        if Thread32First(snapshot, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    if let Ok(h) = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID) {
                        SuspendThread(h);
                        handles.push(h);
                    }
                }
                if Thread32Next(snapshot, &mut te).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    Ok(handles)
}

/// 恢復所有執行緒（修補後呼叫）
pub fn resume_threads(handles: Vec<HANDLE>) {
    for h in handles {
        unsafe {
            ResumeThread(h);
            let _ = CloseHandle(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_snapshot_retries_error_bad_length() {
        assert!(should_retry_module_snapshot_error(0x80070018u32 as i32));
        assert!(!should_retry_module_snapshot_error(0x80070005u32 as i32));
    }

    #[test]
    fn win32_wide_string_preserves_chinese_paths() {
        let wide = to_wide_null(r"D:\天堂懶人包\TW13081901.bin");
        assert_eq!(wide.last(), Some(&0));

        let without_nul = String::from_utf16(&wide[..wide.len() - 1]).unwrap();
        assert_eq!(without_nul, r"D:\天堂懶人包\TW13081901.bin");
    }
}
