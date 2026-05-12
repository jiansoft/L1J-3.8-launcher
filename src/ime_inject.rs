//! IME overlay DLL 部署 + 注入
//!
//! Lineage 3.8 的 LUnicodeEdit 收到 `WM_IME_NOTIFY(IMN_OPENCANDIDATE)` 沒呼叫
//! `DefWindowProc` → IMM32 預設候選視窗永遠不開。我們自己畫一個 overlay 視窗,
//! 用 TSF `ITfUIElementSink` 直接訂閱候選 UI 事件 + GDI / `UpdateLayeredWindow`
//! 渲染,完全 bypass 遊戲配合。
//!
//! 部署策略(玩家遊戲目錄保持完全乾淨):
//!   1. launcher.exe 內嵌 lineage_ime.dll(`include_bytes!`)
//!   2. 啟動時寫到 `%LOCALAPPDATA%\Lineage38Launcher\ime\`(已存在 byte 相同就 skip)
//!   3. CreateRemoteThread + LoadLibraryW(完整路徑) 把 DLL 預載進遊戲 process
//!
//! 不像 packer 之前要載入的東西,DLL 內 worker thread 會自己 poll 等遊戲主視窗
//! 出來再 subclass — 不需要 CREATE_SUSPENDED 配合,什麼時候 inject 都行。

use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
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

const LINEAGE_IME_DLL: &[u8] =
    include_bytes!("../ime_overlay/target/i686-pc-windows-msvc/release/lineage_ime.dll");

const CACHE_SUBDIR: &str = r"Lineage38Launcher\ime";

/// LoadLibraryW 等待逾時(ms)。系統 DLL 載入應在 < 1s 內完成。
const INJECT_WAIT_MS: u32 = 5_000;

/// 把 IME DLL 寫到 `%LOCALAPPDATA%\Lineage38Launcher\ime\` 並回傳該路徑。
///
/// 已存在且 byte 完全相同就 skip(避免每次啟動重寫盤)。
pub fn ensure_cached() -> Result<PathBuf> {
    let local =
        std::env::var("LOCALAPPDATA").map_err(|_| anyhow!("LOCALAPPDATA 環境變數不存在"))?;
    let cache = PathBuf::from(local).join(CACHE_SUBDIR);
    fs::create_dir_all(&cache)
        .with_context(|| format!("建立 cache 目錄失敗: {}", cache.display()))?;
    deploy(&cache, "lineage_ime.dll", LINEAGE_IME_DLL)?;
    Ok(cache)
}

/// 預載 IME overlay DLL 進目標 process(全程式碼路徑 LoadLibraryW)。
pub fn inject_ime_dll(h: HANDLE, cache_dir: &Path) -> Result<()> {
    let load_lib = load_library_w_addr()?;
    inject_one(h, load_lib, &cache_dir.join("lineage_ime.dll"), "ime-overlay")?;
    Ok(())
}

pub fn inject_dll(h: HANDLE, dll_path: &Path, tag: &str) -> Result<()> {
    let load_lib = load_library_w_addr()?;
    inject_one(h, load_lib, dll_path, tag)
}

fn deploy(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = dir.join(name);
    if let Ok(existing) = fs::read(&path) {
        if existing == bytes {
            return Ok(());
        }
    }
    fs::write(&path, bytes).with_context(|| format!("寫入 {} 失敗", path.display()))?;
    log_line!("[ime-inject] 快取 {} ({} bytes)", name, bytes.len());
    Ok(())
}

/// 取 launcher 自己的 `kernel32!LoadLibraryW` 位址。
///
/// kernel32.dll 在同一 session 的 32-bit process 內載入位址相同(ASLR per boot
/// 但 system DLL 共用),所以這個位址在目標 process 也有效。
fn load_library_w_addr() -> Result<usize> {
    unsafe {
        let kernel32 = GetModuleHandleW(PCWSTR(
            "kernel32.dll\0"
                .encode_utf16()
                .collect::<Vec<u16>>()
                .as_ptr(),
        ))
        .context("GetModuleHandleW(kernel32.dll) 失敗")?;
        let proc = GetProcAddress(kernel32, PCSTR(b"LoadLibraryW\0".as_ptr()))
            .ok_or_else(|| anyhow!("GetProcAddress(LoadLibraryW) 回 NULL"))?;
        Ok(proc as usize)
    }
}

fn inject_one(h: HANDLE, load_lib: usize, dll_path: &Path, tag: &str) -> Result<()> {
    let path_w: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let path_bytes = path_w.len() * 2;

    let remote = unsafe {
        VirtualAllocEx(
            h,
            None,
            path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        bail!(
            "VirtualAllocEx({path_bytes} bytes) 失敗 — {}",
            dll_path.display()
        );
    }

    let result = (|| -> Result<()> {
        let mut written = 0usize;
        unsafe {
            WriteProcessMemory(
                h,
                remote,
                path_w.as_ptr().cast(),
                path_bytes,
                Some(&mut written),
            )
            .with_context(|| format!("WriteProcessMemory @ {remote:p}"))?;
        }
        if written != path_bytes {
            bail!("路徑寫入不完整 ({written}/{path_bytes} bytes)");
        }

        let mut tid = 0u32;
        let thread_handle = unsafe {
            CreateRemoteThread(
                h,
                None,
                0,
                Some(std::mem::transmute(load_lib)),
                Some(remote),
                0,
                Some(&mut tid),
            )
        }
        .context("CreateRemoteThread(LoadLibraryW)")?;

        let wait = unsafe { WaitForSingleObject(thread_handle, INJECT_WAIT_MS) };
        let mut hmod: u32 = 0;
        let _ = unsafe { GetExitCodeThread(thread_handle, &mut hmod) };
        unsafe { CloseHandle(thread_handle).ok() };

        if wait == WAIT_TIMEOUT {
            bail!("LoadLibraryW timeout {INJECT_WAIT_MS}ms (tid={tid})");
        }
        if wait != WAIT_OBJECT_0 {
            bail!("LoadLibraryW 等待非預期 (wait={wait:?}, tid={tid})");
        }
        if hmod == 0 {
            bail!("LoadLibraryW 回 NULL — 載入失敗 (tid={tid})");
        }

        let name = dll_path.file_name().and_then(|s| s.to_str()).unwrap_or("?");
        log_line!("[{tag}] 預載 {name} → HMODULE=0x{hmod:08X}");
        Ok(())
    })();

    unsafe {
        let _ = VirtualFreeEx(h, remote, 0, MEM_RELEASE);
    }
    result
}
