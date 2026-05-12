//! 對 game exe 設「高 DPI 縮放覆寫 = 應用程式」registry,避免 Win11 自動 bitmap 放大造成殘影
//!
//! 沒這個的時候:Win11 看到舊 EXE 沒宣告 DPI awareness,就用 bilinear scale 把 800x600 backbuffer
//! 拉成 1200x900(150% 桌面)→ pixel 對不齊就會在角色邊緣看到雙影/模糊。
//!
//! 對應「右鍵 EXE → 內容 → 相容性 → 變更高 DPI 設定 → 覆寫 → 應用程式」這條 GUI 路徑。
//! Windows 把這個設定存在這個 registry:
//!     HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
//!     value name = exe 完整路徑
//!     value data = "~ HIGHDPIAWARE"
//!
//! 寫了之後遊戲下次啟動:Windows 不再 bitmap-scale,800x600 視窗就是 800x600 螢幕像素。

use anyhow::{bail, Context, Result};
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
    KEY_READ, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
};

use crate::logger::log_line;

const SUBKEY: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
const FLAG_VALUE: &str = "~ HIGHDPIAWARE";
const DISABLE_FULLSCREEN_OPTIMIZATIONS: &str = "DISABLEDXMAXIMIZEDWINDOWEDMODE";

pub fn ensure_disable_fullscreen_optimizations(exe_path: &str) -> Result<()> {
    ensure_compat_flags(exe_path, &[DISABLE_FULLSCREEN_OPTIMIZATIONS])
}

/// 對 exe_path 設定 HIGHDPIAWARE compatibility flag。
/// 若 registry 已含此 flag(玩家自己設過或我們之前設過)就跳過。
/// 失敗回 Err 由呼叫者決定是否致命(這個功能即使失敗,遊戲還是能跑,只是有 ghosting)。
pub fn ensure_high_dpi_aware(exe_path: &str) -> Result<()> {
    let _ = exe_path;
    log_line!("[launch-time] legacy launch mode: skip DPI override");
    return Ok(());

    let canonical = Path::new(exe_path)
        .canonicalize()
        .with_context(|| format!("無法解析絕對路徑: {exe_path}"))?;
    // canonicalize 會回 \\?\ 前綴,Windows 內部會吃但 Layers registry 用一般路徑比較直觀
    let path_str = canonical
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();
    let exe_path_w = to_wide(&path_str);
    let subkey_w = to_wide(SUBKEY);

    unsafe {
        let mut hkey = HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey_w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        );
        if status != ERROR_SUCCESS {
            bail!("RegCreateKeyExW 失敗 (status={})", status.0);
        }

        let result = (|| -> Result<()> {
            // 若已是目標值就不重寫(避免 mtime / registry write 浪費)
            if let Some(existing) = read_value(hkey, &exe_path_w)? {
                if existing.trim() == FLAG_VALUE {
                    return Ok(());
                }
                // 玩家可能有自己的 compat flags,我們不亂蓋掉:
                // 只在沒值或值就是我們設的時候才寫。
                if existing.contains("HIGHDPIAWARE") || existing.contains("DPIUNAWARE") {
                    // DPI 相關 flag 已存在 → 不動,尊重玩家現有設定
                    return Ok(());
                }
                log_line!("[DPI] 既存 compat flag 不含 DPI awareness,新增 HIGHDPIAWARE");
                let merged = format!("{} {}", existing.trim(), FLAG_VALUE);
                write_value(hkey, &exe_path_w, &merged)?;
            } else {
                write_value(hkey, &exe_path_w, FLAG_VALUE)?;
                log_line!("[DPI] 已對 {} 設 HIGHDPIAWARE", path_str);
            }
            Ok(())
        })();

        let _ = RegCloseKey(hkey);
        result
    }
}

fn ensure_compat_flags(exe_path: &str, required_flags: &[&str]) -> Result<()> {
    let canonical = Path::new(exe_path)
        .canonicalize()
        .with_context(|| format!("無法解析絕對路徑: {exe_path}"))?;
    let path_str = canonical
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();
    let exe_path_w = to_wide(&path_str);
    let subkey_w = to_wide(SUBKEY);

    unsafe {
        let mut hkey = HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey_w.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        );
        if status != ERROR_SUCCESS {
            bail!("RegCreateKeyExW failed (status={})", status.0);
        }

        let result = (|| -> Result<()> {
            let existing = read_value(hkey, &exe_path_w)?;
            let merged = merge_compat_flags(existing.as_deref(), required_flags);
            if existing.as_deref().map(str::trim) == Some(merged.as_str()) {
                return Ok(());
            }
            write_value(hkey, &exe_path_w, &merged)?;
            log_line!("[compat] set {} => {}", path_str, merged);
            Ok(())
        })();

        let _ = RegCloseKey(hkey);
        result
    }
}

fn merge_compat_flags(existing: Option<&str>, required_flags: &[&str]) -> String {
    let mut flags: Vec<String> = existing
        .unwrap_or("")
        .split_whitespace()
        .filter(|part| !part.trim().is_empty() && *part != "~")
        .map(|part| part.trim().to_string())
        .collect();

    for required in required_flags {
        if !flags.iter().any(|flag| flag.eq_ignore_ascii_case(required)) {
            flags.push((*required).to_string());
        }
    }

    if flags.is_empty() {
        "~".to_string()
    } else {
        format!("~ {}", flags.join(" "))
    }
}

unsafe fn read_value(hkey: HKEY, name_w: &[u16]) -> Result<Option<String>> {
    let mut size_bytes: u32 = 0;
    let mut kind = windows::Win32::System::Registry::REG_VALUE_TYPE::default();
    let status = RegQueryValueExW(
        hkey,
        PCWSTR(name_w.as_ptr()),
        None,
        Some(&mut kind),
        None,
        Some(&mut size_bytes),
    );
    if status.0 == 2 {
        // ERROR_FILE_NOT_FOUND
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        bail!("RegQueryValueExW 探長度失敗 (status={})", status.0);
    }
    if kind != REG_SZ || size_bytes < 2 {
        return Ok(None);
    }
    let mut buf = vec![0u16; (size_bytes as usize) / 2];
    let mut size_out = size_bytes;
    let status = RegQueryValueExW(
        hkey,
        PCWSTR(name_w.as_ptr()),
        None,
        Some(&mut kind),
        Some(buf.as_mut_ptr() as *mut u8),
        Some(&mut size_out),
    );
    if status != ERROR_SUCCESS {
        bail!("RegQueryValueExW 讀取失敗 (status={})", status.0);
    }
    // 去掉結尾 \0
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(Some(String::from_utf16_lossy(&buf[..len])))
}

unsafe fn write_value(hkey: HKEY, name_w: &[u16], value: &str) -> Result<()> {
    let mut value_w = to_wide(value);
    let bytes = std::slice::from_raw_parts(value_w.as_mut_ptr() as *const u8, value_w.len() * 2);
    let status = RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), None, REG_SZ, Some(bytes));
    if status != ERROR_SUCCESS {
        bail!("RegSetValueExW 失敗 (status={})", status.0);
    }
    Ok(())
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_compat_flags_adds_disable_fullscreen_optimizations() {
        assert_eq!(
            merge_compat_flags(None, &[DISABLE_FULLSCREEN_OPTIMIZATIONS]),
            "~ DISABLEDXMAXIMIZEDWINDOWEDMODE"
        );
    }

    #[test]
    fn merge_compat_flags_preserves_existing_flags() {
        assert_eq!(
            merge_compat_flags(Some("~ HIGHDPIAWARE"), &[DISABLE_FULLSCREEN_OPTIMIZATIONS]),
            "~ HIGHDPIAWARE DISABLEDXMAXIMIZEDWINDOWEDMODE"
        );
    }

    #[test]
    fn merge_compat_flags_is_idempotent_case_insensitive() {
        assert_eq!(
            merge_compat_flags(
                Some("~ disableDxMaximizedWindowedMode"),
                &[DISABLE_FULLSCREEN_OPTIMIZATIONS],
            ),
            "~ disableDxMaximizedWindowedMode"
        );
    }
}
