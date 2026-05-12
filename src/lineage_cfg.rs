//! lineage.cfg 視窗 / 全螢幕 / 解析度設定
//!
//! 為什麼要動這個檔:Win11 + 遊戲走 fullscreen 路徑時,內部狀態鎖死,
//! 玩家從遊戲設定選單切視窗會在 ntdll heap check 崩潰(LinError 紀錄到 0x77d31c89)。
//! 啟動前直接改 cfg 的 FullScreen byte / WindowMode,DDraw 走想要的路徑,永遠不觸發那條 mode-switch。
//!
//! lineage.cfg 結構(逆向自 0x444520 解析函數):
//!   header: 28 bytes("lineage configuration file" + 兩個 padding)
//!   TLV stream:
//!     key < 0x2710: `key:u32 + size:u32 + value:size bytes`
//!     key >= 0x2710: 字串型 — `key:u32 + null-terminated`
//!   終止符: key = 0xFFFFFFFF
//!
//! key 對應(部分):
//!   0x12 size=1 → FullScreen byte → [0x9A84D0]
//!   0x1A size=4 → WindowMode → [0x963E54](4=400x300, 5=800x600, 6=1200x900, 7=1600x1200)
//!   0x1B size=4 → PrevWindowMode → [0x963E58]

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::logger::log_line;

const CFG_FILE: &str = "lineage.cfg";
const HEADER_LEN: usize = 0x1C;
const HEADER: &[u8; HEADER_LEN] = b"lineage configuration file\x1A\0";
const TLV_TERMINATOR: u32 = 0xFFFFFFFF;
const STRING_KEY_THRESHOLD: u32 = 0x2710;
const KEY_FULLSCREEN: u32 = 0x12;
const KEY_WINDOW_MODE: u32 = 0x1A;
const KEY_PREV_WINDOW_MODE: u32 = 0x1B;
const DEFAULT_WINDOW_MODE: u32 = 5;

/// 把 FullScreen byte 改成 value(0=視窗, 1=全螢幕)。
pub fn set_fullscreen(game_dir: &str, value: u8) -> Result<()> {
    update_value(game_dir, KEY_FULLSCREEN, &[value], "FullScreen")
}

/// 把 WindowMode 改成 mode(4=400x300, 5=800x600, 6=1200x900, 7=1600x1200)。
/// 只接受 4..=7,超出範圍直接拒寫。
pub fn set_window_mode(game_dir: &str, mode: u32) -> Result<()> {
    if !(4..=7).contains(&mode) {
        bail!("無效的 WindowMode {mode}(只接受 4..=7)");
    }
    update_value(game_dir, KEY_WINDOW_MODE, &mode.to_le_bytes(), "WindowMode")
}

/// 找到 key 對應的 TLV value 區段,寫入 new_bytes(必須跟 cfg 既有 size 一致)。
/// cfg 不存在或 key 找不到視為 no-op(玩家可能完全沒進過遊戲設定)。
/// 已是目標值就不寫檔(避免每次啟動都動 mtime)。
fn update_value(game_dir: &str, target_key: u32, new_bytes: &[u8], label: &str) -> Result<()> {
    let path = Path::new(game_dir).join(CFG_FILE);
    if !path.exists() {
        create_minimal_cfg(&path, target_key, new_bytes)?;
    }
    let mut data = std::fs::read(&path).with_context(|| format!("讀 {} 失敗", path.display()))?;

    if data.len() < HEADER_LEN + 4 {
        bail!("lineage.cfg 太短(只有 {} bytes)", data.len());
    }

    let mut off = HEADER_LEN;
    while off + 4 <= data.len() {
        let key = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        if key == TLV_TERMINATOR {
            break;
        }
        if key >= STRING_KEY_THRESHOLD {
            // 字串型 — 跳到 null
            let rest = &data[off + 4..];
            let nul = rest
                .iter()
                .position(|&b| b == 0)
                .context("cfg 字串值缺結尾 0")?;
            off += 4 + nul + 1;
            continue;
        }
        if off + 8 > data.len() {
            bail!("cfg 截斷在 size 欄位 @ 0x{off:X}");
        }
        let sz = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
        if sz > 1024 || off + 8 + sz > data.len() {
            bail!("cfg 內容毀損 @ 0x{off:X}(key=0x{key:X} sz={sz})");
        }
        if key == target_key {
            if sz != new_bytes.len() {
                bail!(
                    "{label} cfg size 不符(預期 {} 但實際 {sz})",
                    new_bytes.len()
                );
            }
            let value_off = off + 8;
            if &data[value_off..value_off + sz] != new_bytes {
                data[value_off..value_off + sz].copy_from_slice(new_bytes);
                std::fs::write(&path, &data)
                    .with_context(|| format!("寫 {} 失敗", path.display()))?;
                log_line!("[cfg] {label} → {}", display_value(new_bytes));
            }
            return Ok(());
        }
        off += 8 + sz;
    }
    Ok(())
}

fn create_minimal_cfg(path: &Path, target_key: u32, new_bytes: &[u8]) -> Result<()> {
    let fullscreen = if target_key == KEY_FULLSCREEN && new_bytes.len() == 1 {
        new_bytes[0]
    } else {
        0
    };
    let window_mode = if target_key == KEY_WINDOW_MODE && new_bytes.len() == 4 {
        u32::from_le_bytes(new_bytes.try_into().unwrap())
    } else {
        DEFAULT_WINDOW_MODE
    };

    let mut data = Vec::new();
    data.extend_from_slice(HEADER);
    push_tlv(&mut data, KEY_FULLSCREEN, &[fullscreen]);
    push_tlv(&mut data, KEY_WINDOW_MODE, &window_mode.to_le_bytes());
    push_tlv(&mut data, KEY_PREV_WINDOW_MODE, &window_mode.to_le_bytes());
    data.extend_from_slice(&TLV_TERMINATOR.to_le_bytes());

    std::fs::write(path, &data).with_context(|| format!("建立 {} 失敗", path.display()))?;
    log_line!("[cfg] created missing lineage.cfg");
    Ok(())
}

fn push_tlv(data: &mut Vec<u8>, key: u32, value: &[u8]) {
    data.extend_from_slice(&key.to_le_bytes());
    data.extend_from_slice(&(value.len() as u32).to_le_bytes());
    data.extend_from_slice(value);
}

fn display_value(bytes: &[u8]) -> String {
    match bytes.len() {
        1 => format!("{}", bytes[0]),
        4 => format!("{}", u32::from_le_bytes(bytes.try_into().unwrap())),
        _ => bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_game_dir() -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "login38_lineage_cfg_test_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_cfg(dir: &std::path::Path, fullscreen: u8, window_mode: u32) {
        let mut data = vec![0u8; HEADER_LEN];
        data.extend_from_slice(&KEY_FULLSCREEN.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(fullscreen);
        data.extend_from_slice(&KEY_WINDOW_MODE.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&window_mode.to_le_bytes());
        data.extend_from_slice(&TLV_TERMINATOR.to_le_bytes());
        fs::write(dir.join(CFG_FILE), data).unwrap();
    }

    fn read_cfg_bytes(dir: &std::path::Path) -> Vec<u8> {
        fs::read(dir.join(CFG_FILE)).unwrap()
    }

    fn cfg_value(data: &[u8], target_key: u32) -> Option<Vec<u8>> {
        let mut off = HEADER_LEN;
        while off + 4 <= data.len() {
            let key = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            if key == TLV_TERMINATOR {
                return None;
            }
            if key >= STRING_KEY_THRESHOLD {
                let rest = &data[off + 4..];
                let nul = rest.iter().position(|&b| b == 0)?;
                off += 4 + nul + 1;
                continue;
            }
            let sz = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
            let value_off = off + 8;
            if key == target_key {
                return Some(data[value_off..value_off + sz].to_vec());
            }
            off += 8 + sz;
        }
        None
    }

    #[test]
    fn set_fullscreen_updates_cfg_byte() {
        let dir = temp_game_dir();
        write_cfg(&dir, 1, 5);

        set_fullscreen(dir.to_str().unwrap(), 0).unwrap();

        let data = read_cfg_bytes(&dir);
        assert_eq!(data[HEADER_LEN + 8], 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn set_window_mode_updates_cfg_dword() {
        let dir = temp_game_dir();
        write_cfg(&dir, 0, 5);

        set_window_mode(dir.to_str().unwrap(), 7).unwrap();

        let data = read_cfg_bytes(&dir);
        let mode_off = HEADER_LEN + 4 + 4 + 1 + 4 + 4;
        assert_eq!(
            u32::from_le_bytes(data[mode_off..mode_off + 4].try_into().unwrap()),
            7
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn set_fullscreen_creates_missing_cfg_for_windowed_launch() {
        let dir = temp_game_dir();

        set_fullscreen(dir.to_str().unwrap(), 0).unwrap();

        let data = read_cfg_bytes(&dir);
        assert_eq!(&data[..HEADER_LEN], b"lineage configuration file\x1A\0");
        assert_eq!(cfg_value(&data, KEY_FULLSCREEN), Some(vec![0]));
        assert_eq!(
            cfg_value(&data, KEY_WINDOW_MODE),
            Some(5u32.to_le_bytes().to_vec())
        );
        let _ = fs::remove_dir_all(dir);
    }
}
