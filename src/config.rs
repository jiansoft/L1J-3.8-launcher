//! 使用者偏好設定 — 持久化到 launcher.exe 旁的 launcher.ini
//!
//! 內容是「玩家自己的選擇」(視窗化、解析度等),跟 list.txt 裡 LauncherConfig
//! (伺服器管理員散發的 skin / 公告 URL)是兩件事 — 那邊不該存玩家偏好。
//!
//! 格式:
//! ```ini
//! [Settings]
//! windowed=true
//! window_mode=5
//! ```

use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "launcher.ini";

/// 玩家偏好(視窗化 + 視窗大小)。
#[derive(Debug, Clone)]
pub struct UserPrefs {
    pub windowed: bool,
    /// 4=400x300, 5=800x600, 6=1200x900, 7=1600x1200。
    pub window_mode: u8,
}

impl Default for UserPrefs {
    fn default() -> Self {
        // 預設視窗化 + 800x600,最不會踩 W11 螢幕邊界 + DPI 殘影問題
        Self {
            windowed: true,
            window_mode: 5,
        }
    }
}

impl UserPrefs {
    /// 從 launcher.exe 旁的 launcher.ini 載入,失敗或缺欄位 → 用 default
    pub fn load() -> Self {
        let mut prefs = Self::default();
        let path = match config_path() {
            Some(p) => p,
            None => return prefs,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return prefs,
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('[') {
                continue;
            }
            let Some((key, val)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "windowed" => prefs.windowed = matches!(val.trim(), "true" | "1" | "yes"),
                "window_mode" => {
                    if let Ok(n) = val.trim().parse::<u8>() {
                        if (4..=7).contains(&n) {
                            prefs.window_mode = n;
                        }
                    }
                }
                _ => {}
            }
        }
        prefs
    }

    /// 寫回 launcher.ini。失敗時靜默忽略 — 持久化失敗不該擋啟動。
    pub fn save(&self) {
        let Some(path) = config_path() else { return };
        let content = format!(
            "[Settings]\nwindowed={}\nwindow_mode={}\n",
            self.windowed, self.window_mode
        );
        let _ = std::fs::write(&path, content);
    }
}

fn config_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent().unwrap_or(Path::new(".")).to_path_buf();
    Some(dir.join(CONFIG_FILE))
}
