//! GUI 模組 — WebView2 host（wry）
//!
//! 視窗用 tao（無邊框 760×500），內容用 wry 嵌入 WebView2 載入 skin。
//! Skin = launcher.exe 旁邊的 `skins/<active>/index.html`，使用者可自訂。
//! IPC：JS `window.chrome.webview.postMessage(JSON)` 與 Rust 雙向溝通。

use crate::logger::log_line;
use crate::{inject, GAME_EXE};
use anyhow::{Context, Result};
use launcher::server_list::{parse_list_file, AuxConfig, ServerInfo};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::{Icon, WindowBuilder},
};
use wry::{
    http::{header::CONTENT_TYPE, Request, Response},
    WebViewBuilder,
};

/// JS → Rust 的訊息格式
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum JsMessage {
    /// 頁面載入完成，請發送伺服器清單
    Ready,
    /// 使用者點選了某個伺服器（前端自己維護選中狀態，這邊先不用）
    Select {
        #[allow(dead_code)]
        index: usize,
    },
    /// 啟動遊戲
    Launch {
        #[serde(rename = "serverIdx")]
        server_idx: usize,
        windowed: bool,
        /// 視窗大小:4=400x300, 5=800x600, 6=1200x900, 7=1600x1200。
        /// 缺省或無效 → 使用 5 (800x600,最安全)
        #[serde(rename = "windowMode", default)]
        window_mode: Option<u8>,
    },
    /// 玩家偏好(視窗化 / 解析度)變更 — 任一改動 JS 都送這個 + Rust 立即寫 launcher.ini
    SavePrefs {
        windowed: bool,
        #[serde(rename = "windowMode")]
        window_mode: u8,
    },
    /// 關閉視窗
    Cancel,
    /// 拖曳視窗（無邊框視窗自繪標題列用）
    Drag,
    /// 點擊上方 tab 列連結（官網/客服）— 開啟外部瀏覽器
    #[serde(rename = "openurl")]
    OpenUrl { url: String },
}

/// Rust → JS 推送的伺服器資料
#[derive(Debug, Serialize)]
struct JsServer {
    name: String,
    ip: String,
    port: i32,
    used: bool,
}

/// event loop 的自訂事件
#[derive(Debug)]
enum UserEvent {
    /// 把伺服器清單推送給 JS
    PushServers,
    /// 顯示錯誤對話框
    ShowError(String),
    /// 啟動遊戲（已驗證好參數）
    LaunchGame {
        ip: String,
        port: u16,
        game_dir: String,
        inject_buffer: Option<Vec<u8>>,
        inject_source_path: Option<String>,
        packet_encrypt: Option<crate::PacketEncryptConfig>,
        windowed: bool,
        /// 4..=7,參考 JsMessage::Launch::window_mode
        window_mode: u8,
    },
    /// 關閉視窗
    Close,
    /// 拖曳視窗（HTML drag region 觸發）
    DragWindow,
    /// 用系統預設瀏覽器開啟 URL
    OpenExternal(String),
    /// 更新進度條（current=當前下載 0~100，total=整體階段 0~100）
    PushProgress { current_pct: u8, total_pct: u8 },
    /// 偵測到新版本，請主執行緒提示使用者並由 worker 接手安裝
    AutoUpdatePrompt(crate::http::UpdateInfo),
    /// 鎖定 / 解鎖 UI（自動更新進行中禁止啟動遊戲）
    SetLocked(bool),
    /// 在登入器頁面顯示狀態訊息（空字串 = 隱藏）
    SetStatus(String),
    /// 推送單一伺服器的實際連線狀態（背景 TCP 探測完成）
    PushServerStatus { index: usize, online: bool },
    /// 隱藏 / 顯示 launcher 視窗（不結束 process，保留背景 patch thread 繼續跑）
    SetWindowVisible(bool),
}

/// 自訂 protocol handler：把 `lineage://localhost/<path>` 對映到 `<skin_dir>/<path>`
///
/// 路徑經過正規化（去除 `..` / 絕對路徑）以防止跳出 skin 目錄。
fn packet_encrypt_config_from_server(
    aux: &AuxConfig,
    server: &ServerInfo,
) -> std::result::Result<Option<crate::PacketEncryptConfig>, String> {
    if !aux.packet_encrypt {
        return Ok(None);
    }
    if server.rsa_d == 0 || server.rsa_n == 0 {
        return Err(
            "封包加密已開啟，但所選伺服器沒有 D/N 金鑰；請先在編碼器產生金鑰並重新編碼。"
                .to_string(),
        );
    }
    Ok(Some(crate::PacketEncryptConfig {
        rsa_d: server.rsa_d,
        rsa_n: server.rsa_n,
    }))
}

fn serve_skin_file(
    skin_dir: &std::path::Path,
    req: Request<Vec<u8>>,
) -> Response<std::borrow::Cow<'static, [u8]>> {
    let raw_path = req.uri().path();
    let rel = raw_path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };

    // 安全：拒絕含 `..` 或絕對路徑的請求
    let rel_path = std::path::PathBuf::from(rel);
    if rel_path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Response::builder()
            .status(403)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(std::borrow::Cow::Borrowed(b"forbidden" as &[u8]))
            .unwrap();
    }

    let target = skin_dir.join(&rel_path);
    let mime = match target
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        _ => "application/octet-stream",
    };

    match std::fs::read(&target) {
        Ok(bytes) => Response::builder()
            .status(200)
            .header(CONTENT_TYPE, mime)
            .body(std::borrow::Cow::Owned(bytes))
            .unwrap(),
        Err(_) => Response::builder()
            .status(404)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(std::borrow::Cow::Borrowed(b"not found" as &[u8]))
            .unwrap(),
    }
}

/// 用系統預設瀏覽器開啟 URL（ShellExecuteW，等同雙擊網址）
fn open_external_url(url: &str) {
    use std::os::windows::ffi::OsStrExt;
    let verb: Vec<u16> = std::ffi::OsStr::new("open")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let url_w: Vec<u16> = std::ffi::OsStr::new(url)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(
            None,
            windows::core::PCWSTR(verb.as_ptr()),
            windows::core::PCWSTR(url_w.as_ptr()),
            windows::core::PCWSTR::null(),
            windows::core::PCWSTR::null(),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );
    }
}

const APP_WINDOW_ICON_RGBA: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/app_icon_256.rgba"
));
const APP_WINDOW_ICON_SIZE: u32 = 256;

fn build_tao_app_icon() -> Option<Icon> {
    Icon::from_rgba(
        APP_WINDOW_ICON_RGBA.to_vec(),
        APP_WINDOW_ICON_SIZE,
        APP_WINDOW_ICON_SIZE,
    )
    .map_err(|e| log_line!("[icon] Tao window icon 建立失敗: {e:?}"))
    .ok()
}

fn exe_dir() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn app_window_icon_can_be_built_for_taskbar() {
        let icon = super::build_tao_app_icon();

        assert!(icon.is_some());
    }

    #[test]
    fn packet_encrypt_requires_selected_server_rsa_key() {
        let mut aux = launcher::server_list::AuxConfig::default();
        aux.packet_encrypt = true;
        let server = launcher::server_list::ServerInfo::new("S", "127.0.0.1", 7001);

        let err = super::packet_encrypt_config_from_server(&aux, &server).unwrap_err();

        assert!(err.contains("封包加密"));
        assert!(err.contains("產生金鑰"));
    }

    #[test]
    fn packet_encrypt_uses_selected_server_rsa_key() {
        let mut aux = launcher::server_list::AuxConfig::default();
        aux.packet_encrypt = true;
        let mut server = launcher::server_list::ServerInfo::new("S", "127.0.0.1", 7001);
        server.rsa_d = 12345;
        server.rsa_n = 67890;

        let cfg = super::packet_encrypt_config_from_server(&aux, &server)
            .unwrap()
            .unwrap();

        assert_eq!(cfg.rsa_d, 12345);
        assert_eq!(cfg.rsa_n, 67890);
    }
}

/// 讀 launcher.exe 旁的 list.txt（伺服器列表） + config.ini（[aux] + [launcher] 設定）
///
/// list.txt 跟 config.ini 是分離的：
///   - list.txt：加密伺服器列表(純 [list] 格式,beanfun 客戶端可直接讀)
///   - config.ini：[aux] + [launcher] 設定(無伺服器)
/// 找不到 list.txt 時退讀 config.ini 的 [list](舊版相容)。
fn load_list_file() -> launcher::server_list::ListFile {
    let dir = exe_dir();

    // 1) 讀 [aux] + [launcher] 設定（config.ini 支援 ENC1: 加密與舊版明文）
    let mut file = launcher::server_list::ListFile::default();
    let cfg_path = dir.join("config.ini");
    if cfg_path.exists() {
        if let Ok(raw) = crate::legacy_text::read_text_file(&cfg_path) {
            if let Ok(plain) = launcher::server_list::decrypt_config_text(&raw) {
                if let Ok(parsed) = parse_list_file(&plain) {
                    file.aux = parsed.aux;
                    file.launcher = parsed.launcher;
                    // 舊版 config.ini 內含 [list]，作為 fallback 來源
                    file.servers = parsed.servers;
                }
            }
        }
    }

    // 2) list.txt 優先覆蓋 servers
    let list_path = dir.join("list.txt");
    if list_path.exists() {
        if let Ok(content) = crate::legacy_text::read_text_file(&list_path) {
            if let Ok(servers) = launcher::server_list::parse_list_txt(&content) {
                if !servers.is_empty() {
                    file.servers = servers;
                }
            }
        }
    }

    file
}

/// 驗證所選伺服器並組好 LaunchGame 事件
fn build_launch_event(
    servers: &[ServerInfo],
    idx: usize,
    windowed: bool,
    window_mode: u8,
) -> std::result::Result<UserEvent, String> {
    let s = servers
        .get(idx)
        .ok_or_else(|| "無效的伺服器索引".to_string())?;
    let port: u16 = s
        .port
        .try_into()
        .map_err(|_| format!("Port 超出範圍：{}", s.port))?;

    let dir = exe_dir();
    let game_path = dir.join(GAME_EXE);
    if !game_path.exists() {
        return Err(format!(
            "找不到遊戲主程式：{}\n請將 launcher.exe 放在遊戲目錄下",
            game_path.display()
        ));
    }
    let game_dir = dir.to_string_lossy().into_owned();
    let aux = load_list_file().aux;

    let base = GAME_EXE.replace(".bin", "");
    let txt_path = dir.join(format!("{base}.txt"));
    let pak_path = dir.join(format!("{base}.pak"));
    let force_file_hook_from_pak =
        !aux.transform_file && pak_path.exists() && inject::is_valid_pak(&pak_path);
    let load_inject_file = aux.transform_file || force_file_hook_from_pak;

    let (inject_buffer, inject_source_path) = if load_inject_file {
        if force_file_hook_from_pak {
            log_line!(
                "[inject] transform_file=false but valid pak exists; forcing FileHook: {}",
                pak_path.display()
            );
        }
        let inject_start = std::time::Instant::now();
        let inject_path = if pak_path.exists() && inject::is_valid_pak(&pak_path) {
            pak_path
        } else if txt_path.exists() {
            txt_path
        } else {
            return Err(format!(
                "找不到變身檔：{} 或 {}\n請先用 encoder.exe 產出變身檔到此目錄",
                txt_path.display(),
                pak_path.display()
            ));
        };
        let inject_buffer = inject::load_inject_file(&inject_path.to_string_lossy())
            .map(Some)
            .map_err(|e| format!("載入變身檔失敗：{e:#}"))?;

        log_line!(
            "[inject] selected {} ({} bytes, {:.3}s)",
            inject_path.display(),
            inject_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
            inject_start.elapsed().as_secs_f64()
        );
        (
            inject_buffer,
            Some(inject_path.to_string_lossy().into_owned()),
        )
    } else {
        log_line!("[inject] transform file disabled by config; no valid pak fallback found");
        (None, None)
    };
    let packet_encrypt = packet_encrypt_config_from_server(&aux, s)?;

    Ok(UserEvent::LaunchGame {
        ip: s.ip.clone(),
        port,
        game_dir,
        inject_buffer,
        inject_source_path,
        packet_encrypt,
        windowed,
        window_mode,
    })
}

/// launcher 顯示用的版本字串；自動更新比對也用這個值
pub const APP_VERSION: &str = "0.1.0";

/// 啟動時嘗試從 launcher_cfg.list_update_url 下載新 list.txt 覆蓋本地檔
fn try_list_update(launcher_cfg: &launcher::server_list::LauncherConfig, dir: &std::path::Path) {
    if !launcher_cfg.list_update_enabled {
        return;
    }
    let url = launcher_cfg.list_update_url.trim();
    if url.is_empty() {
        return;
    }
    log_line!("[列表更新] 從 {} 下載 list.txt ...", url);
    match crate::http::http_get(url) {
        Ok(body) => {
            let list_path = dir.join("list.txt");
            if let Err(e) = std::fs::write(&list_path, &body) {
                log_line!("[列表更新] 寫檔失敗：{e}");
            } else {
                log_line!(
                    "[列表更新] 已更新 {}（{} bytes）",
                    list_path.display(),
                    body.len()
                );
            }
        }
        Err(e) => log_line!("[列表更新] 下載失敗：{e:#}"),
    }
}

/// 本機資源版本檔:launcher.exe 旁邊的 `Login.ini.Updated`,格式 `[Update]\nVersion=N\n`。
/// 跟 launcher 自身版本(APP_VERSION)無關 — 這個是「玩家本機已吃到的遊戲資源 patch 版本」。
fn local_version_path() -> std::path::PathBuf {
    exe_dir().join("Login.ini.Updated")
}

/// 讀本機資源版本。檔案不存在 / 解析失敗 / 沒有 Version 鍵 → 0(代表「全部都沒吃過,從 v1 開始吃」)
fn read_local_version() -> u32 {
    let Ok(text) = std::fs::read_to_string(local_version_path()) else {
        return 0;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with(';')
            || line.starts_with('#')
            || line.starts_with('[')
        {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        if key.eq_ignore_ascii_case("version") || key.eq_ignore_ascii_case("ver") {
            if let Ok(n) = v.trim().parse::<u32>() {
                return n;
            }
        }
    }
    0
}

/// 原子寫本機資源版本(tmp → rename),確保中途斷電/當機不會留下半寫入檔案
fn write_local_version(v: u32) -> std::io::Result<()> {
    let path = local_version_path();
    let tmp = exe_dir().join("Login.ini.Updated.tmp");
    std::fs::write(&tmp, format!("[Update]\r\nVersion={v}\r\n"))?;
    std::fs::rename(&tmp, &path)
}

/// 啟動時檢查自動更新。發現新版本(server_version > local_version)就回傳 UpdateInfo;
/// 主流程在 webview 就緒後再彈窗。已是最新、未啟用、URL 空、抓不到都回 None。
fn check_auto_update(
    launcher_cfg: &launcher::server_list::LauncherConfig,
) -> Option<crate::http::UpdateInfo> {
    if !launcher_cfg.auto_update_enabled {
        return None;
    }
    let url = launcher_cfg.auto_update_url.trim();
    if url.is_empty() {
        return None;
    }
    let body = match crate::http::http_get(url) {
        Ok(b) => b,
        Err(e) => {
            log_line!("[自動更新] 下載 {} 失敗：{e:#}", url);
            return None;
        }
    };
    let text = String::from_utf8_lossy(&body);
    let info = crate::http::parse_update_ini(&text, url)?;
    let local = read_local_version();
    if info.server_version <= local {
        log_line!("[自動更新] 已是最新資源版本 v{}", local);
        return None;
    }
    log_line!(
        "[自動更新] 發現新資源版本 v{}（目前 v{}），需吃 {} 包",
        info.server_version,
        local,
        info.server_version - local
    );
    Some(info)
}

/// 在 worker thread 中：依序下載 v(local+1)..=v(server) 的所有 zip(推進度+狀態文字)→ 各自解壓
/// 累積到 patch/ → 全部完成後執行 eat.exe → 寫回 Login.ini.Updated → 解鎖 UI。
///
/// 任一版本失敗就整批中止,Login.ini.Updated 不會更新,下次啟動會從相同的 local 版本重試。
fn run_auto_update_worker(
    info: crate::http::UpdateInfo,
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
) {
    if info.zips.is_empty() {
        let _ = proxy.send_event(UserEvent::SetStatus(format!(
            "發現新資源版本 v{} 但 Update.ini 沒有 zip 條目，請聯絡管理者",
            info.server_version
        )));
        let _ = proxy.send_event(UserEvent::SetLocked(false));
        return;
    }

    let _ = proxy.send_event(UserEvent::SetStatus(format!(
        "發現新資源版本 v{}，正在下載更新...",
        info.server_version
    )));

    match install_auto_update(&info, &proxy) {
        Ok(()) => {
            let _ = proxy.send_event(UserEvent::SetStatus(format!(
                "更新完成 ✓  資源版本 v{} 已就緒，可以進入遊戲",
                info.server_version
            )));
            let _ = proxy.send_event(UserEvent::SetLocked(false));
        }
        Err(e) => {
            log_line!("[自動更新] 失敗：{e:#}");
            let _ = proxy.send_event(UserEvent::SetStatus(format!(
                "更新失敗：{}（可重試或聯絡管理者）",
                short_error(&e)
            )));
            let _ = proxy.send_event(UserEvent::PushProgress {
                current_pct: 0,
                total_pct: 0,
            });
            let _ = proxy.send_event(UserEvent::SetLocked(false));
        }
    }
}

/// 把 anyhow chain 壓成單行，給狀態列顯示用（避免換行擠爆 UI）
fn short_error(e: &anyhow::Error) -> String {
    e.chain()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(" / ")
}

/// 為每個 used=true 的伺服器各 spawn 一個探測執行緒，TCP connect 有逾時，
/// 完成後透過 proxy 把 PushServerStatus 事件送回 event loop 更新 UI。
/// used=false 的 slot 直接送 offline，跳過 TCP 連線（節省時間）。
fn spawn_server_status_probe(
    servers: &[ServerInfo],
    proxy: tao::event_loop::EventLoopProxy<UserEvent>,
) {
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    use std::time::Duration;
    const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

    for (idx, srv) in servers.iter().enumerate() {
        if !srv.used || srv.ip.is_empty() || srv.port <= 0 {
            let _ = proxy.send_event(UserEvent::PushServerStatus {
                index: idx,
                online: false,
            });
            continue;
        }
        let host = srv.ip.clone();
        let port = srv.port as u16;
        let proxy = proxy.clone();
        std::thread::spawn(move || {
            // resolve + TCP connect with timeout；任一失敗即視為離線
            let addr_str = format!("{host}:{port}");
            let online = match addr_str.to_socket_addrs() {
                Ok(mut iter) => match iter.next() {
                    Some(addr) => {
                        TcpStream::connect_timeout(&addr as &SocketAddr, PROBE_TIMEOUT).is_ok()
                    }
                    None => false,
                },
                Err(_) => false,
            };
            let _ = proxy.send_event(UserEvent::PushServerStatus { index: idx, online });
        });
    }
}

/// 公版增量自動更新流程:
///   1. 計算需吃哪些版本(local+1 ..= server)、檢查 Update.ini 是否每一版都有對應 zip
///   2. 逐版下載 zip → **直接解壓覆蓋到 launcher 旁邊**(zip 內路徑就是檔案最終位置)→ 立即刪 zip
///   3. 全部下載完才執行一次 eat.exe(若存在,對 launcher 目錄做後處理)
///   4. 全部成功才原子寫回 Login.ini.Updated = server_version;任一步失敗就 bail,
///      下次啟動會從相同的 local 版本重新整批吃(eat.exe 應為 idempotent)
///
/// 進度條配比:下載+解壓占 0–80%,eat.exe 占 80–100%。
fn install_auto_update(
    info: &crate::http::UpdateInfo,
    proxy: &tao::event_loop::EventLoopProxy<UserEvent>,
) -> Result<()> {
    let dir = exe_dir();
    let local_version = read_local_version();
    let target_version = info.server_version;

    // 前置檢查:eat.exe 必須存在才開始下載(避免下完才發現吃不了),
    // 失敗訊息會被 run_auto_update_worker 接到並透過 SetStatus 顯示給玩家
    let eat_path = dir.join("eat.exe");
    if !eat_path.exists() {
        anyhow::bail!(
            "缺少吃檔工具 eat.exe（應放在 {}）— 請先放置 eat.exe 後再執行自動更新",
            eat_path.display()
        );
    }

    // 構建「需要吃」的版本清單(local+1 ..= target),Update.ini 缺任一版就直接 fail
    let need: Vec<(u32, String)> = (local_version + 1..=target_version)
        .map(|v| {
            info.zips
                .iter()
                .find(|(n, _)| *n == v)
                .map(|(_, e)| (v, e.clone()))
                .ok_or_else(|| anyhow::anyhow!("Update.ini 缺少版本 {} 的 zip 條目", v))
        })
        .collect::<Result<_>>()?;
    let total_count = need.len();
    let base_url = crate::http::base_url_of(&info.source_url);
    log_line!(
        "[自動更新] 計畫吃 {} 個版本({}..={}),base_url={}",
        total_count,
        local_version + 1,
        target_version,
        base_url
    );

    // 下載+解壓占整體 0–80%,平均分給每個版本
    let pct_per_zip: u16 = 80 / (total_count as u16).max(1);

    for (i, (version, entry)) in need.iter().enumerate() {
        let zip_url = crate::http::resolve_zip_url(&base_url, entry);
        let zip_path = dir.join(format!("patch_v{}.zip", version));
        let base_pct: u16 = (i as u16) * pct_per_zip;

        // ── 下載 ──
        log_line!(
            "[自動更新] 下載 v{} {} → {}",
            version,
            zip_url,
            zip_path.display()
        );
        let _ = proxy.send_event(UserEvent::SetStatus(format!(
            "下載 v{}（{}/{}）...",
            version,
            i + 1,
            total_count
        )));
        let proxy_clone = proxy.clone();
        let pct_per = pct_per_zip;
        let body = crate::http::http_get_with_progress(
            &zip_url,
            move |downloaded, total| {
                let cur_pct: u8 = if total > 0 {
                    ((downloaded * 100) / total).min(100) as u8
                } else {
                    ((downloaded / (64 * 1024)).min(95)) as u8
                };
                let tot_pct: u16 = base_pct + cur_pct as u16 * pct_per / 100;
                let _ = proxy_clone.send_event(UserEvent::PushProgress {
                    current_pct: cur_pct,
                    total_pct: tot_pct.min(80) as u8,
                });
            },
            512 * 1024 * 1024,
        )
        .with_context(|| format!("下載 v{} 失敗：{}", version, zip_url))?;
        std::fs::write(&zip_path, &body)
            .with_context(|| format!("寫入 {} 失敗", zip_path.display()))?;
        log_line!("[自動更新] v{} 已下載 {} bytes", version, body.len());

        // ── 直接解壓到 launcher 目錄(zip 內路徑就是檔案最終位置,覆蓋既有檔)──
        let _ = proxy.send_event(UserEvent::SetStatus(format!(
            "解壓 v{}（{}/{}）...",
            version,
            i + 1,
            total_count
        )));
        let count =
            extract_zip(&zip_path, &dir).with_context(|| format!("解壓 v{} 失敗", version))?;
        log_line!(
            "[自動更新] v{} 已解壓 {} 個檔案到 {}",
            version,
            count,
            dir.display()
        );

        // ── 解壓完即刪 zip(主流程已收檔,zip 殘留沒意義);失敗只記 log 不中斷 ──
        match std::fs::remove_file(&zip_path) {
            Ok(()) => log_line!("[自動更新] 已移除 {}", zip_path.display()),
            Err(e) => log_line!("[自動更新] 移除 {} 失敗：{}（忽略）", zip_path.display(), e),
        }

        let _ = proxy.send_event(UserEvent::PushProgress {
            current_pct: 100,
            total_pct: (base_pct + pct_per_zip).min(80) as u8,
        });
    }

    // ── eat.exe 階段:對 launcher 目錄做後處理(80 → 100%) ──
    // eat.exe 存在性已在函式入口前置檢查過,這裡直接執行
    let _ = proxy.send_event(UserEvent::SetStatus("吃檔工具執行中...".into()));
    log_line!("[自動更新] 啟動 eat.exe {}", eat_path.display());
    let status = std::process::Command::new(&eat_path)
        .current_dir(&dir)
        .status()
        .context("啟動 eat.exe 失敗")?;
    if !status.success() {
        anyhow::bail!("eat.exe 退出代碼非 0：{}", status);
    }
    log_line!("[自動更新] eat.exe 完成");

    // ── 全部成功:原子寫回 Login.ini.Updated = target_version ──
    write_local_version(target_version)
        .with_context(|| format!("寫回 Login.ini.Updated = v{} 失敗", target_version))?;
    log_line!("[自動更新] 已記錄本機資源版本 v{}", target_version);

    let _ = proxy.send_event(UserEvent::PushProgress {
        current_pct: 100,
        total_pct: 100,
    });
    Ok(())
}

/// 把 ZIP 解壓到 dest 目錄，回傳寫入的檔案數
fn extract_zip(zip_path: &std::path::Path, dest: &std::path::Path) -> Result<usize> {
    let f = std::fs::File::open(zip_path).context("開啟 zip 失敗")?;
    let mut archive = zip::ZipArchive::new(f).context("解析 zip 失敗")?;
    let mut count = 0usize;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("讀取 zip entry #{i}"))?;
        // mangled_name() 已經處理路徑跳脫（去除 `..` / 絕對路徑），防止 zip slip
        let rel = file.mangled_name();
        let outpath = dest.join(&rel);
        if file.is_dir() {
            std::fs::create_dir_all(&outpath)?;
            continue;
        }
        if let Some(parent) = outpath.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(&outpath)
            .with_context(|| format!("建立 {} 失敗", outpath.display()))?;
        std::io::copy(&mut file, &mut out)?;
        count += 1;
    }
    Ok(count)
}

pub fn run_gui() -> Result<()> {
    // 啟動時的更新流程（同步、無進度 UI）：
    //   list_update 必須在 load_list_file() 之前，後面才會讀到下載後的新 list.txt
    //   auto_update_check 只判斷有沒有新版本，安裝動作延後到 webview 就緒後再彈窗
    let initial_cfg = load_list_file().launcher;
    let dir = exe_dir();
    try_list_update(&initial_cfg, &dir);
    let pending_update = check_auto_update(&initial_cfg);

    let list_file = load_list_file();
    let skin_name = list_file.launcher.active_skin.clone();
    let skin_dir = exe_dir().join("skins").join(&skin_name);
    let index_html = skin_dir.join("index.html");
    if !index_html.exists() {
        anyhow::bail!(
            "找不到 skin：{}\n請確認 skins/{}/index.html 存在",
            index_html.display(),
            skin_name
        );
    }

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let mut window_builder = WindowBuilder::new()
        .with_title("Lineage 3.8 登入器")
        .with_inner_size(LogicalSize::new(760.0, 500.0))
        .with_resizable(false)
        .with_maximizable(false) // 禁止放大(雙擊標題列、Win+Up 等系統手勢)
        .with_minimizable(false) // 禁止縮小到工作列
        .with_decorations(false)
        .with_window_icon(build_tao_app_icon());
    #[cfg(target_os = "windows")]
    {
        use tao::platform::windows::WindowBuilderExtWindows;
        window_builder = window_builder.with_taskbar_icon(build_tao_app_icon());
    }
    let window = window_builder
        .build(&event_loop)
        .context("tao window 建立失敗")?;

    let servers = Arc::new(Mutex::new(list_file.servers.clone()));
    // 公告 URL（啟用時 push 給 webview，未啟用或空字串則跳過）
    let announcement_url = if list_file.launcher.announcement_enabled {
        list_file.launcher.announcement_url.clone()
    } else {
        String::new()
    };
    let official_url = list_file.launcher.official_url.clone();
    let customer_url = list_file.launcher.customer_service_url.clone();

    // 玩家偏好(視窗化 / 解析度) — 載一次,push 給 JS,讓 UI 反映上次選擇
    let user_prefs = crate::config::UserPrefs::load();

    // IPC handler：解析 JS postMessage 字串成 JsMessage 並透過 proxy 派送 UserEvent
    let proxy_for_handler = event_loop.create_proxy();
    let servers_for_handler = servers.clone();
    // pending_update 在第一次 IPC Ready 時被 take() 消費，避免重複彈窗
    let pending_update_shared: Arc<Mutex<Option<crate::http::UpdateInfo>>> =
        Arc::new(Mutex::new(pending_update));
    let pending_for_handler = pending_update_shared.clone();
    let ipc_handler = move |req: Request<String>| {
        let body = req.body();
        let msg: JsMessage = match serde_json::from_str(body) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[IPC] 解析失敗：{e}（body={body:?}）");
                return;
            }
        };
        match msg {
            JsMessage::Ready => {
                let _ = proxy_for_handler.send_event(UserEvent::PushServers);
                // 若有待處理的版本更新，丟給主執行緒彈窗（webview 已就緒）；
                // 否則進度條補滿 100%,讓使用者一眼知道「無更新、可以開始」。
                if let Ok(mut guard) = pending_for_handler.lock() {
                    match guard.take() {
                        Some(info) => {
                            let _ = proxy_for_handler.send_event(UserEvent::AutoUpdatePrompt(info));
                        }
                        None => {
                            let _ = proxy_for_handler.send_event(UserEvent::PushProgress {
                                current_pct: 100,
                                total_pct: 100,
                            });
                        }
                    }
                }
            }
            JsMessage::Select { .. } => {}
            JsMessage::Launch {
                server_idx,
                windowed,
                window_mode,
            } => {
                // 4..=7 是合法 WindowMode,預設 5(800x600)
                let mode = window_mode.filter(|m| (4..=7).contains(m)).unwrap_or(5);
                // 順手把當前選擇寫進 launcher.ini,下次啟動沿用
                crate::config::UserPrefs {
                    windowed,
                    window_mode: mode,
                }
                .save();
                log_line!("[IPC] 收到 launch 請求 server_idx={server_idx} windowed={windowed} window_mode={mode}");
                let list = servers_for_handler.lock().unwrap().clone();
                match build_launch_event(&list, server_idx, windowed, mode) {
                    Ok(ev) => {
                        log_line!("[IPC] build_launch_event OK，送 LaunchGame");
                        let _ = proxy_for_handler.send_event(ev);
                    }
                    Err(msg) => {
                        log_line!("[IPC] build_launch_event 失敗：{msg}");
                        let _ = proxy_for_handler.send_event(UserEvent::ShowError(msg));
                    }
                }
            }
            JsMessage::SavePrefs {
                windowed,
                window_mode,
            } => {
                let mode = if (4..=7).contains(&window_mode) {
                    window_mode
                } else {
                    5
                };
                let prefs = crate::config::UserPrefs {
                    windowed,
                    window_mode: mode,
                };
                prefs.save();
            }
            JsMessage::Cancel => {
                let _ = proxy_for_handler.send_event(UserEvent::Close);
            }
            JsMessage::Drag => {
                let _ = proxy_for_handler.send_event(UserEvent::DragWindow);
            }
            JsMessage::OpenUrl { url } => {
                let trimmed = url.trim();
                if !trimmed.is_empty() {
                    let _ =
                        proxy_for_handler.send_event(UserEvent::OpenExternal(trimmed.to_string()));
                }
            }
        }
    };

    // 用 custom protocol `lineage://` 載入 skin 資源（避免 file:// 在 WebView2 觸發 URI panic）
    // 相對引用 style.css / launcher.js / bg.jpg 會經由同個 protocol 取得
    let skin_dir_for_proto = skin_dir.clone();
    let webview = WebViewBuilder::new(&window)
        .with_custom_protocol("lineage".to_string(), move |req| {
            serve_skin_file(&skin_dir_for_proto, req)
        })
        .with_url("lineage://localhost/index.html")
        .with_ipc_handler(ipc_handler)
        .with_accept_first_mouse(true)
        .build()
        .context("WebView2 建立失敗")?;

    // event loop 內 spawn worker thread 用：worker 透過這個 proxy 把進度 / Close 事件回送
    let proxy_for_loop = event_loop.create_proxy();
    let game_running = Arc::new(AtomicBool::new(false));
    let game_running_for_loop = game_running.clone();
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. }
            | Event::UserEvent(UserEvent::Close) => {
                if game_running_for_loop.load(Ordering::Relaxed) {
                    log_line!("[GUI] game is running; hide launcher instead of exiting");
                    window.set_visible(false);
                } else {
                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::UserEvent(UserEvent::PushServers) => {
                let list = servers.lock().unwrap().clone();
                let js_list: Vec<JsServer> = list.iter().map(|s| JsServer {
                    name: s.name.clone(),
                    ip: s.ip.clone(),
                    port: s.port,
                    used: s.used,
                }).collect();
                let json = serde_json::to_string(&js_list).unwrap_or_else(|_| "[]".into());
                let url_json = serde_json::to_string(&announcement_url).unwrap_or_else(|_| "\"\"".into());
                let official_json = serde_json::to_string(&official_url).unwrap_or_else(|_| "\"\"".into());
                let customer_json = serde_json::to_string(&customer_url).unwrap_or_else(|_| "\"\"".into());
                let prefs_json = format!(
                    "{{\"windowed\":{},\"windowMode\":{}}}",
                    user_prefs.windowed, user_prefs.window_mode
                );
                let script = format!(
                    "if(window.lineage){{\
                       window.lineage.setServers({json});\
                       window.lineage.setVersion('{APP_VERSION}');\
                       if(window.lineage.setAnnouncement)window.lineage.setAnnouncement({url_json});\
                       if(window.lineage.setLinks)window.lineage.setLinks({{official:{official_json},support:{customer_json}}});\
                       if(window.lineage.setPrefs)window.lineage.setPrefs({prefs_json});\
                     }}"
                );
                let _ = webview.evaluate_script(&script);
                // 背景探測每個伺服器的實際連線狀態（TCP connect with timeout）
                spawn_server_status_probe(&list, proxy_for_loop.clone());
            }
            Event::UserEvent(UserEvent::PushServerStatus { index, online }) => {
                let script = format!(
                    "if(window.lineage&&window.lineage.setServerStatus)window.lineage.setServerStatus({index},{});",
                    if online { "true" } else { "false" }
                );
                let _ = webview.evaluate_script(&script);
            }
            Event::UserEvent(UserEvent::ShowError(msg)) => {
                let escaped = msg
                    .replace('\\', "\\\\")
                    .replace('\'', "\\'")
                    .replace('\n', "\\n");
                let _ = webview.evaluate_script(&format!("window.alert('{}')", escaped));
            }
            Event::UserEvent(UserEvent::LaunchGame { ip, port, game_dir, inject_buffer, inject_source_path, packet_encrypt, windowed, window_mode }) => {
                game_running_for_loop.store(true, Ordering::Relaxed);
                // 鎖 UI + 顯示啟動中狀態，避免重複點擊
                let _ = proxy_for_loop.send_event(UserEvent::SetLocked(true));
                let _ = proxy_for_loop.send_event(UserEvent::SetStatus(
                    format!("遊戲啟動中 → {ip}:{port}")
                ));
                let proxy_started = proxy_for_loop.clone();
                let proxy_done = proxy_for_loop.clone();
                let game_running_done = game_running_for_loop.clone();
                std::thread::spawn(move || {
                    // CreateProcess 成功 → 只「隱藏」視窗（不關 process）
                    // 因為 launch_game 後續的 patch thread 跟 WaitForSingleObject 都在這個進程內，
                    // 真的 Exit 會把這些一起殺掉，patch 寫不進去就會跳「RunTime Expired」。
                    let on_started: Option<Box<dyn FnOnce() + Send>> = Some(Box::new(move || {
                        let _ = proxy_started.send_event(UserEvent::SetWindowVisible(false));
                    }));
                    match crate::launch_game(&ip, port, &game_dir, false, inject_buffer, inject_source_path, packet_encrypt, windowed, window_mode, on_started) {
                        Ok(_) => {
                            game_running_done.store(false, Ordering::Relaxed);
                            let _ = proxy_done.send_event(UserEvent::Close);
                            // 遊戲已正常結束（WaitForSingleObject 解開）→ launcher 進程也跟著結束
                            let _ = proxy_done.send_event(UserEvent::Close);
                        }
                        Err(e) => {
                            game_running_done.store(false, Ordering::Relaxed);
                            log_line!("[launch] error: {e:#}");
                            // 啟動或修補階段失敗 → 把視窗叫回來、顯示錯誤、解鎖讓使用者重試
                            log_line!("[啟動] 失敗：{e:#}");
                            let _ = proxy_done.send_event(UserEvent::SetWindowVisible(true));
                            let _ = proxy_done.send_event(UserEvent::ShowError(
                                format!("啟動遊戲失敗：\n{e:#}")
                            ));
                            let _ = proxy_done.send_event(UserEvent::SetStatus(
                                format!("啟動失敗：{}", short_error(&e))
                            ));
                            let _ = proxy_done.send_event(UserEvent::SetLocked(false));
                        }
                    }
                });
                // ※ 不立刻 Exit。CreateProcess 成功後視窗隱藏 → 使用者覺得「launcher 已關」，
                //   但其實 process 還活著等 patch thread 跑完。遊戲結束才真正關閉 launcher process。
            }
            Event::UserEvent(UserEvent::DragWindow) => {
                let _ = window.drag_window();
            }
            Event::UserEvent(UserEvent::SetWindowVisible(v)) => {
                window.set_visible(v);
            }
            Event::UserEvent(UserEvent::OpenExternal(url)) => {
                open_external_url(&url);
            }
            Event::UserEvent(UserEvent::PushProgress { current_pct, total_pct }) => {
                let script = format!(
                    "if(window.lineage&&window.lineage.setProgress)window.lineage.setProgress({current_pct},{total_pct});"
                );
                let _ = webview.evaluate_script(&script);
            }
            Event::UserEvent(UserEvent::SetLocked(locked)) => {
                let script = format!(
                    "if(window.lineage&&window.lineage.setLocked)window.lineage.setLocked({});",
                    if locked { "true" } else { "false" }
                );
                let _ = webview.evaluate_script(&script);
            }
            Event::UserEvent(UserEvent::SetStatus(text)) => {
                let json = serde_json::to_string(&text).unwrap_or_else(|_| "\"\"".into());
                let script = format!(
                    "if(window.lineage&&window.lineage.setStatus)window.lineage.setStatus({json});"
                );
                let _ = webview.evaluate_script(&script);
            }
            Event::UserEvent(UserEvent::AutoUpdatePrompt(info)) => {
                // 立刻鎖 UI：MessageBox 不是 launcher 視窗的 modal，使用者仍能點 launcher 按鈕
                let _ = proxy_for_loop.send_event(UserEvent::SetLocked(true));
                // 在 worker thread 處理：MessageBox 提示 → 下載 zip（推進度）→ 解壓 → 啟動 eat.exe → exit
                let proxy_for_worker = proxy_for_loop.clone();
                std::thread::spawn(move || {
                    run_auto_update_worker(info, proxy_for_worker);
                });
            }
            _ => {}
        }
    });
}
