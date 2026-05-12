//! 極簡 HTTP/HTTPS GET via WinINet
//!
//! 用於登入器啟動時的「列表更新」與「自動更新」。
//! 不引入 ureq/reqwest，避免 launcher.exe 從 ~800KB 膨脹到 ~2MB+。
//!
//! WinINet 走系統 IE/Edge 設定（含 proxy/PAC），對天堂這類老遊戲環境通常都通。

use anyhow::{anyhow, bail, Result};
use std::ffi::c_void;
use windows::core::HSTRING;
use windows::Win32::Networking::WinInet::*;

/// connect / receive / send 都用這個 timeout（毫秒）
const TIMEOUT_MS: u32 = 8000;

/// HTTP/HTTPS GET，回傳 response body（無進度回呼）
pub fn http_get(url: &str) -> Result<Vec<u8>> {
    http_get_with_progress(url, |_, _| {}, 256 * 1024 * 1024)
}

/// HTTP/HTTPS GET，每讀一塊 chunk 回呼 `on_progress(downloaded, total)`
///
/// `total` 從 Content-Length 標頭取得；標頭不存在時為 0（呼叫端應降級顯示）。
/// `max_bytes` 用來避免被惡意大檔灌爆，超過會回 Err。
pub fn http_get_with_progress<F: FnMut(u64, u64)>(
    url: &str,
    mut on_progress: F,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let ua = HSTRING::from("Lineage38Launcher/0.1");
    let url_h = HSTRING::from(url);

    unsafe {
        let h_inet = InternetOpenW(&ua, INTERNET_OPEN_TYPE_PRECONFIG.0, None, None, 0);
        if h_inet.is_null() {
            bail!("InternetOpenW 失敗");
        }

        // 設定三個 timeout，避免使用者卡在啟動畫面
        let timeout: u32 = TIMEOUT_MS;
        let opts = [
            INTERNET_OPTION_CONNECT_TIMEOUT,
            INTERNET_OPTION_RECEIVE_TIMEOUT,
            INTERNET_OPTION_SEND_TIMEOUT,
        ];
        for opt in opts {
            let _ = InternetSetOptionW(
                Some(h_inet),
                opt,
                Some(&timeout as *const u32 as *const c_void),
                std::mem::size_of::<u32>() as u32,
            );
        }

        let h_url = InternetOpenUrlW(
            h_inet,
            &url_h,
            None,
            INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
            Some(0),
        );
        if h_url.is_null() {
            let _ = InternetCloseHandle(h_inet);
            return Err(anyhow!("InternetOpenUrlW 失敗：{url}"));
        }

        // 取 Content-Length（HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER）
        // 失敗或無 header 都回 0，呼叫端要能容忍 total=0
        let total: u64 = {
            let mut value: u32 = 0;
            let mut buflen: u32 = 4;
            const HTTP_QUERY_CONTENT_LENGTH: u32 = 5;
            const HTTP_QUERY_FLAG_NUMBER: u32 = 0x20000000;
            let r = HttpQueryInfoW(
                h_url,
                HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                Some(&mut value as *mut u32 as *mut c_void),
                &mut buflen,
                None,
            );
            if r.is_ok() {
                value as u64
            } else {
                0
            }
        };

        on_progress(0, total);

        let mut result = Vec::with_capacity(if total > 0 { total as usize } else { 4096 });
        let mut buf = [0u8; 16 * 1024];
        loop {
            let mut bytes_read: u32 = 0;
            if InternetReadFile(
                h_url,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut bytes_read,
            )
            .is_err()
            {
                let _ = InternetCloseHandle(h_url);
                let _ = InternetCloseHandle(h_inet);
                bail!("InternetReadFile 失敗");
            }
            if bytes_read == 0 {
                break;
            }
            result.extend_from_slice(&buf[..bytes_read as usize]);
            on_progress(result.len() as u64, total);
            if result.len() as u64 > max_bytes {
                let _ = InternetCloseHandle(h_url);
                let _ = InternetCloseHandle(h_inet);
                bail!("response 超過 {} bytes 上限", max_bytes);
            }
        }

        let _ = InternetCloseHandle(h_url);
        let _ = InternetCloseHandle(h_inet);
        Ok(result)
    }
}

/// 公版 Update.ini 解析。格式:
/// ```ini
/// [Update]
/// version=3
/// 1=foo.zip
/// 2=bar.zip
/// 3=baz.zip
/// ```
/// `version` 是伺服器目前的最新資源版本(整數)。`1=` `2=` ... 各自指向「從 N-1 升到 N」的差異 zip,
/// 值可為相對 Update.ini 的檔名,或絕對 URL。section 名稱不影響(只看鍵名)。
pub fn parse_update_ini(content: &str, source_url: &str) -> Option<UpdateInfo> {
    let mut server_version: Option<u32> = None;
    let mut zips: Vec<(u32, String)> = Vec::new();
    for line in content.lines() {
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
        let val = v.trim().to_string();
        if key.eq_ignore_ascii_case("version") || key.eq_ignore_ascii_case("ver") {
            if let Ok(n) = val.parse::<u32>() {
                server_version = Some(n);
            }
        } else if let Ok(n) = key.parse::<u32>() {
            if !val.is_empty() {
                zips.push((n, val));
            }
        }
    }
    let server_version = server_version?;
    zips.sort_by_key(|&(n, _)| n);
    zips.dedup_by_key(|p| p.0);
    Some(UpdateInfo {
        server_version,
        zips,
        source_url: source_url.to_string(),
    })
}

/// 從 Update.ini 的 URL 推算 base URL(保留到最後一個 `/`),供相對檔名解析用。
pub fn base_url_of(update_ini_url: &str) -> String {
    update_ini_url
        .rfind('/')
        .map(|i| update_ini_url[..=i].to_string())
        .unwrap_or_default()
}

/// 把 zip 條目解析成完整 URL:絕對 URL 直接用,相對檔名接 `base_url`
pub fn resolve_zip_url(base_url: &str, entry: &str) -> String {
    if entry.starts_with("http://") || entry.starts_with("https://") {
        entry.to_string()
    } else {
        format!("{base_url}{entry}")
    }
}

#[derive(Debug, Clone)]
pub struct UpdateInfo {
    /// 伺服器當前最新資源版本
    pub server_version: u32,
    /// 各版本對應的 zip 條目(已依版本號升冪排序、去重)
    pub zips: Vec<(u32, String)>,
    /// 拉到此 manifest 的 URL,供 base URL 解析
    pub source_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_manifest() {
        let raw = "[Update]\nversion=3\n1=a.zip\n2=b.zip\n3=c.zip\n";
        let info = parse_update_ini(raw, "http://x/y/Update.ini").unwrap();
        assert_eq!(info.server_version, 3);
        assert_eq!(
            info.zips,
            vec![
                (1, "a.zip".into()),
                (2, "b.zip".into()),
                (3, "c.zip".into())
            ]
        );
    }

    #[test]
    fn parse_sorts_and_dedups() {
        let raw = "[Update]\n3=c.zip\nversion=3\n1=a.zip\n2=b.zip\n2=B.zip\n";
        let info = parse_update_ini(raw, "").unwrap();
        assert_eq!(info.zips.len(), 3);
        assert_eq!(info.zips[0].0, 1);
        assert_eq!(info.zips[1].0, 2);
        assert_eq!(info.zips[2].0, 3);
    }

    #[test]
    fn parse_missing_version_returns_none() {
        let raw = "1=a.zip\n";
        assert!(parse_update_ini(raw, "").is_none());
    }

    #[test]
    fn base_url_strips_filename() {
        assert_eq!(base_url_of("http://x/y/Update.ini"), "http://x/y/");
        assert_eq!(base_url_of("http://x/Update.ini"), "http://x/");
    }

    #[test]
    fn resolve_handles_absolute_and_relative() {
        let base = "http://x/y/";
        assert_eq!(resolve_zip_url(base, "a.zip"), "http://x/y/a.zip");
        assert_eq!(
            resolve_zip_url(base, "http://other/foo.zip"),
            "http://other/foo.zip"
        );
        assert_eq!(
            resolve_zip_url(base, "https://other/foo.zip"),
            "https://other/foo.zip"
        );
    }
}
