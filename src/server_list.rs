//! list.txt 編碼／解碼 — 與 LinLauncher 原生格式相容
//!
//! 演算法（與 tools/server_config.py 完全一致）：
//!   1. XOR：256 bytes XOR table 與 16-byte key 異或建表，再對資料逐位元組 XOR
//!   2. AES：AES-128-ECB 對「整 16 bytes block」加解密；尾段不足 16 bytes 不處理（XOR 而已）
//!   3. INI：[list] 區段，ServerData0 ~ ServerDataN，每個欄位是 base64
//!
//! Server_Info（213 bytes，#pragma pack(1)，UNICODE 編譯）：
//!   +0x00  64B  wchar_t name[32]
//!   +0x40  32B  char    ip[32]
//!   +0x60   4B  int     port
//!   +0x64   1B  bool    used
//!   +0x65  16B  BYTE    key[16]
//!   +0x75   1B  bool    encrypt
//!   +0x76   1B  bool    usehelper
//!   +0x77   1B  bool    usebd
//!   +0x78  64B  wchar_t bdfile[32]
//!   +0xB8   1B  bool    randkey
//!   +0xB9   4B  ulong   rsa_e
//!   +0xBD   4B  ulong   rsa_d
//!   +0xC1   4B  ulong   rsa_n
//!   +0xC5  16B  BYTE    fix[16]   （保留，全零）

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

use crate::legacy_text::TextEncodingMode;

/// LinLauncher 的固定 list.txt 加密金鑰
pub const SERVER_LIST_KEY: &[u8; 16] = b"4zF8sAc5bYkCRM3w";

/// Server_Info 結構長度（pack(1)）
pub const SIZEOF_SERVER_INFO: usize = 213;

/// LinLauncher 的 list.txt 最多 8 個伺服器
pub const MAX_SERVERS: usize = 8;
pub const DEFAULT_INVENTORY_LIMIT_VALUE: u32 = 255;
pub const MIN_INVENTORY_LIMIT_VALUE: u32 = 1;
pub const MAX_INVENTORY_LIMIT_VALUE: u32 = 999;
pub const DEFAULT_IMG_LIMIT_VALUE: u32 = 50000;
pub const MIN_IMG_LIMIT_VALUE: u32 = 6295;
pub const MAX_IMG_LIMIT_VALUE: u32 = 500000;

/// configenc.cpp 固定 XOR 表（與 tools/server_config.py、launcher/src/inject.rs 同一份）
const XOR_TABLE: [u8; 256] = [
    0x7E, 0x89, 0xDC, 0x78, 0x7F, 0x4B, 0xB6, 0x4F, 0x7D, 0x0D, 0x08, 0x16, 0x7C, 0xCF, 0x62, 0x21,
    0x79, 0x80, 0x74, 0xA4, 0x78, 0x42, 0x1E, 0x93, 0x7A, 0x04, 0xA0, 0xCA, 0x7B, 0xC6, 0xCA, 0xFD,
    0x6C, 0xBC, 0x2E, 0xB0, 0x6D, 0x7E, 0x44, 0x87, 0x6F, 0x38, 0xFA, 0xDE, 0x6E, 0xFA, 0x90, 0xE9,
    0x6B, 0xB5, 0x86, 0x6C, 0x6A, 0x77, 0xEC, 0x5B, 0x68, 0x31, 0x52, 0x02, 0x69, 0xF3, 0x38, 0x35,
    0x62, 0xAF, 0x7F, 0x08, 0x63, 0x6D, 0x15, 0x3F, 0x61, 0x2B, 0xAB, 0x66, 0x60, 0xE9, 0xC1, 0x51,
    0x65, 0xA6, 0xD7, 0xD4, 0x64, 0x64, 0xBD, 0xE3, 0x66, 0x22, 0x03, 0xBA, 0x67, 0xE0, 0x69, 0x8D,
    0x48, 0xD7, 0xCB, 0x20, 0x49, 0x15, 0xA1, 0x17, 0x4B, 0x53, 0x1F, 0x4E, 0x4A, 0x91, 0x75, 0x79,
    0x4F, 0xDE, 0x63, 0xFC, 0x4E, 0x1C, 0x09, 0xCB, 0x4C, 0x5A, 0xB7, 0x92, 0x4D, 0x98, 0xDD, 0xA5,
    0x46, 0xC4, 0x9A, 0x98, 0x47, 0x06, 0xF0, 0xAF, 0x45, 0x40, 0x4E, 0xF6, 0x44, 0x82, 0x24, 0xC1,
    0x41, 0xCD, 0x32, 0x44, 0x40, 0x0F, 0x58, 0x73, 0x42, 0x49, 0xE6, 0x2A, 0x43, 0x8B, 0x8C, 0x1D,
    0x54, 0xF1, 0x68, 0x50, 0x55, 0x33, 0x02, 0x67, 0x57, 0x75, 0xBC, 0x3E, 0x56, 0xB7, 0xD6, 0x09,
    0x53, 0xF8, 0xC0, 0x8C, 0x52, 0x3A, 0xAA, 0xBB, 0x50, 0x7C, 0x14, 0xE2, 0x51, 0xBE, 0x7E, 0xD5,
    0x5A, 0xE2, 0x39, 0xE8, 0x5B, 0x20, 0x53, 0xDF, 0x59, 0x66, 0xED, 0x86, 0x58, 0xA4, 0x87, 0xB1,
    0x5D, 0xEB, 0x91, 0x34, 0x5C, 0x29, 0xFB, 0x03, 0x5E, 0x6F, 0x45, 0x5A, 0x5F, 0xAD, 0x2F, 0x6D,
    0xE1, 0x35, 0x1B, 0x80, 0xE0, 0xF7, 0x71, 0xB7, 0xE2, 0xB1, 0xCF, 0xEE, 0xE3, 0x73, 0xA5, 0xD9,
    0xE6, 0x3C, 0xB3, 0x5C, 0xE7, 0xFE, 0xD9, 0x6B, 0xE5, 0xB8, 0x67, 0x32, 0xE4, 0x7A, 0x0D, 0x05,
];

/// 用 16-byte key 修改 256 bytes 的 XOR 表
fn build_xor_table(key: &[u8; 16]) -> [u8; 256] {
    let mut table = XOR_TABLE;
    for i in 0..256 {
        table[i] ^= key[i % 16];
    }
    table
}

/// 加密：先 XOR table，再 AES-128-ECB 加密「整 16 bytes block」（尾段剩餘不加密）
pub fn config_encrypt(key: &[u8; 16], data: &mut [u8]) {
    let table = build_xor_table(key);
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= table[i % 256];
    }
    let cipher = Aes128::new(key.into());
    for chunk in data.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
}

/// 解密：先 AES-128-ECB 解密「整 16 bytes block」，再 XOR table
pub fn config_decrypt(key: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(key.into());
    for chunk in data.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    let table = build_xor_table(key);
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= table[i % 256];
    }
}

/// config.ini 加密格式標頭。`ENC1:<base64>` 表示「整檔 XOR+AES 加密 + base64」
const CONFIG_ENC_PREFIX: &str = "ENC1:";

/// 加密 config.ini 純文字內容 → `ENC1:<base64>`
pub fn encrypt_config_text(plaintext: &str) -> String {
    let mut buf = plaintext.as_bytes().to_vec();
    config_encrypt(SERVER_LIST_KEY, &mut buf);
    format!("{}{}\n", CONFIG_ENC_PREFIX, B64.encode(&buf))
}

/// 解密 config.ini：自動辨識 `ENC1:` 加密格式或舊版明文 INI
///   - `ENC1:<base64>` → 解密回明文 INI
///   - 開頭是 `[` → 視為舊版明文，原樣回傳
///   - 其他 → 錯誤
pub fn decrypt_config_text(content: &str) -> Result<String> {
    let trimmed = content.trim_start();
    if let Some(rest) = trimmed.strip_prefix(CONFIG_ENC_PREFIX) {
        let b64: String = rest.chars().filter(|c| !c.is_whitespace()).collect();
        let mut buf = B64.decode(&b64).context("config.ini base64 解碼失敗")?;
        config_decrypt(SERVER_LIST_KEY, &mut buf);
        return String::from_utf8(buf).context("config.ini 解密後不是有效 UTF-8");
    }
    if trimmed.starts_with('[') {
        return Ok(content.to_string()); // 舊版明文，遷移用
    }
    bail!("config.ini 格式無法辨識（既非 ENC1: 加密也非 INI 明文）")
}

/// 伺服器配置（對應 SHARE_INFO 共享記憶體欄位）
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    pub name: String,
    pub ip: String,
    pub port: i32,
    pub used: bool,
    pub key: [u8; 16],
    pub encrypt: bool,
    pub usehelper: bool,
    pub usebd: bool,
    pub bdfile: String,
    pub randkey: bool,
    pub rsa_e: u32,
    pub rsa_d: u32,
    pub rsa_n: u32,
}

impl ServerInfo {
    pub fn new(name: &str, ip: &str, port: i32) -> Self {
        Self {
            name: name.to_string(),
            ip: ip.to_string(),
            port,
            used: true,
            ..Default::default()
        }
    }

    /// 序列化為 213 bytes（pack(1)，UNICODE）
    pub fn to_bytes(&self) -> [u8; SIZEOF_SERVER_INFO] {
        let mut buf = [0u8; SIZEOF_SERVER_INFO];

        // name: wchar_t[32] = 64 bytes (UTF-16LE)，留 2 bytes 給 null terminator
        let name_units: Vec<u16> = self.name.encode_utf16().take(31).collect();
        for (i, u) in name_units.iter().enumerate() {
            buf[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }

        // ip: char[32] = 32 bytes (ASCII)
        let ip_bytes = self.ip.as_bytes();
        let ip_len = ip_bytes.len().min(31);
        buf[64..64 + ip_len].copy_from_slice(&ip_bytes[..ip_len]);

        // port
        buf[96..100].copy_from_slice(&self.port.to_le_bytes());
        // used
        buf[100] = self.used as u8;
        // key[16]
        buf[101..117].copy_from_slice(&self.key);
        // flags
        buf[117] = self.encrypt as u8;
        buf[118] = self.usehelper as u8;
        buf[119] = self.usebd as u8;

        // bdfile: wchar_t[32] = 64 bytes
        let bd_units: Vec<u16> = self.bdfile.encode_utf16().take(31).collect();
        for (i, u) in bd_units.iter().enumerate() {
            buf[120 + i * 2..120 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }

        // randkey + RSA
        buf[184] = self.randkey as u8;
        buf[185..189].copy_from_slice(&self.rsa_e.to_le_bytes());
        buf[189..193].copy_from_slice(&self.rsa_d.to_le_bytes());
        buf[193..197].copy_from_slice(&self.rsa_n.to_le_bytes());
        // fix[16] 保留全零

        buf
    }

    /// 反序列化 213 bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < SIZEOF_SERVER_INFO {
            bail!("資料太短：{} < {}", data.len(), SIZEOF_SERVER_INFO);
        }

        let name = decode_utf16_z(&data[0..64]);
        let ip = decode_ascii_z(&data[64..96]);
        let port = i32::from_le_bytes(data[96..100].try_into().unwrap());
        let used = data[100] != 0;
        let mut key = [0u8; 16];
        key.copy_from_slice(&data[101..117]);
        let encrypt = data[117] != 0;
        let usehelper = data[118] != 0;
        let usebd = data[119] != 0;
        let bdfile = decode_utf16_z(&data[120..184]);
        let randkey = data[184] != 0;
        let rsa_e = u32::from_le_bytes(data[185..189].try_into().unwrap());
        let rsa_d = u32::from_le_bytes(data[189..193].try_into().unwrap());
        let rsa_n = u32::from_le_bytes(data[193..197].try_into().unwrap());

        Ok(Self {
            name,
            ip,
            port,
            used,
            key,
            encrypt,
            usehelper,
            usebd,
            bdfile,
            randkey,
            rsa_e,
            rsa_d,
            rsa_n,
        })
    }
}

/// 把 UTF-16LE 緩衝區（含 null terminator）解析為 String
fn decode_utf16_z(buf: &[u8]) -> String {
    let units: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// 把 ASCII 緩衝區（含 null terminator）解析為 String
fn decode_ascii_z(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// 輔助功能開關（寫在 config.ini 的 [aux] section）
///
/// 7 個欄位對齊編碼器「編碼」分頁 7 個 checkbox。
/// launcher.exe 啟動遊戲後讀 [aux]：
///   - "啟動時 patch" 類（封包加密、防外掛、變身檔、移動封包不加密、多開）→ 立即套用
///   - "HOME 鍵切換" 類（內建喝水輔助）→ 進入遊戲後按 HOME 才啟動
#[derive(Debug, Clone)]
pub struct AuxConfig {
    pub packet_encrypt: bool,          // 封包加密
    pub anti_cheat_basic: bool,        // 防外掛
    pub anti_cheat_advanced: bool,     // 進階防外掛
    pub transform_file: bool,          // 變身檔
    pub multi_instance: bool,          // 允許多開
    pub move_packet_no_encrypt: bool,  // 移動封包不加密
    pub lhx_aux_enabled: bool,         // 內建喝水輔助程式
    pub hp_mp_limit_enabled: bool,     // 血魔突破上限
    pub inventory_limit_enabled: bool, // 背包上限
    pub equip_ui_enabled: bool,        // 裝備欄位 7.6
    pub img_limit_enabled: bool,       // IMG 上限
    pub dynamic_dialog_enabled: bool,  // 動態對話檔
    pub pickup_toast_enabled: bool,    // 左下道具提示(撿物 toast)
    pub exp_drift_enabled: bool,       // 金幣經驗值提示(畫面飄字)
    pub inventory_limit_value: u32,
    pub img_limit_value: u32,
    pub text_encoding: TextEncodingMode,
}

impl Default for AuxConfig {
    fn default() -> Self {
        Self {
            packet_encrypt: false,
            anti_cheat_basic: false,
            anti_cheat_advanced: false,
            transform_file: false,
            multi_instance: false,
            move_packet_no_encrypt: false,
            lhx_aux_enabled: true,
            hp_mp_limit_enabled: true,
            inventory_limit_enabled: true,
            equip_ui_enabled: true,
            img_limit_enabled: true,
            dynamic_dialog_enabled: true,
            pickup_toast_enabled: true,
            exp_drift_enabled: true,
            inventory_limit_value: DEFAULT_INVENTORY_LIMIT_VALUE,
            img_limit_value: DEFAULT_IMG_LIMIT_VALUE,
            text_encoding: TextEncodingMode::Big5,
        }
    }
}

fn normalize_aux_config(mut aux: AuxConfig) -> AuxConfig {
    aux.anti_cheat_basic = false;
    aux.anti_cheat_advanced = false;
    aux
}

impl AuxConfig {
    /// 是否需要監聽 HOME 鍵（內建喝水輔助勾起時才需要）
    pub fn needs_home_listener(&self) -> bool {
        self.lhx_aux_enabled
    }
}

/// 登入器外觀設定（寫在 list.txt 的 [launcher] section）
#[derive(Debug, Clone)]
pub struct LauncherConfig {
    /// 作用中的 skin 名稱（對應 launcher.exe 旁的 skins/<name>/ 資料夾）
    pub active_skin: String,
    /// 公告網頁啟用 + URL（登入器啟動時嵌入或開啟）
    pub announcement_enabled: bool,
    pub announcement_url: String,
    /// 列表更新啟用 + URL（從遠端拉 list.txt）
    pub list_update_enabled: bool,
    pub list_update_url: String,
    /// 自動更新啟用 + URL（檢查登入器版本）
    pub auto_update_enabled: bool,
    pub auto_update_url: String,
    /// 上方 tab 列「官網」按下開啟的 URL（空字串則隱藏）
    pub official_url: String,
    /// 上方 tab 列「客服」按下開啟的 URL（空字串則隱藏）
    pub customer_service_url: String,
}

impl Default for LauncherConfig {
    /// 預設 URL 對齊 Encode v3.80 的範例值；公告預設啟用、其他兩項預設關閉
    fn default() -> Self {
        Self {
            active_skin: "default".to_string(),
            announcement_enabled: true,
            announcement_url: "http://tw.beanfun.com/lineage/patch/main_defaultTemplate.asp"
                .to_string(),
            list_update_enabled: false,
            list_update_url: "http://dl.dropbox.com/u/5114050/Login.ini".to_string(),
            auto_update_enabled: false,
            auto_update_url: "http://dl.dropbox.com/u/5114050/LoginUpdate/Update.ini".to_string(),
            official_url: "http://tw.beanfun.com/lineage/".to_string(),
            customer_service_url: "http://tw.beanfun.com/beanfun_help/".to_string(),
        }
    }
}

/// list.txt 完整內容（伺服器列表 + 輔助設定 + 登入器外觀）
#[derive(Debug, Clone, Default)]
pub struct ListFile {
    pub servers: Vec<ServerInfo>,
    pub aux: AuxConfig,
    pub launcher: LauncherConfig,
}

/// 從 list.txt 內容解析所有 ServerData（向後相容單純伺服器列表用法）
pub fn parse_list_txt(content: &str) -> Result<Vec<ServerInfo>> {
    Ok(parse_list_file(content)?.servers)
}

/// 解析 list.txt：[list] section + [aux] section
pub fn parse_list_file(content: &str) -> Result<ListFile> {
    let mut current_section = String::new();
    let mut servers = Vec::new();
    let mut aux = AuxConfig::default();
    let mut launcher = LauncherConfig::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].to_ascii_lowercase();
            continue;
        }

        let (key, value) = match line.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match current_section.as_str() {
            "list" => {
                if !key.starts_with("serverdata") {
                    continue;
                }
                let raw = B64
                    .decode(value)
                    .with_context(|| format!("base64 解碼失敗：{key}"))?;
                if raw.len() < SIZEOF_SERVER_INFO {
                    continue;
                }
                let mut buf = raw;
                config_decrypt(SERVER_LIST_KEY, &mut buf);
                let info =
                    ServerInfo::from_bytes(&buf).with_context(|| format!("{key} 解析失敗"))?;
                servers.push(info);
            }
            "aux" => {
                let v = parse_bool(value);
                match key.as_str() {
                    "packet_encrypt" => aux.packet_encrypt = v,
                    "anti_cheat_basic" => aux.anti_cheat_basic = v,
                    "anti_cheat_advanced" => aux.anti_cheat_advanced = v,
                    "transform_file" => aux.transform_file = v,
                    "multi_instance" => aux.multi_instance = v,
                    "move_packet_no_encrypt" => aux.move_packet_no_encrypt = v,
                    "lhx_aux_enabled" => aux.lhx_aux_enabled = v,
                    "hp_mp_limit_enabled" => aux.hp_mp_limit_enabled = v,
                    "inventory_limit_enabled" => aux.inventory_limit_enabled = v,
                    "equip_ui_enabled" => aux.equip_ui_enabled = v,
                    "img_limit_enabled" => aux.img_limit_enabled = v,
                    "dynamic_dialog_enabled" => aux.dynamic_dialog_enabled = v,
                    "pickup_toast_enabled" => aux.pickup_toast_enabled = v,
                    "exp_drift_enabled" => aux.exp_drift_enabled = v,
                    "inventory_limit_value" => {
                        aux.inventory_limit_value = parse_u32_clamped(
                            value,
                            DEFAULT_INVENTORY_LIMIT_VALUE,
                            MIN_INVENTORY_LIMIT_VALUE,
                            MAX_INVENTORY_LIMIT_VALUE,
                        )
                    }
                    "img_limit_value" => {
                        aux.img_limit_value = parse_u32_clamped(
                            value,
                            DEFAULT_IMG_LIMIT_VALUE,
                            MIN_IMG_LIMIT_VALUE,
                            MAX_IMG_LIMIT_VALUE,
                        )
                    }
                    "text_encoding" => {
                        aux.text_encoding = TextEncodingMode::from_config_value(value)
                    }
                    _ => {} // 未知 key 忽略（容忍舊版 config.ini 多餘欄位）
                }
            }
            "launcher" => match key.as_str() {
                "active_skin" => launcher.active_skin = value.to_string(),
                "announcement_enabled" => launcher.announcement_enabled = parse_bool(value),
                "announcement_url" => launcher.announcement_url = value.to_string(),
                "list_update_enabled" => launcher.list_update_enabled = parse_bool(value),
                "list_update_url" => launcher.list_update_url = value.to_string(),
                "auto_update_enabled" => launcher.auto_update_enabled = parse_bool(value),
                "auto_update_url" => launcher.auto_update_url = value.to_string(),
                "official_url" => launcher.official_url = value.to_string(),
                "customer_service_url" => launcher.customer_service_url = value.to_string(),
                _ => {}
            },
            _ => {} // 未知 section 忽略
        }
    }

    aux = normalize_aux_config(aux);

    Ok(ListFile {
        servers,
        aux,
        launcher,
    })
}

/// 把伺服器列表編碼為 list.txt 文字(純 [list] 格式,beanfun 客戶端可直接讀)
pub fn build_list_txt(servers: &[ServerInfo]) -> Result<String> {
    if servers.len() > MAX_SERVERS {
        return Err(anyhow!(
            "最多 {} 個伺服器，傳入 {} 個",
            MAX_SERVERS,
            servers.len()
        ));
    }
    let mut out = String::from("[list]\n");
    for (i, srv) in servers.iter().enumerate() {
        let mut buf = srv.to_bytes().to_vec();
        config_encrypt(SERVER_LIST_KEY, &mut buf);
        let b64 = B64.encode(&buf);
        out.push_str(&format!("ServerData{}={}\n", i, b64));
    }
    Ok(out)
}

/// 編碼 config.ini（[aux] + [launcher]，不含伺服器列表）
///
/// 伺服器列表獨立寫到 list.txt（用 build_list_txt）。
/// 保留 file.servers 欄位是為了載入舊版 config.ini 時做相容轉換用。
pub fn build_list_file(file: &ListFile) -> Result<String> {
    let mut out = String::from("[aux]\n");
    let a = normalize_aux_config(file.aux.clone());
    out.push_str(&format!("packet_encrypt={}\n", a.packet_encrypt));
    out.push_str(&format!("anti_cheat_basic={}\n", a.anti_cheat_basic));
    out.push_str(&format!("anti_cheat_advanced={}\n", a.anti_cheat_advanced));
    out.push_str(&format!("transform_file={}\n", a.transform_file));
    out.push_str(&format!("multi_instance={}\n", a.multi_instance));
    out.push_str(&format!(
        "move_packet_no_encrypt={}\n",
        a.move_packet_no_encrypt
    ));
    out.push_str(&format!("lhx_aux_enabled={}\n", a.lhx_aux_enabled));
    out.push_str(&format!("hp_mp_limit_enabled={}\n", a.hp_mp_limit_enabled));
    out.push_str(&format!(
        "inventory_limit_enabled={}\n",
        a.inventory_limit_enabled
    ));
    out.push_str(&format!("equip_ui_enabled={}\n", a.equip_ui_enabled));
    out.push_str(&format!("img_limit_enabled={}\n", a.img_limit_enabled));
    out.push_str(&format!(
        "inventory_limit_value={}\n",
        a.inventory_limit_value
    ));
    out.push_str(&format!("img_limit_value={}\n", a.img_limit_value));
    out.push_str(&format!(
        "text_encoding={}\n",
        a.text_encoding.as_config_value()
    ));
    out.push_str(&format!(
        "dynamic_dialog_enabled={}\n",
        a.dynamic_dialog_enabled
    ));
    out.push_str(&format!(
        "pickup_toast_enabled={}\n",
        a.pickup_toast_enabled
    ));
    out.push_str(&format!("exp_drift_enabled={}\n", a.exp_drift_enabled));
    out.push_str("\n[launcher]\n");
    let l = &file.launcher;
    out.push_str(&format!("active_skin={}\n", l.active_skin));
    out.push_str(&format!(
        "announcement_enabled={}\n",
        l.announcement_enabled
    ));
    out.push_str(&format!("announcement_url={}\n", l.announcement_url));
    out.push_str(&format!("list_update_enabled={}\n", l.list_update_enabled));
    out.push_str(&format!("list_update_url={}\n", l.list_update_url));
    out.push_str(&format!("auto_update_enabled={}\n", l.auto_update_enabled));
    out.push_str(&format!("auto_update_url={}\n", l.auto_update_url));
    out.push_str(&format!("official_url={}\n", l.official_url));
    out.push_str(&format!(
        "customer_service_url={}\n",
        l.customer_service_url
    ));
    Ok(out)
}

fn parse_bool(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

fn parse_u32_clamped(s: &str, default: u32, min: u32, max: u32) -> u32 {
    s.trim()
        .parse::<u32>()
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 加密 → 解密回路必須等於原始
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let original: Vec<u8> = (0..213u8).collect();
        let mut data = original.clone();
        config_encrypt(SERVER_LIST_KEY, &mut data);
        assert_ne!(data, original);
        config_decrypt(SERVER_LIST_KEY, &mut data);
        assert_eq!(data, original);
    }

    /// ServerInfo 序列化 → 反序列化必須一致
    #[test]
    fn server_info_roundtrip() {
        let info = ServerInfo::new("測試伺服器", "127.0.0.1", 7001);
        let bytes = info.to_bytes();
        assert_eq!(bytes.len(), SIZEOF_SERVER_INFO);

        let back = ServerInfo::from_bytes(&bytes).unwrap();
        assert_eq!(back.name, "測試伺服器");
        assert_eq!(back.ip, "127.0.0.1");
        assert_eq!(back.port, 7001);
        assert!(back.used);
    }

    /// list.txt 文字 → 結構 → 文字 必須等價
    #[test]
    fn list_txt_roundtrip() {
        let original = vec![
            ServerInfo::new("Server1", "1.2.3.4", 2001),
            ServerInfo::new("Server2", "5.6.7.8", 2002),
        ];
        let txt = build_list_txt(&original).unwrap();
        let parsed = parse_list_txt(&txt).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "Server1");
        assert_eq!(parsed[0].ip, "1.2.3.4");
        assert_eq!(parsed[0].port, 2001);
        assert_eq!(parsed[1].name, "Server2");
        assert_eq!(parsed[1].port, 2002);
    }

    /// [aux] + [launcher] round-trip（config.ini 不含伺服器列表）
    #[test]
    fn list_file_with_aux_roundtrip() {
        let mut aux = AuxConfig::default();
        aux.multi_instance = !aux.multi_instance;
        aux.transform_file = !aux.transform_file;
        aux.lhx_aux_enabled = !aux.lhx_aux_enabled;
        aux.hp_mp_limit_enabled = false;
        aux.inventory_limit_enabled = false;
        aux.equip_ui_enabled = false;
        aux.img_limit_enabled = false;
        aux.dynamic_dialog_enabled = false;
        aux.inventory_limit_value = 300;
        aux.img_limit_value = 75000;
        aux.text_encoding = TextEncodingMode::Gbk;

        let original = ListFile {
            servers: vec![],
            aux: aux.clone(),
            launcher: LauncherConfig::default(),
        };
        let txt = build_list_file(&original).unwrap();
        assert!(txt.contains("[aux]"));
        assert!(txt.contains(&format!("multi_instance={}", aux.multi_instance)));
        assert!(txt.contains(&format!("transform_file={}", aux.transform_file)));
        assert!(txt.contains(&format!("hp_mp_limit_enabled={}", aux.hp_mp_limit_enabled)));
        assert!(txt.contains(&format!(
            "inventory_limit_enabled={}",
            aux.inventory_limit_enabled
        )));
        assert!(txt.contains(&format!("equip_ui_enabled={}", aux.equip_ui_enabled)));
        assert!(txt.contains(&format!("img_limit_enabled={}", aux.img_limit_enabled)));
        assert!(txt.contains(&format!(
            "inventory_limit_value={}",
            aux.inventory_limit_value
        )));
        assert!(txt.contains(&format!("img_limit_value={}", aux.img_limit_value)));
        assert!(txt.contains("text_encoding=gbk"));
        assert!(txt.contains(&format!(
            "dynamic_dialog_enabled={}",
            aux.dynamic_dialog_enabled
        )));
        assert!(!txt.contains("[list]")); // 確認伺服器列表被拆出去

        let parsed = parse_list_file(&txt).unwrap();
        assert_eq!(parsed.aux.multi_instance, aux.multi_instance);
        assert_eq!(parsed.aux.transform_file, aux.transform_file);
        assert_eq!(parsed.aux.lhx_aux_enabled, aux.lhx_aux_enabled);
        assert_eq!(parsed.aux.hp_mp_limit_enabled, aux.hp_mp_limit_enabled);
        assert_eq!(
            parsed.aux.inventory_limit_enabled,
            aux.inventory_limit_enabled
        );
        assert_eq!(parsed.aux.equip_ui_enabled, aux.equip_ui_enabled);
        assert_eq!(parsed.aux.img_limit_enabled, aux.img_limit_enabled);
        assert_eq!(parsed.aux.inventory_limit_value, aux.inventory_limit_value);
        assert_eq!(parsed.aux.img_limit_value, aux.img_limit_value);
        assert_eq!(parsed.aux.text_encoding, aux.text_encoding);
        assert_eq!(
            parsed.aux.dynamic_dialog_enabled,
            aux.dynamic_dialog_enabled
        );
    }

    #[test]
    fn core_patch_toggles_default_to_enabled_for_legacy_configs() {
        let parsed = parse_list_file("[aux]\npacket_encrypt=true\n").unwrap();
        assert!(parsed.aux.hp_mp_limit_enabled);
        assert!(parsed.aux.inventory_limit_enabled);
        assert!(parsed.aux.equip_ui_enabled);
        assert!(parsed.aux.img_limit_enabled);
        assert!(parsed.aux.dynamic_dialog_enabled);
        assert!(parsed.aux.pickup_toast_enabled);
        assert!(parsed.aux.exp_drift_enabled);
        assert_eq!(
            parsed.aux.inventory_limit_value,
            DEFAULT_INVENTORY_LIMIT_VALUE
        );
        assert_eq!(parsed.aux.img_limit_value, DEFAULT_IMG_LIMIT_VALUE);
        assert_eq!(parsed.aux.text_encoding, TextEncodingMode::Big5);
    }

    /// 撿物 toast / EXP 飄字 兩個 toggle 走 parse → build round-trip 必須保留值
    #[test]
    fn pickup_and_exp_toggles_roundtrip() {
        let parsed = parse_list_file(
            "[aux]\npickup_toast_enabled=false\nexp_drift_enabled=false\n",
        )
        .unwrap();
        assert!(!parsed.aux.pickup_toast_enabled);
        assert!(!parsed.aux.exp_drift_enabled);

        // build → parse 等價
        let serialized = build_list_file(&parsed).unwrap();
        let reparsed = parse_list_file(&serialized).unwrap();
        assert!(!reparsed.aux.pickup_toast_enabled);
        assert!(!reparsed.aux.exp_drift_enabled);
    }

    #[test]
    fn deprecated_anticheat_flags_are_forced_off_when_parsing_config() {
        let parsed = parse_list_file(
            "[aux]\nanti_cheat_basic=true\nanti_cheat_advanced=true\npacket_encrypt=true\n",
        )
        .unwrap();

        assert!(!parsed.aux.anti_cheat_basic);
        assert!(!parsed.aux.anti_cheat_advanced);
        assert!(parsed.aux.packet_encrypt);
    }

    /// 解析舊版 config.ini（含 [list]）時 servers 仍能讀出 — 向後相容遷移用
    #[test]
    fn parse_legacy_list_section_still_works() {
        let txt = build_list_txt(&[ServerInfo::new("S", "1.1.1.1", 1234)]).unwrap();
        let parsed = parse_list_file(&txt).unwrap();
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].port, 1234);
        // 沒寫 [aux] 的舊檔走預設值
        assert!(parsed.aux.lhx_aux_enabled);
        assert!(!parsed.aux.packet_encrypt);
    }

    /// needs_home_listener 行為驗證（只看 lhx_aux_enabled）
    #[test]
    fn home_listener_logic() {
        let mut a = AuxConfig::default();
        assert!(a.needs_home_listener());
        a.lhx_aux_enabled = false;
        assert!(!a.needs_home_listener());
    }

    /// 與 tools/server_config.py 的 XOR 表一致性檢查
    /// （第一筆值 0x7E 與 SERVER_LIST_KEY[0]='4'=0x34 異或後得 0x4A）
    #[test]
    fn xor_table_first_byte() {
        let table = build_xor_table(SERVER_LIST_KEY);
        assert_eq!(table[0], 0x7E ^ b'4');
    }

    /// config.ini 加密 round-trip
    #[test]
    fn config_text_encrypt_roundtrip() {
        let plain =
            "[aux]\npacket_encrypt=true\nlhx_aux_enabled=false\n[launcher]\nactive_skin=default\n";
        let enc = encrypt_config_text(plain);
        assert!(enc.starts_with("ENC1:"));
        assert!(!enc.contains("[aux]"));
        let dec = decrypt_config_text(&enc).unwrap();
        assert_eq!(dec, plain);
    }

    /// 解密能 fallback 到舊版明文 INI（向後相容）
    #[test]
    fn config_text_legacy_plaintext_pass_through() {
        let plain = "[aux]\npacket_encrypt=true\n";
        let dec = decrypt_config_text(plain).unwrap();
        assert_eq!(dec, plain);
    }

    /// 完整 build_list_file → encrypt → decrypt → parse_list_file 流程驗證
    #[test]
    fn config_ini_full_pipeline() {
        let mut aux = AuxConfig::default();
        aux.packet_encrypt = true;
        aux.transform_file = true;
        aux.multi_instance = true;

        let original = ListFile {
            servers: vec![],
            aux: aux.clone(),
            launcher: LauncherConfig::default(),
        };
        let plaintext = build_list_file(&original).unwrap();
        let encrypted = encrypt_config_text(&plaintext);
        let decrypted = decrypt_config_text(&encrypted).unwrap();
        let parsed = parse_list_file(&decrypted).unwrap();
        assert_eq!(parsed.aux.packet_encrypt, true);
        assert_eq!(parsed.aux.transform_file, true);
        assert_eq!(parsed.aux.multi_instance, true);
        assert_eq!(parsed.aux.lhx_aux_enabled, aux.lhx_aux_enabled);
    }
}
