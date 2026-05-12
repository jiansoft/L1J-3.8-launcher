//! encoder.exe — 3.8 list.txt 編碼器
//!
//! 仿 Encode v5.68 介面排版：3 分頁（編碼/工具/補丁）。
//! 編碼分頁：左欄伺服器表單 + 經典風格主題 8 項；右欄遊戲修補 10 項 + LHX 5 項 + 創角控制 3 項
//! 工具分頁：產生金鑰 / Skin 圖片編碼 / 變檔編碼
//! 補丁分頁：留空（後續擴充）
//!
//! 加密：XOR table + AES-128-ECB（key=4zF8sAc5bYkCRM3w，與 LinLauncher 完全相容）

#![windows_subsystem = "windows"]

extern crate native_windows_derive as nwd;
extern crate native_windows_gui as nwg;

use anyhow::{anyhow, bail, Context, Result};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use launcher::legacy_text::TextEncodingMode;
use launcher::morph_auth::{morph_mac, MORPH_MAC_LEN};
use launcher::rsa32;
use launcher::server_list::{
    build_list_file, build_list_txt, config_encrypt, decrypt_config_text, encrypt_config_text,
    parse_list_file, parse_list_txt, AuxConfig, LauncherConfig, ListFile, ServerInfo,
    DEFAULT_IMG_LIMIT_VALUE, DEFAULT_INVENTORY_LIMIT_VALUE, MAX_IMG_LIMIT_VALUE,
    MAX_INVENTORY_LIMIT_VALUE, MAX_SERVERS, MIN_IMG_LIMIT_VALUE, MIN_INVENTORY_LIMIT_VALUE,
};
use launcher::spr_action_sql::generate_spr_action_sql;
use nwd::NwgUi;
use nwg::NativeUi;
use std::cell::RefCell;
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::System::Console::{AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS};

const ENCODER_WINDOW_ICON_BYTES: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/encoder.ico"));

// ════════════════════════════════════════════════
// 入口
// ════════════════════════════════════════════════

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() <= 1 {
        if let Err(e) = run_gui() {
            eprintln!("[錯誤] GUI 啟動失敗: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            let _ = AllocConsole();
        }
    }

    let result = match args[1].as_str() {
        "gen" => cmd_gen(&args[2..]),
        "dec" => cmd_dec(&args[2..]),
        "morph" => cmd_morph(&args[2..]),
        "verify" => cmd_verify(&args[2..]),
        "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("未知子命令：{other}");
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("[錯誤] {e:#}");
        std::process::exit(1);
    }
}

fn normalize_encoder_aux_options(mut aux: AuxConfig) -> AuxConfig {
    aux.anti_cheat_basic = false;
    aux.anti_cheat_advanced = false;
    aux
}

fn lock_encoder_server_options(mut server: ServerInfo) -> ServerInfo {
    server.usehelper = false;
    server.usebd = false;
    server.bdfile.clear();
    server
}

fn morph_version_options() -> Vec<String> {
    vec!["TW13081901".to_string()]
}

fn morph_sql_button_enabled() -> bool {
    true
}

fn build_encoder_window_icon() -> Option<nwg::Icon> {
    let mut icon = nwg::Icon::default();
    match nwg::Icon::builder()
        .source_bin(Some(ENCODER_WINDOW_ICON_BYTES))
        .build(&mut icon)
    {
        Ok(()) => Some(icon),
        Err(_) => None,
    }
}

fn is_selectable_morph_pak_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("pak"))
        .unwrap_or(false)
}

fn spr_action_sql_output_path_for_exe(exe_path: Option<&Path>) -> std::path::PathBuf {
    exe_path
        .and_then(|path| path.parent())
        .map(|dir| dir.join("spr_action.sql"))
        .unwrap_or_else(|| std::path::PathBuf::from("spr_action.sql"))
}

fn spr_action_sql_output_path() -> std::path::PathBuf {
    let exe_path = std::env::current_exe().ok();
    spr_action_sql_output_path_for_exe(exe_path.as_deref())
}

fn sibling_output_path_for_exe(exe_path: Option<&Path>, name: &str) -> std::path::PathBuf {
    exe_path
        .and_then(|path| path.parent())
        .map(|dir| dir.join(name))
        .unwrap_or_else(|| std::path::PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_aux_options_lock_anticheat_before_export() {
        let mut aux = AuxConfig::default();
        aux.packet_encrypt = true;
        aux.anti_cheat_basic = true;
        aux.anti_cheat_advanced = true;
        aux.transform_file = true;
        aux.multi_instance = true;
        aux.move_packet_no_encrypt = true;
        aux.lhx_aux_enabled = true;

        let locked = normalize_encoder_aux_options(aux);

        assert!(locked.packet_encrypt);
        assert!(locked.lhx_aux_enabled);
        assert!(locked.move_packet_no_encrypt);
        assert!(!locked.anti_cheat_basic);
        assert!(!locked.anti_cheat_advanced);
        assert!(locked.transform_file);
        assert!(locked.multi_instance);
    }

    #[test]
    fn locked_server_options_strip_legacy_dll_fields_before_export() {
        let mut server = ServerInfo::new("Server", "127.0.0.1", 7001);
        server.usehelper = true;
        server.usebd = true;
        server.bdfile = "legacy.dll".to_string();
        server.encrypt = true;
        server.rsa_d = 123;
        server.rsa_n = 456;

        let locked = lock_encoder_server_options(server);

        assert!(!locked.usehelper);
        assert!(!locked.usebd);
        assert!(locked.bdfile.is_empty());
        assert!(locked.encrypt);
        assert_eq!(locked.rsa_d, 123);
        assert_eq!(locked.rsa_n, 456);
    }

    #[test]
    fn morph_tool_versions_are_limited_to_tw13081901_and_sql_is_available() {
        assert_eq!(morph_version_options(), vec!["TW13081901".to_string()]);
        assert!(!morph_version_options().iter().any(|v| v == "15041620"));
        assert!(morph_sql_button_enabled());
    }

    #[test]
    fn encoder_window_icon_is_embedded_ico() {
        assert!(ENCODER_WINDOW_ICON_BYTES.len() > 22);
        assert_eq!(&ENCODER_WINDOW_ICON_BYTES[..4], &[0, 0, 1, 0]);
    }

    #[test]
    fn morph_combo_accepts_pak_by_extension_without_mac_scan() {
        assert!(is_selectable_morph_pak_path(Path::new("TW13081901.PAK")));
        assert!(!is_selectable_morph_pak_path(Path::new("TW13081901.txt")));
    }

    #[test]
    fn morph_encode_rejects_pak_source_to_prevent_double_wrapping() {
        let err = validate_morph_source_path(Path::new("TW13081901.pak")).unwrap_err();
        assert!(
            err.to_string().contains("TW13081901.txt"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn encoder_passthrough_does_not_preprocess_morph_text() {
        // 順跑預處理 (RunL/RunR -> slot 98/99、過濾 >=121 動作) 是 launcher (inject.rs)
        // 的職責。encoder 跟 launcher 都跑會雙跑(idempotency 失敗,在 sprite 邊界
        // 重複插入 110/98/99 共 46 行錯位),怪物模式下會看到走路動畫飄。
        // 因此 encoder 對變身原始檔只做 utf-8 sanity check,內容原封不動。
        let raw = b"100 0 41210\n\
#100 32=777 high_action_walk\n\
\t0.walk(1 4,0.0:2 0.1:2 0.2:2 0.3:2)\n\
\t0-1.RunL(1 4,16.0:2 16.1:2 16.2:2 16.3:2)\n\
\t0-2.RunR(1 4,24.0:2 24.1:2 24.2:2 24.3:2)\n\
\t120.supported(1 4,10.0:2 10.1:2 10.2:2 10.3:2)\n\
\t121.unsupported(1 4,11.0:2 11.1:2 11.2:2 11.3:2)\n";

        let prepared = prepare_morph_plaintext(raw).unwrap();
        assert_eq!(prepared.as_slice(), raw, "encoder 不應改動變身原始檔內容");
    }

    #[test]
    fn spr_action_sql_is_written_next_to_encoder_exe() {
        assert_eq!(
            spr_action_sql_output_path_for_exe(Some(Path::new(
                r"D:\login3.8pro\launcher\encoder.exe"
            ))),
            std::path::PathBuf::from(r"D:\login3.8pro\launcher\spr_action.sql")
        );
    }

    #[test]
    fn encoder_outputs_stay_next_to_encoder_exe() {
        assert_eq!(
            sibling_output_path_for_exe(
                Some(Path::new(r"D:\login3.8pro\launcher\編碼器\encoder.exe")),
                "config.ini"
            ),
            std::path::PathBuf::from(r"D:\login3.8pro\launcher\編碼器\config.ini")
        );
    }
}

fn print_usage() {
    eprintln!("encoder — 3.8 list.txt / 變身檔編碼器");
    eprintln!();
    eprintln!("用法:");
    eprintln!("  encoder                                                       GUI 編輯器（預設）");
    eprintln!("  encoder gen --ip <IP> --port <PORT> [--name N] [-o 檔案]      產生 list.txt");
    eprintln!("  encoder dec <list.txt>                                        解碼 list.txt 顯示");
    eprintln!("  encoder morph <input.txt> [-o out.pak] [--no-compress] [-l N] 變身檔編碼為 .pak");
    eprintln!("  encoder verify <file.pak>                                     驗證 .pak 簽章");
}

fn cmd_verify(args: &[String]) -> Result<()> {
    let path = args.first().ok_or_else(|| anyhow!("缺少檔案路徑"))?;
    let p = Path::new(path);
    if is_our_morph_pak(p) {
        println!("[OK] {} 是本編碼器產出的 .pak", p.display());
        Ok(())
    } else {
        println!(
            "[REJECT] {} 不是本編碼器產出的（簽章驗證失敗或格式錯誤）",
            p.display()
        );
        std::process::exit(2);
    }
}

// ════════════════════════════════════════════════
// CLI 模式
// ════════════════════════════════════════════════

fn cmd_gen(args: &[String]) -> Result<()> {
    let mut ip: Option<String> = None;
    let mut port: Option<i32> = None;
    let mut name = "Server".to_string();
    let mut output = "config.ini".to_string();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ip" => {
                ip = args.get(i + 1).cloned();
                i += 2;
            }
            "--port" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok());
                i += 2;
            }
            "--name" => {
                if let Some(v) = args.get(i + 1) {
                    name = v.clone();
                }
                i += 2;
            }
            "-o" | "--output" => {
                if let Some(v) = args.get(i + 1) {
                    output = v.clone();
                }
                i += 2;
            }
            other => bail!("未知參數：{other}"),
        }
    }

    let ip = ip.ok_or_else(|| anyhow!("缺少 --ip"))?;
    let port = port.ok_or_else(|| anyhow!("缺少 --port"))?;

    let server = lock_encoder_server_options(ServerInfo::new(&name, &ip, port));
    let txt = build_list_txt(&[server])?;
    std::fs::write(&output, txt.as_bytes())?;

    println!("[OK] 已產出 {}（{}:{} {}）", output, ip, port, name);
    Ok(())
}

fn cmd_morph(args: &[String]) -> Result<()> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut compress = true;
    let mut level: u32 = 1;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                if let Some(v) = args.get(i + 1) {
                    output = Some(v.clone());
                }
                i += 2;
            }
            "--no-compress" => {
                compress = false;
                i += 1;
            }
            "--compress" => {
                compress = true;
                i += 1;
            }
            "-l" | "--level" => {
                level = args
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| anyhow!("--level 需要數字 0-9"))?;
                i += 2;
            }
            other if input.is_none() && !other.starts_with('-') => {
                input = Some(other.to_string());
                i += 1;
            }
            other => bail!("未知參數：{other}"),
        }
    }

    let input = input.ok_or_else(|| anyhow!("缺少輸入檔"))?;
    let input_path = Path::new(&input);
    let out_path = output
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| input_path.with_extension("pak"));

    let stat = encode_morph_to_pak(input_path, &out_path, compress, level)?;
    println!("[OK] 變身檔編碼完成");
    println!("  來源：{}", input_path.display());
    println!("  輸出：{}", out_path.display());
    println!("  原始：{} bytes（含 'S' 前綴）", stat.orig_len);
    if compress {
        println!(
            "  壓縮：{} bytes（壓縮率 {:.1}%）",
            stat.compressed_len, stat.compress_ratio
        );
    } else {
        println!("  模式：未壓縮");
    }
    println!("  .pak：{} bytes", stat.pak_size);
    println!("  金鑰：{}", stat.key_hex);
    Ok(())
}

fn cmd_dec(args: &[String]) -> Result<()> {
    let path = args.first().ok_or_else(|| anyhow!("缺少檔案路徑"))?;
    let content = launcher::legacy_text::read_text_file(Path::new(path))?;
    let servers = parse_list_txt(&content)?;

    if servers.is_empty() {
        println!("[警告] 沒有找到任何 ServerData");
        return Ok(());
    }

    for (i, s) in servers.iter().enumerate() {
        println!();
        println!("=== 伺服器 {} ===", i);
        println!("  名稱:     {}", s.name);
        println!("  IP:       {}", s.ip);
        println!("  端口:     {}", s.port);
        println!("  啟用:     {}", s.used);
    }
    println!();
    println!("共 {} 個伺服器（上限 {}）", servers.len(), MAX_SERVERS);
    Ok(())
}

// ════════════════════════════════════════════════
// GUI 模式 — 仿 Encode v5.68 介面
// ════════════════════════════════════════════════

#[derive(Default, NwgUi)]
pub struct EncoderApp {
    #[nwg_control(
        size: (510, 400),
        position: (340, 160),
        title: "Lineage 3.8 編碼器",
        flags: "WINDOW|VISIBLE|MINIMIZE_BOX"
    )]
    #[nwg_events(OnWindowClose: [EncoderApp::on_exit])]
    window: nwg::Window,

    #[nwg_control(parent: window, position: (5, 5), size: (500, 365))]
    tabs: nwg::TabsContainer,

    // ════════════════ Tab 1：編碼 ════════════════
    #[nwg_control(parent: tabs, text: "編碼")]
    tab_encode: nwg::Tab,

    // ─── 左欄：伺服器表單 ───
    #[nwg_control(parent: tab_encode, text: "名稱",
                  position: (15, 18), size: (45, 22),
                  background_color: Some([255, 255, 255]))]
    name_label: nwg::Label,

    #[nwg_control(parent: tab_encode, text: "Server",
                  position: (65, 15), size: (180, 24))]
    name_input: nwg::TextInput,

    #[nwg_control(parent: tab_encode, text: "IP",
                  position: (15, 48), size: (45, 22),
                  background_color: Some([255, 255, 255]))]
    ip_label: nwg::Label,

    #[nwg_control(parent: tab_encode, text: "127.0.0.1",
                  position: (65, 45), size: (180, 24))]
    ip_input: nwg::TextInput,

    #[nwg_control(parent: tab_encode, text: "Port",
                  position: (15, 78), size: (45, 22),
                  background_color: Some([255, 255, 255]))]
    port_label: nwg::Label,

    #[nwg_control(parent: tab_encode, text: "7001",
                  position: (65, 75), size: (90, 24))]
    port_input: nwg::TextInput,

    #[nwg_control(parent: tab_encode, text: "版本",
                  position: (15, 108), size: (45, 22),
                  background_color: Some([255, 255, 255]))]
    version_label: nwg::Label,

    #[nwg_control(parent: tab_encode,
                  position: (65, 105), size: (180, 26),
                  collection: vec!["TW13081901".to_string()],
                  selected_index: Some(0))]
    version_combo: nwg::ComboBox<String>,

    // ─── 右欄：checkbox 列表 ───
    #[nwg_control(parent: tab_encode, text: "封包加密",
                  position: (260, 18), size: (180, 22),
                  background_color: Some([255, 255, 255]))]
    cb_packet_encrypt: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "防外掛",
                  position: (260, 43), size: (180, 22),
                  background_color: Some([255, 255, 255]))]
    cb_anti_cheat_basic: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "進階防外掛",
                  position: (260, 68), size: (180, 22),
                  background_color: Some([255, 255, 255]))]
    cb_anti_cheat: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "變身檔",
                  position: (260, 93), size: (75, 22),
                  background_color: Some([255, 255, 255]))]
    cb_transform_file: nwg::CheckBox,

    #[nwg_control(parent: tab_encode,
                  position: (340, 91), size: (140, 26),
                  collection: vec!["（自動偵測）".to_string()],
                  selected_index: Some(0))]
    transform_file_combo: nwg::ComboBox<String>,

    #[nwg_control(parent: tab_encode, text: "內建喝水輔助程式",
                  position: (260, 118), size: (200, 22),
                  background_color: Some([255, 255, 255]))]
    cb_lhx_enabled: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "移動封包不加密",
                  position: (260, 143), size: (200, 22),
                  background_color: Some([255, 255, 255]))]
    cb_move_no_encrypt: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "血魔突破上限",
                  position: (15, 140), size: (150, 22),
                  background_color: Some([255, 255, 255]))]
    cb_hp_mp_limit: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "背包上限",
                  position: (15, 165), size: (105, 22),
                  background_color: Some([255, 255, 255]))]
    cb_inventory_limit: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "255",
                  position: (125, 162), size: (70, 24))]
    inventory_limit_input: nwg::TextInput,

    #[nwg_control(parent: tab_encode, text: "裝備欄位 7.6",
                  position: (15, 190), size: (150, 22),
                  background_color: Some([255, 255, 255]))]
    cb_equip_ui: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "IMG 上限",
                  position: (15, 215), size: (105, 22),
                  background_color: Some([255, 255, 255]))]
    cb_img_limit: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "50000",
                  position: (125, 212), size: (70, 24))]
    img_limit_input: nwg::TextInput,

    #[nwg_control(parent: tab_encode, text: "動態對話檔",
                  position: (15, 240), size: (150, 22),
                  background_color: Some([255, 255, 255]))]
    cb_dynamic_dialog: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "左下道具提示",
                  position: (15, 265), size: (150, 22),
                  background_color: Some([255, 255, 255]))]
    cb_pickup_toast: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "金幣經驗值提示",
                  position: (15, 290), size: (150, 22),
                  background_color: Some([255, 255, 255]))]
    cb_exp_drift: nwg::CheckBox,

    #[nwg_control(parent: tab_encode, text: "語系",
                  position: (260, 168), size: (70, 22),
                  background_color: Some([255, 255, 255]))]
    text_encoding_label: nwg::Label,

    #[nwg_control(parent: tab_encode,
                  position: (335, 166), size: (145, 26),
                  collection: vec!["繁體".to_string(), "簡體".to_string()],
                  selected_index: Some(1))]
    text_encoding_combo: nwg::ComboBox<String>,

    // ─── 下方：Server 槽位選擇 + 編碼 ───
    #[nwg_control(parent: tab_encode,
                  position: (260, 230), size: (130, 26),
                  collection: vec!["Server1".to_string(), "Server2".to_string(),
                                   "Server3".to_string(), "Server4".to_string(),
                                   "Server5".to_string(), "Server6".to_string(),
                                   "Server7".to_string(), "Server8".to_string()],
                  selected_index: Some(0))]
    #[nwg_events(OnComboxBoxSelection: [EncoderApp::on_server_combo_change])]
    server_combo: nwg::ComboBox<String>,

    #[nwg_control(parent: tab_encode, text: "編碼",
                  position: (400, 228), size: (80, 30))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_save])]
    save_btn: nwg::Button,

    // ════════════════ Tab 2：工具 ════════════════
    #[nwg_control(parent: tabs, text: "工具")]
    tab_tools: nwg::Tab,

    // ─── 伺服器綑綁金鑰 group（RSA-32） ───
    #[nwg_control(parent: tab_tools, text: "伺服器綑綁金鑰（RSA-32 → pack.properties）",
                  position: (10, 8), size: (470, 20),
                  background_color: Some([255, 255, 255]))]
    keygen_label: nwg::Label,

    #[nwg_control(parent: tab_tools, text: "RSA E：",
                  position: (10, 36), size: (55, 20),
                  background_color: Some([255, 255, 255]))]
    rsa_e_label: nwg::Label,

    #[nwg_control(parent: tab_tools, text: "",
                  position: (70, 34), size: (180, 22),
                  flags: "VISIBLE|DISABLED")]
    rsa_e_input: nwg::TextInput,

    #[nwg_control(parent: tab_tools, text: "RSA D：",
                  position: (10, 62), size: (55, 20),
                  background_color: Some([255, 255, 255]))]
    rsa_d_label: nwg::Label,

    #[nwg_control(parent: tab_tools, text: "",
                  position: (70, 60), size: (180, 22),
                  flags: "VISIBLE|DISABLED")]
    rsa_d_input: nwg::TextInput,

    #[nwg_control(parent: tab_tools, text: "RSA N：",
                  position: (10, 88), size: (55, 20),
                  background_color: Some([255, 255, 255]))]
    rsa_n_label: nwg::Label,

    #[nwg_control(parent: tab_tools, text: "",
                  position: (70, 86), size: (180, 22),
                  flags: "VISIBLE|DISABLED")]
    rsa_n_input: nwg::TextInput,

    #[nwg_control(parent: tab_tools, text: "產生金鑰",
                  position: (270, 36), size: (100, 28))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_keygen])]
    keygen_btn: nwg::Button,

    #[nwg_control(parent: tab_tools,
                  text: "產生後寫入選中槽位 + encoder.exe 旁產生 pack.properties",
                  position: (10, 116), size: (470, 18),
                  background_color: Some([255, 255, 255]))]
    keygen_note: nwg::Label,

    // ─── 變檔編碼 group ───
    #[nwg_control(parent: tab_tools, text: "變檔編碼",
                  position: (10, 148), size: (470, 20),
                  background_color: Some([255, 255, 255]))]
    morph_label: nwg::Label,

    #[nwg_control(parent: tab_tools, text: "原始檔：",
                  position: (10, 178), size: (55, 20),
                  background_color: Some([255, 255, 255]))]
    morph_src_label: nwg::Label,

    #[nwg_control(parent: tab_tools, text: "",
                  position: (70, 176), size: (300, 22))]
    morph_src_input: nwg::TextInput,

    #[nwg_control(parent: tab_tools, text: "瀏覽",
                  position: (375, 175), size: (60, 26))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_morph_browse])]
    morph_browse_btn: nwg::Button,

    #[nwg_control(parent: tab_tools, text: "版本：",
                  position: (10, 210), size: (55, 20),
                  background_color: Some([255, 255, 255]))]
    morph_ver_label: nwg::Label,

    #[nwg_control(parent: tab_tools,
                  position: (70, 208), size: (110, 24),
                  collection: morph_version_options(),
                  selected_index: Some(0))]
    morph_ver_combo: nwg::ComboBox<String>,

    #[nwg_control(parent: tab_tools, text: "變檔編碼",
                  position: (190, 207), size: (90, 26))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_morph_encode])]
    morph_encode_btn: nwg::Button,

    #[nwg_control(parent: tab_tools, text: "產生 SQL",
                  position: (285, 207), size: (90, 26),
                  flags: "VISIBLE|DISABLED")]
    #[nwg_events(OnButtonClick: [EncoderApp::on_morph_sql])]
    morph_sql_btn: nwg::Button,

    // ════════════════ Tab 3：Skin（登入器介面管理） ════════════════
    #[nwg_control(parent: tabs, text: "Skin")]
    tab_skin: nwg::Tab,

    #[nwg_control(parent: tab_skin, text: "登入器 Skin",
                  position: (10, 8), size: (470, 20),
                  background_color: Some([255, 255, 255]))]
    skin_section_label: nwg::Label,

    #[nwg_control(parent: tab_skin, text: "選擇 Skin：",
                  position: (10, 38), size: (75, 20),
                  background_color: Some([255, 255, 255]))]
    skin_pick_label: nwg::Label,

    #[nwg_control(parent: tab_skin, position: (90, 36), size: (170, 24),
                  collection: vec!["default".to_string()],
                  selected_index: Some(0))]
    skin_combo: nwg::ComboBox<String>,

    #[nwg_control(parent: tab_skin, text: "重新掃描",
                  position: (270, 36), size: (90, 26))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_skin_rescan])]
    skin_rescan_btn: nwg::Button,

    #[nwg_control(parent: tab_skin, text: "開啟資料夾",
                  position: (370, 36), size: (110, 26))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_skin_open_folder])]
    skin_open_btn: nwg::Button,

    #[nwg_control(parent: tab_skin, text: "背景圖片：",
                  position: (10, 72), size: (75, 20),
                  background_color: Some([255, 255, 255]))]
    skin_bg_label: nwg::Label,

    #[nwg_control(parent: tab_skin, text: "",
                  position: (90, 70), size: (210, 24))]
    skin_bg_input: nwg::TextInput,

    #[nwg_control(parent: tab_skin, text: "瀏覽",
                  position: (305, 70), size: (60, 26))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_skin_bg_browse])]
    skin_bg_browse_btn: nwg::Button,

    #[nwg_control(parent: tab_skin, text: "套用為 bg.jpg",
                  position: (370, 70), size: (110, 26))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_skin_bg_apply])]
    skin_bg_apply_btn: nwg::Button,

    #[nwg_control(parent: tab_skin,
                  text: "說明：在 launcher.exe 旁 skins/ 目錄複製 default 改名為新 skin，\n再修改 index.html / style.css / launcher.js 自訂介面。\n所選 skin 會寫入 config.ini 的 [launcher] active_skin。",
                  position: (10, 110), size: (470, 70),
                  background_color: Some([255, 255, 255]))]
    skin_help_label: nwg::Label,

    // ════════════════ Tab 4：其他（公告 / 列表更新 / 自動更新） ════════════════
    #[nwg_control(parent: tabs, text: "其他")]
    tab_misc: nwg::Tab,

    // ─── 公告網頁 ───
    #[nwg_control(parent: tab_misc, text: "公告網頁",
                  position: (15, 22), size: (90, 22),
                  background_color: Some([255, 255, 255]))]
    cb_announcement: nwg::CheckBox,

    #[nwg_control(parent: tab_misc, text: "",
                  position: (110, 20), size: (370, 24))]
    announcement_input: nwg::TextInput,

    // ─── 列表更新 ───
    #[nwg_control(parent: tab_misc, text: "列表更新",
                  position: (15, 56), size: (90, 22),
                  background_color: Some([255, 255, 255]))]
    cb_list_update: nwg::CheckBox,

    #[nwg_control(parent: tab_misc, text: "",
                  position: (110, 54), size: (370, 24))]
    list_update_input: nwg::TextInput,

    // ─── 自動更新 ───
    #[nwg_control(parent: tab_misc, text: "自動更新",
                  position: (15, 90), size: (90, 22),
                  background_color: Some([255, 255, 255]))]
    cb_auto_update: nwg::CheckBox,

    #[nwg_control(parent: tab_misc, text: "",
                  position: (110, 88), size: (370, 24))]
    auto_update_input: nwg::TextInput,

    // ─── 上方 tab 列：官網/客服 超連結 ───
    #[nwg_control(parent: tab_misc, text: "官網 URL：",
                  position: (15, 132), size: (90, 22),
                  background_color: Some([255, 255, 255]))]
    official_label: nwg::Label,

    #[nwg_control(parent: tab_misc, text: "",
                  position: (110, 130), size: (370, 24))]
    official_input: nwg::TextInput,

    #[nwg_control(parent: tab_misc, text: "客服 URL：",
                  position: (15, 166), size: (90, 22),
                  background_color: Some([255, 255, 255]))]
    customer_label: nwg::Label,

    #[nwg_control(parent: tab_misc, text: "",
                  position: (110, 164), size: (370, 24))]
    customer_input: nwg::TextInput,

    #[nwg_control(parent: tab_misc, text: "(空字串則隱藏對應的上方連結)",
                  position: (110, 195), size: (370, 22),
                  background_color: Some([255, 255, 255]))]
    topbar_note: nwg::Label,

    // ─── 儲存 ───
    #[nwg_control(parent: tab_misc, text: "儲存",
                  position: (380, 240), size: (100, 30))]
    #[nwg_events(OnButtonClick: [EncoderApp::on_save])]
    misc_save_btn: nwg::Button,

    // 共享狀態
    /// 8 個伺服器槽位（對應 server_combo 8 個項目）
    servers: RefCell<Vec<ServerInfo>>,
    aux_config: RefCell<AuxConfig>,
    /// 目前正在編輯的伺服器索引
    current_idx: RefCell<usize>,
}

impl EncoderApp {
    fn prime_initial_tab_paint(&self) {
        if self.tabs.tab_count() > 1 {
            self.tabs.set_selected_tab(1);
        }
        self.tabs.set_selected_tab(0);
        self.window.invalidate();
    }

    /// 用空 server 填滿 8 個槽位
    fn init_servers(&self) {
        let mut v = self.servers.borrow_mut();
        v.clear();
        for i in 0..MAX_SERVERS {
            v.push(ServerInfo {
                name: format!("Server{}", i + 1),
                ip: "127.0.0.1".to_string(),
                port: 7001,
                used: i == 0,
                ..Default::default()
            });
        }
    }

    /// 從表單欄位寫回目前選中的伺服器
    /// used 自動 = 名稱非空（沿用 v3.80 編碼器邏輯：留白即視為未啟用槽位）
    fn flush_form_to_server(&self) {
        let idx = *self.current_idx.borrow();
        let mut v = self.servers.borrow_mut();
        if let Some(s) = v.get_mut(idx) {
            s.name = self.name_input.text();
            s.ip = self.ip_input.text();
            s.port = self.port_input.text().parse().unwrap_or(s.port);
            s.used = !s.name.trim().is_empty();
        }
    }

    /// 把指定伺服器的欄位填入表單
    fn fill_form_from_server(&self, idx: usize) {
        let v = self.servers.borrow();
        if let Some(s) = v.get(idx) {
            self.name_input.set_text(&s.name);
            self.ip_input.set_text(&s.ip);
            self.port_input.set_text(&s.port.to_string());
            // RSA 欄位（綁在 Tools 分頁）也同步顯示，方便辨識每個槽位的金鑰
            let show = |v: u32| if v == 0 { String::new() } else { v.to_string() };
            self.rsa_e_input.set_text(&show(s.rsa_e));
            self.rsa_d_input.set_text(&show(s.rsa_d));
            self.rsa_n_input.set_text(&show(s.rsa_n));
        }
    }

    /// 從 7 個 checkbox 收集 AuxConfig
    fn collect_aux(&self) -> AuxConfig {
        normalize_encoder_aux_options(AuxConfig {
            packet_encrypt: self.is_checked(&self.cb_packet_encrypt),
            anti_cheat_basic: self.is_checked(&self.cb_anti_cheat_basic),
            anti_cheat_advanced: self.is_checked(&self.cb_anti_cheat),
            transform_file: self.is_checked(&self.cb_transform_file),
            multi_instance: self.aux_config.borrow().multi_instance,
            move_packet_no_encrypt: self.is_checked(&self.cb_move_no_encrypt),
            lhx_aux_enabled: self.is_checked(&self.cb_lhx_enabled),
            hp_mp_limit_enabled: self.is_checked(&self.cb_hp_mp_limit),
            inventory_limit_enabled: self.is_checked(&self.cb_inventory_limit),
            equip_ui_enabled: self.is_checked(&self.cb_equip_ui),
            img_limit_enabled: self.is_checked(&self.cb_img_limit),
            dynamic_dialog_enabled: self.is_checked(&self.cb_dynamic_dialog),
            pickup_toast_enabled: self.is_checked(&self.cb_pickup_toast),
            exp_drift_enabled: self.is_checked(&self.cb_exp_drift),
            inventory_limit_value: Self::parse_limit_input(
                &self.inventory_limit_input,
                DEFAULT_INVENTORY_LIMIT_VALUE,
                MIN_INVENTORY_LIMIT_VALUE,
                MAX_INVENTORY_LIMIT_VALUE,
            ),
            img_limit_value: Self::parse_limit_input(
                &self.img_limit_input,
                DEFAULT_IMG_LIMIT_VALUE,
                MIN_IMG_LIMIT_VALUE,
                MAX_IMG_LIMIT_VALUE,
            ),
            text_encoding: self.selected_text_encoding_mode(),
        })
    }

    /// 把 AuxConfig 套到 7 個 checkbox
    fn apply_aux(&self, a: &AuxConfig) {
        let a = normalize_encoder_aux_options(a.clone());
        *self.aux_config.borrow_mut() = a.clone();
        self.set_checked(&self.cb_packet_encrypt, a.packet_encrypt);
        self.set_checked(&self.cb_anti_cheat_basic, a.anti_cheat_basic);
        self.set_checked(&self.cb_anti_cheat, a.anti_cheat_advanced);
        self.cb_anti_cheat_basic.set_enabled(false);
        self.cb_anti_cheat.set_enabled(false);
        self.set_checked(&self.cb_transform_file, a.transform_file);
        self.set_checked(&self.cb_move_no_encrypt, a.move_packet_no_encrypt);
        self.set_checked(&self.cb_lhx_enabled, a.lhx_aux_enabled);
        self.set_checked(&self.cb_hp_mp_limit, a.hp_mp_limit_enabled);
        self.set_checked(&self.cb_inventory_limit, a.inventory_limit_enabled);
        self.set_checked(&self.cb_equip_ui, a.equip_ui_enabled);
        self.set_checked(&self.cb_img_limit, a.img_limit_enabled);
        self.set_checked(&self.cb_dynamic_dialog, a.dynamic_dialog_enabled);
        self.set_checked(&self.cb_pickup_toast, a.pickup_toast_enabled);
        self.set_checked(&self.cb_exp_drift, a.exp_drift_enabled);
        self.inventory_limit_input
            .set_text(&a.inventory_limit_value.to_string());
        self.img_limit_input
            .set_text(&a.img_limit_value.to_string());
        self.text_encoding_combo
            .set_selection(Some(Self::text_encoding_mode_index(a.text_encoding)));
    }

    fn selected_text_encoding_mode(&self) -> TextEncodingMode {
        match self.text_encoding_combo.selection().unwrap_or(0) {
            0 => TextEncodingMode::Big5,
            _ => TextEncodingMode::Gbk,
        }
    }

    fn text_encoding_mode_index(mode: TextEncodingMode) -> usize {
        match mode {
            TextEncodingMode::Big5 => 0,
            TextEncodingMode::Auto | TextEncodingMode::Gbk => 1,
        }
    }

    fn is_checked(&self, cb: &nwg::CheckBox) -> bool {
        matches!(cb.check_state(), nwg::CheckBoxState::Checked)
    }

    fn parse_limit_input(input: &nwg::TextInput, default: u32, min: u32, max: u32) -> u32 {
        input
            .text()
            .trim()
            .parse::<u32>()
            .map(|v| v.clamp(min, max))
            .unwrap_or(default)
    }

    fn set_checked(&self, cb: &nwg::CheckBox, v: bool) {
        cb.set_check_state(if v {
            nwg::CheckBoxState::Checked
        } else {
            nwg::CheckBoxState::Unchecked
        });
    }

    fn alert(&self, msg: &str) {
        nwg::modal_info_message(&self.window, "編碼器", msg);
    }

    fn on_server_combo_change(&self) {
        // 切換到另一個槽位前先把當前表單寫回
        self.flush_form_to_server();
        if let Some(new_idx) = self.server_combo.selection() {
            *self.current_idx.borrow_mut() = new_idx;
            self.fill_form_from_server(new_idx);
        }
    }

    /// encoder.exe 旁的 config.ini（[aux] + [launcher]）
    fn config_ini_path() -> std::path::PathBuf {
        Self::sibling_path("config.ini")
    }

    /// encoder.exe 旁的 list.txt（[list]，加密伺服器列表）
    fn list_txt_path() -> std::path::PathBuf {
        Self::sibling_path("list.txt")
    }

    fn sibling_path(name: &str) -> std::path::PathBuf {
        let exe_path = std::env::current_exe().ok();
        sibling_output_path_for_exe(exe_path.as_deref(), name)
    }

    fn on_load(&self) {
        // 1) 先讀伺服器列表 (list.txt)
        let mut servers_loaded: Vec<ServerInfo> = Vec::new();
        let list_path = Self::list_txt_path();
        if list_path.exists() {
            if let Ok(content) = launcher::legacy_text::read_text_file(&list_path) {
                match parse_list_txt(&content) {
                    Ok(v) => servers_loaded = v,
                    Err(e) => self.alert(&format!("list.txt 解析失敗：{e}")),
                }
            }
        }

        // 2) 再讀設定 (config.ini，支援 ENC1: 加密與舊版明文)
        let cfg_path = Self::config_ini_path();
        let mut aux_loaded = AuxConfig::default();
        let mut launcher_loaded = LauncherConfig::default();
        if cfg_path.exists() {
            if let Ok(raw) = launcher::legacy_text::read_text_file(&cfg_path) {
                match decrypt_config_text(&raw)
                    .and_then(|plain| parse_list_file(&plain).map_err(Into::into))
                {
                    Ok(file) => {
                        aux_loaded = file.aux;
                        launcher_loaded = file.launcher;
                        if servers_loaded.is_empty() && !file.servers.is_empty() {
                            servers_loaded = file.servers; // legacy migrate
                        }
                    }
                    Err(e) => self.alert(&format!("config.ini 解析失敗：{e}")),
                }
            }
        }

        // 補滿 8 槽
        let mut v = self.servers.borrow_mut();
        v.clear();
        for s in &servers_loaded {
            v.push(lock_encoder_server_options(s.clone()));
        }
        while v.len() < MAX_SERVERS {
            let n = v.len() + 1;
            v.push(ServerInfo {
                name: format!("Server{}", n),
                ip: "127.0.0.1".to_string(),
                port: 7001,
                used: false,
                ..Default::default()
            });
        }
        drop(v);

        self.apply_aux(&aux_loaded);
        self.apply_launcher_cfg(&launcher_loaded);
        *self.current_idx.borrow_mut() = 0;
        self.server_combo.set_selection(Some(0));
        self.fill_form_from_server(0);
    }

    /// 編碼 / 儲存：每次只編當前選中槽位的伺服器（讀現有 list.txt → 替換該槽位 → 寫回），
    /// 設定（[aux]+[launcher]）整份加密後寫 config.ini。
    fn on_save(&self) {
        self.flush_form_to_server();

        let idx = *self.current_idx.borrow();
        let current = {
            let v = self.servers.borrow();
            match v.get(idx).cloned() {
                Some(s) if !s.name.trim().is_empty() => s,
                _ => {
                    self.alert("目前槽位的伺服器名稱為空，無法編碼");
                    return;
                }
            }
        };
        let current = lock_encoder_server_options(current);

        // 讀現有 list.txt，把 current 塞到第 idx 個位置，其他槽位保留
        let list_path = Self::list_txt_path();
        let mut existing: Vec<ServerInfo> = if list_path.exists() {
            launcher::legacy_text::read_text_file(&list_path)
                .ok()
                .and_then(|c| parse_list_txt(&c).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // 補空位以對齊 idx；空位用 used=false placeholder
        while existing.len() < idx {
            existing.push(ServerInfo::default());
        }
        if existing.len() == idx {
            existing.push(current.clone());
        } else {
            existing[idx] = current.clone();
        }
        // 寫出時過濾掉空名稱的 placeholder
        let active: Vec<ServerInfo> = existing
            .into_iter()
            .map(lock_encoder_server_options)
            .filter(|s| !s.name.trim().is_empty())
            .collect();

        match build_list_txt(&active) {
            Ok(txt) => {
                if let Err(e) = std::fs::write(&list_path, txt.as_bytes()) {
                    self.alert(&format!("list.txt 寫檔失敗：{e}"));
                    return;
                }
            }
            Err(e) => {
                self.alert(&format!("list.txt 編碼失敗：{e}"));
                return;
            }
        }

        // [aux] + [launcher] 加密後寫 config.ini
        let aux = self.collect_aux();
        let launcher = self.collect_launcher_cfg();
        let file = ListFile {
            servers: vec![],
            aux,
            launcher,
        };
        let cfg_path = Self::config_ini_path();
        match build_list_file(&file) {
            Ok(plain) => {
                let enc = encrypt_config_text(&plain);
                match std::fs::write(&cfg_path, enc.as_bytes()) {
                    Ok(_) => {
                        self.alert(&format!(
                        "已編碼伺服器：{} ({}:{})\nlist.txt 共 {} 個槽位\nconfig.ini 已加密寫入",
                        current.name, current.ip, current.port, active.len()
                    ))
                    }
                    Err(e) => self.alert(&format!("config.ini 寫檔失敗：{e}")),
                }
            }
            Err(e) => self.alert(&format!("config.ini 編碼失敗：{e}")),
        }
    }

    // ─── 工具分頁 ───

    /// 產生 RSA-32 伺服器綑綁金鑰：
    ///   1. 寫入目前選中槽位的 ServerInfo（rsa_e/rsa_d/rsa_n）
    ///   2. 把 E/N 寫到 encoder.exe 旁的 pack.properties（給 server 端）
    ///   3. UI 顯示三組值
    fn on_keygen(&self) {
        // 寫表單回去，避免 ServerInfo 與 UI 不同步
        self.flush_form_to_server();

        let key = rsa32::generate();

        // 寫入目前選中的槽位
        let idx = *self.current_idx.borrow();
        {
            let mut v = self.servers.borrow_mut();
            if let Some(s) = v.get_mut(idx) {
                s.rsa_e = key.e;
                s.rsa_d = key.d;
                s.rsa_n = key.n;
            }
        }

        // UI 顯示
        self.rsa_e_input.set_text(&key.e.to_string());
        self.rsa_d_input.set_text(&key.d.to_string());
        self.rsa_n_input.set_text(&key.n.to_string());

        // 產生 pack.properties（server 端讀 RSA_KEY_E + RSA_KEY_N，D 留作備份）
        let path = Self::pack_properties_path();
        let content = format!(
            "; 由 encoder.exe 產生 — 伺服器綑綁金鑰\n\
             ; 把這個檔案放到伺服器的 ./config/pack.properties\n\
             ; 客戶端的 D/N 已經寫進 ServerInfo（list.txt），不需要客戶端讀這個檔\n\
             Autoentication=True\n\
             RSA_KEY_E={}\n\
             RSA_KEY_D={}\n\
             RSA_KEY_N={}\n",
            key.e, key.d, key.n
        );
        match std::fs::write(&path, content.as_bytes()) {
            Ok(_) => self.alert(&format!(
                "已產生伺服器綑綁金鑰\n\nE = {}\nD = {}\nN = {}\n\n\
                 已寫入 {}\n（請將此檔放到伺服器的 ./config/ 目錄）\n\n\
                 同時已將 E/D/N 套用到目前選中的伺服器槽位 (Server{}).",
                key.e,
                key.d,
                key.n,
                path.display(),
                idx + 1
            )),
            Err(e) => self.alert(&format!(
                "金鑰已生成但 pack.properties 寫檔失敗：{e}\n\nE = {}\nD = {}\nN = {}",
                key.e, key.d, key.n
            )),
        }
    }

    /// pack.properties 固定寫在 encoder.exe 旁
    fn pack_properties_path() -> std::path::PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("pack.properties")))
            .unwrap_or_else(|| std::path::PathBuf::from("pack.properties"))
    }

    /// 掃描 encoder.exe 旁所有合格的變身檔 .pak（只認我們編碼的格式）
    /// 回傳檔名（不含路徑）
    fn scan_morph_paks(&self) -> Vec<String> {
        let dir = match std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            Some(d) => d,
            None => return Vec::new(),
        };
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if !is_selectable_morph_pak_path(&path) {
                    continue;
                }
                if let Some(n) = path.file_name().and_then(|n| n.to_str()) {
                    names.push(n.to_string());
                }
            }
        }
        names.sort();
        names
    }

    /// 重新掃描並更新「變身檔」下拉選單
    /// 沒有合格檔案時顯示「（無偵測到檔案）」
    fn refresh_morph_combo(&self) {
        let prev = self.transform_file_combo.selection_string();
        let mut items = self.scan_morph_paks();
        if items.is_empty() {
            items.push("（無偵測到檔案）".to_string());
            self.transform_file_combo.set_collection(items);
            self.transform_file_combo.set_selection(Some(0));
            return;
        }
        // 還原上次選擇（若仍存在），否則選第一個
        let new_idx = prev
            .as_ref()
            .and_then(|p| items.iter().position(|n| n == p))
            .unwrap_or(0);
        self.transform_file_combo.set_collection(items);
        self.transform_file_combo.set_selection(Some(new_idx));
    }

    fn on_morph_browse(&self) {
        let mut dialog = Default::default();
        if nwg::FileDialog::builder()
            .title("選擇變身原始檔")
            .action(nwg::FileDialogAction::Open)
            .filters("變身原始檔(*.txt)")
            .build(&mut dialog)
            .is_ok()
            && dialog.run(Some(&self.window))
        {
            if let Ok(path) = dialog.get_selected_item() {
                // 強制解析為絕對路徑（避免後續 with_extension 落到 CWD）
                let abs = resolve_abs_path(Path::new(&path));
                self.morph_src_input.set_text(&abs.to_string_lossy());
            }
        }
    }

    fn on_morph_encode(&self) {
        let src = self.morph_src_input.text();
        let src = src.trim();
        if src.is_empty() {
            self.alert("請先選擇變身原始檔");
            return;
        }
        // 強制絕對路徑：使用者若手輸入相對路徑、或對話框改變 CWD 都不影響來源讀取
        let abs_src = resolve_abs_path(Path::new(src));
        if !abs_src.exists() {
            self.alert(&format!("原始檔不存在：{}", abs_src.display()));
            return;
        }
        // 輸出固定在 encoder.exe 旁邊（檔名沿用來源 stem + .pak 副檔名）
        let out_name = abs_src
            .file_stem()
            .map(|s| format!("{}.pak", s.to_string_lossy()))
            .unwrap_or_else(|| "morph.pak".to_string());
        let out_path = Self::sibling_path(&out_name);

        match encode_morph_to_pak(&abs_src, &out_path, true, 1) {
            Ok(stat) => {
                // 編碼後立即刷新「變身檔」下拉選單，新檔案會出現
                self.refresh_morph_combo();
                self.alert(&format!(
                    "變身檔編碼完成\n\n\
                     來源：{}\n\
                     輸出：{}\n\n\
                     原始：{} bytes（含 'S' 前綴）\n\
                     壓縮：{} bytes（壓縮率 {:.1}%）\n\
                     .pak：{} bytes",
                    abs_src.display(),
                    out_path.display(),
                    stat.orig_len,
                    stat.compressed_len,
                    stat.compress_ratio,
                    stat.pak_size,
                ));
            }
            Err(e) => self.alert(&format!("變身檔編碼失敗：{e:#}")),
        }
    }

    fn on_morph_sql(&self) {
        let input_path = {
            let typed = self.morph_src_input.text();
            let trimmed = typed.trim();
            let typed_path = Path::new(trimmed);
            let is_txt = typed_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("txt"))
                .unwrap_or(false);
            if !trimmed.is_empty() && typed_path.exists() && is_txt {
                resolve_abs_path(typed_path)
            } else {
                let mut dialog = Default::default();
                if let Err(e) = nwg::FileDialog::builder()
                    .title("Select morph txt")
                    .action(nwg::FileDialogAction::Open)
                    .filters("Text files (*.txt)|*.txt|All files (*.*)|*.*")
                    .build(&mut dialog)
                {
                    self.alert(&format!("build file dialog failed: {e:?}"));
                    return;
                }
                if !dialog.run(Some(&self.window)) {
                    return;
                }
                match dialog.get_selected_item() {
                    Ok(path) => std::path::PathBuf::from(path),
                    Err(e) => {
                        self.alert(&format!("read selected file failed: {e:?}"));
                        return;
                    }
                }
            }
        };

        if !input_path.exists() {
            self.alert(&format!("input file not found: {}", input_path.display()));
            return;
        }

        let output_path = spr_action_sql_output_path();

        let input_text = match launcher::legacy_text::read_text_file(&input_path) {
            Ok(text) => text,
            Err(e) => {
                self.alert(&format!("read morph txt failed: {e}"));
                return;
            }
        };

        let output = match generate_spr_action_sql(&input_text) {
            Ok(output) => output,
            Err(e) => {
                self.alert(&format!("generate spr_action.sql failed: {e:#}"));
                return;
            }
        };

        if let Err(e) = std::fs::write(&output_path, output.sql.as_bytes()) {
            self.alert(&format!("write spr_action.sql failed: {e}"));
            return;
        }

        self.alert(&format!(
            "spr_action.sql generated\n\nInput: {}\nOutput: {}\nRows: {}",
            input_path.display(),
            output_path.display(),
            output.row_count
        ));
    }

    // ─── 介面 Skin 分頁 ───

    /// encoder.exe 旁邊的 skins/ 目錄
    fn skins_dir() -> std::path::PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("skins")))
            .unwrap_or_else(|| std::path::PathBuf::from("skins"))
    }

    /// 掃描 skins/ 目錄，列出所有子資料夾名稱（每個 = 一個 skin）
    fn scan_skins(&self) -> Vec<String> {
        let dir = Self::skins_dir();
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if entry.path().join("index.html").exists() {
                        if let Some(name) = entry.file_name().to_str() {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }
        if names.is_empty() {
            names.push("default".to_string());
        }
        names.sort();
        names
    }

    /// 重新掃描 skins 目錄並更新 ComboBox
    fn on_skin_rescan(&self) {
        let names = self.scan_skins();
        let current = self
            .skin_combo
            .selection_string()
            .unwrap_or_else(|| "default".to_string());
        self.skin_combo.set_collection(names.clone());
        let new_idx = names.iter().position(|n| n == &current).unwrap_or(0);
        self.skin_combo.set_selection(Some(new_idx));
    }

    fn on_skin_open_folder(&self) {
        let dir = Self::skins_dir();
        if !dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                self.alert(&format!("建立 skins/ 失敗：{e}"));
                return;
            }
        }
        // 用 explorer 打開目錄
        let _ = std::process::Command::new("explorer").arg(&dir).spawn();
    }

    fn on_skin_bg_browse(&self) {
        let mut dialog = Default::default();
        if nwg::FileDialog::builder()
            .title("選擇背景圖片")
            .action(nwg::FileDialogAction::Open)
            .filters("圖片(*.jpg;*.jpeg;*.png)")
            .build(&mut dialog)
            .is_ok()
            && dialog.run(Some(&self.window))
        {
            if let Ok(path) = dialog.get_selected_item() {
                self.skin_bg_input.set_text(&path.to_string_lossy());
            }
        }
    }

    /// 把使用者選的圖片複製到 skins/<active>/bg.jpg
    fn on_skin_bg_apply(&self) {
        let src = self.skin_bg_input.text();
        if src.trim().is_empty() {
            self.alert("請先選擇圖片");
            return;
        }
        let src_path = std::path::PathBuf::from(&src);
        if !src_path.exists() {
            self.alert("圖片檔不存在");
            return;
        }
        let active_skin = self
            .skin_combo
            .selection_string()
            .unwrap_or_else(|| "default".to_string());
        let target_dir = Self::skins_dir().join(&active_skin);
        if !target_dir.exists() {
            self.alert(&format!("Skin 目錄不存在：{}", target_dir.display()));
            return;
        }
        let target = target_dir.join("bg.jpg");
        match std::fs::copy(&src_path, &target) {
            Ok(_) => self.alert(&format!("已套用背景圖到 {}", target.display())),
            Err(e) => self.alert(&format!("複製失敗：{e}")),
        }
    }

    fn collect_launcher_cfg(&self) -> LauncherConfig {
        LauncherConfig {
            active_skin: self
                .skin_combo
                .selection_string()
                .unwrap_or_else(|| "default".to_string()),
            announcement_enabled: self.is_checked(&self.cb_announcement),
            announcement_url: self.announcement_input.text(),
            list_update_enabled: self.is_checked(&self.cb_list_update),
            list_update_url: self.list_update_input.text(),
            auto_update_enabled: self.is_checked(&self.cb_auto_update),
            auto_update_url: self.auto_update_input.text(),
            official_url: self.official_input.text(),
            customer_service_url: self.customer_input.text(),
        }
    }

    fn apply_launcher_cfg(&self, cfg: &LauncherConfig) {
        // 重新掃描以確保 ComboBox 包含所選的 skin
        let names = self.scan_skins();
        self.skin_combo.set_collection(names.clone());
        let idx = names
            .iter()
            .position(|n| n == &cfg.active_skin)
            .unwrap_or(0);
        self.skin_combo.set_selection(Some(idx));

        self.set_checked(&self.cb_announcement, cfg.announcement_enabled);
        self.announcement_input.set_text(&cfg.announcement_url);
        self.set_checked(&self.cb_list_update, cfg.list_update_enabled);
        self.list_update_input.set_text(&cfg.list_update_url);
        self.set_checked(&self.cb_auto_update, cfg.auto_update_enabled);
        self.auto_update_input.set_text(&cfg.auto_update_url);
        self.official_input.set_text(&cfg.official_url);
        self.customer_input.set_text(&cfg.customer_service_url);
    }

    fn on_exit(&self) {
        nwg::stop_thread_dispatch();
    }
}

// ════════════════════════════════════════════════
// 變身檔 .pak 編碼（XOR table + AES-128-ECB + zlib，與 pak_encoder.py 相容）
// ════════════════════════════════════════════════

struct EncodeStat {
    orig_len: usize,       // 含 'S' 前綴的明文長度
    compressed_len: usize, // zlib 壓縮後長度（無壓縮時 == orig_len）
    compress_ratio: f64,   // 壓縮率（%）
    pak_size: usize,       // 最終 .pak 檔大小（含 4+16 檔頭）
    key_hex: String,       // 16-byte 金鑰 hex
}

fn encode_morph_to_pak(
    input: &Path,
    output: &Path,
    compress: bool,
    level: u32,
) -> Result<EncodeStat> {
    validate_morph_source_path(input)?;
    let raw = std::fs::read(input).with_context(|| format!("讀取 {} 失敗", input.display()))?;
    let raw = prepare_morph_plaintext(&raw)?;

    // 'S' 前綴（FileHook 內 add eax,1 跳過）
    let mut with_prefix = Vec::with_capacity(1 + raw.len());
    with_prefix.push(b'S');
    with_prefix.extend_from_slice(&raw);
    let orig_len = with_prefix.len();

    // 壓縮（可選）
    let mut payload = if compress {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(level));
        enc.write_all(&with_prefix).context("zlib 寫入失敗")?;
        enc.finish().context("zlib 完成失敗")?
    } else {
        with_prefix
    };
    let compressed_len = payload.len();

    // 隨機 16-byte 金鑰（SplitMix64，安全性無所謂——key 直接寫在 pak 檔頭）
    let key = gen_random_key();

    // XOR + AES-128-ECB
    config_encrypt(&key, &mut payload);

    // 組裝 [orig_len:4][key:16][encrypted:N][mac:16]
    if orig_len > u32::MAX as usize {
        bail!("檔案過大，無法寫入 4-byte 長度欄位");
    }
    let mut pak = Vec::with_capacity(20 + payload.len() + MORPH_MAC_LEN);
    pak.extend_from_slice(&(orig_len as u32).to_le_bytes());
    pak.extend_from_slice(&key);
    pak.extend_from_slice(&payload);
    // 內容綁定 MAC：launcher 端驗證，沒通過直接拒絕載入
    let mac = morph_mac(&pak);
    pak.extend_from_slice(&mac);
    let pak_size = pak.len();

    std::fs::write(output, &pak).with_context(|| format!("寫入 {} 失敗", output.display()))?;

    let compress_ratio = if compress && orig_len > 0 {
        (1.0 - compressed_len as f64 / orig_len as f64) * 100.0
    } else {
        0.0
    };

    Ok(EncodeStat {
        orig_len,
        compressed_len,
        compress_ratio,
        pak_size,
        key_hex: key.iter().map(|b| format!("{b:02x}")).collect(),
    })
}

fn validate_morph_source_path(input: &Path) -> Result<()> {
    if input
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("pak"))
        .unwrap_or(false)
    {
        bail!("請選 TW13081901.txt 原始檔，不要把已編碼的 .pak 再拿去編碼");
    }
    Ok(())
}

fn prepare_morph_plaintext(raw: &[u8]) -> Result<Vec<u8>> {
    // 順跑預處理 (注入 slot 98/99、過濾 >=121 動作) 是 launcher (inject.rs) 端的職責,
    // encoder 端不再做,避免兩邊都跑造成 idempotency 失敗(重複注入 + sprite 邊界錯位)。
    // encoder 對變身原始檔不做任何字元集假設(Big5/UTF-8/其他都直接 passthrough),
    // 內容原封不動寫進 .pak,讓 launcher 端按需處理。
    Ok(raw.to_vec())
}

/// 驗證指定 .pak 是否為「我們的編碼器」產出的格式
///
/// 檢查項（任一不合即拒絕）：
/// 1. 檔案至少 4 + 16 + 16(AES block) + 16(MAC) bytes
/// 2. orig_len 在合理範圍 (1 .. 100MB)
/// 3. 末 16 bytes MAC 通過 `morph_mac` 驗證（綁定金鑰 = MORPH_AUTH_KEY）
///
/// 與 `inject.rs::load_inject_file` 的拒絕邏輯一致：別人用 pak_encoder.py 產的、
/// 改名的、舊版的 .pak 都會被擋下。
fn is_our_morph_pak(path: &Path) -> bool {
    let Ok(raw) = std::fs::read(path) else {
        return false;
    };
    let min_size = 4 + 16 + 16 + MORPH_MAC_LEN;
    if raw.len() < min_size {
        return false;
    }
    let orig_len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if !(1..=100_000_000).contains(&orig_len) {
        return false;
    }
    // 末 16 bytes 是 MAC，前面是受保護的 preamble
    let split = raw.len() - MORPH_MAC_LEN;
    let preamble = &raw[..split];
    let mac_bytes = &raw[split..];
    let expected = morph_mac(preamble);
    mac_bytes == expected
}

/// 將輸入路徑解析為絕對路徑：
///   - 已是絕對路徑 → 直接回傳
///   - 相對路徑 → 以「來源檔所在目錄」為錨；若仍無法決定，退回 CWD + 相對路徑
///
/// 不依賴 fs::canonicalize（檔案不存在時會失敗），只做 join。
fn resolve_abs_path(p: &Path) -> std::path::PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    // 嘗試先用 canonicalize 取得真實絕對路徑（檔案存在時）
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    // Fallback：基於 CWD
    std::env::current_dir()
        .map(|d| d.join(p))
        .unwrap_or_else(|_| p.to_path_buf())
}

/// SplitMix64 產生 16-byte 金鑰（與 rsa32::Lcg 同演算法）
fn gen_random_key() -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x12345678);
    let mut state = nanos.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    let mut next = || -> u64 {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };
    let mut key = [0u8; 16];
    key[0..8].copy_from_slice(&next().to_le_bytes());
    key[8..16].copy_from_slice(&next().to_le_bytes());
    key
}

fn run_gui() -> Result<()> {
    nwg::init().map_err(|e| anyhow!("nwg init: {e:?}"))?;

    let mut font = nwg::Font::default();
    nwg::Font::builder()
        .family("Microsoft JhengHei UI")
        .size(15)
        .build(&mut font)
        .map_err(|e| anyhow!("font build: {e:?}"))?;
    nwg::Font::set_global_default(Some(font));

    let app = EncoderApp::build_ui(Default::default()).map_err(|e| anyhow!("build ui: {e:?}"))?;
    if let Some(icon) = build_encoder_window_icon() {
        let icon = Box::leak(Box::new(icon));
        app.window.set_icon(Some(icon));
    }
    app.morph_sql_btn.set_enabled(morph_sql_button_enabled());

    // 初始化 8 槽伺服器、AuxConfig、掃描 skins/
    app.init_servers();
    app.on_skin_rescan();
    app.apply_aux(&AuxConfig::default());
    app.apply_launcher_cfg(&LauncherConfig::default());
    app.fill_form_from_server(0);

    // 啟動時若 encoder.exe 旁邊已有 list.txt，自動載入
    app.on_load();

    // 掃描 encoder.exe 旁邊已有的變身檔 .pak，填到「變身檔」下拉選單
    app.refresh_morph_combo();
    app.prime_initial_tab_paint();

    nwg::dispatch_thread_events();
    Ok(())
}
