# L1J-3.8-launcher

> 天堂 3.8 登入器 (Lineage 3.8 Launcher) — 以 **Rust** 撰寫的開源天堂客戶端啟動器與輔助系統,專為 `TW13081901.bin` (天堂 3.8 客戶端) 設計。
> 內建 WebView2 介面、雙階段注入、自動喝水/施法/撿物通知/順跑等完整輔助功能。

![Language](https://img.shields.io/badge/language-Rust-orange)
![Edition](https://img.shields.io/badge/edition-2021-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Game](https://img.shields.io/badge/game-TW13081901-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

---

## 📦 配套核心 (必裝)

本登入器必須搭配模擬器核心使用:

> 🔗 **[L1JGO-Whale](https://github.com/rdtc8822-debug/L1JGO-Whale)** — 天堂 3.8 開源遊戲伺服器核心 (Whale)

> 當然你有能力也可以使用自己的模擬器，可參考Whale

| 元件 | 職責 | 倉庫 |
|------|------|------|
| **L1JGO-Whale** | 遊戲模擬器 | [rdtc8822-debug/L1JGO-Whale](https://github.com/rdtc8822-debug/L1JGO-Whale) |
| **本專案** | 啟動 `TW13081901.bin`、Stage2 修補、輔助 UI、玩家偏好 | (此 repo) |


---

## 🏗️ 架構總覽

啟動流程分為**兩階段**:

1. **Stage1 (launcher GUI)**:WebView2 渲染 skin → 玩家選伺服器/視窗模式 → `CreateProcess(TW13081901.bin)` 啟動遊戲 → 立即 spawn stage2 自己
2. **Stage2 (patcher)**:等遊戲解密完成 → 套用時間保護 bypass、AC bypass、IMG 上限、HP/MP 上限、裝備 UI、順跑 hook、LHX 注入等

---

## ✨ 核心功能

### 🔐 登入系統

| 功能 | 說明 | 關鍵檔案 |
|------|------|---------|
| **伺服器清單加密** | `list.txt` 採 XOR + AES-128-ECB 雙層加密 | `src/server_list.rs` |
| **Server_Info 結構** | 213 bytes 嚴格對齊,含名稱/IP/Port/RSA 金鑰/加密旗標 | `src/server_list.rs` |
| **帳號密碼 Hook** | 相容 `0x77` opcode 登入封包 (legacy `Login.dll` 格式) | `src/login.rs` |
| **Connect Redirect** | 攔截 `WSAConnect` 重導到自訂 IP/Port | `src/hook.rs` |
| **RSA 封包代理** | 本機代理伺服器負責封包加解密 (127.0.0.1 隨機端口) | `src/packet_proxy.rs` |


### 🎨 自訂變身檔

支援動態載入兩種格式:

- **`.pak`** — AES-128 + HMAC-SHA256 + zlib 壓縮 (防篡改)
- **`.txt`** — 純文字 morph SQL

**variant line 預處理 pipeline** (`src/smooth_run/`):自動清理機型不相容的 variant 行,提升順跑流暢度。預設啟用,可透過環境變數 `LOGIN38_MORPH_PREPROCESS=0` 關閉。

簽名工具:`encoder.exe input.txt output.pak`。

### 🍶 LHZ 輔助視窗 (Home 鍵呼叫)

啟動遊戲後按 **Home 鍵** 叫出 8 分頁的輔助視窗 (基於 NWG 原生 Windows GUI):

| 分頁 | 名稱 | 功能 |
|------|------|------|
| 0 | 喝水 (Potion) | 自動喝水 支援多列規則 |
| 1 | 輔助 (Buff) | 自動偵測然後施放輔助技能 |
| 2 | 狀態 (Status) | 自動吃肉/磨刀石修武器/顯示經驗值/自動變身/自動解毒 F1~F4自訂快鍵 |
| 3 | 刪物 | 選擇要刪除或溶解的道具 |
| 4 | 喊話 | 自動說話可訂多組輪詢 |
| 5 | 其他 | 全白天/海底抽水/降低CPU/怪物等級色彩/顯示遊戲時鐘/顯示攻擊傷害 |
| 6 | 定時 | 可定時(秒)自動使用道具/技能 |


實作:`src/aux/lhx_window.rs` + `src/aux/runtime.rs` (AuxScheduler 全域排程器 + Arc<RwLock<AuxSettings>> 無鎖共享)

### 🎁 撿物通知 + EXP 飄字

| 元件 | 職責 | 檔案 |
|------|------|------|
| Packet Hook | 攔截 `PACKETBOX` opcode 250 | `src/aux/notification/packet_hook.rs` |
| Dispatcher | 道具 ID → 名稱/圖示解析 | `src/aux/notification/dispatcher.rs` |
| ImageElement Hook | 攔截遊戲繪圖呼叫 (`0x42F450`) | `src/aux/notification/image_draw_hook.rs` |
| Queue + Overlay | 通知佇列管理與螢幕繪製 | `src/aux/notification/{queue,overlay}.rs` |

- 左下 toast: 撿到物品名稱 + 圖示
- 螢幕中央飄字: EXP / 金幣增量
- 採 `AtomicBool::load(Relaxed)` 確保高頻路徑零鎖

### 🏃 3.8順跑系統 (Smooth Run)

| 項目 | 內容 |
|------|------|
| 中段 hook | `0x00449776` (per-entity 版) |
| 加速偵測 | `entity+0x29` 標誌位 |
| 左右腳選擇 | RunL/RunR toggle (基於 action_state) |
| 動作編號 | `0, 4, 11, 20, 24, 40, 46, 50, 54, 58, 62, 83` |
| Entity 解析 | EBP chain → `[[EBP]-0x5C]` |
| Morph pipeline | `src/smooth_run/` 完整子目錄 |

可透過環境變數 `LOGIN38_DISABLE_SMOOTH_RUN_HOOK=1` 或 marker file `disable_smooth_run_hook.flag` 停用。

### 🛠️ 其他輔助功能

- **怪物等級顏色** (`monster_color_patch.rs`)
- **攻擊傷害顯示** (`attack_damage_hook.rs` / `attack_damage_feet_hook.rs`)
- **全白天** (`toggle/all_day.rs`)
- **海底抽水** (`toggle/underwater_pump.rs`)
- **聊天框寬度** (`chat_width.rs`)
- **快鍵系統** (`hotkey.rs`)
- **輸入模擬** (`input_sim.rs`)
- **經驗追蹤** (`exp_tracker.rs`)
- **角色 profile** (`profile.rs`)


---

## 🔧 編譯

### 環境需求

- **Rust** 1.70+ (edition 2021)
- **Windows** 10/11 (64-bit OS,目標遊戲為 32-bit)
- **MSVC Toolchain** (`stable-x86_64-pc-windows-msvc`)
- **WebView2 Runtime** (Windows 11 內建,Windows 10 需手動安裝)

### 編譯指令

```powershell
# Release 編譯 (建議,啟用 LTO + strip symbols)
cargo build --release

# 產物位於:
#   target\release\launcher.exe    主程式
#   target\release\encoder.exe     morph 加密工具
```

`Cargo.toml` 已預設 release profile 體積最佳化:

```toml
[profile.release]
opt-level = "z"      # 體積優先
lto = true           # 連結時最佳化
strip = "symbols"    # 移除符號
codegen-units = 1    # 單一編譯單元
```

### 可選 features

```powershell
cargo build --release --features verbose-log
```

`verbose-log` 啟用詳細日誌輸出 (寫至 launcher.exe 旁 `launcher.log`)。

---

## 🚀 安裝與使用

### 1. 佈署檔案

將以下檔案放在**同一個目錄**:

```
GameFolder/
├── launcher.exe              # 編譯產物
├── encoder.exe               # 編譯產物 (僅打包 morph 時需要)
├── TW13081901.bin            # 遊戲執行檔
├── TW13081901.txt            # 預設 morph (或 .pak)
├── list.txt                  # 伺服器清單 (編碼器產出,加密格式)
├── launcher.ini              # 玩家偏好 (首次啟動自動建立)
├── lineage.cfg               # 遊戲視窗設定 (launcher 自動寫入)
└── skins/
    └── default/
        ├── index.html        # WebView2 主頁
        ├── style.css
        └── ...
```

### 2. 取得 `list.txt`

`list.txt` 採 (XOR + AES-128-ECB),由 登入器編碼器產出

### 3. 啟動

雙擊 `launcher.exe` → WebView2 介面載入 → 選伺服器 → 點啟動。

---

## 🖥️ 執行模式

### GUI 模式 (預設)

```powershell
launcher.exe
```

無參數啟動 → 開啟 760×500 無邊框 WebView2 視窗 → 讀 `skins/<active>/index.html`。
玩家選伺服器與視窗大小後,launcher 自動 spawn 遊戲與 stage2。

### CLI 模式

```powershell
# 直接連接指定伺服器
launcher.exe <IP> <PORT>

# 範例: 連 127.0.0.1:2000
launcher.exe 127.0.0.1 2000

# 注入自訂 morph
launcher.exe 127.0.0.1 2000 --inject custom.pak

# 跳過 connect hook (僅啟動遊戲,不重導網路)
launcher.exe --no-connect

# 顯示幫助
launcher.exe --help
```

### Stage2 模式 (內部用,勿手動執行)

```powershell
launcher.exe --stage2 <PID> <IP> <PORT> <GAME_DIR> [--delay-ms N] [--inject FILE]
```

由 stage1 自動呼叫,負責 attach 已啟動的遊戲行程進行修補。

### Morph 加密工具

```powershell
# 將純文字 morph 加密為 .pak (AES-128 + HMAC-SHA256)
encoder.exe input.txt output.pak
```

---

## ⚙️ 設定檔說明

### `launcher.ini` (玩家偏好)

由 `launcher.exe` 自動讀寫,放在程式同目錄:

```ini
[Settings]
windowed=true           ; 視窗化 (true/false/1/0/yes/no)
window_mode=5           ; 視窗大小: 4=400x300, 5=800x600, 6=1200x900, 7=1600x1200
```

預設 `windowed=true`、`window_mode=5` (W11 最相容)。

### `list.txt` (伺服器清單)

Server_Info 結構 (213 bytes,`#[repr(C, packed)]`):

| 欄位 | 大小 | 說明 |
|------|------|------|
| `name` | 32 wchar | 伺服器顯示名稱 |
| `ip` | 32 char | 伺服器 IP/網域 |
| `port` | u32 | 連線埠 |
| `used` | u8 | 是否啟用 |
| `key` | [u8; 16] | 封包加密金鑰 |
| `encrypt` | u8 | 是否啟用加密 |
| `usehelper` | u8 | LinHelper 相容旗標 |
| `usebd` | u8 | Big Data 支援 |
| `bdfile` | 32 wchar | BD 檔名 |
| `randkey` | u8 | 隨機金鑰 |
| `rsa_e` | u32 | RSA 公鑰指數 |
| `rsa_d` | u32 | RSA 私鑰 |
| `rsa_n` | u32 | RSA 模數 |
| `fix` | [u8; 16] | 保留 |

整檔以 `4zF8sAc5bYkCRM3w` 為 key 做 XOR + AES-128-ECB 加密。

### 環境變數 (進階)

| 變數 | 預設 | 說明 |
|------|------|------|
| `LOGIN38_CONNECT_HOOK` | `1` | Connect hook 開關 |
| `LOGIN38_DISABLE_SMOOTH_RUN_HOOK` | `0` | 停用順跑 hook |
| `LOGIN38_DISABLE_IMG_HOVER` | `0` | 停用動態對話框 |
| `LOGIN38_DISABLE_IMG_LIMIT` | `0` | 停用 IMG 上限解除 |
| `LOGIN38_DISABLE_HP_MP_LIMIT` | `0` | 停用 HP/MP 上限解除 |
| `LOGIN38_DISABLE_EQUIP_UI` | `0` | 停用裝備欄 UI patch |
| `LOGIN38_MORPH_PREPROCESS` | `1` | Morph variant line 預處理 |
| `LOGIN38_STAGE2_DELAY_MS` | `0` | Stage2 啟動延遲 (毫秒) |
| `LOGIN38_STAGE2_REMAINING_DELAY_MS` | `0` | 後續 patch 延遲 |
| `LOGIN38_GAME_IP_ARG` | `1` | 傳 IP 參數給遊戲 |
| `LOGIN38_KEEP_LAUNCHER_ALIVE` | `0` | 保持 launcher 行程 |
| `LOGIN38_STAGE2_ATTACH_BEFORE_WINDOW` | `0` | 視窗建立前 attach |

### Marker 旗標檔

在 launcher.exe 同目錄放置以下空檔即可停用對應功能:

```
disable_smooth_run_hook.flag
disable_img_hover.flag
disable_img_limit.flag
disable_hp_mp_limit.flag
disable_equip_ui.flag
```

適合一鍵停用單一功能而不需設環境變數。

---

## 🔬 進階開發者資訊

### 核心 Offset 對照表

```
0x004E204E   Packer 解密完成標記 (Stage2 等待信號)
0x00722761   PatchCode_Point1
0x00772BA0   Login packet custom opcode
0x0077317D   Username hook
0x004AA38E   Password hook
0x00772E07   Login77 hook (opcode 0x77 相容)
0x00402800   Password byte converter
0x00580E50   SendPacketData (施法封包送出)
0x004B3EE0   USE_ITEM 函式 (cdecl, 1 參)
0x00449776   Smooth run hook (per-entity)
0x0097C910   Target ID 全域變數
0x00ABF4B4   Self Char ID
0x008DC08C   Entity vfptr (實體掃描)
0x00437500   ChatDispatch
0x00437D30   ChatSideEffect
0x0042F450   ImageElement::draw (通知 hook)
0x75FAA350   WSAConnect (Connect hook 目標)
```

### Logging

- 日誌寫到 `launcher.exe` 旁 `launcher.log`
- 啟用 `verbose-log` feature 可看 hook 安裝與 packet 細節
- 加 `LOGIN38_KEEP_LAUNCHER_ALIVE=1` 可保持 launcher 行程觀察 stage2 輸出

---

## ⚠️ 免責聲明

- 本專案**僅供學習研究與私服架設**使用
- 不得用於商業營利、破壞官方服務、或任何違反當地法律的行為
- 使用者應自行承擔使用風險,專案維護者不負責任何後果
- 天堂 (Lineage) 為 NCsoft 註冊商標,本專案與 NCsoft 無任何關聯

---

## 📜 授權

本專案採 **MIT License** 發佈。詳見 [LICENSE](./LICENSE)。

---

## 🙏 致謝與相關專案

- 🐳 **[L1JGO-Whale](https://github.com/rdtc8822-debug/L1JGO-Whale)** — 配套核心
- 🦀 **Rust ecosystem** — `windows-rs` / `wry` / `tao` / `native-windows-gui` / `parking_lot` 等優秀 crate

---

## 📮 回饋與貢獻

歡迎 Issue 與 Pull Request。回報問題時請附:

- Windows 版本與 build
- launcher.log 內容
- 重現步驟

