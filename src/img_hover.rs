//! img hover 功能模組 — v20 hook draw call site
//!
//! 核心改變：hook 0x491174（draw call site）而非 GetSurfResource 入口。
//! draw 每幀呼叫 → 可即時替換 surface + 即時讀取座標。
//!
//! 架構：
//!   1. 從 0x4263AB 動態解析 GetSurfResource 和 SurfManager 位址
//!   2. 從 0x491174 讀取 draw 函數位址
//!   3. 在 0x491174 安裝 call hook → codecave
//!   4. codecave: 讀 element src_id → 查映射 → 替換時呼叫 GetSurfResource(hl_id)
//!   5. jmp draw（尾呼叫）

use crate::logger::log_line;
use crate::{memory, process};
use anyhow::{bail, Result};
use std::sync::atomic::{AtomicI32, Ordering};
use windows::Win32::Foundation::HANDLE;

/// debug 用 log — 只在 verbose-log feature 啟用時輸出
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(feature = "verbose-log")]
        log_line!($($arg)*);
    };
}

// F6 動態校準的 offset（blit×1.5 + offset = client）
static CALIB_OFF_X: AtomicI32 = AtomicI32::new(-121);
static CALIB_OFF_Y: AtomicI32 = AtomicI32::new(-94);

// 動態解析用的 call site（GetSurfResource）
const GSR_CALL_SITE: u32 = 0x004263AB;
const GSR_SITE_CHECK: [u8; 5] = [0x8B, 0x48, 0x20, 0x51, 0xB9];

// draw call site（每幀呼叫）
const DRAW_CALL_SITE: u32 = 0x00491174;

// GetSurfResource prologue
const GSR_PROLOGUE: [u8; 3] = [0x55, 0x8B, 0xEC];

// data 從 0x100 開始（shellcode 最大 256 bytes，雙模式需 ~189 bytes）
const OFF_DRAW_ADDR: u32 = 0x100;
const OFF_GSR_ORIG: u32 = 0x104;
const OFF_SURF_MGR: u32 = 0x108;
const OFF_COUNT: u32 = 0x10C;
const OFF_HOVER_ID: u32 = 0x110; // g_hover_id — polling 寫 surface_data，draw hook 讀
const OFF_MAP: u32 = 0x120; // [(src_id:4, hl_id:4)] × N
const OFF_SURF_PTRS: u32 = 0x160; // [surface_data:4] × N — 學習模式記錄
const OFF_HL_SURFS: u32 = 0x180; // [highlight_surface_ptr:4] × N — 學習模式記錄
const OFF_LEARNED: u32 = 0x1A0; // 已學習數量（== count 時進入重播模式）
const OFF_ELEM_PTR: u32 = 0x1A4; // element 指標 — 學習模式寫，polling 讀
const MAP_ENTRY: u32 = 8;

// blit hook 常數
const BLIT_B_ADDR: u32 = 0x00555CE0; // blit_B runtime 位址
const BLIT_PROLOGUE: [u8; 6] = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14];
// blit codecave data 偏移
const BLIT_OFF_SCREEN_POS: u32 = 0x80; // [(x:4, y:4)] × N — blit hook 寫（必須在 shellcode 之後！）
const BLIT_OFF_COUNT: u32 = 0x60;
const BLIT_OFF_SURF_PTRS_ADDR: u32 = 0x64; // 指向 draw cave 的 surf_ptrs

// HOVER_MAP 已移除 — 改由運行時記憶體掃描 highlight 屬性動態建立
const MAX_HOVER_ENTRIES: u32 = 8; // codecave 映射表最大容量

pub struct HoverHookResult {
    pub cave_draw: u32,
    pub cave_blit: u32,
    pub game_handle: HANDLE,
    pub pid: u32,
    pub draw_hook_bytes: [u8; 5], // hook 的 call 指令（重裝用）
    pub draw_orig_bytes: [u8; 5], // 原始 call 指令（卸載用）
}

/// 取得 hover count 在 codecave 中的位址（供 connect hook 重置用）
pub fn hover_count_addr(cave_draw: u32) -> u32 {
    cave_draw + OFF_COUNT
}

pub fn install_img_hover_hook(h: HANDLE, pid: u32) -> Result<Option<HoverHookResult>> {
    log_line!("\n--- img hover hook（v21: 學習+重播雙模式）---");

    // 映射表由 polling 動態填入（掃描 highlight 屬性），install 時初始化為空

    // === 1. 動態解析 GetSurfResource + SurfManager ===
    let site_bytes = memory::read_bytes(h, GSR_CALL_SITE, 14)?;
    if site_bytes[..5] != GSR_SITE_CHECK {
        bail!("GSR call site 不符");
    }
    if site_bytes[9] != 0xE8 {
        bail!("GSR call site +9 不是 E8");
    }

    let surf_mgr = u32::from_le_bytes([site_bytes[5], site_bytes[6], site_bytes[7], site_bytes[8]]);
    let gsr_rel = i32::from_le_bytes([
        site_bytes[10],
        site_bytes[11],
        site_bytes[12],
        site_bytes[13],
    ]);
    let gsr_addr = ((GSR_CALL_SITE + 9) as i64 + 5 + gsr_rel as i64) as u32;
    debug_log!("[INFO] GetSurfResource=0x{gsr_addr:08X}, SurfManager=0x{surf_mgr:08X}");

    // === 2. 讀取 draw call site 的目標位址 ===
    let draw_site = memory::read_bytes(h, DRAW_CALL_SITE, 5)?;
    if draw_site[0] != 0xE8 {
        bail!(
            "draw call site 0x{DRAW_CALL_SITE:08X} 不是 E8，而是 {:02X}",
            draw_site[0]
        );
    }
    let draw_rel = i32::from_le_bytes([draw_site[1], draw_site[2], draw_site[3], draw_site[4]]);
    let draw_addr = (DRAW_CALL_SITE as i64 + 5 + draw_rel as i64) as u32;
    debug_log!("[INFO] draw=0x{draw_addr:08X}");

    // === 3. 讀取 GetSurfResource prologue（用於建立 original call path）===
    let gsr_bytes = memory::read_bytes(h, gsr_addr, 10)?;
    if gsr_bytes[..3] != GSR_PROLOGUE {
        bail!(
            "GSR prologue 不符: {:02X} {:02X} {:02X}",
            gsr_bytes[0],
            gsr_bytes[1],
            gsr_bytes[2]
        );
    }
    let gsr_prologue_len = if gsr_bytes[3] == 0x83 {
        6
    } else if gsr_bytes[3] == 0x81 {
        8
    } else {
        bail!("GSR prologue byte 4: {:02X}", gsr_bytes[3]);
    };
    let gsr_retn = gsr_addr + gsr_prologue_len as u32;

    // === 4. 分配 codecave ===
    let n = 0u32; // 初始映射為空，由 polling 掃描 highlight 後動態填入
    let cave_size = 0x200;
    let cave_addr = memory::alloc_exec(h, cave_size)?;

    // === 5. 建立 GetSurfResource original trampoline（跳過我們的 hook）===
    // 放在 cave + 0x140（遠離 shellcode 和 data，避免 overlap）
    let gsr_orig_off = 0x1C0u32; // 在所有 data 之後（OFF_ELEM_PTR=0x1A4 + 4 → 0x1A8，遠離 0x1C0）
    let gsr_orig_addr = cave_addr + gsr_orig_off;
    let mut gsr_tramp: Vec<u8> = Vec::new();
    gsr_tramp.extend_from_slice(&gsr_bytes[..gsr_prologue_len]); // original prologue
    gsr_tramp.push(0xE9); // jmp gsr_retn
    let jmp_from = gsr_orig_addr + gsr_tramp.len() as u32 + 4;
    gsr_tramp.extend_from_slice(&gsr_retn.wrapping_sub(jmp_from).to_le_bytes());
    memory::write_code(h, gsr_orig_addr, &gsr_tramp)?;
    debug_log!("[INFO] GSR original trampoline @ 0x{gsr_orig_addr:08X}");

    // === 6. 組裝 draw hook shellcode ===
    let sc = build_draw_hook_v2(cave_addr, draw_addr, gsr_orig_addr, surf_mgr);
    log_line!(
        "[INFO] draw hook shellcode: {} bytes（data@0xA0=160）",
        sc.len()
    );
    // hex dump 前 40 bytes 驗證 count guard + vfptr check 編碼
    let dump: String = sc
        .iter()
        .take(40)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    log_line!("[INFO] shellcode[0..40]: {dump}");
    memory::write_code(h, cave_addr, &sc)?;

    // === 7. 寫 data 區 ===
    memory::write_code(h, cave_addr + OFF_DRAW_ADDR, &draw_addr.to_le_bytes())?;
    memory::write_code(h, cave_addr + OFF_GSR_ORIG, &gsr_orig_addr.to_le_bytes())?;
    memory::write_code(h, cave_addr + OFF_SURF_MGR, &surf_mgr.to_le_bytes())?;
    memory::write_code(h, cave_addr + OFF_COUNT, &n.to_le_bytes())?;
    memory::write_code(h, cave_addr + OFF_HOVER_ID, &0u32.to_le_bytes())?;

    // 映射表初始化為零（最大 MAX_HOVER_ENTRIES 個 entry）
    memory::write_code(
        h,
        cave_addr + OFF_MAP,
        &vec![0u8; MAX_HOVER_ENTRIES as usize * 8],
    )?;
    memory::write_code(
        h,
        cave_addr + OFF_SURF_PTRS,
        &vec![0u8; MAX_HOVER_ENTRIES as usize * 4],
    )?;
    // 學習/重播模式資料初始化
    memory::write_code(
        h,
        cave_addr + OFF_HL_SURFS,
        &vec![0u8; MAX_HOVER_ENTRIES as usize * 4],
    )?;
    memory::write_code(h, cave_addr + OFF_LEARNED, &0u32.to_le_bytes())?;
    memory::write_code(h, cave_addr + OFF_ELEM_PTR, &0u32.to_le_bytes())?;

    // === 8. 安裝 draw call hook ===
    // 保存原始指令（卸載用）
    let orig_bytes_vec = memory::read_bytes(h, DRAW_CALL_SITE, 5)?;
    let mut draw_orig_bytes = [0u8; 5];
    draw_orig_bytes.copy_from_slice(&orig_bytes_vec);

    let mut draw_hook_bytes = [0u8; 5];
    draw_hook_bytes[0] = 0xE8;
    let rel = cave_addr.wrapping_sub(DRAW_CALL_SITE + 5) as i32;
    draw_hook_bytes[1..5].copy_from_slice(&rel.to_le_bytes());

    // 安裝 draw hook
    let threads = process::suspend_threads(pid)?;
    match memory::write_code(h, DRAW_CALL_SITE, &draw_hook_bytes) {
        Ok(()) => {
            process::resume_threads(threads);
            log_line!("[OK] draw hook @ 0x{DRAW_CALL_SITE:08X} → 0x{cave_addr:08X}");
        }
        Err(e) => {
            process::resume_threads(threads);
            bail!("draw hook 安裝失敗: {e}");
        }
    }

    // === 9. 安裝 blit hook — 動態讀 prologue ===
    let blit_bytes = memory::read_bytes(h, BLIT_B_ADDR, 10)?;
    debug_log!("[INFO] blit 0x{BLIT_B_ADDR:08X}: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
        blit_bytes[0], blit_bytes[1], blit_bytes[2], blit_bytes[3], blit_bytes[4],
        blit_bytes[5], blit_bytes[6], blit_bytes[7], blit_bytes[8], blit_bytes[9]);

    if blit_bytes[0] != 0x55 || blit_bytes[1] != 0x8B || blit_bytes[2] != 0xEC {
        log_line!("[警告] blit prologue 不符，跳過");
    } else {
        let blit_plen = if blit_bytes[3] == 0x83 {
            6usize
        } else if blit_bytes[3] == 0x81 {
            8
        } else {
            log_line!("[警告] blit byte3={:02X}，跳過", blit_bytes[3]);
            0
        };

        if blit_plen > 0 {
            let blit_prologue = &blit_bytes[..blit_plen];
            let blit_retn = BLIT_B_ADDR + blit_plen as u32;
            let surf_ptrs_addr = cave_addr + OFF_SURF_PTRS;
            let blit_cave = memory::alloc_exec(h, 0x100)?;

            let blit_sc = build_blit_hook(blit_cave, blit_retn, blit_prologue, surf_ptrs_addr, n);
            debug_log!(
                "[INFO] blit hook: {} bytes, prologue={blit_plen}, cave=0x{blit_cave:08X}",
                blit_sc.len()
            );
            memory::write_code(h, blit_cave, &blit_sc)?;
            memory::write_code(
                h,
                blit_cave + BLIT_OFF_SCREEN_POS,
                &vec![0u8; MAX_HOVER_ENTRIES as usize * 8],
            )?;
            // 寫入 blit cave data 區（之前漏了！）
            memory::write_code(h, blit_cave + BLIT_OFF_COUNT, &n.to_le_bytes())?;
            memory::write_code(
                h,
                blit_cave + BLIT_OFF_SURF_PTRS_ADDR,
                &surf_ptrs_addr.to_le_bytes(),
            )?;
            debug_log!("[INFO] blit data: count={n}, surf_ptrs=0x{surf_ptrs_addr:08X}");

            let mut bhook = vec![0x90u8; blit_plen];
            bhook[0] = 0xE9;
            let brel = blit_cave.wrapping_sub(BLIT_B_ADDR + 5) as i32;
            bhook[1..5].copy_from_slice(&brel.to_le_bytes());

            let t2 = process::suspend_threads(pid)?;
            match memory::write_code(h, BLIT_B_ADDR, &bhook) {
                Ok(()) => {
                    process::resume_threads(t2);
                    log_line!("[OK] blit hook @ 0x{BLIT_B_ADDR:08X} → 0x{blit_cave:08X}");
                }
                Err(e) => {
                    process::resume_threads(t2);
                    log_line!("[警告] blit hook 失敗: {e}");
                }
            }

            return Ok(Some(HoverHookResult {
                cave_draw: cave_addr,
                cave_blit: blit_cave,
                game_handle: h,
                pid,
                draw_hook_bytes,
                draw_orig_bytes,
            }));
        }
    }

    Ok(Some(HoverHookResult {
        cave_draw: cave_addr,
        cave_blit: 0,
        game_handle: h,
        pid,
        draw_hook_bytes,
        draw_orig_bytes,
    }))
}

/// 組裝 draw hook codecave（舊版，已被 v2 取代）
#[allow(dead_code)]
fn _build_draw_hook_old(cave_addr: u32, draw_addr: u32, gsr_orig: u32, surf_mgr: u32) -> Vec<u8> {
    let mut sc: Vec<u8> = Vec::with_capacity(96);
    let a_count = cave_addr + OFF_COUNT;
    let a_map = cave_addr + OFF_MAP;

    // === 讀 src_id ===
    // push eax; push edx; push esi
    sc.push(0x50);
    sc.push(0x52);
    sc.push(0x56);

    // mov eax, [ebp-0x44]    ; element ptr
    sc.extend_from_slice(&[0x8B, 0x45, 0xBC]); // 0xBC = -0x44 as u8
                                               // mov edx, [eax+0x20]    ; src_id
    sc.extend_from_slice(&[0x8B, 0x50, 0x20]);

    // === 掃描映射表 ===
    sc.extend_from_slice(&[0x8B, 0x35]); // mov esi, [a_count]
    sc.extend_from_slice(&a_count.to_le_bytes());
    sc.push(0x50); // push eax (save element ptr)
    sc.push(0xB8); // mov eax, a_map
    sc.extend_from_slice(&a_map.to_le_bytes());

    let scan_off = sc.len();
    sc.extend_from_slice(&[0x85, 0xF6]); // test esi, esi
    sc.push(0x74);
    let jz_nm = sc.len();
    sc.push(0x00); // jz .no_match
    sc.extend_from_slice(&[0x39, 0x10]); // cmp [eax], edx (compare map.src_id with edx=src_id)
    sc.push(0x74);
    let je_found = sc.len();
    sc.push(0x00); // je .found
    sc.extend_from_slice(&[0x83, 0xC0, MAP_ENTRY as u8]); // add eax, 8
    sc.push(0x4E); // dec esi
    sc.push(0xEB);
    let jmp_scan = sc.len();
    sc.push(0x00);
    sc[jmp_scan] = (scan_off as u8).wrapping_sub((jmp_scan + 1) as u8);

    // .no_match:
    let nm_off = sc.len();
    sc[jz_nm] = (nm_off - jz_nm - 1) as u8;
    sc.push(0x58); // pop eax (discard saved element ptr)
    sc.push(0xEB);
    let jmp_done = sc.len();
    sc.push(0x00); // jmp .done

    // .found: eax = &map_entry, edx = src_id
    let found_off = sc.len();
    sc[je_found] = (found_off - je_found - 1) as u8;
    sc.push(0x58); // pop eax (discard saved element ptr)

    // 永遠替換模式（暫時不檢查 hover，先測 draw hook 有效性）
    // 取 highlight_id
    // eax 被 pop 了，需要重新載入 map entry... 改用不同方式

    // 重新載入 map entry: edx 仍有 src_id，重掃一次太慢
    // 改用更簡單的方式：在 scan 時保存 eax（map entry ptr）

    // 其實上面 pop eax 丟棄的是 element ptr，而 eax 在 scan loop 結束時指向匹配的 entry。
    // 但 pop eax 覆蓋了它。改設計：用 esi 保存 entry。

    // 重新設計，更簡潔：
    // 算了，讓我重寫。上面的設計有 register 衝突。

    sc.clear();

    // === 重新設計 ===
    // push eax; push edx
    sc.push(0x50);
    sc.push(0x52);

    // mov eax, [ebp-0x44]    ; element
    sc.extend_from_slice(&[0x8B, 0x45, 0xBC]);
    // mov eax, [eax+0x20]    ; src_id
    sc.extend_from_slice(&[0x8B, 0x40, 0x20]);
    // eax = src_id

    // 掃描映射表（用 edx 做 counter/pointer）
    push_scan_loop(&mut sc, cave_addr, a_count, a_map);

    // jmp 到 .done（scan_loop 內部處理了 found/not_found）
    // scan_loop 會設置 ecx = highlight surface 或保持不變

    // pop edx; pop eax
    sc.push(0x5A);
    sc.push(0x58);

    // jmp draw
    sc.push(0xE9);
    let jmp_from = cave_addr + sc.len() as u32 + 4;
    sc.extend_from_slice(&draw_addr.wrapping_sub(jmp_from).to_le_bytes());

    sc
}

/// 組裝映射表掃描 + 替換邏輯
/// 進入: eax = src_id, ecx = current surface
/// 出口: ecx = (可能替換的) surface
fn push_scan_loop(sc: &mut Vec<u8>, cave_addr: u32, a_count: u32, a_map: u32) {
    let gsr_orig = cave_addr + 0x60; // GetSurfResource original trampoline
    let surf_mgr_addr = cave_addr + OFF_SURF_MGR;

    // push esi; push edi
    sc.push(0x56);
    sc.push(0x57);

    // mov esi, [a_count]
    sc.extend_from_slice(&[0x8B, 0x35]);
    sc.extend_from_slice(&a_count.to_le_bytes());
    // mov edi, a_map
    sc.push(0xBF);
    sc.extend_from_slice(&a_map.to_le_bytes());

    let scan_off = sc.len();
    // test esi, esi
    sc.extend_from_slice(&[0x85, 0xF6]);
    // jz .no_match
    sc.push(0x74);
    let jz_nm = sc.len();
    sc.push(0x00);
    // cmp [edi], eax (map.src_id == src_id?)
    sc.extend_from_slice(&[0x39, 0x07]);
    // je .found
    sc.push(0x74);
    let je_found = sc.len();
    sc.push(0x00);
    // add edi, 8; dec esi; jmp .scan
    sc.extend_from_slice(&[0x83, 0xC7, MAP_ENTRY as u8]);
    sc.push(0x4E);
    sc.push(0xEB);
    let jmp_scan = sc.len();
    sc.push(0x00);
    sc[jmp_scan] = (scan_off as u8).wrapping_sub((jmp_scan + 1) as u8);

    // .no_match:
    let nm_off = sc.len();
    sc[jz_nm] = (nm_off - jz_nm - 1) as u8;
    // pop edi; pop esi; ret (不替換)
    sc.push(0x5F);
    sc.push(0x5E);
    sc.push(0xEB);
    let jmp_end = sc.len();
    sc.push(0x00); // jmp .end

    // .found: edi = &map_entry, [edi+4] = highlight_id
    let found_off = sc.len();
    sc[je_found] = (found_off - je_found - 1) as u8;

    // 永遠替換（測試版 — 不檢查 g_hover_id）
    // 呼叫 GetSurfResource_original(highlight_id)
    // push highlight_id
    sc.extend_from_slice(&[0xFF, 0x77, 0x04]); // push [edi+4] = highlight_id
                                               // mov ecx, [surf_mgr_addr]
    sc.extend_from_slice(&[0x8B, 0x0D]);
    sc.extend_from_slice(&surf_mgr_addr.to_le_bytes());
    // call gsr_orig (original GetSurfResource, no hook)
    sc.push(0xE8);
    let call_from = cave_addr + sc.len() as u32 + 4; // approximate, adjusted later
                                                     // 需要知道 sc 在 cave 中的偏移... 但 push_scan_loop 是被 build_draw_hook 呼叫的
                                                     // sc 的偏移 = build_draw_hook 呼叫前的長度 + 當前長度
                                                     // 這不好計算，用一個 placeholder 然後修正
    let call_fixup = sc.len();
    sc.extend_from_slice(&[0; 4]); // placeholder

    // GetSurfResource returns in eax, ret 4 cleans highlight_id
    // ecx = eax (highlight surface)
    sc.extend_from_slice(&[0x8B, 0xC8]); // mov ecx, eax

    // pop edi; pop esi
    sc.push(0x5F);
    sc.push(0x5E);

    // .end:
    let end_off = sc.len();
    sc[jmp_end] = (end_off - jmp_end - 1) as u8;

    // 修正 call gsr_orig 的 rel32
    // 問題：我們不知道 sc 在整個 shellcode 中的偏移
    // 需要在 build_draw_hook 裡修正
    // 標記位置供外部修正
    // 用一個 hack：在 scan_loop 開頭記錄起始偏移

    // 暫時用絕對地址跳轉代替 rel32 call
    // 改用 call [addr] 間接呼叫
    // 但 GetSurfResource 是 thiscall + push arg，不能用 call [addr]

    // 最簡單：改用 FF 15 (call [imm32]) 間接呼叫
    // 但 GetSurfResource original trampoline 不是存在指標裡，它是一段代碼
    // 需要用 E8 rel32 直接 call

    // 問題：push_scan_loop 不知道自己在整體 shellcode 中的偏移
    // 解決：讓 build_draw_hook 在呼叫後修正 rel32

    // 在 call_fixup 位置留下一個標記，讓 build_draw_hook 計算並填入正確的 rel32
    // 返回 call_fixup 的位置給外部
    // 但 Rust 函數已經返回... 用一個 known pattern 做標記

    // 算了，把整個邏輯放在 build_draw_hook 裡，不要用子函數
}

// draw hook v21: 學習+重播雙模式（重播模式不讀 [ebp-0x44]，防重登閃退）
fn build_draw_hook_v2(cave_addr: u32, draw_addr: u32, gsr_orig: u32, surf_mgr: u32) -> Vec<u8> {
    let mut sc: Vec<u8> = Vec::with_capacity(160);
    let a_count = cave_addr + OFF_COUNT;
    let a_hover_id = cave_addr + OFF_HOVER_ID;
    let a_map = cave_addr + OFF_MAP;
    let a_surf_ptrs = cave_addr + OFF_SURF_PTRS;
    let a_hl_surfs = cave_addr + OFF_HL_SURFS;
    let a_learned = cave_addr + OFF_LEARNED;
    let a_elem = cave_addr + OFF_ELEM_PTR;

    // 進入: ecx = surface（永遠有效）, [esp] = ret addr
    // EBP = caller frame, [ebp-0x44] = element（學習模式才安全讀取）

    // === count guard（用 near jump 避免 signed byte 溢位）===
    sc.push(0x50); // push eax
    sc.extend_from_slice(&[0xA1]);
    sc.extend_from_slice(&a_count.to_le_bytes()); // mov eax, [a_count]
    sc.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    sc.push(0x58); // pop eax
                   // jnz .count_ok（短跳 +5 bytes 跳過 jmp）; jmp draw（near jump，不受距離限制）
    sc.push(0x75);
    sc.push(0x05); // jnz +5
    sc.push(0xE9); // jmp draw（count=0 → 直接跳到 draw）
    let jf_guard = cave_addr + sc.len() as u32 + 4;
    sc.extend_from_slice(&draw_addr.wrapping_sub(jf_guard).to_le_bytes());
    // .count_ok: count > 0

    // === 模式切換：learned >= count → 重播模式 ===
    sc.push(0x50); // push eax
    sc.extend_from_slice(&[0xA1]);
    sc.extend_from_slice(&a_learned.to_le_bytes()); // mov eax, [a_learned]
    sc.extend_from_slice(&[0x3B, 0x05]);
    sc.extend_from_slice(&a_count.to_le_bytes()); // cmp eax, [a_count]
    sc.push(0x58); // pop eax
    sc.push(0x7D);
    let jge_replay = sc.len();
    sc.push(0x00); // jge .replay_mode

    // ========== 學習模式（[ebp-0x44] 有效 — 對話剛開啟）==========
    sc.push(0x50);
    sc.push(0x51);
    sc.push(0x52);
    sc.push(0x56);
    sc.push(0x57); // push eax,ecx,edx,esi,edi

    sc.extend_from_slice(&[0x8B, 0x45, 0xBC]); // mov eax, [ebp-0x44] (element)
    sc.push(0xA3);
    sc.extend_from_slice(&a_elem.to_le_bytes()); // mov [a_elem], eax
    sc.extend_from_slice(&[0x8B, 0x40, 0x20]); // mov eax, [eax+0x20] (src_id)

    // 掃描映射表
    sc.extend_from_slice(&[0x8B, 0x35]);
    sc.extend_from_slice(&a_count.to_le_bytes()); // mov esi, [a_count]
    sc.push(0xBF);
    sc.extend_from_slice(&a_map.to_le_bytes()); // mov edi, a_map
    sc.push(0xBA);
    sc.extend_from_slice(&a_surf_ptrs.to_le_bytes()); // mov edx, a_surf_ptrs

    let learn_scan = sc.len();
    sc.extend_from_slice(&[0x85, 0xF6]); // test esi, esi
    sc.push(0x74);
    let jz_learn_nm = sc.len();
    sc.push(0x00); // jz .learn_no_match
    sc.extend_from_slice(&[0x39, 0x07]); // cmp [edi], eax
    sc.push(0x74);
    let je_learn_found = sc.len();
    sc.push(0x00); // je .learn_found
    sc.extend_from_slice(&[0x83, 0xC7, MAP_ENTRY as u8]); // add edi, 8
    sc.extend_from_slice(&[0x83, 0xC2, 0x04]); // add edx, 4
    sc.push(0x4E); // dec esi
    sc.push(0xEB);
    let jmp_learn_loop = sc.len();
    sc.push(0x00);
    sc[jmp_learn_loop] = (learn_scan as u8).wrapping_sub((jmp_learn_loop + 1) as u8);

    // .learn_no_match:
    let learn_nm = sc.len();
    sc[jz_learn_nm] = (learn_nm - jz_learn_nm - 1) as u8;
    sc.push(0xEB);
    let jmp_learn_done = sc.len();
    sc.push(0x00); // jmp .learn_done

    // .learn_found: edi=&entry, edx=&surf_ptrs[i], eax=src_id, ecx=surface
    let learn_found = sc.len();
    sc[je_learn_found] = (learn_found - je_learn_found - 1) as u8;

    // 檢查 surf_ptrs[i] 是否已記錄（非零則跳過）
    sc.extend_from_slice(&[0x83, 0x3A, 0x00]); // cmp dword [edx], 0
    sc.push(0x75);
    let jnz_already = sc.len();
    sc.push(0x00); // jnz .learn_done

    // 記錄原始 surface_data: surf_ptrs[i] = [ecx+4]
    sc.push(0x56); // push esi
    sc.extend_from_slice(&[0x8B, 0x71, 0x04]); // mov esi, [ecx+4]
    sc.extend_from_slice(&[0x89, 0x32]); // mov [edx], esi  (surf_ptrs[i] = surface_data)
    sc.push(0x5E); // pop esi

    // 記錄 highlight surface: 呼叫 GSR_original(hl_id) → 存到 hl_surfs[i]
    // ★ GSR call 會破壞 edx/ecx，必須保存
    sc.push(0x52); // push edx（保存 &surf_ptrs[i]，GSR 會破壞 edx）
    sc.extend_from_slice(&[0xFF, 0x77, 0x04]); // push [edi+4] = highlight_id
    sc.push(0xB9);
    sc.extend_from_slice(&surf_mgr.to_le_bytes()); // mov ecx, surf_mgr（破壞 ecx）
    sc.push(0xE8); // call gsr_orig（ret 4 清理 arg）
    let call_from = cave_addr + sc.len() as u32;
    sc.extend_from_slice(&gsr_orig.wrapping_sub(call_from + 4).to_le_bytes());
    // eax = highlight surface. edx 已被 GSR 破壞 → pop 還原
    sc.push(0x5A); // pop edx（還原 &surf_ptrs[i]）
    let hl_offset = (OFF_HL_SURFS - OFF_SURF_PTRS) as u8;
    sc.extend_from_slice(&[0x89, 0x42, hl_offset]); // mov [edx+hl_offset], eax (hl_surfs[i])

    // 遞增 learned 計數器
    sc.extend_from_slice(&[0xFF, 0x05]); // inc dword [a_learned]
    sc.extend_from_slice(&a_learned.to_le_bytes());

    // .learn_done:
    let learn_done = sc.len();
    sc[jmp_learn_done] = (learn_done - jmp_learn_done - 1) as u8;
    sc[jnz_already] = (learn_done - jnz_already - 1) as u8;

    sc.push(0x5F);
    sc.push(0x5E);
    sc.push(0x5A);
    sc.push(0x59);
    sc.push(0x58); // pop edi,esi,edx,ecx,eax
    sc.push(0xE9); // jmp draw（ecx = 原始 surface，已還原）
    let jf_learn = cave_addr + sc.len() as u32 + 4;
    sc.extend_from_slice(&draw_addr.wrapping_sub(jf_learn).to_le_bytes());

    // ========== 重播模式（只用 ecx，不碰 [ebp-0x44]）==========
    let replay_off = sc.len();
    sc[jge_replay] = (replay_off - jge_replay - 1) as u8;

    sc.push(0x50);
    sc.push(0x52);
    sc.push(0x56);
    sc.push(0x57); // push eax,edx,esi,edi

    sc.extend_from_slice(&[0x8B, 0x41, 0x04]); // mov eax, [ecx+4] (surface_data, 永遠安全)

    // 比對 g_hover_id（存的是 hovered 的 surface_data）
    sc.extend_from_slice(&[0x3B, 0x05]);
    sc.extend_from_slice(&a_hover_id.to_le_bytes()); // cmp eax, [a_hover_id]
    sc.push(0x75);
    let jne_replay_done = sc.len();
    sc.push(0x00); // jne .replay_done

    // hover 有效! 找對應的 hl_surf
    sc.extend_from_slice(&[0x8B, 0x35]);
    sc.extend_from_slice(&a_count.to_le_bytes()); // mov esi, [a_count]
    sc.push(0xBF);
    sc.extend_from_slice(&a_surf_ptrs.to_le_bytes()); // mov edi, a_surf_ptrs
    sc.push(0xBA);
    sc.extend_from_slice(&a_hl_surfs.to_le_bytes()); // mov edx, a_hl_surfs

    let replay_scan = sc.len();
    sc.extend_from_slice(&[0x85, 0xF6]); // test esi, esi
    sc.push(0x74);
    let jz_replay_nm = sc.len();
    sc.push(0x00); // jz .replay_done
    sc.extend_from_slice(&[0x39, 0x07]); // cmp [edi], eax (surf_ptrs[i] == surface_data?)
    sc.push(0x74);
    let je_replay_found = sc.len();
    sc.push(0x00); // je .replay_replace
    sc.extend_from_slice(&[0x83, 0xC7, 0x04]); // add edi, 4
    sc.extend_from_slice(&[0x83, 0xC2, 0x04]); // add edx, 4
    sc.push(0x4E); // dec esi
    sc.push(0xEB);
    let jmp_replay_loop = sc.len();
    sc.push(0x00);
    sc[jmp_replay_loop] = (replay_scan as u8).wrapping_sub((jmp_replay_loop + 1) as u8);

    // .replay_replace:
    let replay_found = sc.len();
    sc[je_replay_found] = (replay_found - je_replay_found - 1) as u8;
    sc.extend_from_slice(&[0x8B, 0x0A]); // mov ecx, [edx] (ecx = hl_surfs[i])
    sc.extend_from_slice(&[0x85, 0xC9]); // test ecx, ecx
    sc.push(0x74);
    let jz_null_hl = sc.len();
    sc.push(0x00); // jz .replay_done (null → skip)

    // .replay_done:
    let replay_done = sc.len();
    sc[jne_replay_done] = (replay_done - jne_replay_done - 1) as u8;
    sc[jz_replay_nm] = (replay_done - jz_replay_nm - 1) as u8;
    sc[jz_null_hl] = (replay_done - jz_null_hl - 1) as u8;

    sc.push(0x5F);
    sc.push(0x5E);
    sc.push(0x5A);
    sc.push(0x58); // pop edi,esi,edx,eax
    sc.push(0xE9); // jmp draw
    let jf_replay = cave_addr + sc.len() as u32 + 4;
    sc.extend_from_slice(&draw_addr.wrapping_sub(jf_replay).to_le_bytes());

    // .skip_all 已移除 — count guard 用 near jump 直接跳到 draw

    sc
}

/// 組裝 blit hook shellcode — 完整掃描版
/// blit_B 入口棧: [esp+4]=surface_data, [esp+16]=screen_X, [esp+20]=screen_Y
/// push 4 regs 後(+16): [esp+20]=surface_data, [esp+32]=screen_X, [esp+36]=screen_Y
fn build_blit_hook(
    blit_cave: u32,
    blit_retn: u32,
    blit_prologue: &[u8],
    _surf_ptrs_addr: u32,
    _n: u32,
) -> Vec<u8> {
    let mut sc: Vec<u8> = Vec::with_capacity(96);
    let a_count = blit_cave + BLIT_OFF_COUNT; // +0x60
    let a_surf_ptrs = blit_cave + BLIT_OFF_SURF_PTRS_ADDR; // +0x64（存的是指標值）
    let a_screen_pos = blit_cave + BLIT_OFF_SCREEN_POS; // +0x40

    // push eax, ecx, esi, edi（+16 bytes on stack）
    sc.push(0x50);
    sc.push(0x51);
    sc.push(0x56);
    sc.push(0x57);

    // mov eax, [esp+20] — surface_data（原 [esp+4] + 16）
    sc.extend_from_slice(&[0x8B, 0x44, 0x24, 20]);

    // mov ecx, [a_count] — entry 數量
    sc.extend_from_slice(&[0x8B, 0x0D]);
    sc.extend_from_slice(&a_count.to_le_bytes());

    // test ecx, ecx; jz .no_match
    sc.extend_from_slice(&[0x85, 0xC9]);
    sc.push(0x74);
    let jz_nm = sc.len();
    sc.push(0x00);

    // mov esi, [a_surf_ptrs] — 指向 draw cave 的 surf_data_ptrs 陣列
    sc.extend_from_slice(&[0x8B, 0x35]);
    sc.extend_from_slice(&a_surf_ptrs.to_le_bytes());

    // mov edi, esi — 保存 base 供後面算 index
    sc.extend_from_slice(&[0x8B, 0xFE]); // mov edi, esi

    // .scan:
    let scan_off = sc.len();
    // cmp eax, [esi]
    sc.extend_from_slice(&[0x3B, 0x06]);
    // je .found
    sc.push(0x74);
    let je_found = sc.len();
    sc.push(0x00);
    // add esi, 4
    sc.extend_from_slice(&[0x83, 0xC6, 0x04]);
    // dec ecx; jnz .scan
    sc.push(0x49);
    sc.push(0x75);
    let jnz_scan = sc.len();
    sc.push(0x00);
    sc[jnz_scan] = (scan_off as u8).wrapping_sub((jnz_scan + 1) as u8);
    // fall through → .no_match
    sc.push(0xEB);
    let jmp_nm = sc.len();
    sc.push(0x00); // jmp .no_match

    // .found: esi = &surf_data_ptrs[i], edi = &surf_data_ptrs[0]
    let found_off = sc.len();
    sc[je_found] = (found_off - je_found - 1) as u8;

    // 計算 index: esi - edi = i*4，screen_pos 每 entry 8 bytes → offset = (esi-edi)*2
    // sub esi, edi → esi = i*4
    sc.extend_from_slice(&[0x2B, 0xF7]); // sub esi, edi
                                         // shl esi, 1 → esi = i*8
    sc.extend_from_slice(&[0xD1, 0xE6]);
    // add esi, a_screen_pos → esi → screen_pos[i]
    sc.extend_from_slice(&[0x81, 0xC6]);
    sc.extend_from_slice(&a_screen_pos.to_le_bytes());

    // mov edi, [esp+32] — screen_X（原 [esp+16] + 16）
    sc.extend_from_slice(&[0x8B, 0x7C, 0x24, 32]);
    // mov [esi], edi
    sc.extend_from_slice(&[0x89, 0x3E]);
    // mov edi, [esp+36] — screen_Y（原 [esp+20] + 16）
    sc.extend_from_slice(&[0x8B, 0x7C, 0x24, 36]);
    // mov [esi+4], edi
    sc.extend_from_slice(&[0x89, 0x7E, 0x04]);

    // .no_match:
    let nm_off = sc.len();
    sc[jz_nm] = (nm_off - jz_nm - 1) as u8;
    sc[jmp_nm] = (nm_off - jmp_nm - 1) as u8;

    // pop edi, esi, ecx, eax
    sc.push(0x5F);
    sc.push(0x5E);
    sc.push(0x59);
    sc.push(0x58);

    // 原始 blit prologue
    sc.extend_from_slice(blit_prologue);
    // jmp blit_retn
    sc.push(0xE9);
    let jf = blit_cave + sc.len() as u32 + 4;
    sc.extend_from_slice(&blit_retn.wrapping_sub(jf).to_le_bytes());

    sc
}

/// polling: 從 blit hook 的 screen_pos 做碰撞檢測
pub fn poll_hover_tick(
    h: HANDLE,
    cave_draw: u32,
    blit_cave: u32,
    pid: u32,
    cursor_x: i32,
    cursor_y: i32,
    _draw_hook_bytes: &[u8; 5],
    _draw_orig_bytes: &[u8; 5],
) -> Result<()> {
    static SCAN_TICKS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let tick = SCAN_TICKS.fetch_add(1, Ordering::Relaxed);
    let cur_count = memory::read_u32(h, cave_draw + OFF_COUNT).unwrap_or(0);

    // 定期掃描 highlight（每 ~300ms，count=0 時）
    if cur_count == 0 && tick % 10 == 0 {
        let mappings = scan_highlight_mappings(h, 0);
        if !mappings.is_empty() {
            update_hover_map_in_cave(h, cave_draw, blit_cave, pid, &mappings);
        }
    }

    // 重登偵測由 connect hook 處理（connect hook 在重連時重置 count）

    let n = memory::read_u32(h, cave_draw + OFF_COUNT)? as usize;
    if n == 0 {
        return Ok(());
    }

    // 讀 blit 記錄的螢幕座標（每幀更新）
    let pos_data = memory::read_bytes(h, blit_cave + BLIT_OFF_SCREEN_POS, n * 8)?;
    // 讀映射表（取 src_id）
    let map_data = memory::read_bytes(h, cave_draw + OFF_MAP, n * MAP_ENTRY as usize)?;

    // 碰撞檢測：client = blit × 1.5 + offset（F6 動態校準）
    let off_x = CALIB_OFF_X.load(Ordering::Relaxed);
    let off_y = CALIB_OFF_Y.load(Ordering::Relaxed);

    let mut hovered = 0u32;
    for i in 0..n {
        let sx = i32::from_le_bytes(pos_data[i * 8..i * 8 + 4].try_into().unwrap());
        let sy = i32::from_le_bytes(pos_data[i * 8 + 4..i * 8 + 8].try_into().unwrap());
        if sx == 0 && sy == 0 {
            continue;
        }
        let src_id = u32::from_le_bytes(map_data[i * 8..i * 8 + 4].try_into().unwrap());

        // client = blit * 3/2 + offset
        let screen_left = sx * 3 / 2 + off_x;
        let screen_top = sy * 3 / 2 + off_y;
        let screen_right = (sx + 60) * 3 / 2 + off_x;
        let screen_bottom = (sy + 80) * 3 / 2 + off_y;

        if cursor_x >= screen_left
            && cursor_x < screen_right
            && cursor_y >= screen_top
            && cursor_y < screen_bottom
        {
            // 寫 surface_data（不是 src_id）— 重播模式用 surface_data 比對
            hovered = memory::read_u32(h, cave_draw + OFF_SURF_PTRS + (i as u32) * 4).unwrap_or(0);
            break;
        }
    }

    // 一次性：顯示碰撞範圍 + 搜尋 highlight 屬性
    static DEBUG_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !DEBUG_DONE.load(Ordering::Relaxed) {
        let first_x = i32::from_le_bytes(pos_data[0..4].try_into().unwrap());
        if first_x != 0 {
            for i in 0..n {
                let sx = i32::from_le_bytes(pos_data[i * 8..i * 8 + 4].try_into().unwrap());
                let sy = i32::from_le_bytes(pos_data[i * 8 + 4..i * 8 + 8].try_into().unwrap());
                let sid = u32::from_le_bytes(map_data[i * 8..i * 8 + 4].try_into().unwrap());
                let cl = sx * 3 / 2 + off_x;
                let ct = sy * 3 / 2 + off_y;
                debug_log!(
                    "[hover] #{sid}: blit=({sx},{sy}) → client=({cl},{ct})~({},{})",
                    cl + 90,
                    ct + 120
                );
            }
            debug_log!("[hover] offset=({off_x},{off_y}) — 按 F6 校準");

            // 搜尋 highlight：遍歷 element chain 的文字
            let elem = memory::read_u32(h, cave_draw + OFF_ELEM_PTR).unwrap_or(0);
            if elem > 0x10000 {
                scan_element_chain_for_highlight(h, elem);
            }

            DEBUG_DONE.store(true, Ordering::Relaxed);
        }
    }

    memory::write_code(h, cave_draw + OFF_HOVER_ID, &hovered.to_le_bytes())?;
    Ok(())
}

/// 掃描 heap 記憶體找 highlight="#XXXX" pattern，動態建立映射
fn scan_highlight_mappings(h: HANDLE, elem_ptr: u32) -> Vec<(u32, u32)> {
    // 搜尋 ASCII pattern: highlight="#
    let pattern: Vec<Option<u8>> = b"highlight=\"#".iter().map(|&b| Some(b)).collect();

    // 三層掃描：16MB（最快）→ 96MB → 767MB（完整）
    let mut hits =
        memory::scan_pattern_all(h, 0x21000000, 0x22000000, &pattern).unwrap_or_default();
    if hits.is_empty() {
        hits = memory::scan_pattern_all(h, 0x1F000000, 0x25000000, &pattern).unwrap_or_default();
    }
    if hits.is_empty() {
        hits = memory::scan_pattern_all(h, 0x00100000, 0x30000000, &pattern).unwrap_or_default();
    }

    if hits.is_empty() {
        // Unicode 版: h\0i\0g\0h\0l\0i\0g\0h\0t\0=\0\"\0#\0
        let uni: Vec<Option<u8>> = "highlight=\"#"
            .bytes()
            .flat_map(|b| [Some(b), Some(0)])
            .collect();
        let uhits = memory::scan_pattern_all(h, 0x00100000, 0x30000000, &uni).unwrap_or_default();
        if uhits.is_empty() {
            return Vec::new();
        }
        return parse_hits_unicode(h, &uhits);
    }

    let mut mappings = Vec::new();
    for &addr in &hits {
        // 直接從 hit+12 讀 highlight 數字（跳過 'highlight="#'）
        let hl = match memory::read_bytes(h, addr + 12, 10) {
            Ok(buf) => {
                let s = String::from_utf8_lossy(&buf);
                let end = s.find('"').unwrap_or(s.len());
                s[..end].parse::<u32>().unwrap_or(0)
            }
            Err(_) => 0,
        };
        if hl == 0 {
            continue;
        }

        // 往前讀 80 bytes，rfind 找最近的 src="#
        if let Ok(buf) = memory::read_bytes(h, addr.saturating_sub(80), 80) {
            let text = String::from_utf8_lossy(&buf);
            if let Some(pos) = text.rfind("src=\"#") {
                let rest = &text[pos + 6..]; // "src=\"#" = 6 chars
                if let Some(end) = rest.find('"') {
                    if let Ok(src) = rest[..end].parse::<u32>() {
                        if !mappings.iter().any(|&(s, _)| s == src) {
                            mappings.push((src, hl));
                        }
                    }
                }
            }
        }
    }
    mappings
}

/// 從 Unicode hit 解析映射
fn parse_hits_unicode(h: HANDLE, hits: &[u32]) -> Vec<(u32, u32)> {
    let mut mappings = Vec::new();
    for &addr in hits {
        let read_start = addr.saturating_sub(240);
        if let Ok(buf) = memory::read_bytes(h, read_start, 600) {
            let u16s: Vec<u16> = buf
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let text = String::from_utf16_lossy(&u16s);
            if let Some((src, hl)) = parse_img_tag_from_context(&text) {
                if !mappings.iter().any(|&(s, _)| s == src) {
                    mappings.push((src, hl));
                }
            }
        }
    }
    mappings
}

/// 從 context 中找 highlight 最近的 <img 標籤，提取 src 和 highlight
fn parse_img_tag_from_context(text: &str) -> Option<(u32, u32)> {
    let hl_pos = text.find("highlight=\"#")?;
    // 往前找最近的 <img（rfind = 從後往前找，確保是同一個標籤）
    let before = &text[..hl_pos];
    let img_pos = before.rfind("<img").or_else(|| before.rfind("<IMG"))?;
    let tag = &text[img_pos..];
    let src = extract_attr_from_context(tag, "src=\"#")?;
    let hl = extract_attr_from_context(tag, "highlight=\"#")?;
    Some((src, hl))
}

/// 從上下文文字中提取屬性值（如 `src="#3431"` → 3431）
fn extract_attr_from_context(text: &str, prefix: &str) -> Option<u32> {
    let pos = text.find(prefix)? + prefix.len();
    let rest = &text[pos..];
    let end = rest.find('"')?;
    rest[..end].parse().ok()
}

/// 動態更新 codecave 的映射表 + blit cave 的 count
fn update_hover_map_in_cave(
    h: HANDLE,
    cave_draw: u32,
    blit_cave: u32,
    pid: u32,
    mappings: &[(u32, u32)],
) {
    let n = mappings.len().min(MAX_HOVER_ENTRIES as usize) as u32;
    log_line!("[hover] 動態映射 {n} 個:");
    for &(src, hl) in mappings.iter().take(n as usize) {
        log_line!("[hover]   #{src} → #{hl}");
    }

    let threads = process::suspend_threads(pid).unwrap_or_default();

    // 寫入映射表
    let _ = memory::write_code(h, cave_draw + OFF_COUNT, &n.to_le_bytes());
    for (i, &(src, hl)) in mappings.iter().take(n as usize).enumerate() {
        let off = OFF_MAP + (i as u32) * 8;
        let _ = memory::write_code(h, cave_draw + off, &src.to_le_bytes());
        let _ = memory::write_code(h, cave_draw + off + 4, &hl.to_le_bytes());
    }
    // 清零學習模式資料（觸發重新學習）
    let _ = memory::write_code(h, cave_draw + OFF_SURF_PTRS, &vec![0u8; n as usize * 4]);
    let _ = memory::write_code(h, cave_draw + OFF_HL_SURFS, &vec![0u8; n as usize * 4]);
    let _ = memory::write_code(h, cave_draw + OFF_LEARNED, &0u32.to_le_bytes());

    // 更新 blit cave
    if blit_cave != 0 {
        let _ = memory::write_code(h, blit_cave + BLIT_OFF_COUNT, &n.to_le_bytes());
        let _ = memory::write_code(
            h,
            blit_cave + BLIT_OFF_SCREEN_POS,
            &vec![0u8; n as usize * 8],
        );
    }

    process::resume_threads(threads);
}

/// 遍歷 element chain，搜尋 "highlight" 字串（debug 用）
fn scan_element_chain_for_highlight(h: HANDLE, start_elem: u32) {
    debug_log!("[scan] 搜尋 highlight 屬性...");

    // 往前走到鏈表頭
    let mut cur = start_elem;
    for _ in 0..50 {
        let prev = memory::read_u32(h, cur + 0x18).unwrap_or(0);
        if prev == 0 || prev < 0x10000 {
            break;
        }
        cur = prev;
    }

    // 從頭往後遍歷
    let mut idx = 0u32;
    let mut found_any = false;
    while cur != 0 && cur > 0x10000 && idx < 50 {
        let src_id = memory::read_u32(h, cur + 0x20).unwrap_or(0);

        // 讀取大量文字（+0x04 開始到 +0x200）
        if let Ok(raw) = memory::read_bytes(h, cur + 0x04, 0x200) {
            let text = String::from_utf8_lossy(&raw);
            // 搜尋 "highlight"（不區分大小寫）
            let lower = text.to_lowercase();
            if lower.contains("highlight") {
                debug_log!("[scan] 元素 #{idx} src_id={src_id}: 找到 highlight!");
                // 顯示包含 highlight 的上下文
                if let Some(pos) = lower.find("highlight") {
                    let start = pos.saturating_sub(30);
                    let end = (pos + 40).min(text.len());
                    let ctx = &text[start..end];
                    debug_log!("[scan]   上下文: ...{ctx}...");
                }
                found_any = true;
            }

            // 也搜尋 "<img"
            if lower.contains("<img") {
                if let Some(pos) = lower.find("<img") {
                    let end = (pos + 80).min(text.len());
                    let ctx = &text[pos..end];
                    debug_log!("[scan] 元素 #{idx}: 找到 <img>: {ctx}");
                    found_any = true;
                }
            }
        }

        cur = memory::read_u32(h, cur + 0x14).unwrap_or(0);
        idx += 1;
    }

    if !found_any {
        debug_log!("[scan] 在 {idx} 個 element 中未找到 highlight 或 <img>");
        // 備選：掃描 shared renderer 附近的記憶體
        let shared = memory::read_u32(h, start_elem + 0x44).unwrap_or(0);
        if shared > 0x10000 {
            debug_log!("[scan] 嘗試掃描 shared renderer 0x{shared:08X} 附近...");
            // 讀 shared renderer 指向的 buffer chain
            for ptr_off in [0x04u32, 0x14, 0x28, 0x30, 0x50] {
                let ptr = memory::read_u32(h, shared + ptr_off).unwrap_or(0);
                if ptr > 0x10000 {
                    if let Ok(buf) = memory::read_bytes(h, ptr, 0x400) {
                        let text = String::from_utf8_lossy(&buf);
                        let lower = text.to_lowercase();
                        if lower.contains("highlight") {
                            debug_log!(
                                "[scan] shared+0x{ptr_off:02X} → 0x{ptr:08X}: 找到 highlight!"
                            );
                            if let Some(pos) = lower.find("highlight") {
                                let start = pos.saturating_sub(20);
                                let end = (pos + 60).min(text.len());
                                debug_log!("[scan]   {}", &text[start..end]);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// F6 按下時：自動找最近圖片 → 計算 offset → 更新碰撞
pub fn log_calibration(h: HANDLE, cave_draw: u32, blit_cave: u32, cursor_x: i32, cursor_y: i32) {
    let n = memory::read_u32(h, cave_draw + OFF_COUNT).unwrap_or(0) as usize;
    if n == 0 {
        debug_log!("[F6] 無 hover 映射");
        return;
    }

    let pos_data = match memory::read_bytes(h, blit_cave + BLIT_OFF_SCREEN_POS, n * 8) {
        Ok(d) => d,
        Err(_) => {
            debug_log!("[F6] 讀取失敗");
            return;
        }
    };

    // 找 cursor 最近的圖片（用當前 offset 估算 client 位置，比較 Y 中心距離）
    let cur_off_x = CALIB_OFF_X.load(Ordering::Relaxed);
    let cur_off_y = CALIB_OFF_Y.load(Ordering::Relaxed);
    let mut best_idx = 0usize;
    let mut best_dist = i32::MAX;
    for i in 0..n {
        let sx = i32::from_le_bytes(pos_data[i * 8..i * 8 + 4].try_into().unwrap());
        let sy = i32::from_le_bytes(pos_data[i * 8 + 4..i * 8 + 8].try_into().unwrap());
        if sx == 0 && sy == 0 {
            continue;
        }
        // 估算圖片中心的 client 座標
        let cx = (sx + 30) * 3 / 2 + cur_off_x;
        let cy = (sy + 40) * 3 / 2 + cur_off_y;
        let dist = (cursor_x - cx).abs() + (cursor_y - cy).abs(); // 曼哈頓距離
        if dist < best_dist {
            best_dist = dist;
            best_idx = i;
        }
    }

    let best_sx = i32::from_le_bytes(pos_data[best_idx * 8..best_idx * 8 + 4].try_into().unwrap());
    let best_sy = i32::from_le_bytes(
        pos_data[best_idx * 8 + 4..best_idx * 8 + 8]
            .try_into()
            .unwrap(),
    );

    // 假設 cursor 在圖片中心 → offset = cursor - blit_center * 1.5
    let new_off_x = cursor_x - (best_sx + 30) * 3 / 2;
    let new_off_y = cursor_y - (best_sy + 40) * 3 / 2;

    CALIB_OFF_X.store(new_off_x, Ordering::Relaxed);
    CALIB_OFF_Y.store(new_off_y, Ordering::Relaxed);

    // log
    if let Ok(map_data) = memory::read_bytes(h, cave_draw + OFF_MAP, n * MAP_ENTRY as usize) {
        let sid = u32::from_le_bytes(map_data[best_idx * 8..best_idx * 8 + 4].try_into().unwrap());
        debug_log!(
            "[F6] cursor=({cursor_x},{cursor_y}) 校準圖片=#{sid} blit=({best_sx},{best_sy})"
        );
    }
    debug_log!("[F6] 新 offset=({new_off_x},{new_off_y})（舊 offset=({cur_off_x},{cur_off_y})）");

    // 顯示校準後的碰撞範圍
    if let Ok(map_data) = memory::read_bytes(h, cave_draw + OFF_MAP, n * MAP_ENTRY as usize) {
        for i in 0..n {
            let sx = i32::from_le_bytes(pos_data[i * 8..i * 8 + 4].try_into().unwrap());
            let sy = i32::from_le_bytes(pos_data[i * 8 + 4..i * 8 + 8].try_into().unwrap());
            let sid = u32::from_le_bytes(map_data[i * 8..i * 8 + 4].try_into().unwrap());
            let l = sx * 3 / 2 + new_off_x;
            let t = sy * 3 / 2 + new_off_y;
            debug_log!("[F6] #{sid}: client=({l},{t})~({},{})", l + 90, t + 120);
        }
    }
}

pub fn find_hwnd_by_pid(target_pid: u32) -> Result<isize> {
    #[link(name = "user32")]
    extern "system" {
        fn GetTopWindow(hwnd: isize) -> isize;
        fn GetWindow(hwnd: isize, cmd: u32) -> isize;
        fn GetWindowThreadProcessId(hwnd: isize, pid: *mut u32) -> u32;
        fn GetWindowTextLengthW(hwnd: isize) -> i32;
        fn GetParent(hwnd: isize) -> isize;
    }
    const GW_HWNDNEXT: u32 = 2;
    for attempt in 0..30 {
        let mut hwnd = unsafe { GetTopWindow(0) };
        while hwnd != 0 {
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
            if pid == target_pid
                && unsafe { GetWindowTextLengthW(hwnd) } > 0
                && unsafe { GetParent(hwnd) } == 0
            {
                log_line!(
                    "[INFO] 找到頂層視窗: HWND=0x{:X}（嘗試 {}）",
                    hwnd,
                    attempt + 1
                );
                return Ok(hwnd);
            }
            hwnd = unsafe { GetWindow(hwnd, GW_HWNDNEXT) };
        }
        if attempt < 29 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    bail!("找不到 PID={target_pid} 的頂層視窗");
}
