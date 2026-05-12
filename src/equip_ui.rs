//! 裝備欄擴展模組 — 25 slot 支援（server index 1-31，附加式 XML 佈局）
//!
//! Patch A: ServerIndex_to_UISlot codecave（AOB 定位 + 擴展映射 1-31）
//! Patch B: SetupSlots 雙 Hook（B1 函數出口追加 + B2 bg index 修正）
//! Patch D: Surf ID bounds check 擴展（固定位址，已驗證）

use crate::logger::log_line;
use crate::{memory, process};
use anyhow::Result;
use windows::Win32::Foundation::HANDLE;

// === 常數 ===

/// AOB 掃描範圍（裝備欄相關函數所在區域）
const SCAN_START: u32 = 0x790000;
const SCAN_END: u32 = 0x7A0000;

/// Surf bounds check（運行時已驗證正確的固定位址）
const SURF_BOUNDS_CHECK: u32 = 0x4387DB;

/// AOB helper
const fn s(b: u8) -> Option<u8> {
    Some(b)
}
const W: Option<u8> = None;

/// Lookup table: server_index (0-31) → UI slot number（0 = 無效）
const EQUIP_LOOKUP_TABLE: [u8; 32] = [
    0,  // idx 0: unused
    2,  // idx 1:  Helm → UI#2
    5,  // idx 2:  Armor → UI#5
    4,  // idx 3:  TShirt → UI#4
    6,  // idx 4:  Cloak → UI#6
    11, // idx 5:  Boots → UI#11
    7,  // idx 6:  Glove → UI#7
    9,  // idx 7:  Shield → UI#9
    14, // idx 8:  Weapon → UI#14
    16, // idx 9:  Arrow → UI#16
    3,  // idx 10: Amulet → UI#3
    8,  // idx 11: Belt → UI#8
    1,  // idx 12: Earring → UI#1
    0, 0, 0, 0, 0,  // idx 13-17: unused
    10, // idx 18: Ring1 → UI#10
    12, // idx 19: Ring2 → UI#12
    13, // idx 20: Ring3/Lv80 → UI#13
    15, // idx 21: Ring4/Lv85 → UI#15
    17, // idx 22: Rune → UI#17
    18, // idx 23: 第二符石 → UI#18
    19, // idx 24: 第二耳環 → UI#19
    16, // idx 25: 褲子 → UI#16
    46, // idx 26: ExSlot1 → child#46（附加式佈局）
    47, // idx 27: ExSlot2 → child#47
    48, // idx 28: ExSlot3 → child#48
    49, // idx 29: ExSlot4 → child#49
    50, // idx 30: 徽章 → child#50
    51, // idx 31: 盾甲 → child#51
];

/// 主入口：安裝裝備欄擴展 patch（A + B + D）
pub fn install_equip_ui_patches(h: HANDLE, pid: u32) -> Result<()> {
    log_line!("\n--- 裝備欄擴展（附加式佈局）---");

    patch_server_index_to_ui_slot(h, pid)?;
    patch_setup_slots_hooks(h)?;
    patch_surf_bounds_check(h)?;

    log_line!("[OK] 裝備欄擴展 A+B+D 完成");
    Ok(())
}

// =========================================================================
// Patch A: ServerIndex_to_UISlot — AOB 定位 + codecave 替換
// =========================================================================

/// ServerIndex_to_UISlot switch 語句的 AOB 特徵碼
/// sub ecx,1; mov [ebp-0x0C],ecx; cmp [ebp-0x0C],0x15; ja ??; mov edx,[ebp-0x0C]; jmp [edx*4+table]
const AOB_SERVER_INDEX: [Option<u8>; 22] = [
    s(0x83),
    s(0xE9),
    s(0x01), // sub ecx, 1
    s(0x89),
    s(0x4D),
    s(0xF4), // mov [ebp-0x0C], ecx
    s(0x83),
    s(0x7D),
    s(0xF4),
    s(0x15), // cmp [ebp-0x0C], 0x15
    s(0x0F),
    s(0x87),
    W,
    W,
    W,
    W, // ja <default>（偏移 wildcard）
    s(0x8B),
    s(0x55),
    s(0xF4), // mov edx, [ebp-0x0C]
    s(0xFF),
    s(0x24),
    s(0x95), // jmp [edx*4 + table]
];

fn patch_server_index_to_ui_slot(h: HANDLE, pid: u32) -> Result<()> {
    let aob_addr = match memory::scan_pattern(h, SCAN_START, SCAN_END, &AOB_SERVER_INDEX)? {
        Some(a) => a,
        None => {
            log_line!("[警告] 找不到 ServerIndex_to_UISlot AOB，跳過 Patch A");
            return Ok(());
        }
    };

    log_line!("  Patch A: AOB 匹配 @ 0x{aob_addr:08X}");

    let func_entry = find_func_entry(h, aob_addr, 0x30)?;
    let func_entry = match func_entry {
        Some(e) => e,
        None => {
            log_line!("[警告] 找不到 ServerIndex_to_UISlot 函數入口，跳過 Patch A");
            return Ok(());
        }
    };

    let orig = memory::read_bytes(h, func_entry, 1)?;
    if orig[0] == 0xE9 {
        log_line!("[跳過] ServerIndex_to_UISlot 已被 hook");
        return Ok(());
    }

    let cave = memory::alloc_exec(h, 64)?;
    let table_addr = cave + 32;

    let mut sc: Vec<u8> = Vec::with_capacity(64);
    sc.extend_from_slice(&[0x55, 0x8B, 0xEC]); // push ebp; mov ebp, esp
    sc.extend_from_slice(&[0x8B, 0x45, 0x08]); // mov eax, [ebp+8]
    sc.extend_from_slice(&[0x83, 0xF8, 0x1F]); // cmp eax, 31
    sc.extend_from_slice(&[0x77, 0x0F]); // ja .ret_zero
    sc.extend_from_slice(&[0x85, 0xC0]); // test eax, eax
    sc.extend_from_slice(&[0x74, 0x0B]); // jz .ret_zero
    sc.extend_from_slice(&[0x0F, 0xB6, 0x80]); // movzx eax, byte [eax + table]
    sc.extend_from_slice(&table_addr.to_le_bytes());
    sc.extend_from_slice(&[0x5D, 0xC2, 0x04, 0x00]); // pop ebp; ret 4
    sc.extend_from_slice(&[0x31, 0xC0, 0x5D, 0xC2, 0x04, 0x00]); // xor eax,eax; pop ebp; ret 4
    assert_eq!(sc.len(), 32);
    sc.extend_from_slice(&EQUIP_LOOKUP_TABLE);

    memory::write_code(h, cave, &sc)?;

    let mut jmp = [0u8; 5];
    jmp[0] = 0xE9;
    let rel = cave.wrapping_sub(func_entry + 5) as i32;
    jmp[1..5].copy_from_slice(&rel.to_le_bytes());

    let threads = process::suspend_threads(pid)?;
    let result = memory::write_code(h, func_entry, &jmp);
    process::resume_threads(threads);
    result?;

    log_line!("[OK] Patch A: ServerIndex_to_UISlot @ 0x{func_entry:08X} → codecave 0x{cave:08X}");
    Ok(())
}

// =========================================================================
// Patch B: SetupSlots 雙 Hook — 附加式佈局（不改迴圈上限）
// =========================================================================
//
// 附加式 XML 佈局：新 ItemIcon 在 child 46-51，新 BgImage 在 child 52-57
// Lock Images/Labels 保持在原位（child 20-25），遊戲硬編碼不需修改。
//
// 原始 SetupSlots 迴圈只處理 slot 1-19。
// Hook B1: 在函數出口追加 6 次 helper 呼叫（child 46-51）
// Hook B2: helper 內 bg index 計算修正（>= 46 時 +6 而非 +0x1A）

/// SetupSlots 迴圈的 AOB（cmp 值用 wildcard，相容 0x14 或 0x1A）
const AOB_SETUP_SLOTS: [Option<u8>; 22] = [
    s(0xC7),
    s(0x45),
    s(0xF8),
    s(0x01),
    s(0x00),
    s(0x00),
    s(0x00), // mov [ebp-8], 1
    s(0xEB),
    s(0x09), // jmp +9
    s(0x8B),
    s(0x4D),
    s(0xF8), // mov ecx, [ebp-8]
    s(0x83),
    s(0xC1),
    s(0x01), // add ecx, 1
    s(0x89),
    s(0x4D),
    s(0xF8), // mov [ebp-8], ecx
    s(0x83),
    s(0x7D),
    s(0xF8),
    W, // cmp [ebp-8], ?? (wildcard)
];

fn patch_setup_slots_hooks(h: HANDLE) -> Result<()> {
    let aob_addr = match memory::scan_pattern(h, SCAN_START, SCAN_END, &AOB_SETUP_SLOTS)? {
        Some(a) => a,
        None => {
            log_line!("[警告] 找不到 SetupSlots AOB，跳過 Patch B");
            return Ok(());
        }
    };
    log_line!("  Patch B: AOB 匹配 @ 0x{aob_addr:08X}");

    // --- 計算 hook 點位址（都是 AOB 的相對偏移）---
    let exit_addr = aob_addr + 0x2E; // 函數 epilogue: mov esp,ebp; pop ebp; ret; int3
    let call_addr = aob_addr + 0x27; // call helper 指令
    let bg_calc_addr = aob_addr + 0xBB8; // helper 內 bg index 計算

    // 檢查 B1 是否已安裝
    let exit_bytes = memory::read_bytes(h, exit_addr, 5)?;
    if exit_bytes[0] == 0xE9 {
        log_line!("[跳過] Patch B: SetupSlots 已被 hook");
        return Ok(());
    }

    // 驗證 exit 原始 bytes: 8B E5 5D C3 CC
    if exit_bytes != [0x8B, 0xE5, 0x5D, 0xC3, 0xCC] {
        log_line!(
            "[警告] Patch B1: exit bytes 不符 [{:02X} {:02X} {:02X} {:02X} {:02X}]",
            exit_bytes[0],
            exit_bytes[1],
            exit_bytes[2],
            exit_bytes[3],
            exit_bytes[4]
        );
        return Ok(());
    }

    // 動態取得 helper 函數位址（從 call 指令的 rel32）
    let call_bytes = memory::read_bytes(h, call_addr, 5)?;
    if call_bytes[0] != 0xE8 {
        log_line!("[警告] Patch B: call 指令不符 (0x{:02X})", call_bytes[0]);
        return Ok(());
    }
    let rel32 = i32::from_le_bytes([call_bytes[1], call_bytes[2], call_bytes[3], call_bytes[4]]);
    let helper_addr = (call_addr as i64 + 5 + rel32 as i64) as u32;
    log_line!("  helper 函數 @ 0x{helper_addr:08X}");

    // 驗證 B2 hook 點原始 bytes: 8B 4D 0C 83 C1 1A 51
    let bg_bytes = memory::read_bytes(h, bg_calc_addr, 7)?;
    if bg_bytes != [0x8B, 0x4D, 0x0C, 0x83, 0xC1, 0x1A, 0x51] {
        log_line!("[警告] Patch B2: bg bytes 不符 @ 0x{bg_calc_addr:08X}");
        return Ok(());
    }

    // --- 分配 codecave（B1 + B2 共用）---
    let cave = memory::alloc_exec(h, 128)?;
    let cave_b1 = cave;
    let cave_b2 = cave + 80;

    // === 組裝 Hook B1 codecave（函數出口追加 6 次 helper 呼叫）===
    let mut b1: Vec<u8> = Vec::with_capacity(80);
    // mov dword [ebp-8], 0  ; j = 0
    b1.extend_from_slice(&[0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00]);
    let loop_top = b1.len(); // .loop 偏移 = 7
                             // cmp dword [ebp-8], 6
    b1.extend_from_slice(&[0x83, 0x7D, 0xF8, 0x06]);
    // jge .done (rel8 placeholder)
    b1.extend_from_slice(&[0x7D, 0x00]);
    let jge_rel8_pos = b1.len() - 1;
    // push 0 (visible)
    b1.extend_from_slice(&[0x6A, 0x00]);
    // push 0 (equip_data)
    b1.extend_from_slice(&[0x6A, 0x00]);
    // mov edx, [ebp-8]
    b1.extend_from_slice(&[0x8B, 0x55, 0xF8]);
    // add edx, 46 (0x2E)
    b1.extend_from_slice(&[0x83, 0xC2, 0x2E]);
    // push edx (slot_index = j + 46)
    b1.push(0x52);
    // mov eax, [ebp-4] (parent_window)
    b1.extend_from_slice(&[0x8B, 0x45, 0xFC]);
    // push eax
    b1.push(0x50);
    // mov ecx, [ebp-0xC] (this)
    b1.extend_from_slice(&[0x8B, 0x4D, 0xF4]);
    // call helper (E8 rel32)
    b1.push(0xE8);
    let call_site = cave_b1 + b1.len() as u32;
    let helper_rel = (helper_addr as i64 - (call_site as i64 + 4)) as i32;
    b1.extend_from_slice(&helper_rel.to_le_bytes());
    // inc dword [ebp-8] (FF 45 F8)
    b1.extend_from_slice(&[0xFF, 0x45, 0xF8]);
    // jmp .loop (EB rel8)
    let jmp_rel = loop_top as i32 - b1.len() as i32 - 2;
    b1.extend_from_slice(&[0xEB, jmp_rel as u8]);
    // .done: 填回 jge 的 rel8
    let done_pos = b1.len();
    b1[jge_rel8_pos] = (done_pos - jge_rel8_pos - 1) as u8;
    // mov esp, ebp ; pop ebp ; ret（原始 epilogue）
    b1.extend_from_slice(&[0x8B, 0xE5, 0x5D, 0xC3]);

    // === 組裝 Hook B2 codecave（bg index 條件修正）===
    let mut b2: Vec<u8> = Vec::with_capacity(16);
    // mov ecx, [ebp+0xC]
    b2.extend_from_slice(&[0x8B, 0x4D, 0x0C]);
    // cmp ecx, 46
    b2.extend_from_slice(&[0x83, 0xF9, 0x2E]);
    // jl .normal (+4)
    b2.extend_from_slice(&[0x7C, 0x04]);
    // add ecx, 6 ; ret（新 slot: bg = child_index + 6 → child 52-57）
    b2.extend_from_slice(&[0x83, 0xC1, 0x06, 0xC3]);
    // .normal: add ecx, 0x1A ; ret（原始: bg = child_index + 26 → child 27-45）
    b2.extend_from_slice(&[0x83, 0xC1, 0x1A, 0xC3]);

    // --- 寫入 codecave ---
    memory::write_code(h, cave_b1, &b1)?;
    memory::write_code(h, cave_b2, &b2)?;

    // --- 安裝 Hook B1: exit → jmp codecave_b1 ---
    let mut hook_b1 = [0u8; 5];
    hook_b1[0] = 0xE9;
    let rel_b1 = (cave_b1 as i64 - (exit_addr as i64 + 5)) as i32;
    hook_b1[1..5].copy_from_slice(&rel_b1.to_le_bytes());
    memory::write_code(h, exit_addr, &hook_b1)?;

    // --- 安裝 Hook B2: bg_calc → call codecave_b2; push ecx; nop ---
    let mut hook_b2 = [0u8; 7];
    hook_b2[0] = 0xE8;
    let rel_b2 = (cave_b2 as i64 - (bg_calc_addr as i64 + 5)) as i32;
    hook_b2[1..5].copy_from_slice(&rel_b2.to_le_bytes());
    hook_b2[5] = 0x51; // push ecx
    hook_b2[6] = 0x90; // nop
    memory::write_code(h, bg_calc_addr, &hook_b2)?;

    log_line!("[OK] Patch B: 雙 Hook 安裝完成");
    log_line!("  B1: exit hook @ 0x{exit_addr:08X} → 0x{cave_b1:08X}");
    log_line!("  B2: bg hook @ 0x{bg_calc_addr:08X} → 0x{cave_b2:08X}");
    Ok(())
}

// =========================================================================
// Patch D: Surf ID bounds check — 固定位址（已驗證）
// =========================================================================

fn patch_surf_bounds_check(h: HANDLE) -> Result<()> {
    let orig = memory::read_bytes(h, SURF_BOUNDS_CHECK, 6)?;

    if orig[0] == 0x81 && orig[1] == 0xFA {
        log_line!("[跳過] Surf bounds check 已擴展");
        return Ok(());
    }

    log_line!(
        "  Patch D: 0x{SURF_BOUNDS_CHECK:08X} = [{:02X} {:02X} {:02X} {:02X} {:02X} {:02X}]",
        orig[0],
        orig[1],
        orig[2],
        orig[3],
        orig[4],
        orig[5]
    );

    if orig != [0x3B, 0x15, 0xB0, 0xD0, 0xC2, 0x00] {
        log_line!("[警告] Surf bounds check 指令不符");
    }

    // cmp edx, 0x7533 (30003)
    memory::write_code(h, SURF_BOUNDS_CHECK, &[0x81, 0xFA, 0x33, 0x75, 0x00, 0x00])?;

    log_line!("[OK] Patch D: Surf bounds check → cmp edx, 30003");
    Ok(())
}

// =========================================================================
// 工具函數
// =========================================================================

/// 從指定位址向前搜尋函數入口（55 8B EC prologue）
fn find_func_entry(h: HANDLE, from: u32, max_back: u32) -> Result<Option<u32>> {
    let start = from.saturating_sub(max_back);
    let size = (from - start) as usize;
    let data = memory::read_bytes(h, start, size)?;

    for i in (0..data.len().saturating_sub(2)).rev() {
        if data[i] == 0x55 && data[i + 1] == 0x8B && data[i + 2] == 0xEC {
            return Ok(Some(start + i as u32));
        }
    }
    Ok(None)
}
