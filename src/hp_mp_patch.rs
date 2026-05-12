//! HP/MP 32-bit 擴展 — 6 Opcode 完整修補
//!
//! ## 背景
//! 伺服器已將 6 個封包的 HP/MP 欄位從 WriteH(2B) 改為 WriteD(4B)。
//! 客戶端需配合修改：
//! - Phase 1: 格式字串修補（S_STATUS, S_CHARACTER_INFO, S_CHARSYNACK×2）
//! - Phase 2: ReadH→ReadD codecave（S_HIT_POINT, S_MANA_POINT 的 inline 封包讀取）
//! - Phase 3: 全域變數讀寫指令修補（maxHP, maxMP 的 movzx/movsx/mov word）

use anyhow::{Context, Result};
use windows::Win32::Foundation::HANDLE;

use crate::log_line;
use crate::memory::{alloc_exec, read_bytes, scan_pattern_all, write_code};

// ════════════════════════════════════════════════
// 常數定義
// ════════════════════════════════════════════════

/// maxHP 全域變數位址
const MAX_HP_ADDR: u32 = 0x00C31E90;
/// maxMP 全域變數位址
const MAX_MP_ADDR: u32 = 0x00C31E8C;

/// .text 段掃描範圍
const TEXT_START: u32 = 0x00401000;
const TEXT_END: u32 = 0x008C0000;

/// 直接定址 [disp32] 的合法 ModRM byte（mod=00, rm=101, reg=0~7）
const DIRECT_MODRM: [u8; 8] = [0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D];

/// ReadH 原始函數位址（S_HIT_POINT / S_MANA_POINT 共用）
const READ_H_ADDR: u32 = 0x005239F0;

// ════════════════════════════════════════════════
// Phase 1: 格式字串修補
// ════════════════════════════════════════════════

/// 格式字串修補定義
struct FormatPatch {
    name: &'static str,
    addr: u32,                  // .rdata 格式字串位址
    offset: u32,                // 修補偏移
    expected: &'static [u8],    // 修補前預期 bytes
    replacement: &'static [u8], // 修補後 bytes
}

/// 所有需要修補的格式字串
const FORMAT_PATCHES: &[FormatPatch] = &[
    // S_STATUS (opcode 8): format[9..12] "hhhh" → "dddd"
    // 原始: "dcdcccccchhhhcdcchhhhh"
    // 欄位: curHP=h[9], maxHP=h[10], curMP=h[11], maxMP=h[12]
    FormatPatch {
        name: "S_STATUS",
        addr: 0x8D46F4,
        offset: 9,
        expected: b"hhhh",
        replacement: b"dddd",
    },
    // S_CHARACTER_INFO (opcode 11/12): format[5..6] "hh" → "dd"
    // 原始: "sscchhhcccccccccdc"
    // 欄位: [4]=lawful(h不改), [5]=maxHP, [6]=maxMP
    FormatPatch {
        name: "S_CHAR_INFO",
        addr: 0x8D4DCC,
        offset: 5,
        expected: b"hh",
        replacement: b"dd",
    },
    // S_CHARSYNACK fmt1 (opcode 64 初始化): format[0..1] "hh" → "dd"
    // 原始: "hhcc"
    FormatPatch {
        name: "S_CHARSYNACK_1",
        addr: 0x8D72CC,
        offset: 0,
        expected: b"hh",
        replacement: b"dd",
    },
    // S_CHARSYNACK fmt2 (opcode 64 升級): format[2..3] "hh" → "dd"
    // 原始: "cchhhcccccc"
    // 欄位: [2]=maxHP, [3]=maxMP, [4]=AC(h不改)
    FormatPatch {
        name: "S_CHARSYNACK_2",
        addr: 0x8D72D4,
        offset: 2,
        expected: b"hh",
        replacement: b"dd",
    },
];

/// 修補所有格式字串，回傳成功數
fn patch_all_format_strings(h: HANDLE) -> Result<usize> {
    let mut count = 0;
    for p in FORMAT_PATCHES {
        let addr = p.addr + p.offset;
        let len = p.expected.len();

        let before =
            read_bytes(h, addr, len).with_context(|| format!("讀取 {} 格式字串失敗", p.name))?;

        if before == p.expected {
            // 需要修補
            write_code(h, addr, p.replacement)
                .with_context(|| format!("寫入 {} 格式字串失敗", p.name))?;

            // 驗證
            let after = read_bytes(h, addr, len)?;
            if after != p.replacement {
                log_line!("[HP/MP] 錯誤：{} 格式字串寫入驗證失敗", p.name);
                continue;
            }
            log_line!("[HP/MP] {} 格式字串 @ 0x{:08X} 修補完成", p.name, addr);
            count += 1;
        } else if before == p.replacement {
            // 已修補
            log_line!("[HP/MP] {} 格式字串已修補，跳過", p.name);
            count += 1;
        } else {
            log_line!(
                "[HP/MP] 警告：{} @ 0x{:08X} 不符預期（{:02X?}），跳過",
                p.name,
                addr,
                before
            );
        }
    }
    Ok(count)
}

// ════════════════════════════════════════════════
// Phase 2: ReadH → ReadD（S_HIT_POINT / S_MANA_POINT）
// ════════════════════════════════════════════════

/// ReadD 函數機器碼（37 bytes）
/// 從封包 buffer 讀取 4 bytes (dword)，推進指標 4，回傳 EAX
///
/// 對照原始 ReadH (0x5239F0, 37 bytes):
///   讀 2B → 讀 4B     (66 8B 11    → 8B 11 90)
///   存 2B → 存 4B     (66 89 55 FC → 89 55 FC 90)
///   進 2  → 進 4      (83 C1 02    → 83 C1 04)
///   返 16 → 返 32     (66 8B 45 FC → 8B 45 FC 90)
const READ_D_CODE: [u8; 37] = [
    0x55, 0x8B, 0xEC, 0x51, // push ebp; mov ebp,esp; push ecx
    0x8B, 0x45, 0x08, 0x8B, 0x08, // mov eax,[ebp+8]; mov ecx,[eax]
    0x8B, 0x11, 0x90, // mov edx,[ecx]; nop           ← 讀 4B
    0x89, 0x55, 0xFC, 0x90, // mov [ebp-4],edx; nop        ← 存 4B
    0x8B, 0x45, 0x08, 0x8B, 0x08, // mov eax,[ebp+8]; mov ecx,[eax]
    0x83, 0xC1, 0x04, // add ecx,4                   ← 推進 4
    0x8B, 0x55, 0x08, 0x89, 0x0A, // mov edx,[ebp+8]; mov [edx],ecx
    0x8B, 0x45, 0xFC, 0x90, // mov eax,[ebp-4]; nop        ← 回傳 32-bit
    0x8B, 0xE5, 0x5D, 0xC3, // mov esp,ebp; pop ebp; ret
];

/// 需要從 ReadH 重導向到 ReadD 的 call site
struct CallRedirect {
    name: &'static str,
    call_addr: u32, // E8 指令的位址
}

const CALL_REDIRECTS: &[CallRedirect] = &[
    CallRedirect {
        name: "S_HIT_POINT curHP",
        call_addr: 0x523990,
    },
    CallRedirect {
        name: "S_HIT_POINT maxHP",
        call_addr: 0x5239AA,
    },
    CallRedirect {
        name: "S_MANA_POINT curMP",
        call_addr: 0x533800,
    },
    CallRedirect {
        name: "S_MANA_POINT maxMP",
        call_addr: 0x53381A,
    },
];

/// movsx edx, ax → mov edx, eax; nop 的修補位置
/// ReadD 回傳 32-bit EAX，不需 sign-extend
struct MovsxPatch {
    name: &'static str,
    addr: u32,
}

const MOVSX_PATCHES: &[MovsxPatch] = &[
    MovsxPatch {
        name: "S_HIT_POINT",
        addr: 0x523998,
    },
    MovsxPatch {
        name: "S_MANA_POINT",
        addr: 0x533808,
    },
];

/// 0F BF D0 = movsx edx, ax
const MOVSX_EXPECTED: [u8; 3] = [0x0F, 0xBF, 0xD0];
/// 8B D0 90 = mov edx, eax; nop
const MOVSX_REPLACEMENT: [u8; 3] = [0x8B, 0xD0, 0x90];

/// 封包 handler 內的 movzx word [ebp-XX] 截斷修補（4 bytes）
/// movzx reg, word [ebp-XX] → mov reg, dword [ebp-XX]; nop
///
/// 根因：S_STATUS 反序列化已正確寫入 32-bit 到 stack local，
/// 但傳給 XOR 加密 setter(0x579E10) 時用 movzx word 截斷為 16-bit。
/// setter 內 XOR ecx,[ebp+8] 使用完整 32-bit，所以只要傳入正確值即可。
struct MovzxLocalPatch {
    name: &'static str,
    addr: u32,
    expected: [u8; 4],
    replacement: [u8; 4],
}

const MOVZX_LOCAL_PATCHES: &[MovzxLocalPatch] = &[
    // S_STATUS: curHP local → XOR setter（截斷為 16-bit → 顯示 16959）
    MovzxLocalPatch {
        name: "S_STATUS curHP→setter",
        addr: 0x523547,
        expected: [0x0F, 0xB7, 0x55, 0xEC], // movzx edx, word [ebp-0x14]
        replacement: [0x8B, 0x55, 0xEC, 0x90], // mov edx, [ebp-0x14]; nop
    },
    // S_STATUS: curMP local → XOR setter
    MovzxLocalPatch {
        name: "S_STATUS curMP→setter",
        addr: 0x523556,
        expected: [0x0F, 0xB7, 0x45, 0xF0], // movzx eax, word [ebp-0x10]
        replacement: [0x8B, 0x45, 0xF0, 0x90], // mov eax, [ebp-0x10]; nop
    },
    // S_STATUS: curHP local → HP% 計算 (curHP*100/maxHP)
    MovzxLocalPatch {
        name: "S_STATUS curHP→HP%",
        addr: 0x523585,
        expected: [0x0F, 0xB7, 0x45, 0xEC], // movzx eax, word [ebp-0x14]
        replacement: [0x8B, 0x45, 0xEC, 0x90], // mov eax, [ebp-0x14]; nop
    },
];

/// Phase 2: 分配 ReadD codecave，重導向 call，修補 movsx/movzx
fn install_read_d_patches(h: HANDLE) -> Result<usize> {
    let mut count = 0;

    // 1. 分配 codecave 並寫入 ReadD
    let read_d_addr = alloc_exec(h, READ_D_CODE.len()).context("分配 ReadD codecave 失敗")?;
    write_code(h, read_d_addr, &READ_D_CODE).context("寫入 ReadD 函數失敗")?;
    log_line!(
        "[HP/MP] ReadD @ 0x{:08X} ({} bytes)",
        read_d_addr,
        READ_D_CODE.len()
    );

    // 2. 重導向 4 個 call site: call ReadH → call ReadD
    for cr in CALL_REDIRECTS {
        let current = read_bytes(h, cr.call_addr, 5)?;
        if current[0] != 0xE8 {
            log_line!(
                "[HP/MP] 警告：{} @ 0x{:08X} 不是 E8 call（{:02X}），跳過",
                cr.name,
                cr.call_addr,
                current[0]
            );
            continue;
        }

        // 解碼目前 call target
        let cur_rel32 = i32::from_le_bytes([current[1], current[2], current[3], current[4]]);
        let cur_target = (cr.call_addr as i64 + 5 + cur_rel32 as i64) as u32;

        if cur_target == READ_H_ADDR {
            // 目前指向 ReadH → 改指向 ReadD
            let new_rel32 = read_d_addr as i32 - (cr.call_addr as i32 + 5);
            let mut patch = [0u8; 5];
            patch[0] = 0xE8;
            patch[1..5].copy_from_slice(&new_rel32.to_le_bytes());
            write_code(h, cr.call_addr, &patch)?;
            log_line!("[HP/MP] {} @ 0x{:08X}: ReadH→ReadD", cr.name, cr.call_addr);
            count += 1;
        } else if cur_target == read_d_addr {
            log_line!("[HP/MP] {} 已重導向 ReadD，跳過", cr.name);
            count += 1;
        } else {
            log_line!(
                "[HP/MP] 警告：{} @ 0x{:08X} 目標非 ReadH（0x{:08X}），跳過",
                cr.name,
                cr.call_addr,
                cur_target
            );
        }
    }

    // 3. 修補 S_HIT_POINT/S_MANA_POINT: movsx edx, ax → mov edx, eax; nop
    for mp in MOVSX_PATCHES {
        let current = read_bytes(h, mp.addr, 3)?;
        if current == MOVSX_EXPECTED {
            write_code(h, mp.addr, &MOVSX_REPLACEMENT)?;
            log_line!("[HP/MP] {} movsx→mov @ 0x{:08X}", mp.name, mp.addr);
            count += 1;
        } else if current == MOVSX_REPLACEMENT {
            log_line!("[HP/MP] {} movsx 已修補，跳過", mp.name);
            count += 1;
        } else {
            log_line!(
                "[HP/MP] 警告：{} movsx @ 0x{:08X} 不符預期（{:02X?}），跳過",
                mp.name,
                mp.addr,
                current
            );
        }
    }

    // 4. 修補 S_STATUS handler: movzx word [ebp-XX] → mov dword [ebp-XX]; nop
    for lp in MOVZX_LOCAL_PATCHES {
        let current = read_bytes(h, lp.addr, 4)?;
        if current == lp.expected {
            write_code(h, lp.addr, &lp.replacement)?;
            log_line!("[HP/MP] {} @ 0x{:08X} 修補完成", lp.name, lp.addr);
            count += 1;
        } else if current == lp.replacement {
            log_line!("[HP/MP] {} 已修補，跳過", lp.name);
            count += 1;
        } else {
            log_line!(
                "[HP/MP] 警告：{} @ 0x{:08X} 不符預期（{:02X?}），跳過",
                lp.name,
                lp.addr,
                current
            );
        }
    }

    Ok(count)
}

// ════════════════════════════════════════════════
// Phase 2b: S_CHAR_INFO handler 局部截斷修補
// ════════════════════════════════════════════════

/// [ebp+disp8] 的 ModR/M bytes（mod=01, rm=101, reg=0~7）
const EBP_DISP8_MODRM: [u8; 8] = [0x45, 0x4D, 0x55, 0x5D, 0x65, 0x6D, 0x75, 0x7D];

/// 掃描定義：handler 名稱、掃描範圍、HP/MP local 的 disp8
struct HandlerScanDef {
    name: &'static str,
    scan_start: u32,
    scan_end: u32,
    hp_disp8: u8, // maxHP local 的 [ebp+disp8]
    mp_disp8: u8, // maxMP local 的 [ebp+disp8]
}

/// 所有需要掃描截斷的 handler 區段
///
/// 反序列化 (0x522110) 寫入 32-bit 到 stack local 後，
/// handler 後續代碼可能用 movzx/movsx/66 word 操作讀取 → 截斷為 16-bit
const HANDLER_SCANS: &[HandlerScanDef] = &[
    // S_CHAR_INFO (opcode 93/127): call @ 0x52CA73 + add esp 之後
    //   maxHP=[ebp-0x10](0xF0), maxMP=[ebp-0x38](0xC8)
    HandlerScanDef {
        name: "CHAR_INFO",
        scan_start: 0x0052CA78,
        scan_end: 0x0052CDD0,
        hp_disp8: 0xF0,
        mp_disp8: 0xC8,
    },
    // S_CHARSYNACK fmt1 ("ddcc"): call @ 0x5439AE + add esp 之後
    //   maxHP=[ebp-8](0xF8), maxMP=[ebp-12](0xF4)
    HandlerScanDef {
        name: "SYNACK_F1",
        scan_start: 0x005439B5,
        scan_end: 0x00543A28,
        hp_disp8: 0xF8,
        mp_disp8: 0xF4,
    },
    // S_CHARSYNACK fmt2 ("ccddhcccccc"): call @ 0x543A5D + add esp 之後
    //   maxHP=[ebp-20](0xEC), maxMP=[ebp-32](0xE0)
    HandlerScanDef {
        name: "SYNACK_F2",
        scan_start: 0x00543A64,
        scan_end: 0x00543C00,
        hp_disp8: 0xEC,
        mp_disp8: 0xE0,
    },
];

/// 掃描多個 handler 的反序列化後代碼，修補 16-bit 截斷
fn patch_handler_local_truncation(h: HANDLE) -> Result<usize> {
    let mut total = 0;

    for def in HANDLER_SCANS {
        let scan_size = (def.scan_end - def.scan_start) as usize;
        let data = read_bytes(h, def.scan_start, scan_size)
            .with_context(|| format!("讀取 {} handler 失敗", def.name))?;

        let targets = [(def.hp_disp8, "maxHP"), (def.mp_disp8, "maxMP")];

        for &(disp8, field) in &targets {
            // 1. movzx/movsx word → mov dword + NOP
            for &opext in &[0xB7u8, 0xBF] {
                for &modrm in &EBP_DISP8_MODRM {
                    for i in 0..data.len().saturating_sub(3) {
                        if data[i] == 0x0F
                            && data[i + 1] == opext
                            && data[i + 2] == modrm
                            && data[i + 3] == disp8
                        {
                            let va = def.scan_start + i as u32;
                            write_code(h, va, &[0x8B, modrm, disp8, 0x90])?;
                            let k = if opext == 0xB7 { "movzx" } else { "movsx" };
                            log_line!("[HP/MP] {} {} {k} @ 0x{va:08X}", def.name, field);
                            total += 1;
                        }
                    }
                }
            }

            // 2. 66 mov → dword mov + NOP
            for &opcode in &[0x89u8, 0x8B] {
                for &modrm in &EBP_DISP8_MODRM {
                    for i in 0..data.len().saturating_sub(3) {
                        if data[i] == 0x66
                            && data[i + 1] == opcode
                            && data[i + 2] == modrm
                            && data[i + 3] == disp8
                        {
                            let va = def.scan_start + i as u32;
                            write_code(h, va, &[opcode, modrm, disp8, 0x90])?;
                            let d = if opcode == 0x89 { "寫入" } else { "讀取" };
                            log_line!("[HP/MP] {} {} 66-{d} @ 0x{va:08X}", def.name, field);
                            total += 1;
                        }
                    }
                }
            }

            // 3. 66 cmp → dword cmp + NOP
            for &opcode in &[0x3Bu8, 0x39] {
                for &modrm in &EBP_DISP8_MODRM {
                    for i in 0..data.len().saturating_sub(3) {
                        if data[i] == 0x66
                            && data[i + 1] == opcode
                            && data[i + 2] == modrm
                            && data[i + 3] == disp8
                        {
                            let va = def.scan_start + i as u32;
                            write_code(h, va, &[opcode, modrm, disp8, 0x90])?;
                            log_line!("[HP/MP] {} {} 66-cmp @ 0x{va:08X}", def.name, field);
                            total += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(total)
}

// ════════════════════════════════════════════════
// Phase 2c: 角色選擇結構 HP/MP 32-bit（setter + getter）
//
// 改用 codecave 儲存 HP/MP 32-bit 值，避免 struct+0x30/+0x34 與
// 其他 .data 全域變數衝突（0xC314E0/E4 被遊戲覆蓋導致重登後顯示錯誤）
// ════════════════════════════════════════════════

/// setter F1 入口（3 引數: HP, MP, class）
const SETTER_F1_ADDR: u32 = 0x00544910;
const SETTER_F1_SIZE: usize = 48; // setter 機器碼大小

/// setter F2 入口（11 引數）
const SETTER_F2_ADDR: u32 = 0x00544940;
const SETTER_F2_SIZE: usize = 120; // setter 機器碼大小

/// Codecave 佈局常數（僅放 setter 代碼，HP/MP 直接用全域變數）
const CAVE_F1_OFFSET: u32 = 0x10; // F1 setter 代碼起始
const CAVE_F2_OFFSET: u32 = 0x40; // F2 setter 代碼起始
const CAVE_TOTAL_SIZE: usize = 256; // 總分配大小

/// HP getter 函數入口
const HP_GETTER_FUNC: u32 = 0x0076D7D0;
/// MP getter 函數入口
const MP_GETTER_FUNC: u32 = 0x0076D7F0;

/// 組裝 F1 setter（48 bytes 以內）
/// 直接寫入 maxHP/maxMP 全域變數（getter 也直接讀全域變數，無 codecave 同步問題）
fn build_setter_f1() -> Vec<u8> {
    let max_hp = MAX_HP_ADDR.to_le_bytes();
    let max_mp = MAX_MP_ADDR.to_le_bytes();
    let mut c = Vec::with_capacity(SETTER_F1_SIZE);
    c.extend_from_slice(&[0x8B, 0xC1]); // mov eax, ecx (this)
                                        // HP → 全域變數
    c.extend_from_slice(&[0x8B, 0x54, 0x24, 0x04]); // mov edx, [esp+4]
    c.extend_from_slice(&[0x89, 0x15]); // mov [maxHP], edx
    c.extend_from_slice(&max_hp);
    // MP → 全域變數
    c.extend_from_slice(&[0x8B, 0x54, 0x24, 0x08]); // mov edx, [esp+8]
    c.extend_from_slice(&[0x89, 0x15]); // mov [maxMP], edx
    c.extend_from_slice(&max_mp);
    // class → struct+0xE
    c.extend_from_slice(&[0x66, 0x8B, 0x54, 0x24, 0x0C]); // mov dx, [esp+0xC]
    c.extend_from_slice(&[0x66, 0x89, 0x50, 0x0E]); // mov [eax+0xE], dx
    c.extend_from_slice(&[0xC2, 0x0C, 0x00]); // ret 12
    while c.len() < SETTER_F1_SIZE {
        c.push(0xCC);
    }
    assert_eq!(c.len(), SETTER_F1_SIZE);
    c
}

/// 組裝 F2 setter（120 bytes 以內，含 CC padding）
/// 直接寫入 maxHP/maxMP 全域變數（getter 也直接讀全域變數，無 codecave 同步問題）
fn build_setter_f2() -> Vec<u8> {
    let max_hp = MAX_HP_ADDR.to_le_bytes();
    let max_mp = MAX_MP_ADDR.to_le_bytes();
    let mut c = Vec::with_capacity(SETTER_F2_SIZE);
    // prologue
    c.extend_from_slice(&[0x55, 0x8B, 0xEC, 0x51]); // push ebp; mov ebp,esp; push ecx
    c.extend_from_slice(&[0x89, 0x4D, 0xFC]); // mov [ebp-4], ecx
    c.extend_from_slice(&[0x8B, 0x45, 0xFC]); // mov eax, [ebp-4] (this)
                                              // arg1 → +0x10, arg2 → +0x11
    c.extend_from_slice(&[0x8A, 0x4D, 0x08, 0x88, 0x48, 0x10]);
    c.extend_from_slice(&[0x8A, 0x4D, 0x0C, 0x88, 0x48, 0x11]);
    // HP → 全域變數
    c.extend_from_slice(&[0x8B, 0x4D, 0x10]); // mov ecx, [ebp+0x10]
    c.extend_from_slice(&[0x89, 0x0D]); // mov [maxHP], ecx
    c.extend_from_slice(&max_hp);
    // MP → 全域變數
    c.extend_from_slice(&[0x8B, 0x4D, 0x14]); // mov ecx, [ebp+0x14]
    c.extend_from_slice(&[0x89, 0x0D]); // mov [maxMP], ecx
    c.extend_from_slice(&max_mp);
    // arg5 → +0xE (class)
    c.extend_from_slice(&[0x66, 0x8B, 0x4D, 0x18]); // mov cx, [ebp+0x18]
    c.extend_from_slice(&[0x66, 0x89, 0x48, 0x0E]); // mov [eax+0xE], cx
                                                    // arg6~arg11: sign-ext byte → struct dword fields
    for &(disp, off) in &[
        (0x1Cu8, 0x14u8),
        (0x20, 0x18),
        (0x24, 0x1C),
        (0x28, 0x20),
        (0x2C, 0x24),
        (0x30, 0x28),
    ] {
        c.extend_from_slice(&[0x0F, 0xBE, 0x4D, disp]); // movsx ecx, byte [ebp+disp]
        c.extend_from_slice(&[0x89, 0x48, off]); // mov [eax+off], ecx
    }
    // epilogue
    c.extend_from_slice(&[0x8B, 0xE5, 0x5D, 0xC2, 0x2C, 0x00]);
    // CC padding
    while c.len() < SETTER_F2_SIZE {
        c.push(0xCC);
    }
    c
}

/// Phase 2c: 修補角色選擇結構的 setter/getter，使 HP/MP 為 32-bit
///
/// **Trampoline 架構**：setter 代碼放在 codecave，原始位址只寫 5-byte JMP。
/// 原始 0x544910/0x544940 是 switch case entries（各 14/17 bytes），
/// 舊版直接覆寫 48/120 bytes 會破壞相鄰的 case entries，
/// 導致重登時其他 sub-handler 無法正確執行。
fn patch_charselect_struct(h: HANDLE) -> Result<usize> {
    let mut count = 0;

    // 用 HP getter 函數入口判斷是否已修補
    let hp_head = read_bytes(h, HP_GETTER_FUNC, 1)?;
    if hp_head[0] == 0xA1 {
        log_line!("[HP/MP] 角色選擇結構已修補（codecave 版），跳過");
        return Ok(4);
    }
    if hp_head[0] != 0x55 {
        log_line!(
            "[HP/MP] 警告: HP getter @ 0x{HP_GETTER_FUNC:08X} 不匹配: {:02X}",
            hp_head[0]
        );
        return Ok(0);
    }

    // 分配 codecave（256B: F1/F2 setter 代碼）
    let cave = alloc_exec(h, CAVE_TOTAL_SIZE).context("分配 HP/MP codecave 失敗")?;
    let f1_code = cave + CAVE_F1_OFFSET;
    let f2_code = cave + CAVE_F2_OFFSET;
    log_line!("[HP/MP] codecave @ 0x{cave:08X} (F1+0x10, F2+0x40)");

    // F1 setter 代碼寫入 codecave（48 bytes）
    let f1 = build_setter_f1();
    write_code(h, f1_code, &f1)?;
    // F1 trampoline: 僅 5-byte JMP，不覆寫相鄰 switch entries
    let f1_rel = f1_code as i32 - (SETTER_F1_ADDR as i32 + 5);
    let mut f1_tramp = [0u8; 5];
    f1_tramp[0] = 0xE9;
    f1_tramp[1..5].copy_from_slice(&f1_rel.to_le_bytes());
    write_code(h, SETTER_F1_ADDR, &f1_tramp)?;
    log_line!("[HP/MP] F1 setter: trampoline 0x{SETTER_F1_ADDR:08X} → 0x{f1_code:08X}");
    count += 1;

    // F2 setter 代碼寫入 codecave（120 bytes）
    let f2 = build_setter_f2();
    write_code(h, f2_code, &f2)?;
    // F2 trampoline: 僅 5-byte JMP
    let f2_rel = f2_code as i32 - (SETTER_F2_ADDR as i32 + 5);
    let mut f2_tramp = [0u8; 5];
    f2_tramp[0] = 0xE9;
    f2_tramp[1..5].copy_from_slice(&f2_rel.to_le_bytes());
    write_code(h, SETTER_F2_ADDR, &f2_tramp)?;
    log_line!("[HP/MP] F2 setter: trampoline 0x{SETTER_F2_ADDR:08X} → 0x{f2_code:08X}");
    count += 1;

    // HP getter: mov eax,[maxHP]; ret（6 bytes + NOP 填充）
    // 直接讀全域變數 — 所有封包 handler 都寫入同一位址，重登也正確
    let mut hp_getter = vec![0xA1u8];
    hp_getter.extend_from_slice(&MAX_HP_ADDR.to_le_bytes());
    hp_getter.push(0xC3);
    while hp_getter.len() < 18 {
        hp_getter.push(0x90);
    }
    write_code(h, HP_GETTER_FUNC, &hp_getter)?;
    log_line!("[HP/MP] HP getter @ 0x{HP_GETTER_FUNC:08X}: 讀 maxHP 0x{MAX_HP_ADDR:08X}");
    count += 1;

    // MP getter: mov eax,[maxMP]; ret（6 bytes + NOP 填充）
    let mut mp_getter = vec![0xA1u8];
    mp_getter.extend_from_slice(&MAX_MP_ADDR.to_le_bytes());
    mp_getter.push(0xC3);
    while mp_getter.len() < 18 {
        mp_getter.push(0x90);
    }
    write_code(h, MP_GETTER_FUNC, &mp_getter)?;
    log_line!("[HP/MP] MP getter @ 0x{MP_GETTER_FUNC:08X}: 讀 maxMP 0x{MAX_MP_ADDR:08X}");
    count += 1;

    Ok(count)
}

// ════════════════════════════════════════════════
// Phase 2d: getter 呼叫者截斷修補
// ════════════════════════════════════════════════

/// HP getter 唯一呼叫者 @ 0x76C859 → call 後 0x76C85E:
///   原始: 0F BF C8 = movsx ecx, ax（把 32-bit EAX 截回 16-bit）
///   修補: 8B C8 90 = mov ecx, eax; nop（保留完整 32-bit）
const HP_CALLER_TRUNC_ADDR: u32 = 0x0076C85E;
const HP_CALLER_TRUNC_ORIG: [u8; 3] = [0x0F, 0xBF, 0xC8];
const HP_CALLER_TRUNC_NEW: [u8; 3] = [0x8B, 0xC8, 0x90];

/// MP getter 唯一呼叫者 @ 0x76C8A4 → call 後 0x76C8A9:
///   原始: 98 = cwde（符號擴展 AX→EAX，覆蓋上位 bits）
///   修補: 90 = nop（EAX 已是完整 32-bit，不需擴展）
const MP_CALLER_TRUNC_ADDR: u32 = 0x0076C8A9;
const MP_CALLER_TRUNC_ORIG: [u8; 1] = [0x98];
const MP_CALLER_TRUNC_NEW: [u8; 1] = [0x90];

/// 修補 getter 呼叫者的截斷指令
fn patch_getter_caller_truncation(h: HANDLE) -> Result<usize> {
    let mut count = 0;

    // HP getter 呼叫者: movsx ecx, ax → mov ecx, eax; nop
    let hp_cur = read_bytes(h, HP_CALLER_TRUNC_ADDR, 3)?;
    if hp_cur == HP_CALLER_TRUNC_ORIG {
        write_code(h, HP_CALLER_TRUNC_ADDR, &HP_CALLER_TRUNC_NEW)?;
        log_line!(
            "[HP/MP] HP getter caller @ 0x{:08X}: movsx ecx,ax → mov ecx,eax",
            HP_CALLER_TRUNC_ADDR
        );
        count += 1;
    } else if hp_cur == HP_CALLER_TRUNC_NEW {
        log_line!("[HP/MP] HP getter caller 已修補，跳過");
        count += 1;
    } else {
        log_line!(
            "[HP/MP] 警告: HP getter caller @ 0x{:08X} 不符預期: {:02X?}",
            HP_CALLER_TRUNC_ADDR,
            hp_cur
        );
    }

    // MP getter 呼叫者: cwde → nop
    let mp_cur = read_bytes(h, MP_CALLER_TRUNC_ADDR, 1)?;
    if mp_cur == MP_CALLER_TRUNC_ORIG {
        write_code(h, MP_CALLER_TRUNC_ADDR, &MP_CALLER_TRUNC_NEW)?;
        log_line!(
            "[HP/MP] MP getter caller @ 0x{:08X}: cwde → nop",
            MP_CALLER_TRUNC_ADDR
        );
        count += 1;
    } else if mp_cur == MP_CALLER_TRUNC_NEW {
        log_line!("[HP/MP] MP getter caller 已修補，跳過");
        count += 1;
    } else {
        log_line!(
            "[HP/MP] 警告: MP getter caller @ 0x{:08X} 不符預期: {:02X?}",
            MP_CALLER_TRUNC_ADDR,
            mp_cur
        );
    }

    Ok(count)
}

// ════════════════════════════════════════════════
// Phase 3: 全域變數讀寫指令修補
// ════════════════════════════════════════════════

/// 修補讀取指令：movzx/movsx reg, word [addr] (7B) → mov reg, dword [addr] (6B) + NOP
fn patch_reads_to_dword(h: HANDLE, target_addr: u32, name: &str) -> Result<usize> {
    let addr_bytes = target_addr.to_le_bytes();
    let mut total = 0;

    for &modrm in &DIRECT_MODRM {
        for &opext in &[0xB7u8, 0xBF] {
            let pattern: Vec<Option<u8>> = vec![
                Some(0x0F),
                Some(opext),
                Some(modrm),
                Some(addr_bytes[0]),
                Some(addr_bytes[1]),
                Some(addr_bytes[2]),
                Some(addr_bytes[3]),
            ];
            let matches = scan_pattern_all(h, TEXT_START, TEXT_END, &pattern)
                .with_context(|| format!("掃描 {name} 讀取失敗"))?;

            for &match_addr in &matches {
                // 7B → 6B+NOP: 8B ModRM addr[4] 90
                let new_bytes = [
                    0x8B,
                    modrm,
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                    0x90,
                ];
                write_code(h, match_addr, &new_bytes)?;
            }
            total += matches.len();
        }
    }

    if total > 0 {
        log_line!("[HP/MP] {name} 讀取: {total} 個 movzx/movsx→mov dword");
    }
    Ok(total)
}

/// 修補寫入指令：mov word [addr], reg/ax → mov dword [addr], reg/eax
///
/// Type A: 66 A3 addr (6B) → A3 addr 90 (5B + NOP)
/// Type B: 66 89 ModRM addr (7B) → 89 ModRM addr 90 (6B + NOP)
fn patch_writes_to_dword(h: HANDLE, target_addr: u32, name: &str) -> Result<usize> {
    let addr_bytes = target_addr.to_le_bytes();
    let mut total = 0;

    // Type A: 66 A3 addr — mov word [addr], ax
    {
        let pattern: Vec<Option<u8>> = vec![
            Some(0x66),
            Some(0xA3),
            Some(addr_bytes[0]),
            Some(addr_bytes[1]),
            Some(addr_bytes[2]),
            Some(addr_bytes[3]),
        ];
        let matches = scan_pattern_all(h, TEXT_START, TEXT_END, &pattern)
            .with_context(|| format!("掃描 {name} 寫入 TypeA 失敗"))?;

        for &match_addr in &matches {
            let new_bytes = [
                0xA3,
                addr_bytes[0],
                addr_bytes[1],
                addr_bytes[2],
                addr_bytes[3],
                0x90,
            ];
            write_code(h, match_addr, &new_bytes)?;
        }
        total += matches.len();
    }

    // Type B: 66 89 ModRM addr — mov word [addr], reg
    for &modrm in &DIRECT_MODRM {
        let pattern: Vec<Option<u8>> = vec![
            Some(0x66),
            Some(0x89),
            Some(modrm),
            Some(addr_bytes[0]),
            Some(addr_bytes[1]),
            Some(addr_bytes[2]),
            Some(addr_bytes[3]),
        ];
        let matches = scan_pattern_all(h, TEXT_START, TEXT_END, &pattern)
            .with_context(|| format!("掃描 {name} 寫入 TypeB 失敗"))?;

        for &match_addr in &matches {
            let new_bytes = [
                0x89,
                modrm,
                addr_bytes[0],
                addr_bytes[1],
                addr_bytes[2],
                addr_bytes[3],
                0x90,
            ];
            write_code(h, match_addr, &new_bytes)?;
        }
        total += matches.len();
    }

    if total > 0 {
        log_line!("[HP/MP] {name} 寫入: {total} 個 mov word→mov dword");
    }
    Ok(total)
}

// ════════════════════════════════════════════════
// 主入口
// ════════════════════════════════════════════════

/// 安裝 HP/MP 32-bit 擴展修補（6 Opcode 完整版）
pub fn install_hp_mp_patches(h: HANDLE, _pid: u32) -> Result<()> {
    log_line!("\n--- HP/MP 32-bit 擴展（6 Opcode）---");

    // Phase 1: 格式字串（S_STATUS + S_CHARACTER_INFO + S_CHARSYNACK×2）
    let fmt_count = patch_all_format_strings(h)?;
    log_line!(
        "[HP/MP] Phase 1: {fmt_count}/{} 格式字串",
        FORMAT_PATCHES.len()
    );

    // Phase 2: ReadH→ReadD + movsx/movzx 修補
    let readd_count = install_read_d_patches(h)?;
    let readd_total = CALL_REDIRECTS.len() + MOVSX_PATCHES.len() + MOVZX_LOCAL_PATCHES.len();
    log_line!("[HP/MP] Phase 2: {readd_count}/{readd_total} 封包處理修補");

    // Phase 2b: 封包 handler 局部截斷修補（CHAR_INFO + CHARSYNACK）
    let handler_count = patch_handler_local_truncation(h)?;
    log_line!("[HP/MP] Phase 2b: {handler_count} 封包 handler 局部截斷");

    // Phase 2c: 角色選擇結構 setter/getter（struct+0x30/0x34）
    let cs_count = patch_charselect_struct(h)?;
    log_line!("[HP/MP] Phase 2c: {cs_count} 角色選擇結構修補");

    // Phase 2d: getter 呼叫者截斷修補（movsx/cwde → 保留 32-bit）
    let gc_count = patch_getter_caller_truncation(h)?;
    log_line!("[HP/MP] Phase 2d: {gc_count} getter 呼叫者截斷");

    // Phase 3: 全域變數讀寫指令（maxHP + maxMP）
    let r1 = patch_reads_to_dword(h, MAX_HP_ADDR, "maxHP")?;
    let r2 = patch_reads_to_dword(h, MAX_MP_ADDR, "maxMP")?;
    let w1 = patch_writes_to_dword(h, MAX_HP_ADDR, "maxHP")?;
    let w2 = patch_writes_to_dword(h, MAX_MP_ADDR, "maxMP")?;
    let rw_total = r1 + r2 + w1 + w2;
    log_line!(
        "[HP/MP] Phase 3: 讀取 {}+{}, 寫入 {}+{}, 共 {} 處",
        r1,
        r2,
        w1,
        w2,
        rw_total
    );

    // Phase 5: 血條 UI（置中 + 百分比）— 必須在 Phase 4 之前！
    // Phase 4 的 patch_reads_to_dword 會修改 movsx word [0xC2FDE0/DC] 指令，
    // 而 Phase 5 的 sprintf hook 驗證依賴這些原始位元組。
    // Phase 5 暫時停用（百分比顯示 + x 置中需重新設計）
    let ui_count = 0;
    log_line!("[HP/MP] Phase 5: 停用（待重新設計）");

    // Phase 4: HP/MP display value（血條渲染用）16-bit → 32-bit
    const HP_DISPLAY_ADDR: u32 = 0x00C2FDE0;
    const MP_DISPLAY_ADDR: u32 = 0x00C2FDDC;
    let r3 = patch_reads_to_dword(h, HP_DISPLAY_ADDR, "HP_display")?;
    let r4 = patch_reads_to_dword(h, MP_DISPLAY_ADDR, "MP_display")?;
    let w3 = patch_writes_to_dword(h, HP_DISPLAY_ADDR, "HP_display")?;
    let w4 = patch_writes_to_dword(h, MP_DISPLAY_ADDR, "MP_display")?;
    let disp_total = r3 + r4 + w3 + w4;
    log_line!(
        "[HP/MP] Phase 4: display 讀取 {}+{}, 寫入 {}+{}, 共 {} 處",
        r3,
        r4,
        w3,
        w4,
        disp_total
    );

    log_line!("[HP/MP] 完成：{} 格式 + {} ReadD + {} handler截斷 + {} 選角結構 + {} caller截斷 + {} 全域指令 + {} display指令",
             fmt_count, readd_count, handler_count, cs_count, gc_count, rw_total, disp_total);

    Ok(())
}

// ════════════════════════════════════════════════
// Phase 5: 血條 UI — 文字百分比 + 置中
//
// runtime 發現：Themida 同時重配 .text 和 .rdata。
// 改用 maxHP/maxMP（.data，穩定）作為 AOB 錨點，
// 動態找到 sprintf 區域和 x 座標分支。
// ════════════════════════════════════════════════

struct BarUiConfig {
    name: &'static str,
    max_addr: u32,     // .data: maxHP/maxMP
    buf_ebp_off: u8,   // fallback buffer [ebp-XX]
    x_offset: u32,     // 文字 x 偏移（遊戲常數）
    prefix_mode: bool, // true = "XX% N/M"（HP 左側），false = "N/M XX%"（MP 右側）
}

/// widget getter：thiscall, ecx=widget, ret 0, 回傳解密值
const WIDGET_GETTER: u32 = 0x402800;
/// 血條文字區域視覺寬度（px）
const BAR_TEXT_WIDTH: u32 = 200;

fn install_bar_ui_patches(h: HANDLE) -> Result<usize> {
    let mut count = 0;
    // MP 先安裝（較穩定），記錄已佔用的 call_addr
    let mut used_addrs = std::collections::HashSet::new();
    count += install_bar_ui(
        h,
        &BarUiConfig {
            name: "MP",
            max_addr: MAX_MP_ADDR,
            buf_ebp_off: 0x40,
            x_offset: 0x1A7,
            prefix_mode: false,
        },
        &mut used_addrs,
    )?;
    // HP 排除 MP 已佔用的地址，避免互搶
    count += install_bar_ui(
        h,
        &BarUiConfig {
            name: "HP",
            max_addr: MAX_HP_ADDR,
            buf_ebp_off: 0x2C,
            x_offset: 0x192,
            prefix_mode: false,
        },
        &mut used_addrs,
    )?;
    Ok(count)
}

/// 單一血條 UI 修補（sprintf 百分比 + x 置中）
fn install_bar_ui(
    h: HANDLE,
    cfg: &BarUiConfig,
    used_addrs: &mut std::collections::HashSet<u32>,
) -> Result<usize> {
    let mut count = 0;

    // ── 1. 用 maxAddr 作錨點找 sprintf 區域 ──
    // 特徵: mov reg,[maxAddr]; nop; push reg; mov ecx,widget
    // 用萬用字元匹配任何暫存器（edx=8B 15/push 52, eax=8B 05/push 50）
    let ma = cfg.max_addr.to_le_bytes();
    let anchor: Vec<Option<u8>> = vec![
        Some(0x8B),
        None,
        Some(ma[0]),
        Some(ma[1]),
        Some(ma[2]),
        Some(ma[3]),
        Some(0x90),
        None,
        Some(0xB9),
    ];
    let hits = scan_pattern_all(h, TEXT_START, TEXT_END, &anchor)?;
    if hits.is_empty() {
        log_line!("[BarUI] {} 找不到 maxAddr 錨點", cfg.name);
        return Ok(0);
    }

    // 驗證 WIDGET_GETTER call 來篩選正確的命中，收集所有有效錨點
    let mut valid_anchors: Vec<(u32, u32)> = Vec::new(); // (area_start, widget_addr)
    for &hit in &hits {
        let chunk = read_bytes(h, hit, 40)?;
        if chunk.len() < 35 {
            continue;
        }
        // +8: B9 [widget:4] → +13: E8 [rel32]
        if chunk[8] != 0xB9 || chunk[13] != 0xE8 {
            continue;
        }
        let call_off = i32::from_le_bytes([chunk[14], chunk[15], chunk[16], chunk[17]]);
        let call_target = (hit + 18).wrapping_add(call_off as u32);
        if call_target == WIDGET_GETTER {
            let wa = u32::from_le_bytes([chunk[9], chunk[10], chunk[11], chunk[12]]);
            valid_anchors.push((hit, wa));
        }
    }
    if valid_anchors.is_empty() {
        log_line!("[BarUI] {} 找不到 WIDGET_GETTER call", cfg.name);
        return Ok(0);
    }
    log_line!(
        "[BarUI] {} 找到 {} 個有效錨點",
        cfg.name,
        valid_anchors.len()
    );

    // ── 收集錨點 + 過濾：call 目標必須在遊戲模組外（DLL 空間 = 真 sprintf）──
    const GAME_END: u32 = 0x01C79000; // base 0x400000 + module 0x1879000
    struct AnchorInfo {
        cleanup_addr: u32,
        call_addr: u32,
        sprintf_addr: u32,
    }
    let mut candidates: Vec<AnchorInfo> = Vec::new();

    for (anchor_idx, &(area_start, _widget_addr)) in valid_anchors.iter().enumerate() {
        // 搜尋 80 bytes 視窗，遍歷所有 add esp,0x10 匹配點
        let ext = read_bytes(h, area_start + 24, 80)?;
        let mut found_any = false;
        for i in 0..ext.len().saturating_sub(3) {
            if ext[i] != 0x83 || ext[i + 1] != 0xC4 || ext[i + 2] != 0x10 {
                continue;
            }
            let cleanup_addr = area_start + 24 + i as u32;
            let call_addr = cleanup_addr - 5;
            if used_addrs.contains(&call_addr) {
                log_line!(
                    "[BarUI] {}   skip 0x{:08X}（已被其他 bar 佔用）",
                    cfg.name,
                    call_addr
                );
                continue;
            }
            let cb = read_bytes(h, call_addr, 5)?;
            if cb[0] != 0xE8 {
                continue;
            }
            let rel32 = i32::from_le_bytes([cb[1], cb[2], cb[3], cb[4]]);
            let sprintf_addr = (call_addr + 5).wrapping_add(rel32 as u32);
            if sprintf_addr < GAME_END {
                log_line!(
                    "[BarUI] {}   skip 0x{:08X} → 0x{:08X}（遊戲模組內）",
                    cfg.name,
                    call_addr,
                    sprintf_addr
                );
                continue;
            }
            log_line!(
                "[BarUI] {}   call @ 0x{:08X} → sprintf=0x{:08X} ✓",
                cfg.name,
                call_addr,
                sprintf_addr
            );
            used_addrs.insert(call_addr);
            candidates.push(AnchorInfo {
                cleanup_addr,
                call_addr,
                sprintf_addr,
            });
            found_any = true;
        }
        if !found_any {
            log_line!(
                "[BarUI] {}   錨點#{} @ 0x{:08X} 無匹配（80B 內無 DLL sprintf）",
                cfg.name,
                anchor_idx,
                area_start
            );
        }
    }
    log_line!(
        "[BarUI] {} 通過過濾的錨點: {}/{}",
        cfg.name,
        candidates.len(),
        valid_anchors.len()
    );
    if candidates.is_empty() {
        return Ok(0);
    }

    // ── 對每個有效錨點安裝 hook ──
    for cand in &candidates {
        let AnchorInfo {
            cleanup_addr,
            call_addr,
            sprintf_addr,
        } = *cand;

        let cave = alloc_exec(h, 256)?;
        let mut code: Vec<u8> = Vec::with_capacity(256);

        // 呼叫真正的 sprintf（stack 已有 [buf][fmt][curHP][maxHP]）
        let cs = cave + code.len() as u32;
        code.push(0xE8);
        code.extend_from_slice(&sprintf_addr.wrapping_sub(cs + 5).to_le_bytes());

        // pushad
        code.push(0x60);

        // 從 stack 讀取（pushad 偏移 32）
        code.extend_from_slice(&[0x8B, 0x7C, 0x24, 0x20]); // mov edi, [esp+0x20] ; buf
        code.extend_from_slice(&[0x8B, 0x74, 0x24, 0x2C]); // mov esi, [esp+0x2C] ; maxHP

        // 安全檢查：maxHP == 0 → 跳過
        code.extend_from_slice(&[0x85, 0xF6]);
        code.push(0x0F);
        code.push(0x84);
        let skip_fixup = code.len();
        code.extend_from_slice(&[0x00; 4]);

        // ── strlen → ecx ──
        code.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx
        let sl = code.len();
        code.extend_from_slice(&[0x80, 0x3C, 0x0F, 0x00]); // cmp byte [edi+ecx], 0
        code.push(0x74);
        let sj = code.len();
        code.push(0x00);
        code.push(0x41); // inc ecx
        code.extend_from_slice(&[0x83, 0xF9, 0x1E]); // cmp ecx, 30
        code.push(0x7C);
        code.push(((sl as isize - code.len() as isize - 1) & 0xFF) as u8);
        code[sj] = (code.len() - sj - 1) as u8;
        // ecx = strlen("N/M"), edi = buf

        // ── 百分比: curHP * 100 / maxHP → eax ──
        code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x28]); // mov eax, [esp+0x28] ; curHP
        code.extend_from_slice(&[0x6B, 0xC0, 0x64]); // imul eax, 100
        code.push(0x99); // cdq
        code.extend_from_slice(&[0xF7, 0xFE]); // idiv esi → eax=pct

        // ── 計算 pct_len（含 '%'）→ edx ──
        // 100: 4 字元 | 10-99: 3 字元 | 0-9: 2 字元
        code.extend_from_slice(&[0xBA, 0x02, 0x00, 0x00, 0x00]); // mov edx, 2
        code.extend_from_slice(&[0x83, 0xF8, 0x0A]); // cmp eax, 10
        code.push(0x7C);
        code.push(0x11); // jl +17 (.got_len)
        code.extend_from_slice(&[0xBA, 0x03, 0x00, 0x00, 0x00]); // mov edx, 3
        code.extend_from_slice(&[0x3D, 0x64, 0x00, 0x00, 0x00]); // cmp eax, 100
        code.push(0x7C);
        code.push(0x05); // jl +5 (.got_len)
        code.extend_from_slice(&[0xBA, 0x04, 0x00, 0x00, 0x00]); // mov edx, 4
                                                                 // .got_len: edx = pct_len

        // ── 總長度安全檢查（防止 stack 緩衝區溢位）──
        // total = strlen + 1(空白) + pct_len + 1(null)
        // total > BUF_SAFE → 跳過百分比
        const BUF_SAFE: u8 = 15; // 15 bytes 已驗證安全（target34-v1）
        code.extend_from_slice(&[0x89, 0xCB]); // mov ebx, ecx
        code.extend_from_slice(&[0x01, 0xD3]); // add ebx, edx
        code.extend_from_slice(&[0x83, 0xC3, 0x02]); // add ebx, 2
        code.extend_from_slice(&[0x83, 0xFB, BUF_SAFE]); // cmp ebx, BUF_SAFE
        code.push(0x0F);
        code.push(0x8F); // jg near .skip_all
        let skip_total_fixup = code.len();
        code.extend_from_slice(&[0x00; 4]);

        if cfg.prefix_mode {
            // ── HP 前綴模式: "XX% N/M" ──
            // prefix_len = pct_len + 1（加 ' '）
            code.push(0x42); // inc edx → edx = prefix_len

            // 保存 pct(eax) 和 prefix_len(edx)
            code.push(0x50); // push eax
            code.push(0x52); // push edx

            // 右移字串: for i = strlen(ecx) downto 0, buf[i+prefix_len] = buf[i]
            code.extend_from_slice(&[0x89, 0xCB]); // mov ebx, ecx
            let shift_loop = code.len();
            code.extend_from_slice(&[0x8A, 0x0C, 0x1F]); // mov cl, [edi+ebx]
            code.extend_from_slice(&[0x8D, 0x04, 0x13]); // lea eax, [ebx+edx]
            code.extend_from_slice(&[0x88, 0x0C, 0x07]); // mov [edi+eax], cl
            code.push(0x4B); // dec ebx
            code.push(0x79); // jns .shift
            code.push(((shift_loop as isize - code.len() as isize - 1) & 0xFF) as u8);

            // 恢復 prefix_len 和 pct
            code.push(0x5A); // pop edx（prefix_len，不再需要）
            code.push(0x58); // pop eax（pct）

            // 重設寫入位置 → buf[0] 開始寫前綴
            code.extend_from_slice(&[0x31, 0xC9]); // xor ecx, ecx
        } else {
            // ── MP 後綴模式: "N/M XX%" ──
            // 寫 1 個空白分隔
            code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x20]); // mov byte [edi+ecx], ' '
            code.push(0x41); // inc ecx
        }

        // ── 寫百分比數字（eax = pct，0-100，共用）──
        // 先處理 100
        code.extend_from_slice(&[0x3D, 0x64, 0x00, 0x00, 0x00]); // cmp eax, 100
        code.push(0x7C);
        let j100 = code.len();
        code.push(0x00); // jl .two_or_less
                         // 100: 硬寫 "100"
        code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x31]);
        code.push(0x41); // '1', inc ecx
        code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x30]);
        code.push(0x41); // '0', inc ecx
        code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x30]);
        code.push(0x41); // '0', inc ecx
        code.push(0xEB);
        let jp100 = code.len();
        code.push(0x00); // jmp .write_pct
                         // .two_or_less:
        code[j100] = (code.len() - j100 - 1) as u8;
        code.extend_from_slice(&[0x83, 0xF8, 0x0A]); // cmp eax, 10
        code.push(0x7C);
        let j10 = code.len();
        code.push(0x00); // jl .single
                         // 10-99: div 10 → 十位 + 個位
        code.push(0x51); // push ecx
        code.extend_from_slice(&[0xB1, 0x0A, 0x31, 0xD2, 0x0F, 0xB6, 0xC9]); // cl=10;xor edx;movzx ecx,cl
        code.extend_from_slice(&[0xF7, 0xF1]); // div ecx → eax=十位, edx=個位
        code.extend_from_slice(&[0x89, 0xD6]); // mov esi, edx（保存個位）
        code.push(0x59); // pop ecx
        code.extend_from_slice(&[0x04, 0x30, 0x88, 0x04, 0x0F]);
        code.push(0x41); // 十位
        code.extend_from_slice(&[0x89, 0xF0, 0x04, 0x30, 0x88, 0x04, 0x0F]);
        code.push(0x41); // 個位
        code.push(0xEB);
        let jp2 = code.len();
        code.push(0x00); // jmp .write_pct
                         // .single (0-9):
        code[j10] = (code.len() - j10 - 1) as u8;
        code.extend_from_slice(&[0x04, 0x30, 0x88, 0x04, 0x0F]);
        code.push(0x41); // 個位
                         // .write_pct:
        code[jp100] = (code.len() - jp100 - 1) as u8;
        code[jp2] = (code.len() - jp2 - 1) as u8;

        if cfg.prefix_mode {
            // 前綴: '%' + ' '（不寫 '\0'，右移已保留原始 null）
            code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x25]);
            code.push(0x41); // '%'
            code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x20]); // ' '
        } else {
            // 後綴: '%' + '\0'
            code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x25]);
            code.push(0x41); // '%'
            code.extend_from_slice(&[0xC6, 0x04, 0x0F, 0x00]); // '\0'
        }

        // ── 更新 EAX = 新的字串長度 ──
        // 遊戲可能用 sprintf 返回值（EAX）決定渲染長度。
        // 遍歷 buf 計算新的 strlen，寫入 pushad 保存的 EAX [esp+0x1C]。
        code.extend_from_slice(&[0x31, 0xDB]); // xor ebx, ebx
        let count_loop = code.len();
        code.extend_from_slice(&[0x80, 0x3C, 0x1F, 0x00]); // cmp byte [edi+ebx], 0
        code.push(0x74); // je .done_count
        let count_done_fixup = code.len();
        code.push(0x00);
        code.push(0x43); // inc ebx
        code.extend_from_slice(&[0x83, 0xFB, 0x1E]); // cmp ebx, 30
        code.push(0x7C); // jl .count_loop
        code.push(((count_loop as isize - code.len() as isize - 1) & 0xFF) as u8);
        code[count_done_fixup] = (code.len() - count_done_fixup - 1) as u8;
        code.extend_from_slice(&[0x89, 0x5C, 0x24, 0x1C]); // mov [esp+0x1C], ebx

        // .skip_all（maxHP==0 或 總長度超限跳到這）
        let skip_target = code.len();
        let d = (skip_target - skip_fixup - 4) as u32;
        code[skip_fixup..skip_fixup + 4].copy_from_slice(&d.to_le_bytes());
        let d2 = (skip_target - skip_total_fixup - 4) as u32;
        code[skip_total_fixup..skip_total_fixup + 4].copy_from_slice(&d2.to_le_bytes());

        // popad
        code.push(0x61);
        // jmp → cleanup_addr
        let js = cave + code.len() as u32;
        code.push(0xE9);
        code.extend_from_slice(&cleanup_addr.wrapping_sub(js + 5).to_le_bytes());

        log_line!(
            "[BarUI] {} codecave {} bytes @ 0x{:08X}",
            cfg.name,
            code.len(),
            cave
        );
        write_code(h, cave, &code)?;

        // 安裝 5-byte hook
        let mut hook = vec![0xE9u8];
        hook.extend_from_slice(&cave.wrapping_sub(call_addr + 5).to_le_bytes());
        write_code(h, call_addr, &hook)?;
        log_line!(
            "[BarUI] {} hook @ 0x{:08X} → 0x{:08X}",
            cfg.name,
            call_addr,
            cave
        );
        count += 1;
    } // end for cand

    Ok(count)
}

/// 安裝單一 x 置中 hook
fn install_x_center_hook(
    h: HANDLE,
    name: &str,
    addr: u32,
    len: usize,
    reg_is_edx: bool,
    x_offset: u32,
    buf_off: u8,
    base_x_addr: u32,
) -> Result<usize> {
    let cave = alloc_exec(h, 64)?;
    let mut xc: Vec<u8> = Vec::new();

    // push ecx; push esi
    xc.extend_from_slice(&[0x51, 0x56]);
    // strlen: lea esi, [ebp - buf_off]; xor ecx, ecx
    xc.extend_from_slice(&[0x8D, 0x75, (256u16 - buf_off as u16) as u8]);
    xc.extend_from_slice(&[0x31, 0xC9]);
    let xl = xc.len();
    xc.extend_from_slice(&[0x80, 0x3C, 0x0E, 0x00]); // cmp byte [esi+ecx], 0
    xc.push(0x74);
    let xje = xc.len();
    xc.push(0x00); // je .done
    xc.push(0x41); // inc ecx
    xc.extend_from_slice(&[0x83, 0xF9, 0x1E]); // cmp ecx, 30
    xc.push(0x7C);
    let xjl = xc.len();
    xc.push(((xl as isize - xjl as isize - 1) & 0xFF) as u8);
    xc[xje] = (xc.len() - xje - 1) as u8;

    // text_width = ecx * 7
    xc.extend_from_slice(&[0x6B, 0xC9, 0x07]);
    // edx = BAR_TEXT_WIDTH
    xc.push(0xBA);
    xc.extend_from_slice(&BAR_TEXT_WIDTH.to_le_bytes());
    // sub edx, ecx; sar edx, 1
    xc.extend_from_slice(&[0x29, 0xCA, 0xD1, 0xFA]);
    // add edx, [base_x_addr]
    let bx = base_x_addr.to_le_bytes();
    xc.extend_from_slice(&[0x03, 0x15, bx[0], bx[1], bx[2], bx[3]]);
    // add edx, x_offset
    xc.push(0x81);
    xc.push(0xC2);
    xc.extend_from_slice(&x_offset.to_le_bytes());
    // pop esi; pop ecx
    xc.extend_from_slice(&[0x5E, 0x59]);
    // 若目標是 eax: mov eax, edx
    if !reg_is_edx {
        xc.extend_from_slice(&[0x89, 0xD0]);
    }
    // jmp back
    let ret_addr = addr + len as u32;
    let jmp_site = cave + xc.len() as u32;
    xc.push(0xE9);
    xc.extend_from_slice(&ret_addr.wrapping_sub(jmp_site + 5).to_le_bytes());

    write_code(h, cave, &xc)?;
    let mut xhook = vec![0xE9u8];
    xhook.extend_from_slice(&cave.wrapping_sub(addr + 5).to_le_bytes());
    while xhook.len() < len {
        xhook.push(0x90);
    }
    write_code(h, addr, &xhook)?;
    log_line!(
        "[BarUI] {} x分支 @ 0x{:08X} off=0x{:X} base_x=0x{:08X}",
        name,
        addr,
        x_offset,
        base_x_addr
    );

    Ok(1)
}
