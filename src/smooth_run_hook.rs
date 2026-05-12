//! 順跑 runtime hook — per-entity 版（中段 hook 0x449776）
//!
//! 攔截 action table 查表函數，透過 EBP chain 取得 entity 指標，
//! 對每個 entity 獨立判斷加速狀態、獨立管理 RunL/RunR toggle。
//!
//! Per-entity 機制：
//!   - 加速偵測：entity+0x29 (高段加速)
//!   - 左右腳選擇：使用本次查表的 action_state（0=RunL，其餘走路動作=RunR）
//!   - Entity 取得：EBP chain → [[EBP]-0x5C]（MovementFunc 的 entity 指標）
//!   - Return address guard：確認 caller 在 MovementFunc 範圍內
//!
//! 走路動作編號: 0, 4, 11, 20, 24, 40, 46, 50, 54, 58, 62, 83
//!
//! 中段 hook: 覆蓋 0x449776 起 5 bytes (8B 44 C2 04 5D → E9 xxxxxxxx)

use crate::logger::log_line;
use crate::{memory, process};
use anyhow::Result;
use windows::Win32::Foundation::HANDLE;

/// 中段 hook 地址（mov eax, [edx+eax*8+4] 的位置）
const HOOK_ADDR: u32 = 0x00449776;

/// 預期被覆蓋的 5 bytes
const EXPECTED_BYTES: [u8; 5] = [0x8B, 0x44, 0xC2, 0x04, 0x5D];

/// RunL slot 偏移: 98 * 8 + 4 = 0x314
const RUNL_SLOT_OFF: u32 = 0x0314;

/// RunR slot 偏移: 99 * 8 + 4 = 0x31C
const RUNR_SLOT_OFF: u32 = 0x031C;

/// Per-entity 加速欄位偏移
const HASTE_HIGH_OFF: u8 = 0x29; // 高段加速

/// Entity 在 MovementFunc 的 [ebp-0x5C] 偏移（signed: 0xA4 = -0x5C）
const ENTITY_EBP_OFF: u8 = 0xA4; // -0x5C as u8

/// MovementFunc return address guard 範圍
const MOVEMENT_FUNC_LO: u32 = 0x005AA000;
const MOVEMENT_FUNC_HI: u32 = 0x005AAA00;

/// Per-entity foot state table in the codecave.
/// entry: [tag_lo16:2, prev_frame:1, foot_toggle:1]
const HASH_TABLE_OFF: u32 = 0x200;
const HASH_TABLE_SIZE: usize = 64;
const HASH_TABLE_MASK: u8 = 0x3F;

/// 安裝順跑 runtime hook（per-entity 版）
pub fn install_smooth_run_hook(h: HANDLE, pid: u32) -> Result<()> {
    log_line!("\n--- 順跑 runtime hook（per-entity）---");

    // 驗證目標位元組
    let orig = memory::read_bytes(h, HOOK_ADDR, 5)?;
    if orig[0] == 0xE9 {
        log_line!("[跳過] 0x{HOOK_ADDR:08X} 已被 hook");
        return Ok(());
    }
    if orig[..5] != EXPECTED_BYTES {
        log_line!(
            "[警告] 0x{HOOK_ADDR:08X} 位元組不符: {:02X} {:02X} {:02X} {:02X} {:02X}（預期 8B 44 C2 04 5D），跳過",
            orig[0], orig[1], orig[2], orig[3], orig[4]
        );
        return Ok(());
    }

    // 分配 codecave（shellcode）
    let cave_size = (HASH_TABLE_OFF as usize) + HASH_TABLE_SIZE * 4 + 64;
    let cave_addr = memory::alloc_exec(h, cave_size)?;
    log_line!("[OK] codecave: 0x{cave_addr:08X}（{cave_size} bytes）");

    // 組裝 shellcode
    let shellcode = build_shellcode(cave_addr);
    log_line!("[INFO] shellcode: {} bytes", shellcode.len());
    assert!(
        shellcode.len() <= HASH_TABLE_OFF as usize,
        "shellcode ({}) 超過 hash table 偏移 ({})",
        shellcode.len(),
        HASH_TABLE_OFF
    );
    assert!(
        shellcode.len() <= cave_size,
        "shellcode ({}) 超過 codecave 大小 ({})",
        shellcode.len(),
        cave_size
    );

    // 寫入 shellcode
    memory::write_code(h, cave_addr, &shellcode)?;

    // 安裝 JMP hook（暫停 → 寫入 → 恢復）
    let mut jmp = [0u8; 5];
    jmp[0] = 0xE9;
    let rel = cave_addr.wrapping_sub(HOOK_ADDR + 5) as i32;
    jmp[1..5].copy_from_slice(&rel.to_le_bytes());

    let threads = process::suspend_threads(pid)?;
    match memory::write_code(h, HOOK_ADDR, &jmp) {
        Ok(()) => {
            process::resume_threads(threads);
            log_line!(
                "[OK] 順跑 hook @ 0x{HOOK_ADDR:08X} → 0x{cave_addr:08X}（per-entity，anim_frame wrap L/R）"
            );
        }
        Err(e) => {
            process::resume_threads(threads);
            log_line!("[錯誤] 順跑 hook 安裝失敗: {e}");
            return Err(e);
        }
    }

    Ok(())
}

/// 組裝中段 hook shellcode — per-entity 版
///
/// 進入時：
///   edx = sprite table base（sprite_id * 0x3D8 + [TABLE_BASE_PTR]）
///   [ebp+0xC] = action_state
///   ebp = 0x449750 的 frame pointer
///
/// 被替換的指令（5 bytes）：
///   mov eax, [edx+eax*8+4]   ; 4 bytes
///   pop ebp                   ; 1 byte
///
/// 邏輯：
///   1. 原始查表 → eax = frame_data_ptr
///   2. slot 98 有效性檢查
///   3. 走路動作檢查 (0,4,11,20,24,40,46,50,54,58,62,83,88,119)
///   4. Return address guard（確認 caller 是 MovementFunc）
///   5. EBP chain → entity 指標（[[EBP]-0x5C]）
///   6. Per-entity 加速：entity+0x29
///   7. Hash table toggle：偵測 anim_frame 回繞（cur < prev）→ 翻轉
///   8. toggle=0 → slot 98 (RunL)，toggle=1 → slot 99 (RunR)
fn build_shellcode(cave_addr: u32) -> Vec<u8> {
    let mut sc: Vec<u8> = Vec::with_capacity(256);
    let hash_table_addr = cave_addr + HASH_TABLE_OFF;

    // === 1. 原始查表（被覆蓋的指令）===
    // mov eax, [ebp+0xC]      ; action_state
    sc.extend_from_slice(&[0x8B, 0x45, 0x0C]);
    // mov eax, [edx+eax*8+4]  ; 原始 frame_data_ptr
    sc.extend_from_slice(&[0x8B, 0x44, 0xC2, 0x04]);

    // === 2. slot 98 有效性 ===
    // cmp dword [edx + 0x314], 0x10000
    sc.extend_from_slice(&[0x81, 0xBA]);
    sc.extend_from_slice(&RUNL_SLOT_OFF.to_le_bytes());
    sc.extend_from_slice(&0x00010000u32.to_le_bytes());
    // jb .done (rel32)
    sc.extend_from_slice(&[0x0F, 0x82]);
    let jb_done_slot = sc.len();
    sc.extend_from_slice(&[0; 4]);

    // === 3. 走路動作檢查 ===
    // mov ecx, [ebp+0xC]      ; action_state
    sc.extend_from_slice(&[0x8B, 0x4D, 0x0C]);
    // test ecx, ecx (== 0?)
    sc.extend_from_slice(&[0x85, 0xC9]);
    sc.push(0x74); // jz .is_walk (rel8)
    let jz_walk = sc.len();
    sc.push(0x00);

    // cmp ecx, 4
    sc.extend_from_slice(&[0x83, 0xF9, 0x04]);
    sc.push(0x74);
    let je_w1 = sc.len();
    sc.push(0x00);

    // cmp ecx, 11
    sc.extend_from_slice(&[0x83, 0xF9, 0x0B]);
    sc.push(0x74);
    let je_w2 = sc.len();
    sc.push(0x00);

    // cmp ecx, 20
    sc.extend_from_slice(&[0x83, 0xF9, 0x14]);
    sc.push(0x74);
    let je_w3 = sc.len();
    sc.push(0x00);

    // cmp ecx, 24
    sc.extend_from_slice(&[0x83, 0xF9, 0x18]);
    sc.push(0x74);
    let je_w4 = sc.len();
    sc.push(0x00);

    // cmp ecx, 40
    sc.extend_from_slice(&[0x83, 0xF9, 0x28]);
    sc.push(0x74);
    let je_w5 = sc.len();
    sc.push(0x00);

    // cmp ecx, 46
    sc.extend_from_slice(&[0x83, 0xF9, 0x2E]);
    sc.push(0x74);
    let je_w6 = sc.len();
    sc.push(0x00);

    // cmp ecx, 50（雙手劍 largesword）
    sc.extend_from_slice(&[0x83, 0xF9, 0x32]);
    sc.push(0x74);
    let je_w7 = sc.len();
    sc.push(0x00);

    // cmp ecx, 54（雙刀 double sword）
    sc.extend_from_slice(&[0x83, 0xF9, 0x36]);
    sc.push(0x74);
    let je_w8 = sc.len();
    sc.push(0x00);

    // cmp ecx, 58（爪 claw）
    sc.extend_from_slice(&[0x83, 0xF9, 0x3A]);
    sc.push(0x74);
    let je_w9 = sc.len();
    sc.push(0x00);

    // cmp ecx, 62（飛鏢 shuriken）
    sc.extend_from_slice(&[0x83, 0xF9, 0x3E]);
    sc.push(0x74);
    let je_w10 = sc.len();
    sc.push(0x00);

    // cmp ecx, 83（鎖鏈劍 chainsword）
    sc.extend_from_slice(&[0x83, 0xF9, 0x53]);
    sc.push(0x74);
    let je_w11 = sc.len();
    sc.push(0x00);

    // cmp ecx, 88
    sc.extend_from_slice(&[0x83, 0xF9, 0x58]);
    sc.push(0x74);
    let je_w12 = sc.len();
    sc.push(0x00);

    // cmp ecx, 119
    sc.extend_from_slice(&[0x83, 0xF9, 0x77]);
    sc.push(0x74);
    let je_w13 = sc.len();
    sc.push(0x00);

    // 不是走路 → jmp .done (rel32)
    sc.push(0xE9);
    let jmp_done_notwalk = sc.len();
    sc.extend_from_slice(&[0; 4]);

    // === .is_walk ===
    let walk_off = sc.len();
    sc[jz_walk] = (walk_off - jz_walk - 1) as u8;
    sc[je_w1] = (walk_off - je_w1 - 1) as u8;
    sc[je_w2] = (walk_off - je_w2 - 1) as u8;
    sc[je_w3] = (walk_off - je_w3 - 1) as u8;
    sc[je_w4] = (walk_off - je_w4 - 1) as u8;
    sc[je_w5] = (walk_off - je_w5 - 1) as u8;
    sc[je_w6] = (walk_off - je_w6 - 1) as u8;
    sc[je_w7] = (walk_off - je_w7 - 1) as u8;
    sc[je_w8] = (walk_off - je_w8 - 1) as u8;
    sc[je_w9] = (walk_off - je_w9 - 1) as u8;
    sc[je_w10] = (walk_off - je_w10 - 1) as u8;
    sc[je_w11] = (walk_off - je_w11 - 1) as u8;
    sc[je_w12] = (walk_off - je_w12 - 1) as u8;
    sc[je_w13] = (walk_off - je_w13 - 1) as u8;

    // === 4. Return address guard ===
    // mov ecx, [ebp+4]         ; 0x449750 的 return address
    sc.extend_from_slice(&[0x8B, 0x4D, 0x04]);
    // cmp ecx, MOVEMENT_FUNC_LO
    sc.extend_from_slice(&[0x81, 0xF9]);
    sc.extend_from_slice(&MOVEMENT_FUNC_LO.to_le_bytes());
    // jb .done (rel32)
    sc.extend_from_slice(&[0x0F, 0x82]);
    let jb_done_guard1 = sc.len();
    sc.extend_from_slice(&[0; 4]);
    // cmp ecx, MOVEMENT_FUNC_HI
    sc.extend_from_slice(&[0x81, 0xF9]);
    sc.extend_from_slice(&MOVEMENT_FUNC_HI.to_le_bytes());
    // ja .done (rel32)
    sc.extend_from_slice(&[0x0F, 0x87]);
    let ja_done_guard2 = sc.len();
    sc.extend_from_slice(&[0; 4]);

    // === 5. 取 entity 指標 ===
    // mov ecx, [ebp]           ; caller's saved EBP (= MovementFunc's EBP)
    sc.extend_from_slice(&[0x8B, 0x4D, 0x00]);
    // mov ecx, [ecx-0x5C]      ; entity pointer
    sc.extend_from_slice(&[0x8B, 0x49, ENTITY_EBP_OFF]);
    // test ecx, ecx
    sc.extend_from_slice(&[0x85, 0xC9]);
    // jz .done (rel32)
    sc.extend_from_slice(&[0x0F, 0x84]);
    let jz_done_null = sc.len();
    sc.extend_from_slice(&[0; 4]);

    // === 6. Per-entity 加速檢查 ===
    // push eax                 ; 保存原始 frame_data_ptr
    sc.push(0x50);
    // cmp byte [ecx+0x29], 0      ; haste_high
    sc.extend_from_slice(&[0x80, 0x79, HASTE_HIGH_OFF, 0x00]);
    // jz .no_haste_pop (rel8)
    sc.push(0x74);
    let jz_no_haste = sc.len();
    sc.push(0x00);

    // === 7. Stateful foot selection ===
    // Keep the selected foot stable during the current animation. Flip only
    // when the entity animation frame wraps, so the pointer changes at frame 0.
    // push edi
    sc.push(0x57);

    // hash = ((entity_ptr >> 3) & 0x3F) * 4
    // mov eax, ecx             ; entity_ptr
    sc.extend_from_slice(&[0x89, 0xC8]);
    // shr eax, 3
    sc.extend_from_slice(&[0xC1, 0xE8, 0x03]);
    // and eax, HASH_TABLE_MASK
    sc.extend_from_slice(&[0x83, 0xE0, HASH_TABLE_MASK]);
    // shl eax, 2
    sc.extend_from_slice(&[0xC1, 0xE0, 0x02]);
    // add eax, hash_table_addr
    sc.push(0x05);
    sc.extend_from_slice(&hash_table_addr.to_le_bytes());
    // mov edi, eax             ; edi = &hash_table[index]
    sc.extend_from_slice(&[0x89, 0xC7]);

    // cmp word [edi], cx       ; tag = entity_ptr low16
    sc.extend_from_slice(&[0x66, 0x39, 0x0F]);
    // jne .new_entry
    sc.push(0x75);
    let jne_new_entry = sc.len();
    sc.push(0x00);

    // movzx eax, byte [ecx+0x17] ; current anim_frame
    sc.extend_from_slice(&[0x0F, 0xB6, 0x41, 0x17]);
    // cmp al, [edi+2]          ; current frame vs previous frame
    sc.extend_from_slice(&[0x3A, 0x47, 0x02]);
    // jae .no_wrap
    sc.push(0x73);
    let jae_no_wrap = sc.len();
    sc.push(0x00);

    // xor byte [edi+3], 1
    sc.extend_from_slice(&[0x80, 0x77, 0x03, 0x01]);

    // .no_wrap:
    let no_wrap_off = sc.len();
    sc[jae_no_wrap] = (no_wrap_off - jae_no_wrap - 1) as u8;
    // mov [edi+2], al          ; store prev_frame
    sc.extend_from_slice(&[0x88, 0x47, 0x02]);
    // jmp .apply_toggle
    sc.push(0xEB);
    let jmp_apply_toggle = sc.len();
    sc.push(0x00);

    // .new_entry:
    let new_entry_off = sc.len();
    sc[jne_new_entry] = (new_entry_off - jne_new_entry - 1) as u8;
    // mov word [edi], cx       ; tag = entity_ptr low16
    sc.extend_from_slice(&[0x66, 0x89, 0x0F]);
    // movzx eax, byte [ecx+0x17] ; current anim_frame
    sc.extend_from_slice(&[0x0F, 0xB6, 0x41, 0x17]);
    // mov [edi+2], al          ; prev_frame
    sc.extend_from_slice(&[0x88, 0x47, 0x02]);
    // mov byte [edi+3], 0      ; default RunL
    sc.extend_from_slice(&[0xC6, 0x47, 0x03, 0x00]);

    // mov eax, [ebp+0xC]       ; initial action_state
    sc.extend_from_slice(&[0x8B, 0x45, 0x0C]);
    // test eax, eax
    sc.extend_from_slice(&[0x85, 0xC0]);
    // jz .apply_toggle
    sc.push(0x74);
    let jz_apply_toggle = sc.len();
    sc.push(0x00);
    // mov byte [edi+3], 1      ; non-zero action starts at RunR
    sc.extend_from_slice(&[0xC6, 0x47, 0x03, 0x01]);

    // .apply_toggle:
    let apply_toggle_off = sc.len();
    sc[jmp_apply_toggle] = (apply_toggle_off - jmp_apply_toggle - 1) as u8;
    sc[jz_apply_toggle] = (apply_toggle_off - jz_apply_toggle - 1) as u8;
    // movzx eax, byte [edi+3]  ; 0=RunL, 1=RunR
    sc.extend_from_slice(&[0x0F, 0xB6, 0x47, 0x03]);
    // pop edi
    sc.push(0x5F);
    // test eax, eax
    sc.extend_from_slice(&[0x85, 0xC0]);
    // pop ecx                  ; discard saved frame_data_ptr, flags preserved
    sc.push(0x59);
    // jnz .use_runr (rel8)
    sc.push(0x75);
    let jnz_runr = sc.len();
    sc.push(0x00);

    // toggle=0 → RunL: mov eax, [edx + 0x314]
    sc.extend_from_slice(&[0x8B, 0x82]);
    sc.extend_from_slice(&RUNL_SLOT_OFF.to_le_bytes());
    // jmp .done (rel32)
    sc.push(0xE9);
    let jmp_done_runl = sc.len();
    sc.extend_from_slice(&[0; 4]);

    // === .use_runr ===
    let runr_off = sc.len();
    sc[jnz_runr] = (runr_off - jnz_runr - 1) as u8;
    // cmp dword [edx + 0x31C], 0x10000   ; slot 99 有效性
    sc.extend_from_slice(&[0x81, 0xBA]);
    sc.extend_from_slice(&RUNR_SLOT_OFF.to_le_bytes());
    sc.extend_from_slice(&0x00010000u32.to_le_bytes());
    // jb .runr_fallback (rel8)
    sc.push(0x72);
    let jb_fb = sc.len();
    sc.push(0x00);
    // slot 99 有效: mov eax, [edx + 0x31C]
    sc.extend_from_slice(&[0x8B, 0x82]);
    sc.extend_from_slice(&RUNR_SLOT_OFF.to_le_bytes());
    // jmp .done (rel8 — 很近)
    sc.push(0xEB);
    let jmp_done_runr = sc.len();
    sc.push(0x00);

    // .runr_fallback: slot 99 無效 → 退回 slot 98
    let fb_off = sc.len();
    sc[jb_fb] = (fb_off - jb_fb - 1) as u8;
    sc.extend_from_slice(&[0x8B, 0x82]);
    sc.extend_from_slice(&RUNL_SLOT_OFF.to_le_bytes());
    // jmp .done (rel8)
    sc.push(0xEB);
    let jmp_done_fb = sc.len();
    sc.push(0x00);

    // === .no_haste_pop: entity 無加速 → 恢復原始結果 ===
    let no_haste_off = sc.len();
    sc[jz_no_haste] = (no_haste_off - jz_no_haste - 1) as u8;
    // pop eax                      ; 恢復原始 frame_data_ptr
    sc.push(0x58);

    // === .done ===
    let done_off = sc.len();

    // 修正所有 rel32 跳轉到 .done
    for &fixup in &[
        jb_done_slot,
        jmp_done_notwalk,
        jb_done_guard1,
        ja_done_guard2,
        jz_done_null,
        jmp_done_runl,
    ] {
        let rel = ((done_off as i32) - (fixup as i32) - 4).to_le_bytes();
        sc[fixup..fixup + 4].copy_from_slice(&rel);
    }
    // 修正 rel8 跳轉到 .done
    sc[jmp_done_runr] = (done_off - jmp_done_runr - 1) as u8;
    sc[jmp_done_fb] = (done_off - jmp_done_fb - 1) as u8;

    // pop ebp
    sc.push(0x5D);
    // ret
    sc.push(0xC3);

    sc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shellcode_flips_foot_only_on_anim_frame_wrap() {
        let sc = build_shellcode(0x1234_0000);

        assert!(
            sc.windows(4).any(|w| w == [0x0F, 0xB6, 0x41, 0x17]),
            "RunL/RunR selection should observe entity+0x17 anim_frame"
        );
        assert!(
            !sc.windows(7)
                .any(|w| w == [0x8B, 0x4D, 0x0C, 0x85, 0xC9, 0x59, 0x75]),
            "RunL/RunR selection must not hard-switch directly from action_state"
        );
        assert!(
            sc.windows(3).any(|w| w == [0x3A, 0x47, 0x02]),
            "RunL/RunR selection should compare current anim_frame with stored previous frame"
        );
        assert!(
            sc.windows(4).any(|w| w == [0x80, 0x77, 0x03, 0x01]),
            "RunL/RunR selection should flip the stored foot only at an animation boundary"
        );
        assert!(
            sc.windows(4).any(|w| w == [0x83, 0xF9, 0x58, 0x74]),
            "RunL/RunR selection should cover TianM action 88"
        );
        assert!(
            sc.windows(4).any(|w| w == [0x83, 0xF9, 0x77, 0x74]),
            "RunL/RunR selection should cover TianM action 119"
        );
    }
}
