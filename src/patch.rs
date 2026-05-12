//! 靜態修補模組 — 等待解密 + 原子修補（防閃退核心） — v1.0.0 第一版
//!
//! 流程：輪詢等待 packer 解密完成 → 暫停所有執行緒 → 一次寫入兩個 patch → 恢復
//! 這是修復 Python launcher.py 登入畫面閃退的關鍵改進。

use crate::logger::log_line;
use crate::{memory, process};
use anyhow::{bail, Context, Result};
use launcher::server_list::{
    MAX_IMG_LIMIT_VALUE, MAX_INVENTORY_LIMIT_VALUE, MIN_IMG_LIMIT_VALUE, MIN_INVENTORY_LIMIT_VALUE,
};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;

// 解密偵測
const DECRYPT_ADDR: u32 = 0x004E204E;
const DECRYPT_EXPECTED: u32 = 0x0097850F; // JNZ +0x97（原始指令，解密後出現）

// ConditionalPatch：JNZ → NOP+JMP（繞過保護檢查）
const CONDITIONAL_PATCH_VAL: u32 = 0x0097E990; // 90 E9 97 00

// PatchCode_Point1
const PATCHCODE1_ADDR: u32 = 0x00722761;
const PATCHCODE1_VAL: u32 = 0x859001B0;
const FILE_HOOK_ADDR: u32 = 0x0058788B;
const FILE_HOOK_EXPECTED_NEW: u32 = 0x4D8D016A;
const FILE_HOOK_EXPECTED_OLD: u32 = 0x85C0B60F;
const PATHCODE_PATCH_ADDR: u32 = 0x00772BA0;
const USER_HOOK_ADDR: u32 = 0x0077317D;

const TEXT_SCAN_START: u32 = 0x00401000;
const TEXT_SCAN_END: u32 = 0x00830000;
const DECRYPT_WAIT_TIMEOUT_MS: u64 = 120_000;
const DECRYPT_POLL_INTERVAL_MS: u64 = 50;
pub const QUICK_DECRYPT_WAIT_TIMEOUT_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptMarkerState {
    Ready,
    AlreadyPatched,
    NotReady(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitAndPatchOutcome {
    Patched,
    NotReady { last_value: u32 },
}

pub(crate) fn classify_decrypt_marker_value(value: u32) -> DecryptMarkerState {
    match value {
        DECRYPT_EXPECTED => DecryptMarkerState::Ready,
        CONDITIONAL_PATCH_VAL => DecryptMarkerState::AlreadyPatched,
        other => DecryptMarkerState::NotReady(other),
    }
}

fn apply_time_guard_patches(h: HANDLE, pid: u32, already_patched: bool) -> Result<()> {
    let patch1 = CONDITIONAL_PATCH_VAL.to_le_bytes();
    if already_patched {
        log_line!("[OK] ConditionalPatch @ 0x{DECRYPT_ADDR:08X}: already patched");
    } else {
        memory::write_code(h, DECRYPT_ADDR, &patch1).context("ConditionalPatch write failed")?;
        log_line!("[OK] ConditionalPatch @ 0x{DECRYPT_ADDR:08X}: written");
    }

    log_line!("[patch-time] suspend threads for PatchCode_Point1");
    let threads = process::suspend_threads(pid)?;
    log_line!("[OK] suspended {} thread(s)", threads.len());

    let patch_result: Result<()> = (|| {
        let patch2 = PATCHCODE1_VAL.to_le_bytes();
        memory::write_code(h, PATCHCODE1_ADDR, &patch2).context("PatchCode_Point1 write failed")?;
        log_line!("[OK] PatchCode_Point1 @ 0x{PATCHCODE1_ADDR:08X}: 0x{PATCHCODE1_VAL:08X}");

        let v1 =
            memory::read_u32(h, DECRYPT_ADDR).context("ConditionalPatch verify read failed")?;
        let v2 =
            memory::read_u32(h, PATCHCODE1_ADDR).context("PatchCode_Point1 verify read failed")?;
        if v1 != CONDITIONAL_PATCH_VAL || v2 != PATCHCODE1_VAL {
            bail!(
                "time patch verify failed: 0x{DECRYPT_ADDR:08X}=0x{v1:08X}(expected 0x{CONDITIONAL_PATCH_VAL:08X}), \
                 0x{PATCHCODE1_ADDR:08X}=0x{v2:08X}(expected 0x{PATCHCODE1_VAL:08X})"
            );
        }
        Ok(())
    })();

    process::resume_threads(threads);
    patch_result?;
    log_line!("[OK] time guard patches verified; threads resumed");

    Ok(())
}

pub fn try_wait_and_patch(h: HANDLE, pid: u32, timeout_ms: u64) -> Result<WaitAndPatchOutcome> {
    log_line!("[patch-time] quick wait_and_patch timeout={timeout_ms}ms");

    let wait_start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut first_readable_logged = false;
    let mut last_val = 0_u32;
    let mut saw_value = false;

    loop {
        match memory::read_u32(h, DECRYPT_ADDR) {
            Ok(val) => {
                saw_value = true;
                last_val = val;
                match classify_decrypt_marker_value(val) {
                    DecryptMarkerState::Ready => {
                        log_line!(
                            "[patch-time] decrypt marker ready after {:.3}s (0x{DECRYPT_ADDR:08X}=0x{val:08X})",
                            wait_start.elapsed().as_secs_f64()
                        );
                        apply_time_guard_patches(h, pid, false)?;
                        return Ok(WaitAndPatchOutcome::Patched);
                    }
                    DecryptMarkerState::AlreadyPatched => {
                        log_line!(
                            "[patch-time] decrypt marker already patched after {:.3}s (0x{DECRYPT_ADDR:08X}=0x{val:08X})",
                            wait_start.elapsed().as_secs_f64()
                        );
                        apply_time_guard_patches(h, pid, true)?;
                        return Ok(WaitAndPatchOutcome::Patched);
                    }
                    DecryptMarkerState::NotReady(_) => {
                        if !first_readable_logged {
                            first_readable_logged = true;
                            log_line!(
                                "[patch-time] decrypt marker not ready after {:.3}s (0x{DECRYPT_ADDR:08X}=0x{val:08X})",
                                wait_start.elapsed().as_secs_f64()
                            );
                        }
                    }
                }
            }
            Err(_) => {
                if !first_readable_logged {
                    first_readable_logged = true;
                    log_line!("[patch-time] decrypt marker not readable yet");
                }
            }
        }

        let elapsed = wait_start.elapsed();
        if elapsed >= timeout {
            break;
        }

        let remaining = timeout - elapsed;
        std::thread::sleep(remaining.min(Duration::from_millis(DECRYPT_POLL_INTERVAL_MS)));
    }

    if saw_value {
        log_line!(
            "[patch-time] quick wait timed out after {:.3}s; last=0x{last_val:08X}",
            wait_start.elapsed().as_secs_f64()
        );
    } else {
        log_line!(
            "[patch-time] quick wait timed out after {:.3}s; marker unreadable",
            wait_start.elapsed().as_secs_f64()
        );
    }
    Ok(WaitAndPatchOutcome::NotReady {
        last_value: last_val,
    })
}

const MOVE_STATE_OBFUSCATION_PATTERN: &[u8] = &[
    0x0F, 0xBE, 0x42, 0x14, 0x83, 0xF8, 0x08, 0x74, 0x21, 0x8B, 0x0D, 0xB8, 0xD2, 0xC2, 0x00,
];
const MOVE_PACKET_ENCRYPTION_PATTERN: &[u8] = &[
    0x0F, 0xBE, 0x15, 0xE1, 0xAE, 0x9A, 0x00, 0x83, 0xFA, 0x03, 0x75, 0x22, 0xA1, 0xB8, 0xD2, 0xC2,
    0x00, 0x0F, 0xBE, 0x48, 0x15, 0x83, 0xF1, 0x49,
];

#[derive(Clone, Copy)]
struct StartupProbe {
    name: &'static str,
    addr: u32,
    expected: Option<u32>,
}

pub fn spawn_startup_probe(h: HANDLE) {
    let h_raw = h.0 as usize;
    std::thread::spawn(move || {
        let h = HANDLE(h_raw as *mut _);
        let start = Instant::now();
        let probes = [
            StartupProbe {
                name: "decrypt-gate",
                addr: DECRYPT_ADDR,
                expected: Some(DECRYPT_EXPECTED),
            },
            StartupProbe {
                name: "patchcode1",
                addr: PATCHCODE1_ADDR,
                expected: Some(PATCHCODE1_VAL),
            },
            StartupProbe {
                name: "filehook-new",
                addr: FILE_HOOK_ADDR,
                expected: Some(FILE_HOOK_EXPECTED_NEW),
            },
            StartupProbe {
                name: "filehook-old",
                addr: FILE_HOOK_ADDR,
                expected: Some(FILE_HOOK_EXPECTED_OLD),
            },
            StartupProbe {
                name: "pathcode",
                addr: PATHCODE_PATCH_ADDR,
                expected: None,
            },
            StartupProbe {
                name: "user-hook",
                addr: USER_HOOK_ADDR,
                expected: None,
            },
        ];
        let mut matched = vec![false; probes.len()];
        let mut last_sample_second = u64::MAX;

        for _ in 0..12000 {
            let elapsed = start.elapsed().as_secs_f64();
            let elapsed_second = elapsed as u64;
            let sample_now = elapsed_second != last_sample_second
                && matches!(
                    elapsed_second,
                    0 | 1 | 2 | 5 | 10 | 20 | 30 | 45 | 60 | 75 | 90
                );

            let mut sample_parts = Vec::new();
            for (idx, probe) in probes.iter().enumerate() {
                let val = memory::read_u32(h, probe.addr).ok();
                if sample_now {
                    match val {
                        Some(v) => sample_parts.push(format!("{}=0x{v:08X}", probe.name)),
                        None => sample_parts.push(format!("{}=<unreadable>", probe.name)),
                    }
                }

                if let (Some(expected), Some(v)) = (probe.expected, val) {
                    if !matched[idx] && v == expected {
                        matched[idx] = true;
                        log_line!(
                            "[addr-ready] {} @ 0x{:08X}=0x{v:08X} after {:.3}s",
                            probe.name,
                            probe.addr,
                            elapsed
                        );
                    }
                }
            }

            if sample_now {
                log_line!("[addr-probe] t={elapsed:.3}s {}", sample_parts.join(", "));
                last_sample_second = elapsed_second;
            }

            if matched
                .iter()
                .zip(probes.iter())
                .all(|(done, probe)| probe.expected.is_none() || *done)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        log_line!("[addr-probe] monitor stopped after 120s");
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BytePatchSpec {
    pub name: &'static str,
    pub pattern: &'static [u8],
    pub patch_offset: u32,
    pub original: u8,
    pub patched: u8,
}

pub(crate) fn move_packet_no_encrypt_patch_specs() -> [BytePatchSpec; 2] {
    [
        BytePatchSpec {
            name: "move state obfuscation",
            pattern: MOVE_STATE_OBFUSCATION_PATTERN,
            patch_offset: 7,
            original: 0x74,
            patched: 0xEB,
        },
        BytePatchSpec {
            name: "move packet encryption",
            pattern: MOVE_PACKET_ENCRYPTION_PATTERN,
            patch_offset: 10,
            original: 0x75,
            patched: 0xEB,
        },
    ]
}

/// 等待 packer 解密完成，然後原子修補兩個關鍵位址
///
/// 修復閃退的核心邏輯：
/// 1. 輪詢 0x4E204E 直到解密完成
/// 2. 立即暫停所有遊戲執行緒
/// 3. 寫入 ConditionalPatch + PatchCode_Point1
/// 4. 恢復執行緒
pub fn wait_and_patch(h: HANDLE, pid: u32) -> Result<()> {
    log_line!("[等待] 程式碼解密中...");

    // 輪詢等待解密（最多 120 秒，間隔 10ms）
    let mut decrypted = false;
    let mut already_patched = false;
    let wait_start = std::time::Instant::now();
    let mut first_readable_logged = false;
    let mut last_val = 0u32;
    let poll_count = DECRYPT_WAIT_TIMEOUT_MS / DECRYPT_POLL_INTERVAL_MS;
    let log_every = (10_000 / DECRYPT_POLL_INTERVAL_MS).max(1);
    let unreadable_log_every = (5_000 / DECRYPT_POLL_INTERVAL_MS).max(1);
    for i in 0..poll_count {
        match memory::read_u32(h, DECRYPT_ADDR) {
            Ok(val) if val == DECRYPT_EXPECTED => {
                log_line!(
                    "[patch-time] decrypt marker ready after {:.3}s (0x{DECRYPT_ADDR:08X}=0x{val:08X})",
                    wait_start.elapsed().as_secs_f64()
                );
                log_line!("[OK] 程式碼已解密（耗時 {:.1}s）", i as f64 * 0.01);
                decrypted = true;
                break;
            }
            Ok(val) if val == CONDITIONAL_PATCH_VAL => {
                log_line!(
                    "[patch-time] decrypt marker already patched after {:.3}s (0x{DECRYPT_ADDR:08X}=0x{val:08X})",
                    wait_start.elapsed().as_secs_f64()
                );
                decrypted = true;
                already_patched = true;
                break;
            }
            Ok(val) => {
                last_val = val;
                if !first_readable_logged {
                    first_readable_logged = true;
                    log_line!(
                        "[patch-time] decrypt marker readable after {:.3}s (0x{DECRYPT_ADDR:08X}=0x{val:08X})",
                        wait_start.elapsed().as_secs_f64()
                    );
                } else if i > 0 && i % log_every == 0 {
                    log_line!(
                        "[patch-time] waiting decrypt marker {:.3}s (last=0x{last_val:08X})",
                        wait_start.elapsed().as_secs_f64()
                    );
                }
            }
            Err(_) => {
                // 進程可能還在初始化，繼續等待
                if i % unreadable_log_every == 0 && i > 0 {
                    log_line!("[等待] 讀取中... ({:.1}s)", i as f64 * 0.01);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(DECRYPT_POLL_INTERVAL_MS));
    }

    if !decrypted {
        log_line!("[patch-time] wait_and_patch timed out after 120s");
        log_line!("[patch-time] last decrypt marker value 0x{last_val:08X}");
        bail!("等待解密逾時（120s）");
    }

    // === ConditionalPatch：立即寫入（不暫停，避免競態條件） ===
    let patch1 = CONDITIONAL_PATCH_VAL.to_le_bytes();
    if already_patched {
        log_line!("[OK] ConditionalPatch @ 0x{DECRYPT_ADDR:08X}: already patched by StartupHook");
    } else {
        memory::write_code(h, DECRYPT_ADDR, &patch1)?;
        log_line!("[OK] ConditionalPatch @ 0x{DECRYPT_ADDR:08X}: JNZ → NOP+JMP（立即寫入）");
    }

    // === PatchCode_Point1：暫停 → 寫入 → 恢復（原子修補） ===
    log_line!("[修補] 暫停遊戲執行緒...");
    let threads = process::suspend_threads(pid)?;
    log_line!("[OK] 已暫停 {} 個執行緒", threads.len());

    let patch2 = PATCHCODE1_VAL.to_le_bytes();
    match memory::write_code(h, PATCHCODE1_ADDR, &patch2) {
        Ok(()) => {
            log_line!("[OK] PatchCode_Point1 @ 0x{PATCHCODE1_ADDR:08X}: 0x{PATCHCODE1_VAL:08X}")
        }
        Err(e) => {
            process::resume_threads(threads);
            bail!("PatchCode_Point1 寫入失敗: {e}");
        }
    }

    // 驗證修補結果
    let v1 = memory::read_u32(h, DECRYPT_ADDR)?;
    let v2 = memory::read_u32(h, PATCHCODE1_ADDR)?;
    if v1 != CONDITIONAL_PATCH_VAL || v2 != PATCHCODE1_VAL {
        process::resume_threads(threads);
        bail!(
            "修補驗證失敗: 0x{DECRYPT_ADDR:08X}=0x{v1:08X}(預期 0x{CONDITIONAL_PATCH_VAL:08X}), \
             0x{PATCHCODE1_ADDR:08X}=0x{v2:08X}(預期 0x{PATCHCODE1_VAL:08X})"
        );
    }

    process::resume_threads(threads);
    log_line!("[OK] 修補完成，遊戲執行緒已恢復");

    Ok(())
}

/// 修補 AC（反外掛）偵測 — 繞過 CRC 校驗結果檢查
///
/// 遊戲客戶端有內建的記憶體完整性檢查：
/// 1. CRC 函數（0x4A33B0）遍歷所有精靈的 action table + frame_data，計算 hash
/// 2. AC 函數比較 hash 與初始化時的儲存值
/// 3. 不匹配 → MessageBox("ERROR") + ExitProcess
///
/// 有兩個獨立的 AC 檢查：
/// - 檢查 1：CRC 比較 → jz 跳過（動態 hash vs 全域變數）
/// - 檢查 2：固定 hash 比較 → jz 跳過（hash vs 硬編碼常數 0x5967）
///
/// 修補方式：將 JZ（匹配時跳過偵測）改為 JMP（永遠跳過），單字節修改
pub fn patch_ac_check(h: HANDLE) -> Result<()> {
    log_line!("\n--- AC 偵測繞過 ---");

    // === AC 檢查 1：CRC 比較 ===
    // 原始碼模式：
    //   mov [ebp-4], eax        ; 89 45 FC
    //   mov eax, [ebp-4]        ; 8B 45 FC
    //   cmp eax, [stored_crc]   ; 3B 05 ?? ?? ?? ??
    //   jz  skip_detection      ; 74 3C          ← 改為 EB 3C (jmp)
    //   cmp [gameState], 3      ; 83 3D ?? ?? ?? ?? 03
    //   jne skip_detection      ; 75 33
    let pattern1: Vec<Option<u8>> = vec![
        Some(0x89),
        Some(0x45),
        Some(0xFC),
        Some(0x8B),
        Some(0x45),
        Some(0xFC),
        Some(0x3B),
        Some(0x05),
        None,
        None,
        None,
        None,
        Some(0x74),
        Some(0x3C),
        Some(0x83),
        Some(0x3D),
        None,
        None,
        None,
        None,
        Some(0x03),
        Some(0x75),
        Some(0x33),
    ];

    match memory::scan_pattern(h, 0x401000, 0x830000, &pattern1)? {
        Some(addr) => {
            let jz_addr = addr + 12;
            memory::write_code(h, jz_addr, &[0xEB])?;
            log_line!("[OK] AC 檢查 1（CRC 比較）已繞過 @ 0x{jz_addr:08X}");
        }
        None => {
            log_line!("[警告] 找不到 AC 檢查 1 模式");
        }
    }

    // === AC 檢查 2：固定 hash 比較 ===
    // 原始碼模式：
    //   call hash_func          ; E8 ?? ?? ?? ??
    //   add esp, 8              ; 83 C4 08
    //   cmp eax, 0x5967         ; 3D 67 59 00 00
    //   jz  skip_detection      ; 74 2A          ← 改為 EB 2A (jmp)
    let pattern2: Vec<Option<u8>> = vec![
        Some(0x83),
        Some(0xC4),
        Some(0x08),
        Some(0x3D),
        Some(0x67),
        Some(0x59),
        Some(0x00),
        Some(0x00),
        Some(0x74),
        Some(0x2A),
    ];

    match memory::scan_pattern(h, 0x401000, 0x830000, &pattern2)? {
        Some(addr) => {
            let jz_addr = addr + 8;
            memory::write_code(h, jz_addr, &[0xEB])?;
            log_line!("[OK] AC 檢查 2（固定 hash）已繞過 @ 0x{jz_addr:08X}");
        }
        None => {
            log_line!("[警告] 找不到 AC 檢查 2 模式");
        }
    }

    Ok(())
}

/// 修補 MSVCR90.dll 的 _invoke_watson，防止 CRT 無效參數崩潰
///
/// 遊戲使用 VC++ 2008 CRT，某些函數收到無效參數時會呼叫 _invoke_watson
/// 直接終止進程（exit code 0xC0000417）。
/// 修補方式：將 _invoke_watson 替換為 `ret`（__cdecl，呼叫者清理堆疊）
pub fn patch_crt_watson(h: HANDLE, pid: u32) -> Result<()> {
    log_line!("\n--- CRT 無效參數修補 ---");

    // 等待 MSVCR90.dll 載入
    let mut crt_base = None;
    for i in 0..100 {
        match process::find_module(pid, "msvcr90.dll")? {
            Some(base) => {
                crt_base = Some(base);
                break;
            }
            None => {
                if i == 0 {
                    log_line!("[等待] MSVCR90.dll...");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    let crt_base = match crt_base {
        Some(b) => b,
        None => {
            log_line!("[警告] MSVCR90.dll 未載入，跳過 CRT 修補");
            return Ok(());
        }
    };
    log_line!("[OK] MSVCR90.dll 基址: 0x{crt_base:08X}");

    // 找 _invoke_watson 匯出函數
    let watson_addr = match process::find_export(h, crt_base, "_invoke_watson")? {
        Some(addr) => addr,
        None => {
            log_line!("[警告] 找不到 _invoke_watson，跳過");
            return Ok(());
        }
    };
    log_line!("[OK] _invoke_watson 地址: 0x{watson_addr:08X}");

    // 讀取原始指令確認
    let orig = memory::read_bytes(h, watson_addr, 8)?;
    log_line!(
        "[INFO] 原始碼: {}",
        orig.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    if orig[0] == 0xC3 {
        log_line!("[跳過] _invoke_watson 已被修補");
        return Ok(());
    }

    // 寫入 ret（0xC3）— __cdecl 呼叫者清理堆疊
    memory::write_code(h, watson_addr, &[0xC3])?;
    log_line!("[OK] _invoke_watson → ret（CRT 無效參數不再終止進程）");

    Ok(())
}

/// img 圖檔讀取上限突破
///
/// 遊戲 Surf 資源系統有兩層限制：
/// 1. 資源範圍上限 7000 — push 7000; call alloc_range
/// 2. Surf 陣列邊界 6295 — array[id] 的硬編碼邊界 + malloc 大小
///
/// 注意：push 7000/8000 用於 IE FEATURE_BROWSER_EMULATION 的不可動。
pub fn patch_img_limit(h: HANDLE, new_limit: u32) -> Result<()> {
    let new_limit = new_limit.clamp(MIN_IMG_LIMIT_VALUE, MAX_IMG_LIMIT_VALUE);
    let new_bytes = new_limit.to_le_bytes();
    let new_alloc = (new_limit * 4).to_le_bytes(); // 陣列大小 = limit * 4
    let mut count = 0;

    const OLD_LIMIT: u32 = 6295; // 0x1897
    const OLD_ALLOC: u32 = 6295 * 4; // 25180 = 0x625C
    let old_limit_bytes = OLD_LIMIT.to_le_bytes();
    let old_alloc_bytes = OLD_ALLOC.to_le_bytes();

    // ── 第一層: 資源範圍 push 7000 → push 50000 ──
    // AOB: 6A 00 68 ?? ?? ?? ?? 68 58 1B 00 00 E8
    let pat_range: Vec<Option<u8>> = vec![
        Some(0x6A),
        Some(0x00),
        Some(0x68),
        None,
        None,
        None,
        None,
        Some(0x68),
        Some(0x58),
        Some(0x1B),
        Some(0x00),
        Some(0x00),
        Some(0xE8),
    ];
    let hits_range = memory::scan_pattern_all(h, 0x00401000, 0x00800000, &pat_range)?;
    for &hit in &hits_range {
        memory::write_code(h, hit + 8, &new_bytes)?;
        log_line!(
            "[ImgLimit] 資源範圍 @ 0x{:08X}: push 7000 → {}",
            hit + 7,
            new_limit
        );
        count += 1;
    }

    // ── 第二層: Surf 陣列邊界 6295 → 50000 ──
    // 掃描所有 dword 6295 (0x00001897)，檢查前導 byte 判斷是否為 cmp 指令
    let scan_start: u32 = 0x00401000;
    let scan_end: u32 = 0x00800000;
    let pat_6295: Vec<Option<u8>> = old_limit_bytes.iter().map(|&b| Some(b)).collect();
    let hits_6295 = memory::scan_pattern_all(h, scan_start, scan_end, &pat_6295)?;
    for &hit in &hits_6295 {
        // 讀取前面 6 bytes 判斷指令類型
        // 指令格式:
        //   81 7D/79/7B/7E/7F XX [imm32]  = cmp [reg+disp8], imm32  → 81 在 hit-3
        //   81 BD XX XX XX XX [imm32]      = cmp [ebp+disp32], imm32 → 81 在 hit-6
        let prefix = memory::read_bytes(h, hit.saturating_sub(6), 6)?;
        let plen = prefix.len();
        let is_cmp = if plen >= 3 {
            // 81 XX YY [imm32]: 81 在 hit-3, ModRM 在 hit-2, disp8 在 hit-1
            let opc = prefix[plen - 3]; // hit-3
            let modrm = prefix[plen - 2]; // hit-2
            (opc == 0x81 && matches!(modrm, 0x79 | 0x7B | 0x7D | 0x7E | 0x7F))
            // 81 BD [disp32] [imm32]: 81 在 hit-6, BD 在 hit-5
            || (plen >= 6 && prefix[plen - 6] == 0x81 && prefix[plen - 5] == 0xBD)
        } else {
            false
        };

        if is_cmp {
            memory::write_code(h, hit, &new_bytes)?;
            log_line!(
                "[ImgLimit] 邊界檢查 @ 0x{:08X}: cmp 6295 → {}",
                hit,
                new_limit
            );
            count += 1;
        }
    }

    // ── 陣列分配: push 25180 (6295*4) → push 200000 (50000*4) ──
    // AOB: 68 5C 62 00 00
    let pat_alloc: Vec<Option<u8>> = vec![
        Some(0x68),
        Some(old_alloc_bytes[0]),
        Some(old_alloc_bytes[1]),
        Some(old_alloc_bytes[2]),
        Some(old_alloc_bytes[3]),
    ];
    let hits_alloc = memory::scan_pattern_all(h, scan_start, scan_end, &pat_alloc)?;
    for &hit in &hits_alloc {
        memory::write_code(h, hit + 1, &new_alloc)?;
        log_line!(
            "[ImgLimit] 陣列分配 @ 0x{:08X}: push {} → {}",
            hit,
            OLD_ALLOC,
            new_limit * 4
        );
        count += 1;
    }

    if count == 0 {
        log_line!("[ImgLimit] 警告：未找到任何 img 限制位置");
    } else {
        log_line!(
            "[OK] img 圖檔上限突破: {} 處修補（目標 {}）",
            count,
            new_limit
        );
    }
    Ok(())
}

/// PNG 圖檔上限突破 — 擴大 PngSurfManager 預配陣列
///
/// 遊戲啟動時 SurfManager::Init @ 0x0075A9B0 會做一次性預配:
///   1. malloc 0x1870 bytes (= 1564 * 4) 當指標陣列
///   2. for (i=0; i < 0x61C; i++) array[i] = new PngSurf(i)
///   3. 卸載時 for (i=0; i < 0x61C; i++) delete array[i]  // cleanup loop
///
/// 1564 個 slot 對「使用者後續會大量加 PNG」太少。把 3 個常數同步擴大:
///   • push 0x1870  (array malloc 6256 bytes)         → push (limit*4)
///   • cmp [ebp-0x10], 0x61C  (init loop 上限)         → cmp ..., limit
///   • cmp [ebp-4],    0x61C  (cleanup loop 上限)      → cmp ..., limit
///
/// 因為 init loop 在遊戲 startup 早期跑(CRT _initterm),patch 必須在
/// ResumeThread / 解密門檻通過之後、init loop 執行之前下,跟 ConditionalPatch 同窗口。
pub fn patch_png_limit(h: HANDLE, new_limit: u32) -> Result<()> {
    const OLD_LIMIT: u32 = 0x61C; // 1564 — 寫死在 SurfManager::Init 的 cmp 立即數
    const OLD_ALLOC: u32 = 0x1870; // 6256 = 1564 * 4

    let new_limit_bytes = new_limit.to_le_bytes();
    let new_alloc_bytes = (new_limit.saturating_mul(4)).to_le_bytes();
    let old_limit_bytes = OLD_LIMIT.to_le_bytes();
    let old_alloc_bytes = OLD_ALLOC.to_le_bytes();
    let mut count = 0;

    // ── (1) array malloc: push 0x1870 → push (limit*4) ─────────────────
    // AOB 唯一性:在整個 .text 中只會在 SurfManager::Init 出現
    //   68 70 18 00 00          push 0x1870
    //   E8 ?? ?? ?? ??          call malloc
    //   83 C4 04                add esp, 4
    //   89 45 ??                mov [ebp-X], eax  (X=0x14 in observed binary)
    let pat_alloc: Vec<Option<u8>> = vec![
        Some(0x68),
        Some(old_alloc_bytes[0]),
        Some(old_alloc_bytes[1]),
        Some(old_alloc_bytes[2]),
        Some(old_alloc_bytes[3]),
        Some(0xE8),
        None,
        None,
        None,
        None,
        Some(0x83),
        Some(0xC4),
        Some(0x04),
    ];
    match memory::scan_pattern(h, TEXT_SCAN_START, TEXT_SCAN_END, &pat_alloc)? {
        Some(addr) => {
            memory::write_code(h, addr + 1, &new_alloc_bytes)?;
            log_line!(
                "[PngLimit] array malloc @ 0x{:08X}: push {} → push {}",
                addr,
                OLD_ALLOC,
                new_limit.saturating_mul(4)
            );
            count += 1;
        }
        None => {
            log_line!("[PngLimit] 警告: 找不到 array malloc 模式 (push 0x1870 + call malloc)");
        }
    }

    // ── (2) init loop: cmp [ebp-0x10], 0x61C → cmp ..., new_limit ──────
    // AOB:
    //   89 55 F0                mov [ebp-0x10], edx
    //   81 7D F0 1C 06 00 00    cmp [ebp-0x10], 0x61C   ← 立即數在 +6
    //   7D ??                   jge ...
    let pat_init: Vec<Option<u8>> = vec![
        Some(0x89),
        Some(0x55),
        Some(0xF0),
        Some(0x81),
        Some(0x7D),
        Some(0xF0),
        Some(old_limit_bytes[0]),
        Some(old_limit_bytes[1]),
        Some(old_limit_bytes[2]),
        Some(old_limit_bytes[3]),
        Some(0x7D),
    ];
    match memory::scan_pattern(h, TEXT_SCAN_START, TEXT_SCAN_END, &pat_init)? {
        Some(addr) => {
            memory::write_code(h, addr + 6, &new_limit_bytes)?;
            log_line!(
                "[PngLimit] init loop @ 0x{:08X}: cmp 0x{:X} → 0x{:X}",
                addr + 3,
                OLD_LIMIT,
                new_limit
            );
            count += 1;
        }
        None => {
            log_line!("[PngLimit] 警告: 找不到 init loop 模式");
        }
    }

    // ── (3) cleanup loop: cmp [ebp-4], 0x61C → cmp ..., new_limit ──────
    // AOB:
    //   89 4D FC                mov [ebp-4], ecx
    //   81 7D FC 1C 06 00 00    cmp [ebp-4], 0x61C       ← 立即數在 +6
    //   7D ??                   jge ...
    let pat_cleanup: Vec<Option<u8>> = vec![
        Some(0x89),
        Some(0x4D),
        Some(0xFC),
        Some(0x81),
        Some(0x7D),
        Some(0xFC),
        Some(old_limit_bytes[0]),
        Some(old_limit_bytes[1]),
        Some(old_limit_bytes[2]),
        Some(old_limit_bytes[3]),
        Some(0x7D),
    ];
    match memory::scan_pattern(h, TEXT_SCAN_START, TEXT_SCAN_END, &pat_cleanup)? {
        Some(addr) => {
            memory::write_code(h, addr + 6, &new_limit_bytes)?;
            log_line!(
                "[PngLimit] cleanup loop @ 0x{:08X}: cmp 0x{:X} → 0x{:X}",
                addr + 3,
                OLD_LIMIT,
                new_limit
            );
            count += 1;
        }
        None => {
            log_line!("[PngLimit] 警告: 找不到 cleanup loop 模式");
        }
    }

    if count == 0 {
        log_line!("[PngLimit] 警告：未套用任何 PNG 上限 patch (3/3 模式都失敗)");
    } else if count < 3 {
        log_line!(
            "[PngLimit] 部分套用: {}/3 (其餘已套用過或 pattern 找不到)",
            count
        );
    } else {
        log_line!(
            "[OK] PNG 圖檔上限突破: 3/3 處修補,新上限 {} (記憶體成本約 {} KB)",
            new_limit,
            (new_limit.saturating_mul(36)) / 1024
        );
    }
    Ok(())
}

/// 背包物品上限顯示：180 → 255
///
/// 背包底部顯示 "173 / 180"，其中 180 是寫死在格式字串 `"%d / 180"` 中的 ASCII 文字。
/// 修改為 `"%d / 255"` 讓顯示正確反映伺服器端的 255 上限。
pub fn patch_inventory_limit(h: HANDLE, new_limit: u32) -> Result<()> {
    let new_limit = new_limit.clamp(MIN_INVENTORY_LIMIT_VALUE, MAX_INVENTORY_LIMIT_VALUE);
    // 格式字串 "%d / 180\0" → "%d / 255\0"（靜默修補）
    let pat: Vec<Option<u8>> = vec![
        Some(0x25),
        Some(0x64),
        Some(0x20),
        Some(0x2F),
        Some(0x20),
        Some(0x31),
        Some(0x38),
        Some(0x30),
        Some(0x00),
    ];
    if let Some(addr) = memory::scan_pattern(h, 0x800000, 0xA00000, &pat)? {
        let mut bytes = [0u8; 3];
        let digits = new_limit.to_string();
        bytes[..digits.len()].copy_from_slice(digits.as_bytes());
        memory::write_code(h, addr + 5, &bytes)?;
        log_line!("[InventoryLimit] 顯示上限 180 → {new_limit}");
    }
    Ok(())
}

pub fn patch_move_packet_no_encrypt(h: HANDLE) -> Result<()> {
    let mut patched_count = 0;

    for spec in move_packet_no_encrypt_patch_specs() {
        let pattern: Vec<Option<u8>> = spec.pattern.iter().copied().map(Some).collect();
        let base = memory::scan_pattern(h, TEXT_SCAN_START, TEXT_SCAN_END, &pattern)?
            .with_context(|| format!("move packet no-encrypt pattern not found: {}", spec.name))?;
        let patch_addr = base + spec.patch_offset;
        let current = memory::read_bytes(h, patch_addr, 1)?
            .into_iter()
            .next()
            .context("read move packet no-encrypt patch byte failed")?;

        if current == spec.patched {
            log_line!(
                "[MoveNoEncrypt] {} already patched @ 0x{patch_addr:08X}",
                spec.name
            );
            continue;
        }
        if current != spec.original {
            bail!(
                "move packet no-encrypt target mismatch: {} @ 0x{patch_addr:08X}, current=0x{current:02X}, expected=0x{:02X}",
                spec.name,
                spec.original
            );
        }

        memory::write_code(h, patch_addr, &[spec.patched])?;
        log_line!(
            "[MoveNoEncrypt] {} @ 0x{patch_addr:08X}: {:02X} -> {:02X}",
            spec.name,
            spec.original,
            spec.patched
        );
        patched_count += 1;
    }

    log_line!("[OK] 移動封包不加密 patch 已套用：{} 處", patched_count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_packet_no_encrypt_patches_two_runtime_branches() {
        let specs = move_packet_no_encrypt_patch_specs();

        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].name, "move state obfuscation");
        assert_eq!(specs[0].patch_offset, 7);
        assert_eq!(specs[0].original, 0x74);
        assert_eq!(specs[0].patched, 0xEB);
        assert_eq!(specs[1].name, "move packet encryption");
        assert_eq!(specs[1].patch_offset, 10);
        assert_eq!(specs[1].original, 0x75);
        assert_eq!(specs[1].patched, 0xEB);
    }

    #[test]
    fn classifies_decrypt_marker_values() {
        assert_eq!(
            classify_decrypt_marker_value(DECRYPT_EXPECTED),
            DecryptMarkerState::Ready
        );
        assert_eq!(
            classify_decrypt_marker_value(CONDITIONAL_PATCH_VAL),
            DecryptMarkerState::AlreadyPatched
        );
        assert_eq!(
            classify_decrypt_marker_value(0xD34C608D),
            DecryptMarkerState::NotReady(0xD34C608D)
        );
    }
}
