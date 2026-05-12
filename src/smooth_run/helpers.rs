//! 順跑（smooth run）預處理模組 — 直接替換走路動作幀資料
//!
//! 同時支援兩種變身檔格式（內容驅動，無需門檻偵測）：
//!
//! **天r 格式**（dash 子動作）：
//!   `X-1.RunL(...)` / `X-2.RunR(...)` → 移除變體行，幀資料存入 slot 98/99
//!
//! **天m 格式**（獨立跑步精靈條目，動作驅動偵測）：
//!   - 條目內含 `RunL` / `RunR` 動作 → 視為 run 來源（**不依賴名稱**）
//!   - 條目內含走路動作（0/4/...）→ 視為 walk 目標
//!   - 兩者透過共用 gfx_id 或直接精靈 ID 引用自動映射
//!
//! **spr offset 模板**（補強動作驅動,處理動作名被砍光的 case）：
//!   - 模板 A:同 sprite 內 action 0/4 第一個 spr 相差 8 → run sprite
//!   - 模板 B:同 gfx_id 群組內,spr(0) 高出 baseline >=16 → run sprite
//!
//! 兩條路徑始終啟用、互不干擾，可處理混合格式
//!
//! 轉換策略（保留原始 + 額外 slot）：
//! - 原始走路動作（0, 4, 11, 20, 24, 40, 46, 50, 54, 58, 62, 83）→ **保留不動**
//! - slot 98 → RunL 幀資料（加速時左腳）
//! - slot 99 → RunR 幀資料（加速時右腳）
//! - 天r: 所有 -1/-2 變體行移除（parser 不認識）
//! - 天m: RunL/RunR 行保留（作為 _run 精靈的走路動作）
//! - 動作編號 >= 121 → 過濾（3.8 客戶端支援到 120）
//!
//! 原理：
//!   runtime hook 根據加速 buff 決定使用哪個 slot：
//!   無 buff → 原始走路動畫（slot 0/4/...）
//!   有 buff + toggle=0 → RunL（slot 98）
//!   有 buff + toggle=1 → RunR（slot 99）

use std::collections::HashSet;

/// 預處理結果統計
#[allow(dead_code)]
pub struct VariantInfo {
    pub walk_sprites: Vec<u16>,
    pub run_sprites: Vec<u16>,
    pub run_actions: HashSet<u8>,
    pub walk_count: usize,
    pub run_count: usize,
    pub converted_count: usize,
}

// ─── 轉換核心 ───

/// 提取括號內完整內容（含方向數+幀數+幀資料）
///
/// "0-1.RunL(1 8,64.0:2 64.1:2<479 ...)" → "1 8,64.0:2 64.1:2<479 ..."
pub(super) fn extract_frame_content(line: &str) -> &str {
    let trimmed = line.trim_start();
    let Some(paren_start) = trimmed.find('(') else {
        return "";
    };
    let Some(paren_end) = trimmed.rfind(')') else {
        return "";
    };
    if paren_end <= paren_start + 1 {
        return "";
    }
    &trimmed[paren_start + 1..paren_end]
}

// ─── 解析輔助 ───

pub(super) fn parse_sprite_id(trimmed: &str) -> Option<u16> {
    let after_hash = trimmed.strip_prefix('#')?;
    let num_str: String = after_hash
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if num_str.is_empty() {
        return None;
    }
    num_str.parse().ok()
}

pub(super) fn parse_variant_line<'a>(trimmed: &'a str) -> Option<(&'a str, u32, u32, &'a str)> {
    let mut num_end = 0;
    for (i, c) in trimmed.char_indices() {
        if c.is_ascii_digit() {
            num_end = i + 1;
        } else {
            break;
        }
    }
    if num_end == 0 {
        return None;
    }
    let base: u32 = trimmed[..num_end].parse().ok()?;
    let after_num = &trimmed[num_end..];
    if !after_num.starts_with('-') {
        return None;
    }
    let after_dash = &after_num[1..];
    let mut var_end = 0;
    for (i, c) in after_dash.char_indices() {
        if c.is_ascii_digit() {
            var_end = i + 1;
        } else {
            break;
        }
    }
    if var_end == 0 {
        return None;
    }
    let variant: u32 = after_dash[..var_end].parse().ok()?;
    let after_var = &after_dash[var_end..];
    if !after_var.starts_with('.') {
        return None;
    }
    Some(("", base, variant, &after_var[1..]))
}

pub(super) fn parse_action_number(trimmed: &str) -> Option<u32> {
    let mut num_end = 0;
    for (i, c) in trimmed.char_indices() {
        if c.is_ascii_digit() {
            num_end = i + c.len_utf8();
        } else {
            break;
        }
    }
    if num_end == 0 {
        return None;
    }
    if !trimmed[num_end..].starts_with('.') {
        return None;
    }
    trimmed[..num_end].parse().ok()
}

/// 從幀資料內容提取幀數（"1 8,88.0:3 ..." → 8）
pub(super) fn extract_frame_count(content: &str) -> Option<u32> {
    let comma_pos = content.find(',')?;
    let before_comma = &content[..comma_pos];
    let fc_str = before_comma.split_whitespace().last()?;
    fc_str.parse().ok()
}

/// 從動作行提取動作名稱（"0.walkfastI(...)" → "walkfastI"）
pub(super) fn extract_action_name<'a>(trimmed: &'a str) -> &'a str {
    // 找到 "N." 之後、"(" 之前的部分
    let dot_pos = match trimmed.find('.') {
        Some(p) => p,
        None => return "",
    };
    let after_dot = &trimmed[dot_pos + 1..];
    let paren_pos = after_dot.find('(').unwrap_or(after_dot.len());
    after_dot[..paren_pos].trim()
}

/// 天m 格式：解析 header 行的圖片數、圖檔 ID、名稱
///
/// `#14798 360=3213 LMS knight male_run` → (360, Some(3213), "LMS knight male_run")
/// `#14491 448 Dragon_slayer_run` → (448, None, "Dragon_slayer_run")
pub(super) fn parse_header_ext(trimmed: &str) -> Option<(u32, Option<u32>, &str)> {
    let after_hash = trimmed.strip_prefix('#')?;
    // 跳過精靈 ID 數字
    let id_end = after_hash.find(|c: char| !c.is_ascii_digit())?;
    let rest = after_hash[id_end..].trim_start();
    if rest.is_empty() {
        return None;
    }

    // 解析圖片數（第一個數字）
    let num_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if num_end == 0 {
        return None;
    }
    let img_count: u32 = rest[..num_end].parse().ok()?;
    let after_count = &rest[num_end..];

    // 檢查是否有 =GFX_ID
    if let Some(stripped) = after_count.strip_prefix('=') {
        let gfx_end = stripped
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(stripped.len());
        if gfx_end > 0 {
            let gfx_id: u32 = stripped[..gfx_end].parse().ok()?;
            let name = stripped[gfx_end..].trim();
            return Some((img_count, Some(gfx_id), name));
        }
    }

    // 無 =GFX_ID
    let name = after_count.trim();
    Some((img_count, None, name))
}

pub(super) fn is_tianm_interleaved_lr(content_0: &str, content_4: &str) -> bool {
    let Some((header_0, frames_0)) = split_frame_content(content_0) else {
        return false;
    };
    let Some((header_4, frames_4)) = split_frame_content(content_4) else {
        return false;
    };
    if header_0.trim() != header_4.trim() || frames_0.len() != frames_4.len() || frames_0.len() < 2
    {
        return false;
    }

    let Some(row_0_first) = frame_row(frames_0[0]) else {
        return false;
    };
    let Some(row_4_first) = frame_row(frames_4[0]) else {
        return false;
    };
    if row_0_first == row_4_first {
        return false;
    }

    for i in 1..frames_0.len() {
        if frame_row(frames_0[i]) != Some(row_4_first)
            || frame_row(frames_4[i]) != Some(row_0_first)
        {
            return false;
        }
    }

    true
}

pub(super) fn split_frame_content(content: &str) -> Option<(&str, Vec<&str>)> {
    let (header, frame_text) = content.split_once(',')?;
    let frames: Vec<&str> = frame_text.split_whitespace().collect();
    if frames.is_empty() {
        return None;
    }
    Some((header, frames))
}

fn frame_row(frame: &str) -> Option<u32> {
    let dot = frame.find('.')?;
    frame[..dot].parse().ok()
}

/// 天m 格式：更新 header 行的圖片數
///
/// `#61 320=3213 knight` + old=320, new=360 → `#61 360=3213 knight`
pub(super) fn update_header_img_count(line: &str, old_count: u32, new_count: u32) -> String {
    let old_str = old_count.to_string();
    let new_str = new_count.to_string();
    // 找到 header 行中的圖片數位置（# + ID + 空格 + 圖片數）
    if let Some(pos) = line.find(&old_str) {
        let mut result = String::with_capacity(line.len());
        result.push_str(&line[..pos]);
        result.push_str(&new_str);
        result.push_str(&line[pos + old_str.len()..]);
        result
    } else {
        line.to_string()
    }
}

/// 從單行格式中提取指定動作的幀內容 + 名稱（括號配對安全）
///
/// 例如: "#1353 24 great dane 0.run_one(1 4,...) 4.run_two(1 4,...) ..."
/// extract_inline_action_with_name(line, 0) → Some(("1 4,...", "run_one"))
pub(super) fn extract_inline_action_with_name<'a>(
    line: &'a str,
    target_action: u32,
) -> Option<(&'a str, &'a str)> {
    let bytes = line.as_bytes();
    let mut depth: i32 = 0;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'(' => {
                depth += 1;
                i += 1;
                continue;
            }
            b')' => {
                depth -= 1;
                i += 1;
                continue;
            }
            _ => {}
        }
        if depth != 0 {
            i += 1;
            continue;
        }

        // 深度 0：檢查 "N." 模式（前方必須是空白或 ')'）
        if bytes[i].is_ascii_digit() {
            let at_boundary = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b')');
            if at_boundary {
                let num_start = i;
                let mut num_end = i;
                while num_end < bytes.len() && bytes[num_end].is_ascii_digit() {
                    num_end += 1;
                }
                if num_end < bytes.len() && bytes[num_end] == b'.' {
                    if let Ok(action_num) = line[num_start..num_end].parse::<u32>() {
                        if action_num == target_action {
                            if let Some(paren_off) = line[num_end..].find('(') {
                                let paren_abs = num_end + paren_off;
                                // 動作名稱 = dot 之後到 '(' 之前
                                let name = line[num_end + 1..paren_abs].trim();
                                if let Some(close_off) = line[paren_abs + 1..].find(')') {
                                    return Some((
                                        &line[paren_abs + 1..paren_abs + 1 + close_off],
                                        name,
                                    ));
                                }
                            }
                        }
                    }
                }
                i = num_end;
                continue;
            }
        }
        i += 1;
    }
    None
}

/// 從 frame content（"1 8,200.0:2 ..."）取第一張 spr
///
/// 與 `extract_first_spr` 不同:後者吃整行 line(含 `\t32.(...)` 前綴),
/// 此函式吃已剝出來的 content("<dir> <frames>,<spr>.<row>:...")
pub(super) fn first_spr_from_content(content: &str) -> Option<u32> {
    let comma_pos = content.find(',')?;
    let after = content[comma_pos + 1..].trim_start();
    let dot_pos = after.find('.')?;
    after[..dot_pos].trim().parse().ok()
}
