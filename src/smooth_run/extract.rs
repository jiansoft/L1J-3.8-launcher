//! Phase 3:對 Run / Both 角色 sprite 萃取 (RunL_content, RunR_content)。
//!
//! 萃取慣例優先序(對應 legacy 5 條偵測路徑):
//!   1. **Dash variant**:`dash_variant=Some(1)` → RunL,`Some(2)` → RunR
//!   2. **Named (Path B)**:name.starts_with("runl") → RunL,starts_with("runr") → RunR
//!   3. **32/33 結構(Path C)**:action 32 → RunL,action 33 → RunR(strict +8 spr_diff)
//!   4. **0/4 結構(模板 A)**:action 0 → RunL,action 4 → RunR(abs_diff=8 + fc=8)
//!
//! 命中第一條後即停。多 RunL/RunR 候選時取第一見(legacy or_insert 語義)。

use std::collections::HashMap;

use super::helpers::is_tianm_interleaved_lr;
use super::types::{Action, RoleMap, RunPair, RunPairMap, Sprite, SpriteFile, SpriteRole};

pub fn extract(sf: &SpriteFile, roles: &RoleMap) -> RunPairMap {
    let mut runs = HashMap::new();
    for sprite in &sf.sprites {
        // 對所有角色都跑 extract:Walk 也可能透過 builtin LR(0/4 walkfast/run 名)拿到 self RunPair。
        // 對應 legacy line 656-694:builtin LR 不需 sprite_has_run_actions 觸發。
        let role = roles.get(&sprite.sid).copied().unwrap_or(SpriteRole::None);
        if let Some(mut pair) = extract_one(sprite, role) {
            // Template A framerate fallback:對應 legacy line 363-368。
            // 若 sprite 滿足 template A 條件(fc=8 + abs_diff=8 + clean name)
            // 但 pair.framerate 為 None(因 extract_dash 等先 match 而沒帶 framerate),
            // 從 action 0/4 framerate_at_parse 補位 — legacy Template A 在
            // Stage A propagation 中靠這個讓 framerate 流到 gfx 群組內 walk sprite。
            if pair.framerate.is_none() {
                if let Some(fr) = template_a_framerate_fallback(sprite) {
                    pair.framerate = Some(fr);
                }
            }
            runs.insert(sprite.sid, pair);
        }
    }
    runs
}

fn template_a_framerate_fallback(sprite: &Sprite) -> Option<String> {
    let a0 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 0)?;
    let a4 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 4)?;
    if a0.direction != 1 || a4.direction != 1 || a0.frame_count != 8 || a4.frame_count != 8 {
        return None;
    }
    if a0.first_spr.abs_diff(a4.first_spr) != 8 {
        return None;
    }
    if !is_clean_run_source_name(&a0.name) && !is_clean_run_source_name(&a4.name) {
        return None;
    }
    a0.framerate_at_parse
        .clone()
        .or_else(|| a4.framerate_at_parse.clone())
}

fn extract_one(sprite: &Sprite, role: SpriteRole) -> Option<RunPair> {
    if let Some(pair) = extract_dash(sprite) {
        return Some(pair);
    }
    if let Some(pair) = extract_named(sprite) {
        return Some(pair);
    }
    if let Some(pair) = extract_3233_strict(sprite) {
        return Some(pair);
    }
    if let Some(pair) = extract_04_abs(sprite, role) {
        return Some(pair);
    }
    None
}

/// Builtin LR — 對應 legacy line 656-694:action 0/4 名稱含 walkfast/run 前綴 + s0!=s4 + 同 fc。
/// 由 pair.rs Stage 5 在 cross-sprite mapping 之後呼叫,僅對未配對的 sprite 補位。
pub(super) fn extract_builtin_lr(sprite: &Sprite) -> Option<RunPair> {
    let a0 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 0)?;
    let a4 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 4)?;
    if !is_lr_walk_name(&a0.name) {
        return None;
    }
    if a0.first_spr == a4.first_spr {
        return None;
    }
    if a0.frame_count != a4.frame_count {
        return None;
    }
    let framerate = a0
        .framerate_at_parse
        .clone()
        .or_else(|| a4.framerate_at_parse.clone());
    Some(RunPair {
        runl: Some(a0.content.clone()),
        runr: Some(a4.content.clone()),
        framerate,
        source_img_count: sprite.img_count,
    })
}

fn is_lr_walk_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("walkfast") || lower.starts_with("run")
}

fn extract_dash(sprite: &Sprite) -> Option<RunPair> {
    // legacy 把 v1_content / v2_content 各自 or_insert,單側存在也 OK(line 633-642)。
    // 但 base_action >= 121 的 dash variant 會在 legacy line 626-630 整對被 skip
    // (overflow action,3.8 client 不支援);pipeline 同步排除。
    const MAX_ACTION_SLOT: u32 = 121;
    let l = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant == Some(1) && a.base_action < MAX_ACTION_SLOT);
    let r = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant == Some(2) && a.base_action < MAX_ACTION_SLOT);
    if l.is_none() && r.is_none() {
        return None;
    }
    // 對應 legacy line 633-643:variant_map 迭代只 populate runl_data/runr_data,
    // NOT run_framerate_data。dash variant 不帶 framerate;framerate 由 template
    // A/B 或 Path B 在主迴圈外另外計算(template_a_framerate_fallback 補位)。
    Some(RunPair {
        runl: l.map(|a| a.content.clone()),
        runr: r.map(|a| a.content.clone()),
        framerate: None,
        source_img_count: sprite.img_count,
    })
}

fn extract_named(sprite: &Sprite) -> Option<RunPair> {
    // 對應 legacy line 232-249 Path B:看非 dash variant 動作行(legacy 主迴圈
    // 在 variant 路徑會 continue),且 base 不限 — 例如 sprite #18853 的
    // `137.RunR shield axe` action_num=137 仍會被 Path B 收進 tianm_runr;
    // overflow lines (action >= 121) 在 emit 時才被 skip。
    let l = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.name.starts_with("runl"));
    let r = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.name.starts_with("runr"));
    if l.is_none() && r.is_none() {
        return None;
    }
    // legacy 主迴圈在每次 runl/runr 名稱命中時做 `tianm_run_framerate.entry(sid).or_insert(cur_framerate)`,
    // 取首見;對應 pipeline 取 l 的 framerate_at_parse,fallback r。
    let framerate = l
        .and_then(action_runl_runr_framerate)
        .or_else(|| r.and_then(action_runl_runr_framerate));
    Some(RunPair {
        runl: l.map(|a| a.content.clone()),
        runr: r.map(|a| a.content.clone()),
        framerate,
        source_img_count: sprite.img_count,
    })
}

/// 對應 legacy 主迴圈在 runl/runr 命中時取的 framerate(僅看名稱命中那 action 的
/// framerate_at_parse;若該 action 名稱不是 runl/runr 則 None)。
fn action_runl_runr_framerate(a: &Action) -> Option<String> {
    if a.name.starts_with("runl") || a.name.starts_with("runr") {
        a.framerate_at_parse.clone()
    } else {
        None
    }
}

fn extract_3233_strict(sprite: &Sprite) -> Option<RunPair> {
    // Position-agnostic:對應 legacy `find_run_pair_structurally`,允許 32/33 角色互換,
    // 取較低 first_spr 那個當 L、較高 first_spr 那個當 R(spr_diff=+8 strict)。
    // 只看非 dash variant 的動作行(legacy Path C 在主迴圈外,只看 action_map 收集
    // 的非 variant 動作)。
    let a32 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 32)?;
    let a33 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 33)?;
    if a32.direction != 1 || a33.direction != 1 || a32.frame_count != 8 || a33.frame_count != 8 {
        return None;
    }
    let (l, r) = if a33.first_spr.checked_sub(a32.first_spr) == Some(8) {
        (a32, a33)
    } else if a32.first_spr.checked_sub(a33.first_spr) == Some(8) {
        (a33, a32)
    } else {
        return None;
    };
    // Path C 自身不注入 110.framerate;但若同 sprite 模板 A 也命中(0/4 spr 差 8 + 乾淨名),
    // legacy 在那條 path 會用 walk_action_framerate[(sid, 0/4)] populate。
    let framerate = template_a_walk_framerate(sprite);
    Some(RunPair {
        runl: Some(l.content.clone()),
        runr: Some(r.content.clone()),
        framerate,
        source_img_count: sprite.img_count,
    })
}

fn extract_04_abs(sprite: &Sprite, role: SpriteRole) -> Option<RunPair> {
    // 只看非 dash variant 動作:dash variant 已由 extract_dash 處理,這裡對應 legacy
    // Template A(line 320-393)和 Template B(line 395-480)均看 walk_action_content
    // (僅收集 action_num 路徑,非 variant 路徑)。
    let l = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 0);
    let r = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 4);
    if l.is_none() && r.is_none() {
        return None;
    }
    // 單動作 case(對應 legacy 模板 B 單動作 promote):僅 a0 或僅 a4 存在,
    // role 必須為 Run(已由 classify 模板 B 升等)+ fc=8 + 乾淨名。
    if l.is_some() ^ r.is_some() {
        if role != SpriteRole::Run {
            return None;
        }
        let single = l.or(r).unwrap();
        if single.direction != 1 || single.frame_count != 8 {
            return None;
        }
        if !is_clean_run_source_name(&single.name) {
            return None;
        }
        let framerate = single.framerate_at_parse.clone();
        return Some(RunPair {
            runl: l.map(|a| a.content.clone()),
            runr: r.map(|a| a.content.clone()),
            framerate,
            source_img_count: sprite.img_count,
        });
    }
    let l = l.unwrap();
    let r = r.unwrap();
    let framerate = l
        .framerate_at_parse
        .clone()
        .or_else(|| r.framerate_at_parse.clone());
    // Interleaved LR(對應 legacy insert_tianm_run_pair line 1048-1056):
    // action 0/4 frames 行列交錯時直接雙側 populate,不查 clean name guard。
    // 僅在 sprite 已被 classify 為 Run 時接受 — template A(fc=8 + abs_diff=8)
    // 或 template B(同 gfx 群組 spr_diff>=16)其中之一已驗證,避免無 gfx 的
    // fc=4 sprite 過度命中(如 #4569 shadow of flame)。
    if role == SpriteRole::Run && is_tianm_interleaved_lr(&l.content, &r.content) {
        return Some(RunPair {
            runl: Some(l.content.clone()),
            runr: Some(r.content.clone()),
            framerate,
            source_img_count: sprite.img_count,
        });
    }
    // 模板 A:strict fc=8 + dir=1 + abs_diff=8 + 乾淨名
    if l.direction != 1 || r.direction != 1 || l.frame_count != 8 || r.frame_count != 8 {
        return None;
    }
    if l.first_spr.abs_diff(r.first_spr) != 8 {
        return None;
    }
    let clean_l = is_clean_run_source_name(&l.name);
    let clean_r = is_clean_run_source_name(&r.name);
    if !clean_l && !clean_r {
        return None;
    }
    // Asymmetric:乾淨那側才寫入 slot 98/99(對應 legacy `insert_tianm_run_pair` line 1064-1073)。
    Some(RunPair {
        runl: if clean_l {
            Some(l.content.clone())
        } else {
            None
        },
        runr: if clean_r {
            Some(r.content.clone())
        } else {
            None
        },
        framerate,
        source_img_count: sprite.img_count,
    })
}

/// 模板 A walk framerate fallback —— 用於 Path C 同 sprite 也命中模板 A 時。
/// 對應 legacy 模板 A 區塊內的 walk_action_framerate 查詢。
fn template_a_walk_framerate(sprite: &Sprite) -> Option<String> {
    if !template_a_eligible(sprite) {
        return None;
    }
    let a0 = sprite.actions.iter().find(|a| a.base_action == 0);
    let a4 = sprite.actions.iter().find(|a| a.base_action == 4);
    a0.and_then(|a| a.framerate_at_parse.clone())
        .or_else(|| a4.and_then(|a| a.framerate_at_parse.clone()))
}

/// 模板 A(action 0/4,direction=1,frame_count=8,abs_diff=8,乾淨名)— 對應 legacy
/// `is_clean_tianm_run_source_name` 的命中判斷。命中即視為「sprite 本身有 110.framerate
/// 注入資格」。
fn template_a_eligible(sprite: &Sprite) -> bool {
    let Some(a0) = sprite.actions.iter().find(|a| a.base_action == 0) else {
        return false;
    };
    let Some(a4) = sprite.actions.iter().find(|a| a.base_action == 4) else {
        return false;
    };
    if a0.direction != 1 || a4.direction != 1 || a0.frame_count != 8 || a4.frame_count != 8 {
        return false;
    }
    if a0.first_spr.abs_diff(a4.first_spr) != 8 {
        return false;
    }
    is_clean_run_source_name(&a0.name) || is_clean_run_source_name(&a4.name)
}

/// 對應 legacy `is_clean_tianm_run_source_name`:接受空字串、純 walk/runl/runr、
/// walkfast 前綴。拒絕帶武器後綴(避免持劍 bug)。
fn is_clean_run_source_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return true;
    }
    matches!(trimmed, "walk" | "runl" | "runr") || trimmed.starts_with("walkfast")
}

#[cfg(test)]
mod tests {
    use super::super::classify::classify;
    use super::super::parse::parse;
    use super::*;

    fn extract_pair(text: &str, sid: u16) -> Option<RunPair> {
        let sf = parse(text);
        let roles = classify(&sf);
        let pairs = extract(&sf, &roles);
        pairs.get(&sid).cloned()
    }

    #[test]
    fn extract_dash_variant() {
        let text = "100 0 41210\n#7 32=7 ranger\n\t0-1.RunL(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n\t0-2.RunR(1 8,24.0:2 24.1:2 24.2:2 24.3:2 24.4:2 24.5:2 24.6:2 24.7:2)\n";
        let p = extract_pair(text, 7).expect("dash variant 應命中");
        assert!(p.runl.as_deref().unwrap().starts_with("1 8,16.0:2"));
        assert!(p.runr.as_deref().unwrap().starts_with("1 8,24.0:2"));
    }

    #[test]
    fn extract_named_runl_runr() {
        let text = "100 0 41210\n#42 32=42 keina\n\t0.runL(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n\t4.runR(1 8,24.0:2 24.1:2 24.2:2 24.3:2 24.4:2 24.5:2 24.6:2 24.7:2)\n";
        let p = extract_pair(text, 42).expect("named 應命中");
        assert!(p.runl.as_deref().unwrap().starts_with("1 8,16.0:2"));
        assert!(p.runr.as_deref().unwrap().starts_with("1 8,24.0:2"));
    }

    #[test]
    fn extract_32_33_structural_strict_plus_8() {
        let text = "100 0 41210\n#99 32=99 stripped\n\t32.(1 8,100.0:2 100.1:2 100.2:2 100.3:2 100.4:2 100.5:2 100.6:2 100.7:2)\n\t33.(1 8,108.0:2 108.1:2 108.2:2 108.3:2 108.4:2 108.5:2 108.6:2 108.7:2)\n";
        let p = extract_pair(text, 99).expect("Path C 應命中");
        assert!(p.runl.as_deref().unwrap().starts_with("1 8,100.0:2"));
        assert!(p.runr.as_deref().unwrap().starts_with("1 8,108.0:2"));
    }

    #[test]
    fn extract_0_4_template_a_abs_diff() {
        let text = "100 0 41210\n#88 32=88 reverse\n\t0.(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n\t4.(1 8,0.0:2 0.1:2 0.2:2 0.3:2 0.4:2 0.5:2 0.6:2 0.7:2)\n";
        let p = extract_pair(text, 88).expect("模板 A 應命中");
        assert!(p.runl.as_deref().unwrap().starts_with("1 8,8.0:2"));
        assert!(p.runr.as_deref().unwrap().starts_with("1 8,0.0:2"));
    }

    #[test]
    fn extract_returns_none_for_walk_only_sprite() {
        let text = "100 0 41210\n#1 32=1 wolf\n\t0.walk(1 4,0.0:2 0.1:2 0.2:2 0.3:2)\n";
        assert!(extract_pair(text, 1).is_none());
    }

    #[test]
    fn extract_uses_weapon_suffixed_runr_when_no_clean_alternative() {
        let text = "100 0 41210\n#200 32=999 LMS knight male_run\n\t0.runL(1 8,344.0:1 344.1:1 344.2:1 344.3:1 344.4:1 344.5:1 344.6:1 344.7:1)\n\t4.runR onehandsword(1 8,352.0:1 352.1:1 352.2:1 352.3:1 352.4:1 352.5:1 352.6:1 352.7:1)\n";
        let p = extract_pair(text, 200).expect("應命中(weapon-suffixed runR 是唯一 RunR)");
        assert!(p.runl.as_deref().unwrap().starts_with("1 8,344.0:1"));
        assert!(p.runr.as_deref().unwrap().starts_with("1 8,352.0:1"));
    }
}
