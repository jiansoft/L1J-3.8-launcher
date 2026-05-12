//! Phase 2: 對 SpriteFile 中每個 sprite 分類為 [`SpriteRole`]。
//!
//! 分類訊號(沿襲 legacy 主迴圈邏輯):
//! - **walk 訊號**: 有任何 base_action ∈ WALK_ACTIONS 的非 run 動作
//! - **run 訊號**: 任何下列 → 標記為 run sprite
//!     1. dash variant(`dash_variant.is_some()`)
//!     2. 動作名以 "runl" / "runr" 開頭(Path B legacy 名稱)
//!     3. 同 sprite 內結構配對: 有兩個動作 (l, r) 滿足 l.base_action < r.base_action
//!        且 abs(l.first_spr - r.first_spr) == 8 且 l.frame_count==r.frame_count==8
//!        且 l.direction==r.direction==1

use std::collections::{BTreeMap, HashMap};

use super::helpers::is_tianm_interleaved_lr;
use super::types::{RoleMap, Sprite, SpriteFile, SpriteRole};

const WALK_ACTIONS: &[u32] = &[0, 4, 11, 20, 24, 40, 46, 50, 54, 58, 62, 83, 88, 119];

pub fn classify(sf: &SpriteFile) -> RoleMap {
    let mut roles = HashMap::new();
    for sprite in &sf.sprites {
        let role = classify_one(sprite);
        roles.insert(sprite.sid, role);
    }
    // Template B(對應 legacy.rs:395-480):跨 sprite spr_diff>=16 升等。
    // 同 gfx_id 群組內,action 0 first_spr 比 baseline 高 >=16 + 0/4 內容 interleaved
    // 或名稱顯式 run-source → 升等為 Run。
    apply_template_b(&mut roles, sf);
    roles
}

fn classify_one(sprite: &Sprite) -> SpriteRole {
    let has_run = has_run_signal(sprite);
    let has_walk = has_walk_signal(sprite, has_run);
    let role = match (has_walk, has_run) {
        (true, true) => SpriteRole::Both,
        (true, false) => SpriteRole::Walk,
        (false, true) => SpriteRole::Run,
        (false, false) => SpriteRole::None,
    };
    // Legacy 模板 A 升等:Both → Run(action 0/4 結構命中 + 乾淨名 / interleaved)。
    // 對應 legacy.rs:347-348 `sprite_has_walk_actions.remove(&sid)`,
    // 讓此類 sprite 進入 cross-sprite 映射的 runs[] 而非 originals[]。
    if role == SpriteRole::Both && template_a_promotes_to_run(sprite) {
        return SpriteRole::Run;
    }
    role
}

const CROSS_SPRITE_SPR_GAP: u32 = 16;

fn apply_template_b(roles: &mut RoleMap, sf: &SpriteFile) {
    let mut by_gfx: BTreeMap<u32, Vec<(u16, u32)>> = BTreeMap::new();
    for sprite in &sf.sprites {
        let Some(gid) = sprite.gfx_id else { continue };
        let Some(a0) = sprite
            .actions
            .iter()
            .find(|a| a.dash_variant.is_none() && a.base_action == 0)
        else {
            continue;
        };
        by_gfx
            .entry(gid)
            .or_default()
            .push((sprite.sid, a0.first_spr));
    }
    for (_gid, mut entries) in by_gfx {
        if entries.len() < 2 {
            continue;
        }
        entries.sort_by_key(|&(_, spr)| spr);
        let baseline = entries.first().unwrap().1;
        let max_spr = entries.last().unwrap().1;
        if max_spr < baseline + CROSS_SPRITE_SPR_GAP {
            continue;
        }
        for &(sid, spr) in &entries {
            if spr < baseline + CROSS_SPRITE_SPR_GAP {
                continue;
            }
            // 已分類為 Run 略過(template A 已處理,對應 legacy line 428-430)
            if matches!(roles.get(&sid), Some(SpriteRole::Run)) {
                continue;
            }
            let Some(sprite) = sf.sprites.iter().find(|s| s.sid == sid) else {
                continue;
            };
            let Some(a0) = sprite
                .actions
                .iter()
                .find(|a| a.dash_variant.is_none() && a.base_action == 0)
            else {
                continue;
            };
            let a4 = sprite
                .actions
                .iter()
                .find(|a| a.dash_variant.is_none() && a.base_action == 4);
            let promote = if let Some(a4) = a4 {
                // 雙動作:對應 legacy.rs:434 is_cross_sprite_tianm_run_source —
                // interleaved LR 或任一側名稱含 explicit run source(runone/runtwo/runl/runr/walkfast)。
                let interleaved = is_tianm_interleaved_lr(&a0.content, &a4.content);
                let explicit =
                    is_explicit_run_source_name(&a0.name) || is_explicit_run_source_name(&a4.name);
                interleaved || explicit
            } else {
                // 單動作:對應 legacy 模板 B 在僅有 action 0 的 sprite 上仍會 promote
                // (例 keina female_run polymorph 的 walkfastI 單動作 case)。
                // 收緊條件:fc=8 + explicit run name(避免 fc=4 unnamed weapon walk 誤命中)。
                a0.frame_count == 8 && is_explicit_run_source_name(&a0.name)
            };
            if !promote {
                continue;
            }
            roles.insert(sid, SpriteRole::Run);
        }
    }
}

fn is_explicit_run_source_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let trimmed = lower.trim();
    trimmed.starts_with("runl")
        || trimmed.starts_with("runr")
        || trimmed.starts_with("walkfast")
        || matches!(
            trimmed,
            "runone" | "runtwo" | "run_one" | "run_two" | "run one" | "run two"
        )
}

fn template_a_promotes_to_run(sprite: &Sprite) -> bool {
    let Some(a0) = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 0)
    else {
        return false;
    };
    let Some(a4) = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 4)
    else {
        return false;
    };
    if a0.direction != 1 || a4.direction != 1 || a0.frame_count != 8 || a4.frame_count != 8 {
        return false;
    }
    if a0.first_spr.abs_diff(a4.first_spr) != 8 {
        return false;
    }
    // 對應 legacy.rs:354 insert_tianm_run_pair:乾淨名 OR interleaved LR 都接受。
    is_clean_run_source_name(&a0.name)
        || is_clean_run_source_name(&a4.name)
        || is_tianm_interleaved_lr(&a0.content, &a4.content)
}

fn is_clean_run_source_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return true;
    }
    matches!(trimmed, "walk" | "runl" | "runr") || trimmed.starts_with("walkfast")
}

fn has_run_signal(sprite: &Sprite) -> bool {
    // 1. dash variant — 只算 base < 121(對應 legacy line 626 overflow skip)
    if sprite
        .actions
        .iter()
        .any(|a| a.dash_variant.is_some() && a.base_action < 121)
    {
        return true;
    }
    // 2. named runL/runR — 看非 dash variant 動作(legacy 主迴圈在 variant 路徑
    //    會 continue;Path B 對 base 不限,如 #18853 的 137.RunR shield axe 仍命中)
    if sprite.actions.iter().any(|a| {
        a.dash_variant.is_none() && (a.name.starts_with("runl") || a.name.starts_with("runr"))
    }) {
        return true;
    }
    // 3. Path C: 32/33 spr_diff = ±8(position-agnostic — 對應 legacy
    //    `find_run_pair_structurally` 雙向枚舉)
    let a32 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 32);
    let a33 = sprite
        .actions
        .iter()
        .find(|a| a.dash_variant.is_none() && a.base_action == 33);
    if let (Some(l), Some(r)) = (a32, a33) {
        if l.direction == 1 && r.direction == 1 && l.frame_count == 8 && r.frame_count == 8 {
            if l.first_spr.abs_diff(r.first_spr) == 8 {
                return true;
            }
        }
    }
    // 4. 模板 A: 0/4 abs_diff = 8 + (乾淨名 / interleaved)
    if template_a_promotes_to_run(sprite) {
        return true;
    }
    // 注:單純 interleaved 不是 has_run_signal — fc/abs_diff 不嚴格時須由 template B 升等。
    false
}

fn has_walk_signal(sprite: &Sprite, has_run: bool) -> bool {
    for a in &sprite.actions {
        // Dash variant 不是 walk-action 收集對象(legacy line 151 parse_variant_line 後 continue)
        if a.dash_variant.is_some() {
            continue;
        }
        if !WALK_ACTIONS.contains(&a.base_action) {
            continue;
        }
        if has_run && (a.name.starts_with("runl") || a.name.starts_with("runr")) {
            continue;
        }
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse;
    use super::*;

    fn role_of(text: &str, sid: u16) -> SpriteRole {
        let sf = parse(text);
        let roles = classify(&sf);
        *roles.get(&sid).unwrap_or(&SpriteRole::None)
    }

    #[test]
    fn pure_walk_sprite_classified_as_walk() {
        let text = "100 0 41210\n#1 32=1 wolf\n\t0.walk(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n\t4.walk(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n";
        assert_eq!(role_of(text, 1), SpriteRole::Walk);
    }

    #[test]
    fn dash_variant_sprite_classified_as_run() {
        let text = "100 0 41210\n#7 32=7 ranger\n\t0-1.RunL(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n\t0-2.RunR(1 8,24.0:2 24.1:2 24.2:2 24.3:2 24.4:2 24.5:2 24.6:2 24.7:2)\n";
        assert_eq!(role_of(text, 7), SpriteRole::Run);
    }

    #[test]
    fn named_runl_runr_classified_as_run() {
        let text = "100 0 41210\n#42 32=42 keina\n\t0.runL(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n\t4.runR(1 8,24.0:2 24.1:2 24.2:2 24.3:2 24.4:2 24.5:2 24.6:2 24.7:2)\n";
        assert_eq!(role_of(text, 42), SpriteRole::Run);
    }

    #[test]
    fn structural_pair_classified_as_run_even_without_names() {
        let text = "100 0 41210\n#99 32=99 stripped\n\t32.(1 8,100.0:2 100.1:2 100.2:2 100.3:2 100.4:2 100.5:2 100.6:2 100.7:2)\n\t33.(1 8,108.0:2 108.1:2 108.2:2 108.3:2 108.4:2 108.5:2 108.6:2 108.7:2)\n";
        assert_eq!(role_of(text, 99), SpriteRole::Run);
    }

    #[test]
    fn sprite_with_both_walk_and_run_classified_as_both() {
        let text = "100 0 41210\n#5 32=5 wolf_with_run\n\t0.walk(1 8,0.0:2 0.1:2 0.2:2 0.3:2 0.4:2 0.5:2 0.6:2 0.7:2)\n\t11.runL(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n";
        assert_eq!(role_of(text, 5), SpriteRole::Both);
    }

    #[test]
    fn matches_legacy_test_tianm_action_driven_walk_run_polymorph_pair() {
        let input = "300 0 41210\n\
#16140 72=5373 keina walk polymorph\n\
\t0.walk(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n\
\t4.walk onehandsword(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n\
#16141 72=5373 keina run polymorph\n\
\t0.RunL(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n\
\t4.RunR(1 8,24.0:2 24.1:2 24.2:2 24.3:2 24.4:2 24.5:2 24.6:2 24.7:2)\n";
        let sf = parse(input);
        let roles = classify(&sf);
        assert_eq!(roles[&16140], SpriteRole::Walk);
        assert_eq!(roles[&16141], SpriteRole::Run);
    }
}
