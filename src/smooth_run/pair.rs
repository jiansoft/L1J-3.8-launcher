//! Phase 4:把 Walk sprites 對映到對應的 Run pair。
//!
//! 配對規則(沿襲 legacy mapping loop):
//!   - 同 sprite 是 Both → 用自身的 RunPair
//!   - 同 gfx_id 群組內有 Run sprite → 取群組內第一個(BTreeMap 確定性順序)
//!   - 模板 B 跨 sprite gap 升等 — classify 已把 high-spr sprite 標 Run,
//!     此處不需特殊處理

use std::collections::{BTreeMap, HashMap};

use super::extract::extract_builtin_lr;
use super::types::{RoleMap, RunPairMap, SpriteFile, SpriteRole};

pub fn pair_walks_to_runs(sf: &SpriteFile, roles: &RoleMap, runs: &RunPairMap) -> RunPairMap {
    let mut walk_to_run: RunPairMap = HashMap::new();

    // 1. Both 角色 sprite 用自身
    for sprite in &sf.sprites {
        if roles.get(&sprite.sid) == Some(&SpriteRole::Both) {
            if let Some(p) = runs.get(&sprite.sid) {
                walk_to_run.insert(sprite.sid, p.clone());
            }
        }
    }

    // 2. 純 Run 角色 sprite(沒有 Walk 動作)也注入 slot 98/99
    //    這些是 dash variant / named RunL/RunR / 32-33 結構的精靈
    for sprite in &sf.sprites {
        if roles.get(&sprite.sid) == Some(&SpriteRole::Run) {
            if let Some(p) = runs.get(&sprite.sid) {
                walk_to_run.insert(sprite.sid, p.clone());
            }
        }
    }

    // 3. 同 gfx_id 群組:Walk → 群組內第一個 Run 的 RunPair
    let mut gfx_groups: BTreeMap<u32, (Vec<u16>, Vec<u16>)> = BTreeMap::new();
    for sprite in &sf.sprites {
        let Some(gid) = sprite.gfx_id else { continue };
        let role = roles.get(&sprite.sid).copied().unwrap_or(SpriteRole::None);
        let entry = gfx_groups.entry(gid).or_default();
        // Both 也視為 walk-side target — legacy 用 sprite_has_walk_actions(可與
        // sprite_has_run_actions 同時存在),Both-role sprite 進到 originals[]。
        match role {
            SpriteRole::Walk | SpriteRole::Both => entry.0.push(sprite.sid),
            SpriteRole::Run => entry.1.push(sprite.sid),
            _ => {}
        }
    }
    for (_gid, (mut walks, mut run_sids)) in gfx_groups {
        walks.sort();
        run_sids.sort();
        // 對應 legacy line 510-535:迴圈所有 run sprite,對 orig 做 per-field or_insert,
        // 讓後到的 run sprite 補齊先前 run sprite 缺的欄位(例如 framerate)。
        for run_sid in &run_sids {
            let Some(p) = runs.get(run_sid) else { continue };
            for &w in &walks {
                walk_to_run
                    .entry(w)
                    .and_modify(|existing| {
                        if existing.runl.is_none() && p.runl.is_some() {
                            existing.runl = p.runl.clone();
                        }
                        if existing.runr.is_none() && p.runr.is_some() {
                            existing.runr = p.runr.clone();
                        }
                        if existing.framerate.is_none() && p.framerate.is_some() {
                            existing.framerate = p.framerate.clone();
                        }
                        if p.source_img_count > existing.source_img_count {
                            existing.source_img_count = p.source_img_count;
                        }
                    })
                    .or_insert_with(|| p.clone());
            }
        }
    }

    // 4. Stage B: pure-Run sprite 的 gfx_id (as u16) 直接指向某個 walk sprite ID。
    //    對應 legacy.rs:539-587。例:`#10641 56=4910` 把 RunL/RunR 注入 #4910;
    //    `#16851 72=16848` 把 framerate 補進 Both-role #16848(內容已由 Path C 注入)。
    //    walk_sids 包含 Walk 與 Both(legacy 用 sprite_has_walk_actions,Both 也算)。
    let walk_sids: HashMap<u16, ()> = sf
        .sprites
        .iter()
        .filter(|s| {
            matches!(
                roles.get(&s.sid),
                Some(&SpriteRole::Walk) | Some(&SpriteRole::Both)
            )
        })
        .map(|s| (s.sid, ()))
        .collect();
    let mut pure_run_sids: Vec<u16> = sf
        .sprites
        .iter()
        .filter(|s| roles.get(&s.sid) == Some(&SpriteRole::Run))
        .map(|s| s.sid)
        .collect();
    pure_run_sids.sort();
    for run_sid in pure_run_sids {
        let Some(run_sprite) = sf.sprites.iter().find(|s| s.sid == run_sid) else {
            continue;
        };
        let Some(gfx_id) = run_sprite.gfx_id else {
            continue;
        };
        if gfx_id > u16::MAX as u32 {
            continue;
        }
        let candidate = gfx_id as u16;
        if candidate == run_sid {
            continue;
        }
        if !walk_sids.contains_key(&candidate) {
            continue;
        }
        let Some(p) = runs.get(&run_sid) else {
            continue;
        };
        walk_to_run
            .entry(candidate)
            .and_modify(|existing| {
                if existing.framerate.is_none() {
                    existing.framerate = p.framerate.clone();
                }
                if existing.runl.is_none() && p.runl.is_some() {
                    existing.runl = p.runl.clone();
                }
                if existing.runr.is_none() && p.runr.is_some() {
                    existing.runr = p.runr.clone();
                }
            })
            .or_insert_with(|| p.clone());
    }

    // 5. Builtin LR fallback(對應 legacy line 656-694)。
    //    僅對尚未在 walk_to_run 內的 sprite 生效;cross-sprite 映射(Stage 3/4)優先。
    //    處理像 #3409 beast tamer rider:#11200(gfx=3409)的內容透過 Stage 4 注入時,
    //    builtin LR 不能覆寫;但 #3409 自身若 Stage 3/4 都沒命中,則需 builtin LR 補位。
    for sprite in &sf.sprites {
        if walk_to_run.contains_key(&sprite.sid) {
            continue;
        }
        if let Some(p) = extract_builtin_lr(sprite) {
            walk_to_run.insert(sprite.sid, p);
        }
    }

    walk_to_run
}

#[cfg(test)]
mod tests {
    use super::super::{classify::classify, extract::extract, parse::parse};
    use super::*;

    #[test]
    fn pair_via_gfx_id_group() {
        let text = "100 0 41210\n#100 32=777 wolf walk\n\t0.walk(1 8,0.0:2 0.1:2 0.2:2 0.3:2 0.4:2 0.5:2 0.6:2 0.7:2)\n#200 40=777 wolf run\n\t0.runL(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n\t4.runR(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n";
        let sf = parse(text);
        let roles = classify(&sf);
        let runs = extract(&sf, &roles);
        let pairs = pair_walks_to_runs(&sf, &roles, &runs);
        let p = pairs.get(&100).expect("walk #100 應拿到 RunPair");
        assert!(p.runl.as_deref().unwrap().starts_with("1 8,8.0:2"));
        assert!(p.runr.as_deref().unwrap().starts_with("1 8,16.0:2"));
    }
}
