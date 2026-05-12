//! Phase 5:把 SpriteFile + Walk→RunPair 映射 emit 為輸出文字。
//!
//! 流程:
//!   - 逐行 emit `raw_lines`
//!   - dash variant 行 → skip(被結構化的 slot 98/99 取代)
//!   - 動作號 ≥121 → skip(3.8 client 不支援)
//!   - sprite 結束位置 → 為有 RunPair 的 walk sprite 注入 slot 98/99
//!   - 若 source_img_count > sprite.img_count → 改寫 sprite header

use std::collections::HashMap;

use super::helpers::{parse_action_number, update_header_img_count, VariantInfo};
use super::types::{RunPairMap, SpriteFile};

pub fn emit(sf: &SpriteFile, walk_to_run: &RunPairMap) -> (String, VariantInfo) {
    let mut output = String::with_capacity(sf.raw_lines.iter().map(|l| l.len() + 1).sum());
    let info = VariantInfo {
        walk_sprites: Vec::new(),
        run_sprites: Vec::new(),
        run_actions: Default::default(),
        walk_count: 0,
        run_count: 0,
        converted_count: walk_to_run.len(),
    };

    // 建立 sid → &Sprite map(O(1) 查找,避免 O(N×S) 線性掃描 — 對 12K sprites
    // × 250K raw lines 的真實檔案會差 5×)
    let sprite_by_sid: HashMap<u16, &super::types::Sprite> =
        sf.sprites.iter().map(|s| (s.sid, s)).collect();

    // 建立 line_idx → sid mapping(確定每行屬於哪個 sprite)
    let mut sprite_starts: Vec<(usize, u16)> = sf
        .sprites
        .iter()
        .map(|s| (s.header_line_idx, s.sid))
        .collect();
    sprite_starts.sort();
    let mut sid_at_idx: Vec<Option<u16>> = vec![None; sf.raw_lines.len()];
    let mut sprite_iter = sprite_starts.into_iter().peekable();
    let mut current: Option<u16> = None;
    for idx in 0..sf.raw_lines.len() {
        while let Some(&(start_idx, sid)) = sprite_iter.peek() {
            if start_idx == idx {
                current = Some(sid);
                sprite_iter.next();
            } else {
                break;
            }
        }
        sid_at_idx[idx] = current;
    }

    // 預先建立 sid → set<dash_line_idx>(O(1) 查 dash variant 行)
    let mut dash_lines: HashMap<u16, std::collections::HashSet<usize>> = HashMap::new();
    for sprite in &sf.sprites {
        let mut set = std::collections::HashSet::new();
        for action in &sprite.actions {
            if action.dash_variant.is_some() {
                set.insert(action.line_idx);
            }
        }
        if !set.is_empty() {
            dash_lines.insert(sprite.sid, set);
        }
    }

    // 確認哪些行會被跳過(dash variant 或 action >= 121)
    let mut will_skip_line: Vec<bool> = vec![false; sf.raw_lines.len()];
    for (idx, line) in sf.raw_lines.iter().enumerate() {
        if let Some(sid) = sid_at_idx[idx] {
            if dash_lines.get(&sid).is_some_and(|s| s.contains(&idx)) {
                will_skip_line[idx] = true;
                continue;
            }
            let trimmed = line.trim_start();
            if let Some(action_num) = parse_action_number(trimmed) {
                if action_num >= 121 {
                    will_skip_line[idx] = true;
                }
            }
        }
    }

    // 計算每個 sprite 的最後非跳過行(用於注入 slot 98/99)
    let mut last_line_per_sprite: HashMap<u16, usize> = HashMap::new();
    for sprite in &sf.sprites {
        let mut last = sprite.header_line_idx;
        for line_idx in (sprite.header_line_idx + 1)..sf.raw_lines.len() {
            if sid_at_idx[line_idx] != Some(sprite.sid) {
                break;
            }
            if !will_skip_line[line_idx] {
                last = line_idx;
            }
        }
        last_line_per_sprite.insert(sprite.sid, last);
    }

    for (idx, line) in sf.raw_lines.iter().enumerate() {
        // 跳過 dash variant 行(已收集進 RunPair)
        if will_skip_line[idx] {
            continue;
        }

        // header 改寫:若該 sprite 有 walk_to_run 命中且 source_img_count > 自身 img_count
        if let Some(sid) = sid_at_idx[idx] {
            if let Some(sprite) = sprite_by_sid.get(&sid) {
                if sprite.header_line_idx == idx {
                    if let Some(p) = walk_to_run.get(&sid) {
                        if p.source_img_count > sprite.img_count {
                            let new_line =
                                update_header_img_count(line, sprite.img_count, p.source_img_count);
                            output.push_str(&new_line);
                            output.push('\n');
                            continue;
                        }
                    }
                }
            }
        }

        output.push_str(line);

        // 注入 slot 98/99(在 sprite 最後一行 action 之後)
        if let Some(sid) = sid_at_idx[idx] {
            if last_line_per_sprite.get(&sid) == Some(&idx) {
                if let Some(p) = walk_to_run.get(&sid) {
                    // 對應 legacy line 742:只有在 runl/runr 至少一側存在 + framerate 存在時才注入 110.framerate
                    if (p.runl.is_some() || p.runr.is_some()) && p.framerate.is_some() {
                        if let Some(fr) = &p.framerate {
                            output.push('\n');
                            output.push_str(&format!("\t110.framerate({})", fr));
                        }
                    }
                    if let Some(rl) = &p.runl {
                        output.push('\n');
                        output.push_str(&format!("\t98.walk({})", rl));
                    }
                    if let Some(rr) = &p.runr {
                        output.push('\n');
                        output.push_str(&format!("\t99.walk({})", rr));
                    }
                }
            }
        }

        if idx < sf.raw_lines.len() - 1 {
            output.push('\n');
        }
    }

    // 補充尾部 newline(若原始文本以 newline 結尾而輸出沒有)
    if sf.ends_with_newline && !output.ends_with('\n') {
        output.push('\n');
    }

    (output, info)
}

#[cfg(test)]
mod tests {
    use super::super::{
        classify::classify, extract::extract, pair::pair_walks_to_runs, parse::parse,
    };
    use super::*;

    #[test]
    fn emit_injects_slot_98_99_for_walk_with_run_pair() {
        let text = "100 0 41210\n#100 32=777 wolf walk\n\t0.walk(1 8,0.0:2 0.1:2 0.2:2 0.3:2 0.4:2 0.5:2 0.6:2 0.7:2)\n#200 40=777 wolf run\n\t0.runL(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n\t4.runR(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n";
        let sf = parse(text);
        let roles = classify(&sf);
        let runs = extract(&sf, &roles);
        let pairs = pair_walks_to_runs(&sf, &roles, &runs);
        let (output, _) = emit(&sf, &pairs);
        assert!(output.contains("98.walk(1 8,8.0:2"));
        assert!(output.contains("99.walk(1 8,16.0:2"));
    }
}
