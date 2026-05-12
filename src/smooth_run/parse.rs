//! Phase 1:把變身檔文字解析成結構化 [`SpriteFile`] IR。
//! 純 lexer/parser,不做任何分類。複用 legacy 既有 helpers。

use super::helpers::{
    extract_action_name, extract_frame_content, extract_frame_count,
    extract_inline_action_with_name, first_spr_from_content, parse_action_number, parse_header_ext,
    parse_sprite_id, parse_variant_line, split_frame_content,
};
use super::types::{Action, Sprite, SpriteFile};

/// 對應 legacy.rs:126 同一份 inline 掃描範圍(WALK_ACTIONS + 32/33)。
const INLINE_SCAN_ACTIONS: &[u32] = &[
    0, 4, 11, 20, 24, 40, 46, 50, 54, 58, 62, 83, 88, 119, 32, 33,
];

pub fn parse(text: &str) -> SpriteFile {
    let ends_with_newline = text.ends_with('\n');
    let raw_lines: Vec<String> = text.split('\n').map(String::from).collect();
    let file_header = raw_lines.first().cloned().unwrap_or_default();
    let mut sprites: Vec<Sprite> = Vec::new();
    // 對應 legacy `cur_framerate` — sprite-scoped,進入新 sprite 時 reset。
    let mut cur_framerate: Option<String> = None;

    for (idx, line) in raw_lines.iter().enumerate() {
        let trimmed = line.trim_start();

        if trimmed.starts_with('#') {
            if let Some(sid) = parse_sprite_id(trimmed) {
                let (img_count, gfx_id, name) = parse_header_ext(trimmed)
                    .map(|(ic, gid, n)| (ic, gid, n.to_string()))
                    .unwrap_or((0, None, String::new()));
                let mut sprite = Sprite {
                    sid,
                    header_line_idx: idx,
                    header_text: line.clone(),
                    img_count,
                    gfx_id,
                    name,
                    framerate: None,
                    actions: Vec::new(),
                };
                cur_framerate = None;
                // 天R 風格 inline action 掃描:同一份 header 行可能含 0.walkfastI(...)、4.walkfastII(...) 等
                // 對應 legacy.rs:126-144 的 inline 偵測。每個命中的 action 用 line_idx = idx
                // (= header_line_idx),indent = ""。
                for &action_num in INLINE_SCAN_ACTIONS {
                    if let Some((content, name)) =
                        extract_inline_action_with_name(trimmed, action_num)
                    {
                        if content.is_empty() {
                            continue;
                        }
                        if let Some(action) =
                            build_inline_action(idx, action_num, content, name, &cur_framerate)
                        {
                            sprite.actions.push(action);
                        }
                    }
                }
                sprites.push(sprite);
            }
            continue;
        }

        let Some(sprite) = sprites.last_mut() else {
            continue;
        };

        if let Some((_indent, base, variant, _rest)) = parse_variant_line(trimmed) {
            // 對應 legacy line 152:只 capture variant == 1 或 2 為 dash action;
            // 其他 variant(如 0-3.spell no direction)在 legacy 也是 continue 但
            // 不進 variant_map,emit 自然 pass-through。pipeline 同樣不收進
            // sprite.actions,讓 emit 不誤刪。
            if variant == 1 || variant == 2 {
                let indent = &line[..line.len() - trimmed.len()];
                if let Some(action) = build_action(
                    idx,
                    indent,
                    base,
                    Some(variant),
                    line,
                    trimmed,
                    &cur_framerate,
                ) {
                    sprite.actions.push(action);
                }
            }
            continue;
        }

        if let Some(base) = parse_action_number(trimmed) {
            if base == 110 {
                let content = extract_frame_content(line);
                if !content.is_empty() {
                    if sprite.framerate.is_none() {
                        sprite.framerate = Some(content.to_string());
                    }
                    cur_framerate = Some(content.to_string());
                }
            }
            let indent = &line[..line.len() - trimmed.len()];
            if let Some(action) =
                build_action(idx, indent, base, None, line, trimmed, &cur_framerate)
            {
                sprite.actions.push(action);
            }
        }
    }

    SpriteFile {
        file_header,
        sprites,
        raw_lines,
        ends_with_newline,
    }
}

fn build_inline_action(
    line_idx: usize,
    base_action: u32,
    content: &str,
    name: &str,
    cur_framerate: &Option<String>,
) -> Option<Action> {
    let (header, _) = split_frame_content(content)?;
    let mut header_iter = header.split_whitespace();
    let direction: u32 = header_iter.next()?.parse().ok()?;
    let frame_count: u32 = header_iter.next()?.parse().unwrap_or(0);
    let first_spr = first_spr_from_content(content).unwrap_or(0);
    Some(Action {
        line_idx,
        indent: String::new(),
        base_action,
        dash_variant: None,
        name: name.to_lowercase().trim().to_string(),
        content: content.to_string(),
        direction,
        frame_count,
        first_spr,
        framerate_at_parse: cur_framerate.clone(),
    })
}

fn build_action(
    line_idx: usize,
    indent: &str,
    base_action: u32,
    dash_variant: Option<u32>,
    full_line: &str,
    trimmed: &str,
    cur_framerate: &Option<String>,
) -> Option<Action> {
    let content = extract_frame_content(full_line).to_string();
    if content.is_empty() {
        return None;
    }
    let (header, _) = split_frame_content(&content)?;
    let mut header_iter = header.split_whitespace();
    let direction: u32 = header_iter.next()?.parse().ok()?;
    let frame_count: u32 = header_iter.next()?.parse().unwrap_or(0);
    let first_spr = first_spr_from_content(&content).unwrap_or(0);
    let name = extract_action_name(trimmed)
        .to_lowercase()
        .trim()
        .to_string();
    let _ = extract_frame_count(&content);
    Some(Action {
        line_idx,
        indent: indent.to_string(),
        base_action,
        dash_variant,
        name,
        content,
        direction,
        frame_count,
        first_spr,
        framerate_at_parse: cur_framerate.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_input_returns_empty_sprite_file() {
        let result = parse("");
        assert_eq!(result.file_header, "");
        assert!(result.sprites.is_empty());
        assert!(result.raw_lines.is_empty() || result.raw_lines == vec![""]);
    }

    #[test]
    fn parse_single_sprite_with_one_walk_action() {
        let text = "100 0 41210\n#42 32=999 wolf\n\t0.walk(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n";
        let result = parse(text);
        assert_eq!(result.file_header, "100 0 41210");
        assert_eq!(result.sprites.len(), 1);
        let s = &result.sprites[0];
        assert_eq!(s.sid, 42);
        assert_eq!(s.gfx_id, Some(999));
        assert_eq!(s.img_count, 32);
        assert_eq!(s.name, "wolf");
        assert_eq!(s.actions.len(), 1);
        let a = &s.actions[0];
        assert_eq!(a.base_action, 0);
        assert_eq!(a.dash_variant, None);
        assert_eq!(a.name, "walk");
        assert_eq!(a.direction, 1);
        assert_eq!(a.frame_count, 8);
        assert_eq!(a.first_spr, 8);
    }

    #[test]
    fn parse_dash_variant_recognizes_runl_runr() {
        let text = "100 0 41210\n#7 32=777 ranger\n\t0-1.RunL(1 8,16.0:2 16.1:2 16.2:2 16.3:2 16.4:2 16.5:2 16.6:2 16.7:2)\n\t0-2.RunR(1 8,24.0:2 24.1:2 24.2:2 24.3:2 24.4:2 24.5:2 24.6:2 24.7:2)\n";
        let result = parse(text);
        let s = &result.sprites[0];
        assert_eq!(s.actions.len(), 2);
        assert_eq!(s.actions[0].base_action, 0);
        assert_eq!(s.actions[0].dash_variant, Some(1));
        assert_eq!(s.actions[0].name, "runl");
        assert_eq!(s.actions[1].dash_variant, Some(2));
        assert_eq!(s.actions[1].name, "runr");
    }

    #[test]
    fn parse_extracts_framerate_from_action_110() {
        let text = "100 0 41210\n#9 32=888 wizard\n\t0.walk(1 8,8.0:2 8.1:2 8.2:2 8.3:2 8.4:2 8.5:2 8.6:2 8.7:2)\n\t110.framerate(1 8,1 1 1 1 1 1 1 1)\n";
        let result = parse(text);
        let s = &result.sprites[0];
        assert_eq!(s.framerate.as_deref(), Some("1 8,1 1 1 1 1 1 1 1"));
    }

    #[test]
    fn parse_preserves_raw_lines_for_emit_round_trip() {
        let text = "300 0 41210\n#1 32=1 a\n\t0.walk(1 4,0.0:2 0.1:2 0.2:2 0.3:2)\n# comment line(non-header)\n";
        let result = parse(text);
        assert_eq!(result.raw_lines.len(), 5);
        assert_eq!(result.raw_lines[0], "300 0 41210");
        assert_eq!(result.raw_lines[3], "# comment line(non-header)");
        assert_eq!(result.raw_lines[4], "");
    }
}
