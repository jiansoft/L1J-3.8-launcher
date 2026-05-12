use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SprActionSqlOutput {
    pub sql: String,
    pub row_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActionGroup {
    spr_id: u32,
    commands: Vec<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqlRecord {
    spr_id: u32,
    act_id: u32,
    framecount: u32,
    framerate: u32,
}

const SUPPORTED_ACTION_CODES: &[u32] = &[
    0, 1, 4, 5, 11, 12, 17, 18, 19, 20, 21, 24, 25, 28, 29, 30, 31, 40, 41, 46, 47, 50, 51, 54, 55,
    58, 59, 62, 63, 66, 67,
];

fn is_supported_action_code(code: u32) -> bool {
    SUPPORTED_ACTION_CODES.contains(&code)
}

fn framecount_from_command(command: &[String]) -> u32 {
    let mut total = 0u32;
    let mut idx = 5usize;
    while idx < command.len() {
        if let Some(value) = parse_u32_prefix(&command[idx]) {
            total = total.saturating_add(value);
        }
        idx += 3;
    }
    total
}

fn records_to_sql(records: &[SqlRecord]) -> String {
    let mut sql = String::new();
    for record in records {
        sql.push_str(&format!(
            "INSERT INTO `spr_action` VALUES ('{}', '{}', '{}', '{}');\n",
            record.spr_id, record.act_id, record.framecount, record.framerate
        ));
    }
    sql
}

pub fn generate_spr_action_sql(input: &str) -> Result<SprActionSqlOutput> {
    let groups = parse_action_groups(input)?;
    let mut records = Vec::<SqlRecord>::new();

    for group in groups {
        let mut framerate = 24u32;
        for command in group.commands {
            let Some(first) = command.first() else {
                continue;
            };
            if first.contains('=') {
                if let Some((act_id, target_spr_id)) = parse_reference(first) {
                    if let Some(found) = records
                        .iter()
                        .find(|record| record.spr_id == target_spr_id && record.act_id == act_id)
                        .cloned()
                    {
                        records.push(SqlRecord {
                            spr_id: group.spr_id,
                            act_id,
                            framecount: found.framecount,
                            framerate: found.framerate,
                        });
                    }
                }
                continue;
            }

            let Some(act_id) = parse_u32_prefix(first) else {
                continue;
            };

            if act_id == 110 {
                if let Some(value) = command.get(1).and_then(|token| parse_u32_prefix(token)) {
                    framerate = value;
                }
                continue;
            }

            if !is_supported_action_code(act_id) {
                continue;
            }

            records.push(SqlRecord {
                spr_id: group.spr_id,
                act_id,
                framecount: framecount_from_command(&command),
                framerate,
            });
        }
    }

    let sql = records_to_sql(&records);
    Ok(SprActionSqlOutput {
        row_count: records.len(),
        sql,
    })
}

fn parse_u32_prefix(token: &str) -> Option<u32> {
    let digits: String = token.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn parse_reference(token: &str) -> Option<(u32, u32)> {
    let (left, right) = token.split_once('=')?;
    let act_id = parse_u32_prefix(left)?;
    let target_spr_id = parse_u32_prefix(right)?;
    Some((act_id, target_spr_id))
}

#[cfg(test)]
fn legacy_tokens(input: &str) -> Vec<String> {
    let Some(start) = input.find('#') else {
        return Vec::new();
    };

    input[start..]
        .lines()
        .flat_map(legacy_line_tokens)
        .collect()
}

fn legacy_line_tokens(input: &str) -> Vec<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut sanitized = String::with_capacity(chars.len());

    for (idx, ch) in chars.iter().copied().enumerate() {
        let next = chars.get(idx + 1).copied();
        let replace = !ch.is_ascii()
            || ch.is_ascii_alphabetic()
            || ch.is_ascii_whitespace()
            || matches!(ch, '_' | '.' | '(' | ')' | ',' | ';' | ':' | '\'')
            || (ch == '-' && !next.map(|n| n.is_ascii_digit()).unwrap_or(false));

        sanitized.push(if replace { ' ' } else { ch });
    }

    sanitized
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect()
}

fn parse_action_groups(input: &str) -> Result<Vec<ActionGroup>> {
    let mut groups = Vec::<ActionGroup>::new();
    let mut current = None::<ActionGroup>;
    let Some(start) = input.find('#') else {
        bail!("no valid #spr_id group");
    };

    for line in input[start..].lines() {
        let tokens = legacy_line_tokens(line);
        let Some(first) = tokens.first() else {
            continue;
        };

        if let Some(rest) = first.strip_prefix('#') {
            if let Some(group) = current.take() {
                groups.push(group);
            }
            let spr_id = parse_u32_prefix(rest)
                .ok_or_else(|| anyhow::anyhow!("invalid #spr_id token: {first}"))?;
            current = Some(ActionGroup {
                spr_id,
                commands: Vec::new(),
            });
            continue;
        }

        if let Some(group) = current.as_mut() {
            group.commands.push(tokens);
        }
    }

    if let Some(group) = current {
        groups.push(group);
    }

    if groups.is_empty() {
        bail!("no valid #spr_id group");
    }

    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numeric_prefix_like_strtoul() {
        assert_eq!(parse_u32_prefix("2<478"), Some(2));
        assert_eq!(parse_u32_prefix("110"), Some(110));
        assert_eq!(parse_u32_prefix("abc"), None);
        assert_eq!(parse_u32_prefix(""), None);
    }

    #[test]
    fn sanitizes_legacy_action_text_to_numeric_tokens() {
        let tokens = legacy_tokens("header ignored\n#100 80 name\n0.walk(1 2,8.0:3 8.1:4<478)");
        assert_eq!(
            tokens,
            vec!["#100", "80", "0", "1", "2", "8", "0", "3", "8", "1", "4<478"]
        );
    }

    #[test]
    fn sanitizes_non_ascii_legacy_labels_to_spaces() {
        let tokens = legacy_tokens("header ignored\n#100 80 \u{6e2c}\u{8a66}\n0.walk(1 2,8.0:3)");
        assert_eq!(tokens, vec!["#100", "80", "0", "1", "2", "8", "0", "3"]);
    }

    #[test]
    fn parses_commands_under_hash_groups() {
        let groups = parse_action_groups(
            "#100 80 name\n0.walk(1 2,8.0:3 8.1:4)\n#200 90 name\n4.attack(1 1,9.0:5)",
        )
        .unwrap();

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].spr_id, 100);
        assert_eq!(
            groups[0].commands[0],
            vec!["0", "1", "2", "8", "0", "3", "8", "1", "4"]
        );
        assert_eq!(groups[1].spr_id, 200);
        assert_eq!(groups[1].commands[0], vec!["4", "1", "1", "9", "0", "5"]);
    }

    #[test]
    fn rejects_input_without_hash_group() {
        let err = generate_spr_action_sql("0.walk(1 1,8.0:2)").unwrap_err();
        assert!(err.to_string().contains("no valid #spr_id"));
    }

    #[test]
    fn generates_basic_insert_for_supported_action() {
        let out = generate_spr_action_sql("#100 80 name\n0.walk(1 2,8.0:3 8.1:4)").unwrap();
        assert_eq!(out.row_count, 1);
        assert_eq!(
            out.sql,
            "INSERT INTO `spr_action` VALUES ('100', '0', '7', '24');\n"
        );
    }

    #[test]
    fn command_110_updates_framerate_for_following_rows() {
        let out = generate_spr_action_sql("#100 80 name\n110.framerate(30)\n4.attack(1 1,9.0:5)")
            .unwrap();
        assert_eq!(
            out.sql,
            "INSERT INTO `spr_action` VALUES ('100', '4', '5', '30');\n"
        );
    }

    #[test]
    fn skips_ascii_label_tokens_after_header_metadata() {
        let out = generate_spr_action_sql(
            "#18840 64 [弓手黃金]\n110.framerate(25)\n0.walk(1 4,0.0:4 0.1:4 0.2:4 0.3:4)",
        )
        .unwrap();

        assert_eq!(
            out.sql,
            "INSERT INTO `spr_action` VALUES ('18840', '0', '16', '25');\n"
        );
    }

    #[test]
    fn unsupported_action_code_does_not_emit_sql() {
        let out = generate_spr_action_sql("#100 80 name\n100.shadow(1 1,8.0:2)").unwrap();
        assert_eq!(out.row_count, 0);
        assert!(out.sql.is_empty());
    }

    #[test]
    fn reference_copies_previous_matching_action_record() {
        let out = generate_spr_action_sql(
            "#100 80 name\n4.attack(1 1,9.0:5)\n#200 80 name\n4=100 copied_attack",
        )
        .unwrap();

        assert_eq!(
            out.sql,
            concat!(
                "INSERT INTO `spr_action` VALUES ('100', '4', '5', '24');\n",
                "INSERT INTO `spr_action` VALUES ('200', '4', '5', '24');\n"
            )
        );
    }

    #[test]
    fn unresolved_reference_is_skipped() {
        let out = generate_spr_action_sql("#200 80 name\n4=100 copied_attack").unwrap();
        assert_eq!(out.row_count, 0);
        assert!(out.sql.is_empty());
    }

    #[test]
    fn malformed_reference_is_skipped_without_direct_action_fallback() {
        let out = generate_spr_action_sql("#200 80 name\n4=abc copied_attack").unwrap();
        assert_eq!(out.row_count, 0);
        assert!(out.sql.is_empty());
    }

    #[test]
    fn header_label_digits_are_ignored_instead_of_becoming_commands() {
        let out = generate_spr_action_sql(
            "#18840 1 Skill_Elf_Pollute_Water_2026\n102.type(0)\n#18841 1 next\n4.attack(1 1,9.0:5)",
        )
        .unwrap();

        assert_eq!(
            out.sql,
            "INSERT INTO `spr_action` VALUES ('18841', '4', '5', '24');\n"
        );
    }

    #[test]
    fn unsupported_short_metadata_commands_do_not_abort_generation() {
        let out = generate_spr_action_sql("#18840 1 name\n102\n#18841 1 next\n4.attack(1 1,9.0:5)")
            .unwrap();

        assert_eq!(
            out.sql,
            "INSERT INTO `spr_action` VALUES ('18841', '4', '5', '24');\n"
        );
    }
}
