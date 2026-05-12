use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyEncoding {
    Utf8,
    Big5,
    Gbk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncodingMode {
    Auto,
    Big5,
    Gbk,
}

impl Default for TextEncodingMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl TextEncodingMode {
    pub fn from_config_value(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "big5" | "cp950" | "traditional" | "trad" | "tw" => Self::Big5,
            "gbk" | "gb2312" | "simplified" | "simp" | "cn" => Self::Gbk,
            _ => Self::Auto,
        }
    }

    pub fn as_config_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Big5 => "big5",
            Self::Gbk => "gbk",
        }
    }
}

static TEXT_ENCODING_MODE: AtomicU8 = AtomicU8::new(0);

pub fn set_text_encoding_mode(mode: TextEncodingMode) {
    TEXT_ENCODING_MODE.store(text_encoding_mode_to_u8(mode), Ordering::Relaxed);
}

pub fn text_encoding_mode() -> TextEncodingMode {
    text_encoding_mode_from_u8(TEXT_ENCODING_MODE.load(Ordering::Relaxed))
}

pub fn decode_text(bytes: &[u8]) -> (String, LegacyEncoding) {
    decode_text_with_mode(bytes, TextEncodingMode::Auto)
}

pub fn decode_text_with_mode(bytes: &[u8], mode: TextEncodingMode) -> (String, LegacyEncoding) {
    let bytes = strip_utf8_bom(bytes);
    if let Ok(text) = std::str::from_utf8(bytes) {
        return (text.to_string(), LegacyEncoding::Utf8);
    }

    match mode {
        TextEncodingMode::Big5 => {
            let (text, _, _) = encoding_rs::BIG5.decode(bytes);
            return (text.into_owned(), LegacyEncoding::Big5);
        }
        TextEncodingMode::Gbk => {
            let (text, _, _) = encoding_rs::GBK.decode(bytes);
            return (text.into_owned(), LegacyEncoding::Gbk);
        }
        TextEncodingMode::Auto => {}
    }

    let (big5, _, big5_errors) = encoding_rs::BIG5.decode(bytes);
    let (gbk, _, gbk_errors) = encoding_rs::GBK.decode(bytes);

    match (big5_errors, gbk_errors) {
        (false, true) => (big5.into_owned(), LegacyEncoding::Big5),
        (true, false) => (gbk.into_owned(), LegacyEncoding::Gbk),
        _ => {
            let big5_score =
                legacy_text_score(&big5, big5_errors) + codepage_hint_score(&big5, false);
            let gbk_score = legacy_text_score(&gbk, gbk_errors) + codepage_hint_score(&gbk, true);
            if gbk_score > big5_score {
                (gbk.into_owned(), LegacyEncoding::Gbk)
            } else {
                (big5.into_owned(), LegacyEncoding::Big5)
            }
        }
    }
}

pub fn decode_zstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let bytes = &bytes[..end];
    if bytes.is_ascii() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    decode_text_with_mode(bytes, text_encoding_mode()).0
}

pub fn encode_text(text: &str, encoding: LegacyEncoding) -> Vec<u8> {
    match encoding {
        LegacyEncoding::Utf8 => text.as_bytes().to_vec(),
        LegacyEncoding::Big5 => encoding_rs::BIG5.encode(text).0.into_owned(),
        LegacyEncoding::Gbk => encoding_rs::GBK.encode(text).0.into_owned(),
    }
}

pub fn read_text_file(path: &std::path::Path) -> std::io::Result<String> {
    let raw = std::fs::read(path)?;
    Ok(decode_text(&raw).0)
}

fn strip_utf8_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)
}

fn text_encoding_mode_to_u8(mode: TextEncodingMode) -> u8 {
    match mode {
        TextEncodingMode::Auto => 0,
        TextEncodingMode::Big5 => 1,
        TextEncodingMode::Gbk => 2,
    }
}

fn text_encoding_mode_from_u8(value: u8) -> TextEncodingMode {
    match value {
        1 => TextEncodingMode::Big5,
        2 => TextEncodingMode::Gbk,
        _ => TextEncodingMode::Auto,
    }
}

fn legacy_text_score(s: &str, had_errors: bool) -> i32 {
    let mut score = if had_errors { -200 } else { 0 };
    for ch in s.chars() {
        if ch == char::REPLACEMENT_CHARACTER || ch.is_control() {
            score -= 80;
        } else if ('\u{4E00}'..='\u{9FFF}').contains(&ch) {
            score += 4;
        } else if ch.is_ascii_alphanumeric()
            || ch.is_ascii_whitespace()
            || matches!(
                ch,
                '(' | ')'
                    | '['
                    | ']'
                    | '+'
                    | '-'
                    | ','
                    | '.'
                    | ':'
                    | '_'
                    | '/'
                    | '#'
                    | '='
                    | '<'
                    | '>'
                    | '"'
                    | '\''
                    | ';'
            )
        {
            score += 1;
        } else if ('\u{3000}'..='\u{303F}').contains(&ch) || ('\u{FF00}'..='\u{FFEF}').contains(&ch)
        {
            score += 1;
        } else {
            score -= 2;
        }
    }
    score
}

fn codepage_hint_score(s: &str, prefer_simplified: bool) -> i32 {
    const SIMPLIFIED_HINTS: &str =
        "药银剑剂卷轴龙鸟马岛宝矿护强变术书双枪挥坏锅饭绿蓝红黑简体服务器帐号密码金币死亡骑士斗篷头盔手套长靴盔甲烈炎高级皮革勇敢浓缩终极体力恢复传送村庄指定面包精灵饼干蜡烛";
    const TRADITIONAL_HINTS: &str =
        "藥銀劍劑卷軸龍鳥馬島寶礦護強變術書雙槍揮壞鍋飯綠藍紅黑繁體伺服器帳號密碼金幣死亡騎士斗篷頭盔手套長靴盔甲烈炎高級皮革勇敢濃縮終極體力恢復傳送村莊指定麵包精靈餅乾蠟燭";
    let preferred = if prefer_simplified {
        SIMPLIFIED_HINTS
    } else {
        TRADITIONAL_HINTS
    };
    let opposite = if prefer_simplified {
        TRADITIONAL_HINTS
    } else {
        SIMPLIFIED_HINTS
    };

    s.chars().fold(0, |score, ch| {
        score + if preferred.contains(ch) { 12 } else { 0 }
            - if opposite.contains(ch) { 6 } else { 0 }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_big5_traditional_text() {
        let (bytes, _, had_errors) = encoding_rs::BIG5.encode("銀劍 (揮舞)");
        assert!(!had_errors);

        assert_eq!(
            decode_text(&bytes),
            ("銀劍 (揮舞)".to_string(), LegacyEncoding::Big5)
        );
    }

    #[test]
    fn decodes_gbk_simplified_text() {
        let (bytes, _, had_errors) = encoding_rs::GBK.encode("银剑 (挥舞)");
        assert!(!had_errors);

        assert_eq!(
            decode_text(&bytes),
            ("银剑 (挥舞)".to_string(), LegacyEncoding::Gbk)
        );
    }

    #[test]
    fn decodes_ambiguous_gbk_inventory_names_as_simplified() {
        for name in ["金币", "+4 死亡骑士斗篷", "面包", "蜡烛"] {
            let (bytes, _, had_errors) = encoding_rs::GBK.encode(name);
            assert!(!had_errors);

            assert_eq!(decode_text(&bytes), (name.to_string(), LegacyEncoding::Gbk));
        }
    }

    #[test]
    fn forced_gbk_mode_decodes_short_simplified_names_without_guessing() {
        let (bytes, _, had_errors) = encoding_rs::GBK.encode("蜡烛");
        assert!(!had_errors);

        assert_eq!(
            decode_text_with_mode(&bytes, TextEncodingMode::Gbk),
            ("蜡烛".to_string(), LegacyEncoding::Gbk)
        );
    }

    #[test]
    fn forced_big5_mode_decodes_traditional_names_without_guessing() {
        let (bytes, _, had_errors) = encoding_rs::BIG5.encode("蠟燭");
        assert!(!had_errors);

        assert_eq!(
            decode_text_with_mode(&bytes, TextEncodingMode::Big5),
            ("蠟燭".to_string(), LegacyEncoding::Big5)
        );
    }

    #[test]
    fn decodes_utf8_text_first() {
        assert_eq!(
            decode_text("簡體/简体".as_bytes()),
            ("簡體/简体".to_string(), LegacyEncoding::Utf8)
        );
    }

    #[test]
    fn decodes_null_terminated_legacy_text() {
        let (bytes, _, had_errors) = encoding_rs::GBK.encode("服务器\0tail");
        assert!(!had_errors);

        assert_eq!(decode_zstr(&bytes), "服务器");
    }

    #[test]
    fn encodes_back_to_selected_codepage() {
        let encoded = encode_text("服务器", LegacyEncoding::Gbk);
        let (decoded, _, had_errors) = encoding_rs::GBK.decode(&encoded);

        assert!(!had_errors);
        assert_eq!(decoded, "服务器");
    }
}
