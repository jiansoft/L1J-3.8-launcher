//! 5 階段 pipeline 串接。
//!
//! `process_variant_lines_pipeline(text)` 等價於 legacy 的
//! `process_variant_lines(text)`,輸出 byte-equal。

use super::helpers::VariantInfo;

pub fn process_variant_lines_pipeline(text: &str) -> (String, VariantInfo) {
    let sf = super::parse::parse(text);
    let roles = super::classify::classify(&sf);
    let runs = super::extract::extract(&sf, &roles);
    let walk_to_run = super::pair::pair_walks_to_runs(&sf, &roles, &runs);
    super::emit::emit(&sf, &walk_to_run)
}
