//! 順跑(smooth-run)預編碼模組。
//!
//! 公開 API 由 5 階段 pipeline 提供:[`parse`] → [`classify`] → [`extract`]
//! → [`pair`] → [`emit`]。Tier 2 byte-equal 等價於原 monolithic 實作已驗證
//! (天M / 天R / SPR.txt 全 byte-equal,4 輪 deterministic),legacy dispatcher
//! 已於 2026-05-10 移除;`helpers` 模組保留共用 lexer / parser routines。

pub mod classify;
pub mod emit;
pub mod extract;
pub mod helpers;
pub mod pair;
pub mod parse;
pub mod pipeline;
pub mod types;

pub use helpers::VariantInfo;

pub fn process_variant_lines(text: &str) -> (String, VariantInfo) {
    pipeline::process_variant_lines_pipeline(text)
}

pub fn strip_variant_lines(text: &str) -> (String, VariantInfo) {
    process_variant_lines(text)
}
