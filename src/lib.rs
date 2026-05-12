//! launcher crate 的 lib 介面
//!
//! 把需要在 binary 之間（main.rs 與 bin/encoder.rs）共用的模組
//! 暴露為 lib，避免代碼重複。
//!
//! 目前只有 server_list（list.txt 加密 / Server_Info 結構）。
//! 其他模組仍綁在 main.rs 自己的 module tree 內。

pub mod i18n;
pub mod legacy_text;
pub mod logger;
pub mod morph_auth;
pub mod rsa32;
pub mod server_list;
pub mod smooth_run;
pub mod spr_action_sql;
