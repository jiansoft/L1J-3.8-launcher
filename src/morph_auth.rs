//! 變身檔 .pak 內容綁定（authentication tag）
//!
//! 用途：讓 launcher 只接受由「我們的編碼器」產出的 .pak。
//!
//! 機制：在 .pak 末尾附加 16-byte AES-CBC-MAC tag（key 為內嵌的
//! `MORPH_AUTH_KEY`），launcher 載入時驗證；不通過直接拒絕。
//!
//! threat model：阻擋使用 `pak_encoder.py` / 其他相容工具產出的 .pak、
//! 阻擋隨便重新命名同名替換。要偽造必須逆向出 `MORPH_AUTH_KEY`。
//!
//! 格式：
//! ```text
//! [orig_len:4][key:16][encrypted:N][mac:16]
//!                                  ^^^^^^^ 本模組計算/驗證
//! mac = AES-CBC-MAC(MORPH_AUTH_KEY, [orig_len:4][key:16][encrypted:N])
//! ```

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

/// 內嵌綁定金鑰。修改後 encoder 與 launcher 必須一起重編、舊 .pak 全部失效。
pub const MORPH_AUTH_KEY: [u8; 16] = [
    0xC7, 0x9A, 0x14, 0xFE, 0x81, 0x23, 0x6B, 0x4D, 0xA8, 0x50, 0xE2, 0x9C, 0x3F, 0x17, 0xDA, 0x6B,
];

/// MAC 長度（bytes）
pub const MORPH_MAC_LEN: usize = 16;

/// AES-CBC-MAC（含 length-prefix 對抗變長攻擊；ISO 7816-4 padding）
///
/// 不是 NIST CMAC，但對「阻擋 casual 替換」threat model 已足夠。
pub fn morph_mac(data: &[u8]) -> [u8; MORPH_MAC_LEN] {
    let cipher = Aes128::new(&MORPH_AUTH_KEY.into());
    let mut state = [0u8; 16];

    // Block 0：data 長度（u64 LE）+ ISO 7816-4 padding
    let mut blk = [0u8; 16];
    blk[..8].copy_from_slice(&(data.len() as u64).to_le_bytes());
    blk[8] = 0x80;
    cbc_step(&cipher, &mut state, &blk);

    // Data blocks
    let mut i = 0;
    while i < data.len() {
        let n = (data.len() - i).min(16);
        let mut blk = [0u8; 16];
        blk[..n].copy_from_slice(&data[i..i + n]);
        if n < 16 {
            blk[n] = 0x80; // ISO 7816-4 padding
        }
        cbc_step(&cipher, &mut state, &blk);
        i += 16;
    }

    // 若最後一個 data block 剛好填滿 16 bytes，補一個全 padding block
    if !data.is_empty() && data.len() % 16 == 0 {
        let mut blk = [0u8; 16];
        blk[0] = 0x80;
        cbc_step(&cipher, &mut state, &blk);
    }

    state
}

#[inline]
fn cbc_step(cipher: &Aes128, state: &mut [u8; 16], blk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= blk[i];
    }
    let block = aes::Block::from_mut_slice(state);
    cipher.encrypt_block(block);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_deterministic() {
        let a = morph_mac(b"hello world");
        let b = morph_mac(b"hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn mac_differs_on_byte_change() {
        let a = morph_mac(b"hello world");
        let b = morph_mac(b"hello worle");
        assert_ne!(a, b);
    }

    #[test]
    fn mac_differs_on_length_change() {
        let a = morph_mac(b"hello world");
        let b = morph_mac(b"hello world ");
        assert_ne!(a, b);
    }

    #[test]
    fn mac_handles_empty() {
        let _ = morph_mac(b"");
    }

    #[test]
    fn mac_handles_block_boundary() {
        // 剛好 16 bytes（觸發 padding-only block）
        let a = morph_mac(b"0123456789abcdef");
        // 16 + 1 byte（不觸發）
        let b = morph_mac(b"0123456789abcdefX");
        assert_ne!(a, b);
    }
}
