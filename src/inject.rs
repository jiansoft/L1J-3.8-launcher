use crate::logger::log_line;
use crate::{memory, process, smooth_run};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use anyhow::{bail, Result};
use flate2::read::ZlibDecoder;
use launcher::morph_auth::{morph_mac, MORPH_MAC_LEN};
use std::io::Read as _;
use windows::Win32::Foundation::HANDLE;

const FILE_HOOK_ADDR: u32 = 0x0058788B;
const FILE_RETN_ADDR: u32 = 0x0058794F;
const EXPECTED_BYTES: u32 = 0x4D8D016A;

pub fn morph_preprocess_enabled() -> bool {
    let Some(raw) = std::env::var_os("LOGIN38_MORPH_PREPROCESS") else {
        return true;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

const XOR_TABLE: [u8; 256] = [
    0x7E, 0x89, 0xDC, 0x78, 0x7F, 0x4B, 0xB6, 0x4F, 0x7D, 0x0D, 0x08, 0x16, 0x7C, 0xCF, 0x62, 0x21,
    0x79, 0x80, 0x74, 0xA4, 0x78, 0x42, 0x1E, 0x93, 0x7A, 0x04, 0xA0, 0xCA, 0x7B, 0xC6, 0xCA, 0xFD,
    0x6C, 0xBC, 0x2E, 0xB0, 0x6D, 0x7E, 0x44, 0x87, 0x6F, 0x38, 0xFA, 0xDE, 0x6E, 0xFA, 0x90, 0xE9,
    0x6B, 0xB5, 0x86, 0x6C, 0x6A, 0x77, 0xEC, 0x5B, 0x68, 0x31, 0x52, 0x02, 0x69, 0xF3, 0x38, 0x35,
    0x62, 0xAF, 0x7F, 0x08, 0x63, 0x6D, 0x15, 0x3F, 0x61, 0x2B, 0xAB, 0x66, 0x60, 0xE9, 0xC1, 0x51,
    0x65, 0xA6, 0xD7, 0xD4, 0x64, 0x64, 0xBD, 0xE3, 0x66, 0x22, 0x03, 0xBA, 0x67, 0xE0, 0x69, 0x8D,
    0x48, 0xD7, 0xCB, 0x20, 0x49, 0x15, 0xA1, 0x17, 0x4B, 0x53, 0x1F, 0x4E, 0x4A, 0x91, 0x75, 0x79,
    0x4F, 0xDE, 0x63, 0xFC, 0x4E, 0x1C, 0x09, 0xCB, 0x4C, 0x5A, 0xB7, 0x92, 0x4D, 0x98, 0xDD, 0xA5,
    0x46, 0xC4, 0x9A, 0x98, 0x47, 0x06, 0xF0, 0xAF, 0x45, 0x40, 0x4E, 0xF6, 0x44, 0x82, 0x24, 0xC1,
    0x41, 0xCD, 0x32, 0x44, 0x40, 0x0F, 0x58, 0x73, 0x42, 0x49, 0xE6, 0x2A, 0x43, 0x8B, 0x8C, 0x1D,
    0x54, 0xF1, 0x68, 0x50, 0x55, 0x33, 0x02, 0x67, 0x57, 0x75, 0xBC, 0x3E, 0x56, 0xB7, 0xD6, 0x09,
    0x53, 0xF8, 0xC0, 0x8C, 0x52, 0x3A, 0xAA, 0xBB, 0x50, 0x7C, 0x14, 0xE2, 0x51, 0xBE, 0x7E, 0xD5,
    0x5A, 0xE2, 0x39, 0xE8, 0x5B, 0x20, 0x53, 0xDF, 0x59, 0x66, 0xED, 0x86, 0x58, 0xA4, 0x87, 0xB1,
    0x5D, 0xEB, 0x91, 0x34, 0x5C, 0x29, 0xFB, 0x03, 0x5E, 0x6F, 0x45, 0x5A, 0x5F, 0xAD, 0x2F, 0x6D,
    0xE1, 0x35, 0x1B, 0x80, 0xE0, 0xF7, 0x71, 0xB7, 0xE2, 0xB1, 0xCF, 0xEE, 0xE3, 0x73, 0xA5, 0xD9,
    0xE6, 0x3C, 0xB3, 0x5C, 0xE7, 0xFE, 0xD9, 0x6B, 0xE5, 0xB8, 0x67, 0x32, 0xE4, 0x7A, 0x0D, 0x05,
];

fn pak_decrypt(key: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes128::new(key.into());
    for chunk in data.chunks_exact_mut(16) {
        let block = aes::Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    let mut table = XOR_TABLE;
    for i in 0..256 {
        table[i] ^= key[i % 16];
    }
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= table[i % 256];
    }
}

pub fn load_inject_file(path: &str) -> Result<Vec<u8>> {
    let raw = std::fs::read(path)?;
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if ext == "pak" {
        let min_size = 4 + 16 + MORPH_MAC_LEN;
        if raw.len() < min_size {
            bail!(".pak file too small: {} bytes", raw.len());
        }
        let split = raw.len() - MORPH_MAC_LEN;
        let expected = morph_mac(&raw[..split]);
        if expected.as_slice() != &raw[split..] {
            bail!("invalid .pak MAC; please rebuild with launcher/encoder.exe");
        }
        let orig_len = u32::from_le_bytes(raw[0..4].try_into()?);
        if orig_len > 100_000_000 {
            bail!("invalid .pak orig_len={orig_len}");
        }
        let key: [u8; 16] = raw[4..20].try_into()?;
        let mut encrypted = raw[20..split].to_vec();
        log_line!(
            "[INFO] .pak decrypt: size={}, key={}...",
            raw.len(),
            hex::encode(&key[..8])
        );
        pak_decrypt(&key, &mut encrypted);

        let decrypted = if !encrypted.is_empty() && encrypted[0] == b'S' {
            encrypted
        } else {
            let mut decoder = ZlibDecoder::new(&encrypted[..]);
            let mut buffer = Vec::new();
            decoder.read_to_end(&mut buffer)?;
            buffer
        };

        if morph_preprocess_enabled() && decrypted.len() > 1 && decrypted[0] == b'S' {
            let text = String::from_utf8_lossy(&decrypted[1..]);
            let (cleaned, _info) = smooth_run::strip_variant_lines(&text);
            let mut buf = Vec::with_capacity(1 + cleaned.len());
            buf.push(b'S');
            buf.extend_from_slice(cleaned.as_bytes());
            log_line!("[inject-load] morph preprocess enabled; stripped variant lines");
            Ok(buf)
        } else {
            log_line!("[inject-load] morph preprocess disabled; raw morph buffer preserved");
            Ok(decrypted)
        }
    } else {
        let mut buffer = Vec::with_capacity(1 + raw.len());
        buffer.push(b'S');
        buffer.extend_from_slice(&raw);
        log_line!("[inject-load] morph preprocess disabled; raw txt buffer preserved");
        Ok(buffer)
    }
}

pub fn is_valid_pak(path: &std::path::Path) -> bool {
    let Ok(raw) = std::fs::read(path) else {
        return false;
    };
    let min_size = 4 + 16 + MORPH_MAC_LEN;
    if raw.len() < min_size {
        return false;
    }
    let Ok(orig_len) = raw[0..4].try_into().map(u32::from_le_bytes) else {
        return false;
    };
    if orig_len > 100_000_000 {
        return false;
    }
    let split = raw.len() - MORPH_MAC_LEN;
    let expected = morph_mac(&raw[..split]);
    expected.as_slice() == &raw[split..]
}

fn build_file_hook_shellcode(buffer_len: u32, data_addr: u32, sc_addr: u32) -> Vec<u8> {
    let mut sc = Vec::with_capacity(64);
    sc.push(0xB8);
    sc.extend_from_slice(&buffer_len.to_le_bytes());
    sc.extend_from_slice(&[0x89, 0x45, 0xEC]);
    sc.push(0xB8);
    sc.extend_from_slice(&(data_addr + 1).to_le_bytes());
    sc.extend_from_slice(&[0x8B, 0x95, 0xC4, 0xFD, 0xFF, 0xFF]);
    sc.extend_from_slice(&[0x89, 0x42, 0x08]);
    sc.push(0xE9);
    let jmp_from = sc_addr + sc.len() as u32 + 4;
    let rel = FILE_RETN_ADDR.wrapping_sub(jmp_from) as i32;
    sc.extend_from_slice(&rel.to_le_bytes());
    sc
}

pub fn start_file_hook_worker(h: HANDLE, pid: u32, buffer: &[u8]) -> Result<()> {
    log_line!("[FileHookWorker] waiting for target bytes @ 0x{FILE_HOOK_ADDR:08X}");
    for _ in 0..12000 {
        let val = memory::read_u32(h, FILE_HOOK_ADDR).unwrap_or(0);
        if val == EXPECTED_BYTES {
            log_line!("[FileHookWorker] target bytes ready; installing");
            install_file_hook(h, pid, buffer)?;
            return Ok(());
        }
        // 已被先前 worker 安裝(stage1 pre-resume worker → stage2 重複 spawn)→ 不重複裝。
        if (val & 0xFF) == 0xE9 {
            log_line!("[FileHookWorker] FileHook already installed (JMP detected); skipping");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    bail!("FileHook wait timed out before target bytes appeared");
}

pub fn install_file_hook(h: HANDLE, pid: u32, buffer: &[u8]) -> Result<u32> {
    let buffer_len = buffer.len() as u32;
    log_line!("\n--- FileHook install ---");
    let val = memory::read_u32(h, FILE_HOOK_ADDR)?;
    if val != EXPECTED_BYTES {
        bail!("FileHook verify failed: 0x{FILE_HOOK_ADDR:08X}=0x{val:08X}, expected 0x{EXPECTED_BYTES:08X}");
    }

    let data_addr = memory::alloc_exec(h, buffer.len())?;
    memory::write_code(h, data_addr, buffer)?;
    log_line!(
        "[OK] remote buffer: 0x{data_addr:08X} ({} bytes)",
        buffer.len()
    );

    let sc_addr = memory::alloc_exec(h, 64)?;
    let sc = build_file_hook_shellcode(buffer_len, data_addr, sc_addr);
    memory::write_code(h, sc_addr, &sc)?;

    let mut jmp_hook = [0u8; 5];
    jmp_hook[0] = 0xE9;
    let rel = sc_addr.wrapping_sub(FILE_HOOK_ADDR + 5) as i32;
    jmp_hook[1..5].copy_from_slice(&rel.to_le_bytes());

    let threads = process::suspend_threads(pid)?;
    match memory::write_code(h, FILE_HOOK_ADDR, &jmp_hook) {
        Ok(()) => {
            process::resume_threads(threads);
            log_line!("[OK] FileHook @ 0x{FILE_HOOK_ADDR:08X} -> 0x{sc_addr:08X}");
        }
        Err(e) => {
            process::resume_threads(threads);
            bail!("FileHook JMP install failed: {e}");
        }
    }
    Ok(sc_addr)
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}
