//! 記憶體操作模組 — ReadProcessMemory / WriteProcessMemory / VirtualAllocEx — v1.0.0 第一版

use anyhow::{bail, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    PAGE_PROTECTION_FLAGS,
};

/// 讀取 4 bytes 無號整數
pub fn read_u32(h: HANDLE, addr: u32) -> Result<u32> {
    let mut buf = [0u8; 4];
    let mut read = 0usize;
    unsafe {
        ReadProcessMemory(
            h,
            addr as *const _,
            buf.as_mut_ptr().cast(),
            4,
            Some(&mut read),
        )?;
    }
    if read != 4 {
        bail!("讀取 0x{addr:08X} 失敗：只讀到 {read} bytes");
    }
    Ok(u32::from_le_bytes(buf))
}

/// 讀取 N bytes
pub fn read_bytes(h: HANDLE, addr: u32, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut read = 0usize;
    unsafe {
        ReadProcessMemory(
            h,
            addr as *const _,
            buf.as_mut_ptr().cast(),
            size,
            Some(&mut read),
        )?;
    }
    if read != size {
        bail!("讀取 0x{addr:08X} 失敗：預期 {size} bytes，只讀到 {read}");
    }
    Ok(buf)
}

/// 安全寫入程式碼：VirtualProtectEx → Write → 恢復保護 → FlushInstructionCache
pub fn write_code(h: HANDLE, addr: u32, data: &[u8]) -> Result<()> {
    let len = data.len();
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);

    unsafe {
        // 修改頁面保護為可寫
        VirtualProtectEx(
            h,
            addr as *const _,
            len,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )?;

        // 寫入資料
        let mut written = 0usize;
        let result = WriteProcessMemory(
            h,
            addr as *const _,
            data.as_ptr().cast(),
            len,
            Some(&mut written),
        );

        // 恢復原始保護
        let mut dummy = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(h, addr as *const _, len, old_protect, &mut dummy);

        result?;
        if written != len {
            bail!("寫入 0x{addr:08X} 失敗：預期 {len} bytes，只寫入 {written}");
        }

        // 刷新 CPU 指令快取
        FlushInstructionCache(h, Some(addr as *const _), len)?;
    }
    Ok(())
}

/// 搜尋記憶體中的位元組模式（AOB scan）
/// pattern 使用 Option<u8>，None 表示萬用字元（??）
pub fn scan_pattern(
    h: HANDLE,
    start: u32,
    end: u32,
    pattern: &[Option<u8>],
) -> Result<Option<u32>> {
    const CHUNK: usize = 0x10000; // 64KB
    let pat_len = pattern.len();
    let mut addr = start;

    while addr < end {
        let size = std::cmp::min(CHUNK + pat_len, (end - addr) as usize);
        let data = match read_bytes(h, addr, size) {
            Ok(d) => d,
            Err(_) => {
                addr += CHUNK as u32;
                continue;
            }
        };

        'outer: for i in 0..data.len().saturating_sub(pat_len) {
            for (j, p) in pattern.iter().enumerate() {
                if let Some(b) = p {
                    if data[i + j] != *b {
                        continue 'outer;
                    }
                }
            }
            return Ok(Some(addr + i as u32));
        }

        addr += CHUNK as u32;
    }

    Ok(None)
}

/// AOB 掃描 — 回傳所有匹配位址（scan_pattern 的多匹配版本）
pub fn scan_pattern_all(
    h: HANDLE,
    start: u32,
    end: u32,
    pattern: &[Option<u8>],
) -> Result<Vec<u32>> {
    const CHUNK: usize = 0x10000; // 64KB
    let pat_len = pattern.len();
    let mut addr = start;
    let mut results = Vec::new();

    while addr < end {
        let size = std::cmp::min(CHUNK + pat_len, (end - addr) as usize);
        let data = match read_bytes(h, addr, size) {
            Ok(d) => d,
            Err(_) => {
                addr += CHUNK as u32;
                continue;
            }
        };

        'outer: for i in 0..data.len().saturating_sub(pat_len) {
            for (j, p) in pattern.iter().enumerate() {
                if let Some(b) = p {
                    if data[i + j] != *b {
                        continue 'outer;
                    }
                }
            }
            results.push(addr + i as u32);
        }

        addr += CHUNK as u32;
    }

    Ok(results)
}

/// 在目標進程分配可執行記憶體
pub fn alloc_exec(h: HANDLE, size: usize) -> Result<u32> {
    let addr = unsafe {
        VirtualAllocEx(
            h,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if addr.is_null() {
        bail!("VirtualAllocEx 分配 {size} bytes 失敗");
    }
    Ok(addr as u32)
}
