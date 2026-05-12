//! Winsock connect redirection hook.

use crate::logger::log_line;
use crate::{memory, process};
use anyhow::{bail, Result};
use windows::Win32::Foundation::HANDLE;

fn build_shellcode(
    ip_bytes: [u8; 4],
    port_be: [u8; 2],
    original_bytes: &[u8],
    connect_addr: u32,
    cave_addr: u32,
    hover_count_addr: u32,
) -> Vec<u8> {
    let hook_size = original_bytes.len();
    let mut sc: Vec<u8> = Vec::with_capacity(96);

    // pushad
    sc.push(0x60);

    // sockaddr* is the second argument for connect/WSAConnect:
    // esp + pushad(32) + return(4) + socket(4) = esp+0x28
    sc.extend_from_slice(&[0x8B, 0x44, 0x24, 0x28]);

    // cmp word ptr [eax], AF_INET
    sc.extend_from_slice(&[0x66, 0x83, 0x38, 0x02]);

    let jne_skip_pos = sc.len() + 1;
    sc.extend_from_slice(&[0x75, 0x00]);

    // sockaddr_in.sin_port and sin_addr are already network byte order.
    sc.extend_from_slice(&[0x66, 0xC7, 0x40, 0x02]);
    sc.extend_from_slice(&port_be);
    sc.extend_from_slice(&[0xC7, 0x40, 0x04]);
    sc.extend_from_slice(&ip_bytes);

    if hover_count_addr != 0 {
        sc.extend_from_slice(&[0xC7, 0x05]);
        sc.extend_from_slice(&hover_count_addr.to_le_bytes());
        sc.extend_from_slice(&0u32.to_le_bytes());
    }

    let skip_target = sc.len();
    sc[jne_skip_pos] = (skip_target - jne_skip_pos - 1) as u8;

    // popad
    sc.push(0x61);

    sc.extend_from_slice(original_bytes);

    sc.push(0xE9);
    let jmp_from = cave_addr + sc.len() as u32 + 4;
    let jmp_target = connect_addr + hook_size as u32;
    let rel = jmp_target.wrapping_sub(jmp_from) as i32;
    sc.extend_from_slice(&rel.to_le_bytes());

    sc
}

fn parse_ip(ip: &str) -> Result<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        bail!("invalid IPv4: {ip}");
    }
    let mut bytes = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = part
            .parse::<u8>()
            .map_err(|_| anyhow::anyhow!("invalid IPv4 segment: {part}"))?;
    }
    Ok(bytes)
}

fn hook_winsock_connect_fn(
    h: HANDLE,
    func_name: &str,
    ws2_base: u32,
    ip_bytes: [u8; 4],
    port_be: [u8; 2],
    ip: &str,
    port: u16,
    hover_count_addr: u32,
) -> Result<bool> {
    let connect_addr = match process::find_export(h, ws2_base, func_name)? {
        Some(addr) => addr,
        None => {
            log_line!("[ConnectHook] {func_name} export not found");
            return Ok(false);
        }
    };
    log_line!("[ConnectHook] {func_name} address: 0x{connect_addr:08X}");

    let original = memory::read_bytes(h, connect_addr, 16)?;
    log_line!(
        "[ConnectHook] {func_name} original: {}",
        original
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    if original[0] == 0xE9 {
        log_line!("[ConnectHook] {func_name} already hooked");
        return Ok(true);
    }

    let hook_size = 5;
    let original_bytes = &original[..hook_size];
    let cave_addr = memory::alloc_exec(h, 96)?;
    log_line!("[ConnectHook] {func_name} codecave: 0x{cave_addr:08X}");

    let shellcode = build_shellcode(
        ip_bytes,
        port_be,
        original_bytes,
        connect_addr,
        cave_addr,
        hover_count_addr,
    );
    memory::write_code(h, cave_addr, &shellcode)?;

    let mut jmp_hook = [0u8; 5];
    jmp_hook[0] = 0xE9;
    let rel = cave_addr.wrapping_sub(connect_addr + 5) as i32;
    jmp_hook[1..5].copy_from_slice(&rel.to_le_bytes());
    memory::write_code(h, connect_addr, &jmp_hook)?;
    log_line!("[ConnectHook] {func_name} installed -> {ip}:{port}");
    Ok(true)
}

pub fn hook_connect(h: HANDLE, pid: u32, ip: &str, port: u16, hover_count_addr: u32) -> Result<()> {
    let ip_bytes = parse_ip(ip)?;
    let port_be = port.to_be_bytes();

    log_line!("[ConnectHook] installing ws2_32 redirect -> {ip}:{port}");

    let mut ws2_base = None;
    for i in 0..600 {
        match process::find_module(pid, "ws2_32.dll")? {
            Some(base) => {
                ws2_base = Some(base);
                break;
            }
            None => {
                if i % 100 == 0 && i > 0 {
                    log_line!("[ConnectHook] waiting ws2_32.dll {:.1}s", i as f64 * 0.1);
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    let ws2_base = ws2_base.ok_or_else(|| anyhow::anyhow!("ws2_32.dll not loaded after 60s"))?;
    log_line!("[ConnectHook] ws2_32.dll base: 0x{ws2_base:08X}");

    let threads = process::suspend_threads(pid)?;
    let result = (|| -> Result<(bool, bool)> {
        let connect_ok = hook_winsock_connect_fn(
            h,
            "connect",
            ws2_base,
            ip_bytes,
            port_be,
            ip,
            port,
            hover_count_addr,
        )?;
        let wsa_ok = hook_winsock_connect_fn(
            h,
            "WSAConnect",
            ws2_base,
            ip_bytes,
            port_be,
            ip,
            port,
            hover_count_addr,
        )?;
        Ok((connect_ok, wsa_ok))
    })();
    process::resume_threads(threads);

    let (connect_ok, wsa_ok) = result?;
    if !connect_ok && !wsa_ok {
        bail!("connect/WSAConnect hook install failed: no exports hooked");
    }

    log_line!("[ConnectHook] installed summary connect={connect_ok} WSAConnect={wsa_ok}");
    Ok(())
}
