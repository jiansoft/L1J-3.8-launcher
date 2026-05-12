//! Login account/password hooks for the 3.8 client.
//!
//! The older implementation forced a custom 0xD2 login packet at 0x00772BA0.
//! The legacy Login.dll that works with more emulators hooks the native login
//! point at 0x00772E07, but sends opcode 0x77 with the compact
//! "cssddddddd" shape. This module mirrors that packet shape while keeping
//! our existing plaintext account/password capture.

use crate::logger::log_line;
use crate::{memory, process};
use anyhow::{bail, Result};
use windows::Win32::Foundation::HANDLE;

const USER_HOOK_ADDR: u32 = 0x0077317D;
const USER_RETN_ADDR: u32 = 0x00773183;
const PASS_HOOK_ADDR: u32 = 0x004AA38E;
const PASS_RETN_ADDR: u32 = 0x004AA395;

const LOGIN77_HOOK_ADDR: u32 = 0x00772E07;
const LOGIN77_RETN_ADDR: u32 = 0x00772E77;
const LOGIN77_HOOK_SIZE: usize = 10;
const LOGIN77_OPCODE: u32 = 0x77;

const PASS_BYTE_CONVERTER: u32 = 0x00402800;
const SEND_PACKET_DATA: u32 = 0x00580E50;

const CAVE_SIZE: usize = 1024;
const G_ID_OFF: u32 = 0x000;
const G_PWD_OFF: u32 = 0x080;
const G_PWD_POS_OFF: u32 = 0x100;
const G_FMT_OFF: u32 = 0x110;
const USER_CODE_OFF: u32 = 0x120;
const PASS_CODE_OFF: u32 = 0x180;
const LOGIN77_CODE_OFF: u32 = 0x280;
const LOGIN77_FORMAT: &[u8] = b"cssddddddd\0";

fn build_user_shellcode(cave: u32) -> Vec<u8> {
    let g_id = cave + G_ID_OFF;
    let user_code = cave + USER_CODE_OFF;
    let mut sc = Vec::with_capacity(48);

    // Original bytes at 0x77317D: lea eax, [ebp-0x98]
    sc.extend_from_slice(&[0x8D, 0x85, 0x68, 0xFF, 0xFF, 0xFF]);
    sc.push(0x60); // pushad
    sc.extend_from_slice(&[0x8B, 0xF0]); // mov esi, eax
    sc.push(0xBF); // mov edi, g_id
    sc.extend_from_slice(&g_id.to_le_bytes());
    sc.push(0xB9); // mov ecx, 32
    sc.extend_from_slice(&32u32.to_le_bytes());
    sc.push(0xFC); // cld
    sc.extend_from_slice(&[0xF3, 0xA4]); // rep movsb
    sc.push(0x61); // popad
    sc.push(0xE9);
    let jmp_from = user_code + sc.len() as u32 + 4;
    sc.extend_from_slice(&(USER_RETN_ADDR.wrapping_sub(jmp_from) as i32).to_le_bytes());

    sc
}

fn build_pass_shellcode(cave: u32) -> Vec<u8> {
    let g_pwd = cave + G_PWD_OFF;
    let g_pwd_pos = cave + G_PWD_POS_OFF;
    let pass_code = cave + PASS_CODE_OFF;
    let mut sc = Vec::with_capacity(96);

    // Original bytes at 0x4AA38E.
    sc.extend_from_slice(&[0x8B, 0x55, 0xF4]); // mov edx, [ebp-0x0C]
    sc.extend_from_slice(&[0x8B, 0x4C, 0x8A, 0x3C]); // mov ecx, [edx+ecx*4+0x3C]
    sc.push(0x60); // pushad
    sc.push(0xB8); // mov eax, PASS_BYTE_CONVERTER
    sc.extend_from_slice(&PASS_BYTE_CONVERTER.to_le_bytes());
    sc.extend_from_slice(&[0xFF, 0xD0]); // call eax, al = decoded password byte
    sc.extend_from_slice(&[0x8B, 0x0D]); // mov ecx, [g_pwd_pos]
    sc.extend_from_slice(&g_pwd_pos.to_le_bytes());
    sc.extend_from_slice(&[0x85, 0xC9]); // test ecx, ecx
    sc.extend_from_slice(&[0x75, 0x13]); // jne .not_first

    // Clear first 32 bytes of password buffer on the first typed byte.
    sc.push(0x50); // push eax
    sc.push(0x57); // push edi
    sc.push(0xBF); // mov edi, g_pwd
    sc.extend_from_slice(&g_pwd.to_le_bytes());
    sc.extend_from_slice(&[0x33, 0xC0]); // xor eax, eax
    sc.extend_from_slice(&[0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB]); // stosd * 8
    sc.push(0x5F); // pop edi
    sc.push(0x58); // pop eax

    // .not_first
    sc.push(0xBA); // mov edx, g_pwd
    sc.extend_from_slice(&g_pwd.to_le_bytes());
    sc.extend_from_slice(&[0x88, 0x04, 0x0A]); // mov [edx+ecx], al
    sc.push(0x41); // inc ecx
    sc.extend_from_slice(&[0x89, 0x0D]); // mov [g_pwd_pos], ecx
    sc.extend_from_slice(&g_pwd_pos.to_le_bytes());
    sc.push(0x61); // popad
    sc.push(0xE9);
    let jmp_from = pass_code + sc.len() as u32 + 4;
    sc.extend_from_slice(&(PASS_RETN_ADDR.wrapping_sub(jmp_from) as i32).to_le_bytes());

    sc
}

fn push_imm32(sc: &mut Vec<u8>, value: u32) {
    sc.push(0x68);
    sc.extend_from_slice(&value.to_le_bytes());
}

fn build_login77_shellcode(cave: u32) -> Vec<u8> {
    let g_id = cave + G_ID_OFF;
    let g_pwd = cave + G_PWD_OFF;
    let g_pwd_pos = cave + G_PWD_POS_OFF;
    let g_fmt = cave + G_FMT_OFF;
    let login_code = cave + LOGIN77_CODE_OFF;
    let mut sc = Vec::with_capacity(96);

    // Legacy Login.dll compatible call shape:
    // SendPacketData("cssddddddd", 0x77, id, pwd, 127.0.0.1, 0, 0, 0, 0, 0, 0x1F).
    push_imm32(&mut sc, 0x1F);
    push_imm32(&mut sc, 0);
    push_imm32(&mut sc, 0);
    push_imm32(&mut sc, 0);
    push_imm32(&mut sc, 0);
    push_imm32(&mut sc, 0);
    push_imm32(&mut sc, 0x0100007F);
    push_imm32(&mut sc, g_pwd);
    push_imm32(&mut sc, g_id);
    push_imm32(&mut sc, LOGIN77_OPCODE);
    push_imm32(&mut sc, g_fmt);
    sc.push(0xE8);
    let call_from = login_code + sc.len() as u32 + 4;
    sc.extend_from_slice(&(SEND_PACKET_DATA.wrapping_sub(call_from) as i32).to_le_bytes());
    sc.extend_from_slice(&[0x83, 0xC4, 0x2C]); // add esp, 11 args * 4

    // Reset password capture position after sending.
    sc.extend_from_slice(&[0xC7, 0x05]);
    sc.extend_from_slice(&g_pwd_pos.to_le_bytes());
    sc.extend_from_slice(&0u32.to_le_bytes());

    sc.push(0xE9);
    let jmp_from = login_code + sc.len() as u32 + 4;
    sc.extend_from_slice(&(LOGIN77_RETN_ADDR.wrapping_sub(jmp_from) as i32).to_le_bytes());

    sc
}

pub fn install_login_hooks(h: HANDLE, pid: u32) -> Result<()> {
    log_line!("\n--- login hooks (Login.dll-compatible opcode 0x77 mode) ---");

    let cave = memory::alloc_exec(h, CAVE_SIZE)?;
    log_line!("[OK] login codecave: 0x{cave:08X}");

    let user_sc = build_user_shellcode(cave);
    let pass_sc = build_pass_shellcode(cave);
    let login77_sc = build_login77_shellcode(cave);

    log_line!(
        "[INFO] shellcode sizes: UserHook={}, PassHook={}, Login77={}",
        user_sc.len(),
        pass_sc.len(),
        login77_sc.len()
    );

    if user_sc.len() > 0x40 {
        bail!("UserHook shellcode too large: {} > 64", user_sc.len());
    }
    if pass_sc.len() > 0xA0 {
        bail!("PassHook shellcode too large: {} > 160", pass_sc.len());
    }
    if login77_sc.len() > 0x180 {
        bail!("Login77 shellcode too large: {} > 384", login77_sc.len());
    }

    let mut cave_data = vec![0u8; CAVE_SIZE];
    let f = G_FMT_OFF as usize;
    cave_data[f..f + LOGIN77_FORMAT.len()].copy_from_slice(LOGIN77_FORMAT);
    let u = USER_CODE_OFF as usize;
    cave_data[u..u + user_sc.len()].copy_from_slice(&user_sc);
    let p = PASS_CODE_OFF as usize;
    cave_data[p..p + pass_sc.len()].copy_from_slice(&pass_sc);
    let l = LOGIN77_CODE_OFF as usize;
    cave_data[l..l + login77_sc.len()].copy_from_slice(&login77_sc);
    memory::write_code(h, cave, &cave_data)?;

    let user_code = cave + USER_CODE_OFF;
    let pass_code = cave + PASS_CODE_OFF;
    let login77_code = cave + LOGIN77_CODE_OFF;

    let mut user_jmp = [0u8; 6];
    user_jmp[0] = 0xE9;
    let rel = user_code.wrapping_sub(USER_HOOK_ADDR + 5) as i32;
    user_jmp[1..5].copy_from_slice(&rel.to_le_bytes());
    user_jmp[5] = 0x90;

    let mut pass_jmp = [0u8; 7];
    pass_jmp[0] = 0xE9;
    let rel = pass_code.wrapping_sub(PASS_HOOK_ADDR + 5) as i32;
    pass_jmp[1..5].copy_from_slice(&rel.to_le_bytes());
    pass_jmp[5] = 0x90;
    pass_jmp[6] = 0x90;

    let mut login77_jmp = [0x90u8; LOGIN77_HOOK_SIZE];
    login77_jmp[0] = 0xE9;
    let rel = login77_code.wrapping_sub(LOGIN77_HOOK_ADDR + 5) as i32;
    login77_jmp[1..5].copy_from_slice(&rel.to_le_bytes());

    let threads = process::suspend_threads(pid)?;
    let r1 = memory::write_code(h, USER_HOOK_ADDR, &user_jmp);
    let r2 = memory::write_code(h, PASS_HOOK_ADDR, &pass_jmp);
    let r3 = memory::write_code(h, LOGIN77_HOOK_ADDR, &login77_jmp);
    process::resume_threads(threads);

    match &r1 {
        Ok(()) => log_line!("[OK] UserHook @ 0x{USER_HOOK_ADDR:08X} -> 0x{user_code:08X}"),
        Err(e) => log_line!("[ERROR] UserHook: {e}"),
    }
    match &r2 {
        Ok(()) => log_line!("[OK] PassHook @ 0x{PASS_HOOK_ADDR:08X} -> 0x{pass_code:08X}"),
        Err(e) => log_line!("[ERROR] PassHook: {e}"),
    }
    match &r3 {
        Ok(()) => log_line!("[OK] Login77 @ 0x{LOGIN77_HOOK_ADDR:08X} -> 0x{login77_code:08X}"),
        Err(e) => log_line!("[ERROR] Login77: {e}"),
    }

    r1?;
    r2?;
    r3?;

    log_line!("[OK] login hooks installed (cssddddddd opcode 0x77 packet flow)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pushed_immediates_before_call(sc: &[u8]) -> Vec<u32> {
        let mut values = Vec::new();
        let mut i = 0usize;
        while i < sc.len() {
            match sc[i] {
                0x68 => {
                    values.push(u32::from_le_bytes(
                        sc[i + 1..i + 5].try_into().expect("push imm32"),
                    ));
                    i += 5;
                }
                0xE8 => break,
                _ => panic!("unexpected opcode before call at {i}: 0x{:02X}", sc[i]),
            }
        }
        values
    }

    #[test]
    fn login77_packet_places_account_before_password() {
        let cave = 0x1000_0000;
        let sc = build_login77_shellcode(cave);
        let pushes = pushed_immediates_before_call(&sc);
        let args = pushes.into_iter().rev().collect::<Vec<_>>();

        assert_eq!(args[0], cave + G_FMT_OFF);
        assert_eq!(args[1], LOGIN77_OPCODE);
        assert_eq!(args[2], cave + G_ID_OFF);
        assert_eq!(args[3], cave + G_PWD_OFF);
    }
}
