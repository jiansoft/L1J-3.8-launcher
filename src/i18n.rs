//! 繁→簡字元對映 — 只給 LHX 視窗的 UI 字串顯示用。
//! 詳細設計見 docs/superpowers/specs/2026-05-09-lhx-simplified-chinese-ui-design.md

use crate::legacy_text::{set_text_encoding_mode, text_encoding_mode, TextEncodingMode};
use std::borrow::Cow;
use std::iter::once;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE, WPARAM};
use windows::Win32::UI::Controls::{TCIF_TEXT, TCITEMW};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, GetClassNameW, GetWindowTextLengthW, GetWindowTextW, SendMessageW,
    SetWindowTextW,
};

const TCM_FIRST: u32 = 0x1300;
const TCM_GETITEMCOUNT: u32 = TCM_FIRST + 4;
const TCM_GETITEMW: u32 = TCM_FIRST + 60;
const TCM_SETITEMW: u32 = TCM_FIRST + 61;

static T2S: phf::Map<char, char> = phf::phf_map! {
    '術' => '术',  // 加速術/治癒術 等(出現在 INI 對話框預覽 + 測試)
    '備' => '备',  '傷' => '伤',  '刪' => '删',  '動' => '动',
    '啟' => '启',  '單' => '单',  '態' => '态',  '戲' => '戏',
    '擊' => '击',  '數' => '数',  '斷' => '断',  '於' => '于',
    '時' => '时',  '無' => '无',  '狀' => '状',  '級' => '级',
    '經' => '经',  '裝' => '装',  '計' => '计',  '話' => '话',
    '說' => '说',  '變' => '变',  '輔' => '辅',  '遊' => '游',
    '鐘' => '钟',  '間' => '间',  '顯' => '显',  '驗' => '验',
};

pub fn tr(s: &str) -> Cow<'_, str> {
    if text_encoding_mode() != TextEncodingMode::Gbk {
        return Cow::Borrowed(s);
    }
    if s.is_ascii() {
        return Cow::Borrowed(s);
    }
    let mut buf = String::with_capacity(s.len());
    let mut changed = false;
    for ch in s.chars() {
        match T2S.get(&ch) {
            Some(&simp) => {
                buf.push(simp);
                changed = true;
            }
            None => buf.push(ch),
        }
    }
    if changed {
        Cow::Owned(buf)
    } else {
        Cow::Borrowed(s)
    }
}

/// 翻譯整棵 LHX 視窗子樹(含 child controls + tab labels)。
///
/// `build_ui` 完成後呼叫一次。Big5 / Auto 模式下直接 return,零成本。
pub fn retranslate_lhx(hwnd_root: HWND) {
    if text_encoding_mode() != TextEncodingMode::Gbk {
        return;
    }
    unsafe {
        retranslate_one(hwnd_root);
        let _ = EnumChildWindows(Some(hwnd_root), Some(retranslate_enum), LPARAM(0));
        retranslate_tabs_recursive(hwnd_root);
    }
}

unsafe extern "system" fn retranslate_enum(hwnd: HWND, _lp: LPARAM) -> BOOL {
    retranslate_one(hwnd);
    TRUE
}

unsafe fn retranslate_one(hwnd: HWND) {
    let len = GetWindowTextLengthW(hwnd);
    if len <= 0 {
        return;
    }
    let mut buf = vec![0u16; len as usize + 1];
    let read = GetWindowTextW(hwnd, &mut buf);
    if read <= 0 {
        return;
    }
    let cur = String::from_utf16_lossy(&buf[..read as usize]);
    if cur.is_ascii() {
        return;
    }
    if let Cow::Owned(new) = tr(&cur) {
        let new_w: Vec<u16> = new.encode_utf16().chain(once(0)).collect();
        let _ = SetWindowTextW(hwnd, PCWSTR(new_w.as_ptr()));
    }
}

unsafe fn retranslate_tabs_recursive(hwnd_root: HWND) {
    extern "system" fn find_tabs(hwnd: HWND, _lp: LPARAM) -> BOOL {
        unsafe {
            let mut class_buf = [0u16; 64];
            let n = GetClassNameW(hwnd, &mut class_buf);
            if n > 0 {
                let class = String::from_utf16_lossy(&class_buf[..n as usize]);
                if class == "SysTabControl32" {
                    retranslate_one_tab_control(hwnd);
                }
            }
            TRUE
        }
    }
    let _ = EnumChildWindows(Some(hwnd_root), Some(find_tabs), LPARAM(0));
}

unsafe fn retranslate_one_tab_control(hwnd_tab: HWND) {
    let count = SendMessageW(hwnd_tab, TCM_GETITEMCOUNT, None, None).0 as i32;
    if count <= 0 {
        return;
    }
    for i in 0..count {
        let mut buf = [0u16; 256];
        let mut item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: PWSTR(buf.as_mut_ptr()),
            cchTextMax: buf.len() as i32,
            ..Default::default()
        };
        let r = SendMessageW(
            hwnd_tab,
            TCM_GETITEMW,
            Some(WPARAM(i as usize)),
            Some(LPARAM(&mut item as *mut _ as isize)),
        );
        if r.0 == 0 {
            continue;
        }
        let text_len = (0..buf.len()).take_while(|&k| buf[k] != 0).count();
        let cur = String::from_utf16_lossy(&buf[..text_len]);
        if cur.is_ascii() {
            continue;
        }
        if let Cow::Owned(new) = tr(&cur) {
            let mut new_w: Vec<u16> = new.encode_utf16().chain(once(0)).collect();
            let mut new_item = TCITEMW {
                mask: TCIF_TEXT,
                pszText: PWSTR(new_w.as_mut_ptr()),
                cchTextMax: 0,
                ..Default::default()
            };
            let _ = SendMessageW(
                hwnd_tab,
                TCM_SETITEMW,
                Some(WPARAM(i as usize)),
                Some(LPARAM(&mut new_item as *mut _ as isize)),
            );
        }
    }
}

/// 測試專用 — 強制 GBK 模式呼叫 tr() 一次。
/// 不適用於 production 程式碼。
#[doc(hidden)]
pub fn set_and_translate_for_test(s: &str) -> String {
    let prev = text_encoding_mode();
    set_text_encoding_mode(TextEncodingMode::Gbk);
    let result = tr(s).into_owned();
    set_text_encoding_mode(prev);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static MODE_LOCK: Mutex<()> = Mutex::new(());

    fn with_mode<F: FnOnce()>(mode: TextEncodingMode, f: F) {
        let _g = MODE_LOCK.lock().unwrap();
        let prev = text_encoding_mode();
        set_text_encoding_mode(mode);
        f();
        set_text_encoding_mode(prev);
    }

    #[test]
    fn passthrough_in_big5_mode() {
        with_mode(TextEncodingMode::Big5, || {
            let r = tr("加速術");
            assert!(matches!(r, Cow::Borrowed(_)));
            assert_eq!(&*r, "加速術");
        });
    }

    #[test]
    fn ascii_zero_alloc() {
        with_mode(TextEncodingMode::Gbk, || {
            let r = tr("HP");
            assert!(matches!(r, Cow::Borrowed(_)));
            assert_eq!(&*r, "HP");
        });
    }

    #[test]
    fn empty_t2s_passthrough_even_in_gbk() {
        // T2S 已填表,但若整串無命中字元仍應 passthrough(不分配)
        with_mode(TextEncodingMode::Gbk, || {
            let r = tr("喝水秒回");
            assert!(matches!(r, Cow::Borrowed(_)));
            assert_eq!(&*r, "喝水秒回");
        });
    }

    #[test]
    fn converts_traditional_to_simplified_in_gbk() {
        with_mode(TextEncodingMode::Gbk, || {
            let r = tr("加速術");
            assert!(matches!(r, Cow::Owned(_)));
            assert_eq!(&*r, "加速术");
        });
    }

    #[test]
    fn converts_lhx_actual_strings() {
        with_mode(TextEncodingMode::Gbk, || {
            // 來自 lhx_window.rs 的真實 UI 字串
            assert_eq!(&*tr("輔助"), "辅助");
            assert_eq!(&*tr("狀態"), "状态");
            assert_eq!(&*tr("刪物"), "删物");
            assert_eq!(&*tr("變身"), "变身");
            assert_eq!(&*tr("時鐘"), "时钟");
            assert_eq!(
                &*tr("無法刪除或溶解正在使用的裝備!"),
                "无法删除或溶解正在使用的装备!"
            );
        });
    }

    #[test]
    fn passthrough_chars_not_in_table() {
        with_mode(TextEncodingMode::Gbk, || {
            // 喝水兩字繁簡同形,不在 T2S — 整串應為 Borrowed
            let r = tr("喝水");
            assert!(matches!(r, Cow::Borrowed(_)));
        });
    }

    #[test]
    fn t2s_table_has_no_self_mapping() {
        for (k, v) in T2S.entries() {
            assert_ne!(k, v, "T2S 內 '{k}' 對映到自己 — 應從表中移除");
        }
    }
}
