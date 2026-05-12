use std::sync::{mpsc, Mutex, OnceLock};

type SenderList = Mutex<Vec<mpsc::Sender<String>>>;
static LOG_TX: OnceLock<SenderList> = OnceLock::new();

const LOG_FILE: &str = "launcher_debug.log";
const STARTUP_DIAG_FILE: &str = "launcher_startup_timing.log";
const WRITE_LOGS_ENV: &str = "LOGIN38_WRITE_LOGS";

fn senders() -> &'static SenderList {
    LOG_TX.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn subscribe() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    if let Ok(mut v) = senders().lock() {
        v.push(tx);
    }
    rx
}

#[allow(dead_code)]
pub fn init_channel() -> mpsc::Receiver<String> {
    subscribe()
}

pub fn log(msg: String) {
    let startup_diag = is_startup_diag_message(&msg);
    if !logs_enabled() && !startup_diag {
        let _ = msg;
        return;
    }

    let file_name = if startup_diag {
        STARTUP_DIAG_FILE
    } else {
        LOG_FILE
    };
    write_log_file(file_name, &msg);

    if cfg!(feature = "verbose-log") {
        println!("{msg}");
    }

    if let Ok(mut v) = senders().lock() {
        v.retain(|tx| tx.send(msg.clone()).is_ok());
    }
}

fn logs_enabled() -> bool {
    logs_enabled_from_env(
        cfg!(feature = "verbose-log"),
        std::env::var(WRITE_LOGS_ENV).ok().as_deref(),
    )
}

fn logs_enabled_from_env(verbose_log: bool, env_value: Option<&str>) -> bool {
    // 預設開啟(寫入 launcher_debug.log),只有顯式設 LOGIN38_WRITE_LOGS=0/false/no/off 才關閉。
    // 過去預設 off 造成 smooth_run_hook / poison_hook / FileHook 等非 startup_diag 訊息
    // 完全消失,debug 起來困難。
    if verbose_log {
        return true;
    }
    match env_value {
        Some(v) if is_falsy_env(v) => false,
        _ => true,
    }
}

fn is_truthy_env(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn is_falsy_env(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn is_startup_diag_message(msg: &str) -> bool {
    msg.contains("[launch-time]")
        || msg.contains("[patch-time]")
        || msg.contains("[addr-probe]")
        || msg.contains("[addr-ready]")
        || msg.contains("[inject-load]")
        || msg.contains("[inject]")
        || msg.contains("[ime-inject]")
        || msg.contains("[ime-overlay]")
        || msg.contains("[StartupHook]")
        || msg.contains("[stage2]")
        || msg.contains("[ConnectHook]")
        || msg.contains("[ImgLimit]")
        || msg.contains("[NetProxy]")
        || msg.contains("[PacketEncrypt]")
        || msg.contains("[PacketProxy]")
        || msg.contains("[spy]")
        || msg.contains("[FileHookWorker]")
        || msg.contains("[FileHook] ready wait")
        || msg.contains("[FileHook] alloc remote buffer")
        || msg.contains("[FileHook] write remote buffer")
}

fn write_log_file(file_name: &str, msg: &str) {
    let log_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(file_name)))
        .unwrap_or_else(|| std::path::PathBuf::from(file_name));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        use std::io::Write;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{now}] {msg}");
    }
}

macro_rules! log_line {
    ($($arg:tt)*) => {
        $crate::logger::log(format!($($arg)*))
    };
}
pub(crate) use log_line;

#[cfg(test)]
mod tests {
    #[test]
    fn logs_are_enabled_by_default_when_env_unset() {
        // 預設開啟(寫 launcher_debug.log),需顯式關閉才停。
        assert!(super::logs_enabled_from_env(false, None));
        assert!(super::logs_enabled_from_env(false, Some("1")));
        assert!(super::logs_enabled_from_env(false, Some("true")));
        assert!(super::logs_enabled_from_env(true, None));
    }

    #[test]
    fn logs_can_be_explicitly_disabled_via_env() {
        assert!(!super::logs_enabled_from_env(false, Some("0")));
        assert!(!super::logs_enabled_from_env(false, Some("false")));
        assert!(!super::logs_enabled_from_env(false, Some("no")));
        assert!(!super::logs_enabled_from_env(false, Some("off")));
    }

    #[test]
    fn startup_diag_messages_are_still_classified_when_logging_is_enabled() {
        assert!(super::is_startup_diag_message("[stage2] all patches done"));
        assert!(super::is_startup_diag_message(
            "[launch-time] launch_game start"
        ));
        assert!(super::is_startup_diag_message(
            "[inject] transform_file=false but valid pak exists; forcing FileHook: D:\\lineage3.81C\\TW13081901.pak"
        ));
        assert!(!super::is_startup_diag_message("[drink] execute OK"));
    }
}
