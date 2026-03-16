//! Config file parser for trezor-pkcs11.
//!
//! Looks for the config file at (in order):
//!   1. $TREZOR_PKCS11_CONF
//!   Linux:
//!   2. $XDG_CONFIG_HOME/trezor-pkcs11/config  (default: ~/.config/trezor-pkcs11/config)
//!   3. /etc/trezor-pkcs11.conf
//!   Windows:
//!   2. %APPDATA%\trezor-pkcs11\config
//!   3. %LOCALAPPDATA%\trezor-pkcs11\config
//!   4. %USERPROFILE%\.config\trezor-pkcs11\config
//!   5. C:\ProgramData\trezor-pkcs11\config

use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(windows)]
const CSIDL_APPDATA: i32 = 0x001a;       // %APPDATA%  (roaming)
#[cfg(windows)]
const CSIDL_LOCAL_APPDATA: i32 = 0x001c; // %LOCALAPPDATA%

/// Resolve a Windows shell CSIDL folder via `SHGetFolderPathW`.
/// Works even when the corresponding environment variable is not set
/// (e.g. when loaded as a DLL by a MinGW/MSYS2 process).
#[cfg(windows)]
fn shell_folder(csidl: i32) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "shell32")]
    extern "system" {
        fn SHGetFolderPathW(
            hwnd:  *mut std::ffi::c_void,
            csidl: i32,
            token: *mut std::ffi::c_void,
            flags: u32,
            path:  *mut u16,
        ) -> i32;
    }

    let mut buf = [0u16; 260];
    let hr = unsafe {
        SHGetFolderPathW(std::ptr::null_mut(), csidl, std::ptr::null_mut(), 0, buf.as_mut_ptr())
    };
    if hr != 0 { return None; }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(PathBuf::from(OsString::from_wide(&buf[..len])))
}

#[derive(Debug, Clone)]
pub struct SlotConfig {
    pub uri:   String,
    pub label: String,
    pub curve: String,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(flatten)]
    slots: HashMap<String, RawSlot>,
}

#[derive(Debug, Deserialize)]
struct RawSlot {
    uri:   String,
    label: Option<String>,
    curve: Option<String>,
}

pub fn load() -> Vec<SlotConfig> {
    let path = config_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("trezor-pkcs11: could not read config {}: {}", path.display(), e);
            return Vec::new();
        }
    };

    let raw: RawConfig = match toml::from_str(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("trezor-pkcs11: config parse error: {}", e);
            return Vec::new();
        }
    };

    // Collect slot* keys in lexicographic order so numbering is stable.
    let mut keys: Vec<String> = raw.slots.keys()
        .filter(|k| k.starts_with("slot"))
        .cloned()
        .collect();
    keys.sort();

    keys.into_iter().map(|k| {
        let s = &raw.slots[&k];
        SlotConfig {
            uri:   s.uri.clone(),
            label: s.label.clone().unwrap_or_else(|| k.clone()),
            curve: s.curve.clone().unwrap_or_else(|| "nist256p1".to_string()),
        }
    }).collect()
}

fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("TREZOR_PKCS11_CONF") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }

    for p in config_candidates() {
        if p.exists() {
            return p;
        }
    }

    #[cfg(windows)]
    { PathBuf::from(r"C:\ProgramData\trezor-pkcs11\config") }
    #[cfg(not(windows))]
    { PathBuf::from("/etc/trezor-pkcs11.conf") }
}

fn config_candidates() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut out = Vec::new();

        // Prefer Win32 shell API over env vars — env vars may not be available
        // when the DLL is loaded by a MinGW process (e.g. Git Bash ssh-agent).
        for csidl in [CSIDL_APPDATA, CSIDL_LOCAL_APPDATA] {
            if let Some(base) = shell_folder(csidl) {
                let p = base.join("trezor-pkcs11").join("config");
                out.push(p);
            }
        }

        // Env-var fallbacks for environments where shell API is unavailable.
        for var in &["APPDATA", "LOCALAPPDATA"] {
            if let Ok(val) = std::env::var(var) {
                if !val.trim().is_empty() {
                    out.push(PathBuf::from(val).join("trezor-pkcs11").join("config"));
                }
            }
        }

        out
    }
    #[cfg(not(windows))]
    {
        // $XDG_CONFIG_HOME or ~/.config
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            let mut p = PathBuf::from(xdg);
            p.push("trezor-pkcs11");
            p.push("config");
            return vec![p];
        }

        if let Ok(h) = std::env::var("HOME") {
            let mut p = PathBuf::from(h);
            p.push(".config");
            p.push("trezor-pkcs11");
            p.push("config");
            return vec![p];
        }

        Vec::new()
    }
}
