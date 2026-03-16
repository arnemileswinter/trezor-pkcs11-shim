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

        if let Ok(appdata) = std::env::var("APPDATA") {
            if !appdata.trim().is_empty() {
                let mut p = PathBuf::from(appdata);
                p.push("trezor-pkcs11");
                p.push("config");
                out.push(p);
            }
        }

        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                let mut p = PathBuf::from(local);
                p.push("trezor-pkcs11");
                p.push("config");
                out.push(p);
            }
        }

        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            if !user_profile.trim().is_empty() {
                let mut p = PathBuf::from(user_profile);
                p.push(".config");
                p.push("trezor-pkcs11");
                p.push("config");
                out.push(p);
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
