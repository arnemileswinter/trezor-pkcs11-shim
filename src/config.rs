//! Config file parser for trezor-pkcs11.
//!
//! Looks for the config file at (in order):
//!   1. $TREZOR_PKCS11_CONF
//!   Linux:
//!   2. $XDG_CONFIG_HOME/trezor-pkcs11/config  (default: ~/.config/trezor-pkcs11/config)
//!   3. /etc/trezor-pkcs11.conf
//!   Windows:
//!   2. %APPDATA%\trezor-pkcs11\config

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
        return PathBuf::from(p);
    }
    if let Some(mut p) = user_config_dir() {
        p.push("trezor-pkcs11");
        p.push("config");
        if p.exists() {
            return p;
        }
    }
    #[cfg(windows)]
    { PathBuf::from(r"C:\ProgramData\trezor-pkcs11\config") }
    #[cfg(not(windows))]
    { PathBuf::from("/etc/trezor-pkcs11.conf") }
}

fn user_config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        // %APPDATA%\trezor-pkcs11\config
        std::env::var("APPDATA").ok().map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        // $XDG_CONFIG_HOME or ~/.config
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(xdg));
        }
        std::env::var("HOME").ok().map(|h| {
            let mut p = PathBuf::from(h);
            p.push(".config");
            p
        })
    }
}
