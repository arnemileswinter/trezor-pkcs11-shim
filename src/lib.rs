//! trezor-pkcs11: PKCS#11 provider backed by a Trezor hardware wallet.
//!
//! Exposes nist256p1 and secp256k1 keys derived via SLIP-0013 (SignIdentity).
//! Slots are configured in ~/.config/trezor-pkcs11/config (TOML).
//!
//! Entry point for PKCS#11 consumers: C_GetFunctionList.

#![allow(non_snake_case, clippy::missing_safety_doc)]

mod config;
mod pkcs11_types;
mod trezor;

use pkcs11_types::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

// ── Global state ─────────────────────────────────────────────────────────────

struct Session {
    slot_id: CK_SLOT_ID,
    find_results: Option<Vec<CK_OBJECT_HANDLE>>,
    find_pos: usize,
    sign_mechanism: Option<CK_MECHANISM_TYPE>,
    sign_key: Option<CK_OBJECT_HANDLE>,
}

struct State {
    slots: Vec<config::SlotConfig>,
    /// Cached uncompressed 65-byte SEC1 public keys keyed by slot index.
    pubkey_cache: HashMap<usize, Vec<u8>>,
    sessions: HashMap<CK_SESSION_HANDLE, Session>,
    next_session: CK_SESSION_HANDLE,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

// ── Object handle scheme ─────────────────────────────────────────────────────
// Slot N → pubkey handle = N*2+1, privkey handle = N*2+2

fn pubkey_handle(slot: usize)  -> CK_OBJECT_HANDLE { (slot * 2 + 1) as CK_OBJECT_HANDLE }
fn privkey_handle(slot: usize) -> CK_OBJECT_HANDLE { (slot * 2 + 2) as CK_OBJECT_HANDLE }

fn handle_to_slot(h: CK_OBJECT_HANDLE) -> Option<usize> {
    if h == 0 { None } else { Some(((h - 1) / 2) as usize) }
}
fn handle_is_private(h: CK_OBJECT_HANDLE) -> bool { h % 2 == 0 }

// ── Attribute fill helpers ────────────────────────────────────────────────────

unsafe fn fill_attr(attr: &mut CK_ATTRIBUTE, value: &[u8]) -> CK_RV {
    if attr.value.is_null() {
        attr.value_len = value.len() as CK_ULONG;
        return CKR_OK;
    }
    if attr.value_len < value.len() as CK_ULONG {
        attr.value_len = value.len() as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    let dst = std::slice::from_raw_parts_mut(attr.value as *mut u8, value.len());
    dst.copy_from_slice(value);
    attr.value_len = value.len() as CK_ULONG;
    CKR_OK
}

unsafe fn fill_ulong(attr: &mut CK_ATTRIBUTE, v: CK_ULONG) -> CK_RV {
    fill_attr(attr, &v.to_ne_bytes())
}

unsafe fn fill_bool(attr: &mut CK_ATTRIBUTE, v: CK_BBOOL) -> CK_RV {
    fill_attr(attr, &[v])
}

// ── Static function list ──────────────────────────────────────────────────────

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version:                  CK_VERSION { major: 2, minor: 40 },
    C_Initialize:             Some(C_Initialize),
    C_Finalize:               Some(C_Finalize),
    C_GetInfo:                Some(C_GetInfo),
    C_GetFunctionList:        Some(C_GetFunctionList),
    C_GetSlotList:            Some(C_GetSlotList),
    C_GetSlotInfo:            Some(C_GetSlotInfo),
    C_GetTokenInfo:           Some(C_GetTokenInfo),
    C_GetMechanismList:       Some(C_GetMechanismList),
    C_GetMechanismInfo:       Some(C_GetMechanismInfo),
    C_InitToken:              None,
    C_InitPIN:                None,
    C_SetPIN:                 None,
    C_OpenSession:            Some(C_OpenSession),
    C_CloseSession:           Some(C_CloseSession),
    C_CloseAllSessions:       Some(C_CloseAllSessions),
    C_GetSessionInfo:         Some(C_GetSessionInfo),
    C_GetOperationState:      None,
    C_SetOperationState:      None,
    C_Login:                  Some(C_Login),
    C_Logout:                 Some(C_Logout),
    C_CreateObject:           None,
    C_CopyObject:             None,
    C_DestroyObject:          None,
    C_GetObjectSize:          None,
    C_GetAttributeValue:      Some(C_GetAttributeValue),
    C_SetAttributeValue:      None,
    C_FindObjectsInit:        Some(C_FindObjectsInit),
    C_FindObjects:            Some(C_FindObjects),
    C_FindObjectsFinal:       Some(C_FindObjectsFinal),
    C_EncryptInit:            None,
    C_Encrypt:                None,
    C_EncryptUpdate:          None,
    C_EncryptFinal:           None,
    C_DecryptInit:            None,
    C_Decrypt:                None,
    C_DecryptUpdate:          None,
    C_DecryptFinal:           None,
    C_DigestInit:             None,
    C_Digest:                 None,
    C_DigestUpdate:           None,
    C_DigestKey:              None,
    C_DigestFinal:            None,
    C_SignInit:               Some(C_SignInit),
    C_Sign:                   Some(C_Sign),
    C_SignUpdate:             None,
    C_SignFinal:              None,
    C_SignRecoverInit:        None,
    C_SignRecover:            None,
    C_VerifyInit:             None,
    C_Verify:                 None,
    C_VerifyUpdate:           None,
    C_VerifyFinal:            None,
    C_VerifyRecoverInit:      None,
    C_VerifyRecover:          None,
    C_DigestEncryptUpdate:    None,
    C_DecryptDigestUpdate:    None,
    C_SignEncryptUpdate:      None,
    C_DecryptVerifyUpdate:    None,
    C_GenerateKey:            None,
    C_GenerateKeyPair:        None,
    C_WrapKey:                None,
    C_UnwrapKey:              None,
    C_DeriveKey:              None,
    C_SeedRandom:             None,
    C_GenerateRandom:         None,
    C_GetFunctionStatus:      None,
    C_CancelFunction:         None,
    C_WaitForSlotEvent:       None,
};

#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp: *mut *const CK_FUNCTION_LIST) -> CK_RV {
    if pp.is_null() { return CKR_ARGUMENTS_BAD; }
    *pp = &FUNCTION_LIST;
    CKR_OK
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_Initialize(_args: *mut c_void) -> CK_RV {
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    if guard.is_some() { return CKR_CRYPTOKI_ALREADY_INITIALIZED; }
    let slots = config::load();
    *guard = Some(State {
        slots,
        pubkey_cache: HashMap::new(),
        sessions: HashMap::new(),
        next_session: 1,
    });
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Finalize(_args: *mut c_void) -> CK_RV {
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    if guard.is_none() { return CKR_CRYPTOKI_NOT_INITIALIZED; }
    *guard = None;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetInfo(p: *mut CK_INFO) -> CK_RV {
    if p.is_null() { return CKR_ARGUMENTS_BAD; }
    let info = &mut *p;
    info.cryptoki_version = CK_VERSION { major: 2, minor: 40 };
    pad_str(&mut info.manufacturer_id, "trezor-pkcs11");
    info.flags = 0;
    pad_str(&mut info.library_description, "Trezor PKCS#11 shim");
    info.library_version = CK_VERSION { major: 0, minor: 1 };
    CKR_OK
}

// ── Slot / Token ──────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    slot_list: *mut CK_SLOT_ID,
    count: *mut CK_ULONG,
) -> CK_RV {
    if count.is_null() { return CKR_ARGUMENTS_BAD; }
    let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    let n = state.slots.len() as CK_ULONG;
    if slot_list.is_null() { *count = n; return CKR_OK; }
    if *count < n { *count = n; return CKR_BUFFER_TOO_SMALL; }
    for i in 0..state.slots.len() { *slot_list.add(i) = i as CK_SLOT_ID; }
    *count = n;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetSlotInfo(slot: CK_SLOT_ID, p: *mut CK_SLOT_INFO) -> CK_RV {
    if p.is_null() { return CKR_ARGUMENTS_BAD; }
    let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    if slot as usize >= state.slots.len() { return CKR_SLOT_ID_INVALID; }
    let info = &mut *p;
    pad_str(&mut info.slot_description, "Trezor hardware wallet slot");
    pad_str(&mut info.manufacturer_id, "SatoshiLabs");
    info.flags = CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
    info.hardware_version = CK_VERSION { major: 1, minor: 0 };
    info.firmware_version = CK_VERSION { major: 1, minor: 0 };
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetTokenInfo(slot: CK_SLOT_ID, p: *mut CK_TOKEN_INFO) -> CK_RV {
    if p.is_null() { return CKR_ARGUMENTS_BAD; }
    let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    let Some(slot_cfg) = state.slots.get(slot as usize) else { return CKR_SLOT_ID_INVALID };
    let label = slot_cfg.label.clone();
    drop(guard);
    let info = &mut *p;
    pad_str(&mut info.label, &label);
    pad_str(&mut info.manufacturer_id, "SatoshiLabs");
    pad_str(&mut info.model, "Trezor");
    pad_str(&mut info.serial_number, "");
    info.flags = CKF_TOKEN_INITIALIZED
               | CKF_WRITE_PROTECTED
               | CKF_PROTECTED_AUTHENTICATION_PATH;
    info.max_session_count    = CK_ULONG::MAX;
    info.session_count        = CK_ULONG::MAX;
    info.max_rw_session_count = 0;
    info.rw_session_count     = 0;
    info.max_pin_len          = 0;
    info.min_pin_len          = 0;
    info.total_public_memory  = CK_ULONG::MAX;
    info.free_public_memory   = CK_ULONG::MAX;
    info.total_private_memory = CK_ULONG::MAX;
    info.free_private_memory  = CK_ULONG::MAX;
    info.hardware_version     = CK_VERSION { major: 1, minor: 0 };
    info.firmware_version     = CK_VERSION { major: 1, minor: 0 };
    pad_str(&mut info.utc_time, "");
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismList(
    slot: CK_SLOT_ID,
    list: *mut CK_MECHANISM_TYPE,
    count: *mut CK_ULONG,
) -> CK_RV {
    if count.is_null() { return CKR_ARGUMENTS_BAD; }
    let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    if slot as usize >= state.slots.len() { return CKR_SLOT_ID_INVALID; }
    let mechs = [CKM_ECDSA, CKM_ECDSA_SHA256, CKM_EDDSA];
    let n = mechs.len() as CK_ULONG;
    if list.is_null() { *count = n; return CKR_OK; }
    if *count < n { *count = n; return CKR_BUFFER_TOO_SMALL; }
    for (i, m) in mechs.iter().enumerate() { *list.add(i) = *m; }
    *count = n;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slot: CK_SLOT_ID,
    mech: CK_MECHANISM_TYPE,
    p: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    if p.is_null() { return CKR_ARGUMENTS_BAD; }
    let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    if slot as usize >= state.slots.len() { return CKR_SLOT_ID_INVALID; }
    let info = &mut *p;
    info.flags = CKF_HW | CKF_SIGN;
    match mech {
        CKM_ECDSA | CKM_ECDSA_SHA256 => { info.min_key_size = 256; info.max_key_size = 256; }
        CKM_EDDSA                     => { info.min_key_size = 255; info.max_key_size = 255; }
        _                             => return CKR_MECHANISM_INVALID,
    }
    CKR_OK
}

// ── Sessions ──────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_OpenSession(
    slot: CK_SLOT_ID,
    flags: CK_FLAGS,
    _app: *mut c_void,
    _notify: *mut c_void,
    handle: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if handle.is_null() { return CKR_ARGUMENTS_BAD; }
    if flags & CKF_SERIAL_SESSION == 0 { return CKR_SESSION_PARALLEL_NOT_SUPPORTED; }
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    if slot as usize >= state.slots.len() { return CKR_SLOT_ID_INVALID; }
    let id = state.next_session;
    state.next_session += 1;
    state.sessions.insert(id, Session {
        slot_id: slot,
        find_results: None,
        find_pos: 0,
        sign_mechanism: None,
        sign_key: None,
    });
    *handle = id;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_CloseSession(handle: CK_SESSION_HANDLE) -> CK_RV {
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    if state.sessions.remove(&handle).is_none() { return CKR_SESSION_HANDLE_INVALID; }
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_CloseAllSessions(slot: CK_SLOT_ID) -> CK_RV {
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    state.sessions.retain(|_, s| s.slot_id != slot);
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_GetSessionInfo(
    handle: CK_SESSION_HANDLE,
    p: *mut CK_SESSION_INFO,
) -> CK_RV {
    if p.is_null() { return CKR_ARGUMENTS_BAD; }
    let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    let Some(session) = state.sessions.get(&handle) else { return CKR_SESSION_HANDLE_INVALID };
    let info = &mut *p;
    info.slot_id     = session.slot_id;
    info.state       = CKS_RO_USER_FUNCTIONS;
    info.flags       = CKF_SERIAL_SESSION;
    info.device_error = 0;
    CKR_OK
}

// ── Login / Logout — auth handled on-device ───────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_Login(
    _handle: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: *const CK_UTF8CHAR,
    _pin_len: CK_ULONG,
) -> CK_RV { CKR_OK }

#[no_mangle]
pub unsafe extern "C" fn C_Logout(_handle: CK_SESSION_HANDLE) -> CK_RV { CKR_OK }

// ── Object search ─────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsInit(
    handle: CK_SESSION_HANDLE,
    template: *const CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    let Some(session) = state.sessions.get_mut(&handle) else { return CKR_SESSION_HANDLE_INVALID };
    let mut filter_class: Option<CK_OBJECT_CLASS> = None;
    let mut filter_id:    Option<usize>            = None;
    if !template.is_null() && count > 0 {
        for attr in std::slice::from_raw_parts(template, count as usize) {
            if attr.value.is_null() { continue; }
            match attr.attr_type {
                CKA_CLASS if attr.value_len as usize == std::mem::size_of::<CK_ULONG>() => {
                    let bytes = std::slice::from_raw_parts(
                        attr.value as *const u8,
                        std::mem::size_of::<CK_ULONG>(),
                    );
                    filter_class = Some(CK_ULONG::from_ne_bytes(bytes.try_into().unwrap()));
                }
                CKA_ID if attr.value_len == 1 => {
                    filter_id = Some(*(attr.value as *const u8) as usize);
                }
                _ => {}
            }
        }
    }

    // Slot 0 aggregates all keys so that OpenSSH builds which only open one
    // session (always slot 0) can still enumerate every configured identity.
    // Sessions for slot N > 0 return only that slot's objects, preserving
    // isolation for callers that open specific slots (e.g. integration tests).
    let slot_idx = session.slot_id as usize;
    let base_range = if slot_idx == 0 { 0..state.slots.len() } else { slot_idx..slot_idx + 1 };
    // If the caller also specified a CKA_ID, narrow to that slot only.
    let range: Vec<usize> = base_range
        .filter(|i| filter_id.map_or(true, |id| *i == id))
        .collect();
    let results = match filter_class {
        Some(CKO_PUBLIC_KEY)  => range.iter().map(|&i| pubkey_handle(i)).collect(),
        Some(CKO_PRIVATE_KEY) => range.iter().map(|&i| privkey_handle(i)).collect(),
        None => range.iter().flat_map(|&i| [pubkey_handle(i), privkey_handle(i)]).collect(),
        _ => vec![],
    };

    session.find_results = Some(results);
    session.find_pos = 0;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_FindObjects(
    handle: CK_SESSION_HANDLE,
    objects: *mut CK_OBJECT_HANDLE,
    max: CK_ULONG,
    found: *mut CK_ULONG,
) -> CK_RV {
    if objects.is_null() || found.is_null() { return CKR_ARGUMENTS_BAD; }
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    let Some(session) = state.sessions.get_mut(&handle) else { return CKR_SESSION_HANDLE_INVALID };
    let Some(ref results) = session.find_results.clone() else { return CKR_OPERATION_NOT_INITIALIZED };
    let remaining = &results[session.find_pos..];
    let n = remaining.len().min(max as usize);
    for (i, h) in remaining[..n].iter().enumerate() { *objects.add(i) = *h; }
    session.find_pos += n;
    *found = n as CK_ULONG;
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsFinal(handle: CK_SESSION_HANDLE) -> CK_RV {
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    let Some(session) = state.sessions.get_mut(&handle) else { return CKR_SESSION_HANDLE_INVALID };
    session.find_results = None;
    session.find_pos = 0;
    CKR_OK
}

// ── Object attributes ─────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_GetAttributeValue(
    handle: CK_SESSION_HANDLE,
    obj: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    if template.is_null() { return CKR_ARGUMENTS_BAD; }
    let Some(slot_idx) = handle_to_slot(obj) else { return CKR_OBJECT_HANDLE_INVALID };
    let is_private = handle_is_private(obj);

    // Check whether we need the EC point and don't have it cached yet.
    let needs_point = !is_private && {
        let attrs = std::slice::from_raw_parts(template, count as usize);
        attrs.iter().any(|a| a.attr_type == CKA_EC_POINT)
    };

    if needs_point {
        // Read slot config outside the lock to avoid holding it across I/O.
        let (uri, curve) = {
            let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
            let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
            if !state.sessions.contains_key(&handle) { return CKR_SESSION_HANDLE_INVALID; }
            if state.pubkey_cache.contains_key(&slot_idx) {
                // Already cached — skip fetch.
                let Some(slot) = state.slots.get(slot_idx) else { return CKR_OBJECT_HANDLE_INVALID };
                (slot.uri.clone(), slot.curve.clone())
            } else {
                let Some(slot) = state.slots.get(slot_idx) else { return CKR_OBJECT_HANDLE_INVALID };
                (slot.uri.clone(), slot.curve.clone())
            }
        };

        // Only fetch if not cached.
        let already_cached = {
            let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
            guard.as_ref().map_or(false, |s| s.pubkey_cache.contains_key(&slot_idx))
        };

        if !already_cached {
            match trezor::get_public_key(&uri, &curve) {
                Ok(raw) => {
                    // ECDSA curves: Trezor returns 33-byte compressed SEC1 → decompress to 65 bytes.
                    // Ed25519: Trezor returns 33 bytes with a leading prefix byte → strip it, keep 32.
                    let point = if curve == "ed25519" {
                        if raw.len() < 33 { return CKR_DEVICE_ERROR; }
                        raw[1..].to_vec()
                    } else {
                        match trezor::decompress_pubkey(&raw, &curve) {
                            Some(u) => u.to_vec(),
                            None => return CKR_DEVICE_ERROR,
                        }
                    };
                    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
                    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
                    state.pubkey_cache.insert(slot_idx, point);
                }
                Err(e) => {
                    eprintln!("trezor-pkcs11: get_public_key: {}", e);
                    return CKR_DEVICE_ERROR;
                }
            }
        }
    }

    let Ok(guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_ref() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    if !state.sessions.contains_key(&handle) { return CKR_SESSION_HANDLE_INVALID; }
    let Some(slot) = state.slots.get(slot_idx) else { return CKR_OBJECT_HANDLE_INVALID };

    let attrs = std::slice::from_raw_parts_mut(template, count as usize);
    let mut rv = CKR_OK;

    for attr in attrs.iter_mut() {
        let r = match attr.attr_type {
            CKA_CLASS         => fill_ulong(attr, if is_private { CKO_PRIVATE_KEY } else { CKO_PUBLIC_KEY }),
            CKA_TOKEN         => fill_bool(attr, CK_TRUE),
            CKA_PRIVATE       => fill_bool(attr, if is_private { CK_TRUE } else { CK_FALSE }),
            CKA_SENSITIVE     => fill_bool(attr, if is_private { CK_TRUE } else { CK_FALSE }),
            CKA_EXTRACTABLE   => fill_bool(attr, CK_FALSE),
            CKA_NEVER_EXTRACTABLE => fill_bool(attr, if is_private { CK_TRUE } else { CK_FALSE }),
            CKA_ALWAYS_SENSITIVE  => fill_bool(attr, if is_private { CK_TRUE } else { CK_FALSE }),
            CKA_KEY_TYPE      => fill_ulong(attr,
                if slot.curve == "ed25519" { CKK_EC_EDWARDS } else { CKK_EC }),
            CKA_SIGN          => fill_bool(attr, if is_private { CK_TRUE } else { CK_FALSE }),
            CKA_VERIFY        => fill_bool(attr, if is_private { CK_FALSE } else { CK_TRUE }),
            CKA_LABEL         => fill_attr(attr, slot.label.as_bytes()),
            CKA_ID            => fill_attr(attr, &[slot_idx as u8]),
            CKA_EC_PARAMS     => match trezor::ec_params_der(&slot.curve) {
                Some(der) => fill_attr(attr, &der),
                None => { attr.value_len = CK_ULONG::MAX; CKR_ATTRIBUTE_TYPE_INVALID }
            },
            CKA_EC_POINT if !is_private => match state.pubkey_cache.get(&slot_idx) {
                Some(unc) => fill_attr(attr, &trezor::der_octet_string(unc)),
                None      => { attr.value_len = CK_ULONG::MAX; CKR_GENERAL_ERROR }
            },
            _ => { attr.value_len = CK_ULONG::MAX; CKR_ATTRIBUTE_TYPE_INVALID }
        };
        if r != CKR_OK && rv == CKR_OK { rv = r; }
    }
    rv
}

// ── Signing ───────────────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn C_SignInit(
    handle: CK_SESSION_HANDLE,
    mechanism: *const CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    if mechanism.is_null() { return CKR_ARGUMENTS_BAD; }
    let mech = (*mechanism).mechanism;
    if mech != CKM_ECDSA && mech != CKM_ECDSA_SHA256 && mech != CKM_EDDSA { return CKR_MECHANISM_INVALID; }
    if !handle_is_private(key) { return CKR_KEY_TYPE_INCONSISTENT; }
    let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
    let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
    let Some(session) = state.sessions.get_mut(&handle) else { return CKR_SESSION_HANDLE_INVALID };
    if session.sign_mechanism.is_some() { return CKR_OPERATION_ACTIVE; }
    session.sign_mechanism = Some(mech);
    session.sign_key = Some(key);
    CKR_OK
}

#[no_mangle]
pub unsafe extern "C" fn C_Sign(
    handle: CK_SESSION_HANDLE,
    data: *const CK_BYTE,
    data_len: CK_ULONG,
    sig: *mut CK_BYTE,
    sig_len: *mut CK_ULONG,
) -> CK_RV {
    if data.is_null() || sig_len.is_null() { return CKR_ARGUMENTS_BAD; }
    if sig.is_null() { *sig_len = 64; return CKR_OK; }       // size query
    if *sig_len < 64 { *sig_len = 64; return CKR_BUFFER_TOO_SMALL; }

    let (uri, curve, mechanism) = {
        let Ok(mut guard) = STATE.lock() else { return CKR_GENERAL_ERROR };
        let Some(state) = guard.as_mut() else { return CKR_CRYPTOKI_NOT_INITIALIZED };
        let Some(session) = state.sessions.get_mut(&handle) else { return CKR_SESSION_HANDLE_INVALID };
        let Some(mech) = session.sign_mechanism.take() else { return CKR_OPERATION_NOT_INITIALIZED };
        let key = session.sign_key.take().unwrap_or(0);
        let Some(slot_idx) = handle_to_slot(key) else { return CKR_KEY_HANDLE_INVALID };
        let Some(slot) = state.slots.get(slot_idx) else { return CKR_KEY_HANDLE_INVALID };
        (slot.uri.clone(), slot.curve.clone(), mech)
    };

    let input = std::slice::from_raw_parts(data, data_len as usize);

    // Build the challenge to send as challenge_hidden on the wire.
    // CKM_ECDSA:        caller provides SHA256(msg) — pass 32 bytes verbatim.
    // CKM_ECDSA_SHA256: caller provides raw msg — hash it here first.
    // CKM_EDDSA:        caller provides raw msg — pass verbatim; Ed25519 hashes internally.
    let challenge: Vec<u8> = match mechanism {
        CKM_ECDSA_SHA256 => Sha256::digest(input).to_vec(),
        CKM_ECDSA        => { if input.len() != 32 { return CKR_DATA_LEN_RANGE; } input.to_vec() }
        _                => input.to_vec(), // CKM_EDDSA: pass raw data
    };

    match trezor_sign_raw(&uri, &curve, &challenge) {
        Ok(raw_sig) => {
            if raw_sig.len() < 65 { return CKR_DEVICE_ERROR; }
            // raw_sig = 0x00 + r(32) + s(32)
            std::slice::from_raw_parts_mut(sig, 64)
                .copy_from_slice(&raw_sig[1..65]);
            *sig_len = 64;
            CKR_OK
        }
        Err(trezor::TrezorError::UserCancelled) => CKR_FUNCTION_CANCELED,
        Err(e) => { eprintln!("trezor-pkcs11: sign: {}", e); CKR_DEVICE_ERROR }
    }
}

// ── Device sign with pre-hashed challenge ─────────────────────────────────────
//
// Delegates to trezor::sign_identity_raw which uses the proper Transport
// abstraction (USB bulk for Safe 3/Model T, HID for Trezor One).

fn trezor_sign_raw(uri: &str, curve: &str, hash32: &[u8]) -> Result<Vec<u8>, trezor::TrezorError> {
    trezor::sign_identity_raw(uri, curve, hash32)
}
