//! Minimal PKCS#11 (Cryptoki) v2.40 C types for implementing a provider.
//!
//! Only the subset needed for signing (SSH, git, OpenSSL) is defined here.
//! All integer types follow the LP64 model (Linux x86-64).

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_ulong;

pub type CK_BYTE        = u8;
pub type CK_CHAR        = u8;
pub type CK_UTF8CHAR    = u8;
pub type CK_BBOOL       = u8;
pub type CK_ULONG       = c_ulong;
pub type CK_LONG        = i64;
pub type CK_FLAGS       = CK_ULONG;

pub type CK_SLOT_ID         = CK_ULONG;
pub type CK_SESSION_HANDLE  = CK_ULONG;
pub type CK_OBJECT_HANDLE   = CK_ULONG;
pub type CK_MECHANISM_TYPE  = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE  = CK_ULONG;
pub type CK_OBJECT_CLASS    = CK_ULONG;
pub type CK_KEY_TYPE        = CK_ULONG;
pub type CK_USER_TYPE       = CK_ULONG;
pub type CK_STATE           = CK_ULONG;
pub type CK_RV              = CK_ULONG;

// ── CK_BBOOL ────────────────────────────────────────────────────────────────
pub const CK_TRUE:  CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;

// ── CK_RV return codes ───────────────────────────────────────────────────────
pub const CKR_OK:                       CK_RV = 0x00000000;
pub const CKR_CANCEL:                   CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY:              CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID:          CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR:            CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED:          CK_RV = 0x00000006;
pub const CKR_ARGUMENTS_BAD:            CK_RV = 0x00000007;
pub const CKR_NO_EVENT:                 CK_RV = 0x00000008;
pub const CKR_NEED_TO_CREATE_THREADS:   CK_RV = 0x00000009;
pub const CKR_CANT_LOCK:                CK_RV = 0x0000000A;
pub const CKR_ATTRIBUTE_READ_ONLY:      CK_RV = 0x00000010;
pub const CKR_ATTRIBUTE_TYPE_INVALID:   CK_RV = 0x00000012;
pub const CKR_ATTRIBUTE_VALUE_INVALID:  CK_RV = 0x00000013;
pub const CKR_DATA_INVALID:             CK_RV = 0x00000020;
pub const CKR_DATA_LEN_RANGE:          CK_RV = 0x00000021;
pub const CKR_DEVICE_ERROR:             CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY:           CK_RV = 0x00000031;
pub const CKR_DEVICE_REMOVED:          CK_RV = 0x00000032;
pub const CKR_FUNCTION_CANCELED:       CK_RV = 0x00000050;
pub const CKR_FUNCTION_NOT_PARALLEL:   CK_RV = 0x00000051;
pub const CKR_FUNCTION_NOT_SUPPORTED:  CK_RV = 0x00000054;
pub const CKR_KEY_HANDLE_INVALID:      CK_RV = 0x00000060;
pub const CKR_KEY_TYPE_INCONSISTENT:   CK_RV = 0x00000063;
pub const CKR_MECHANISM_INVALID:       CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x00000071;
pub const CKR_OBJECT_HANDLE_INVALID:   CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE:        CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT:           CK_RV = 0x000000A0;
pub const CKR_PIN_INVALID:             CK_RV = 0x000000A1;
pub const CKR_PIN_LEN_RANGE:           CK_RV = 0x000000A2;
pub const CKR_PIN_EXPIRED:             CK_RV = 0x000000A3;
pub const CKR_PIN_LOCKED:              CK_RV = 0x000000A4;
pub const CKR_SESSION_CLOSED:          CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT:           CK_RV = 0x000000B1;
pub const CKR_SESSION_HANDLE_INVALID:  CK_RV = 0x000000B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x000000B4;
pub const CKR_SESSION_READ_ONLY:       CK_RV = 0x000000B5;
pub const CKR_SESSION_EXISTS:          CK_RV = 0x000000B6;
pub const CKR_SESSION_READ_ONLY_EXISTS: CK_RV = 0x000000B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: CK_RV = 0x000000B8;
pub const CKR_SIGNATURE_INVALID:       CK_RV = 0x000000C0;
pub const CKR_SIGNATURE_LEN_RANGE:     CK_RV = 0x000000C1;
pub const CKR_TEMPLATE_INCOMPLETE:     CK_RV = 0x000000D0;
pub const CKR_TEMPLATE_INCONSISTENT:   CK_RV = 0x000000D1;
pub const CKR_TOKEN_NOT_PRESENT:       CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED:    CK_RV = 0x000000E1;
pub const CKR_TOKEN_WRITE_PROTECTED:   CK_RV = 0x000000E2;
pub const CKR_USER_ALREADY_LOGGED_IN:  CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN:      CK_RV = 0x00000101;
pub const CKR_USER_PIN_NOT_INITIALIZED: CK_RV = 0x00000102;
pub const CKR_USER_TYPE_INVALID:       CK_RV = 0x00000103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: CK_RV = 0x00000104;
pub const CKR_USER_TOO_MANY_TYPES:     CK_RV = 0x00000105;
pub const CKR_BUFFER_TOO_SMALL:        CK_RV = 0x00000150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;
pub const CKR_MUTEX_BAD:               CK_RV = 0x000001A0;
pub const CKR_MUTEX_NOT_LOCKED:        CK_RV = 0x000001A1;

// ── CK_FLAGS token/slot flags ────────────────────────────────────────────────
pub const CKF_RNG:                  CK_FLAGS = 0x00000001;
pub const CKF_WRITE_PROTECTED:      CK_FLAGS = 0x00000002;
pub const CKF_LOGIN_REQUIRED:       CK_FLAGS = 0x00000004;
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x00000008;
pub const CKF_RESTORE_KEY_NOT_NEEDED: CK_FLAGS = 0x00000020;
pub const CKF_CLOCK_ON_TOKEN:       CK_FLAGS = 0x00000040;
pub const CKF_PROTECTED_AUTHENTICATION_PATH: CK_FLAGS = 0x00000100;
pub const CKF_DUAL_CRYPTO_OPERATIONS: CK_FLAGS = 0x00000200;
pub const CKF_TOKEN_INITIALIZED:    CK_FLAGS = 0x00000400;
pub const CKF_TOKEN_PRESENT:        CK_FLAGS = 0x00000001; // slot flag
pub const CKF_REMOVABLE_DEVICE:     CK_FLAGS = 0x00000002; // slot flag
pub const CKF_HW_SLOT:              CK_FLAGS = 0x00000004; // slot flag
pub const CKF_SERIAL_SESSION:       CK_FLAGS = 0x00000004; // session flag
pub const CKF_RW_SESSION:           CK_FLAGS = 0x00000002; // session flag
pub const CKF_HW:                   CK_FLAGS = 0x00000001; // mechanism flag
pub const CKF_SIGN:                 CK_FLAGS = 0x00000200; // mechanism flag

// ── CK_USER_TYPE ─────────────────────────────────────────────────────────────
pub const CKU_SO:   CK_USER_TYPE = 0;
pub const CKU_USER: CK_USER_TYPE = 1;

// ── CK_STATE ─────────────────────────────────────────────────────────────────
pub const CKS_RO_PUBLIC_SESSION:  CK_STATE = 0;
pub const CKS_RO_USER_FUNCTIONS:  CK_STATE = 1;
pub const CKS_RW_PUBLIC_SESSION:  CK_STATE = 2;
pub const CKS_RW_USER_FUNCTIONS:  CK_STATE = 3;
pub const CKS_RW_SO_FUNCTIONS:    CK_STATE = 4;

// ── CK_OBJECT_CLASS ──────────────────────────────────────────────────────────
pub const CKO_DATA:          CK_OBJECT_CLASS = 0x00000000;
pub const CKO_CERTIFICATE:   CK_OBJECT_CLASS = 0x00000001;
pub const CKO_PUBLIC_KEY:    CK_OBJECT_CLASS = 0x00000002;
pub const CKO_PRIVATE_KEY:   CK_OBJECT_CLASS = 0x00000003;
pub const CKO_SECRET_KEY:    CK_OBJECT_CLASS = 0x00000004;

// ── CK_KEY_TYPE ──────────────────────────────────────────────────────────────
pub const CKK_RSA:       CK_KEY_TYPE = 0x00000000;
pub const CKK_EC:        CK_KEY_TYPE = 0x00000003;
pub const CKK_EC_EDWARDS: CK_KEY_TYPE = 0x00000040; // Ed25519

// ── CK_ATTRIBUTE_TYPE ────────────────────────────────────────────────────────
pub const CKA_CLASS:          CK_ATTRIBUTE_TYPE = 0x00000000;
pub const CKA_TOKEN:          CK_ATTRIBUTE_TYPE = 0x00000001;
pub const CKA_PRIVATE:        CK_ATTRIBUTE_TYPE = 0x00000002;
pub const CKA_LABEL:          CK_ATTRIBUTE_TYPE = 0x00000003;
pub const CKA_KEY_TYPE:       CK_ATTRIBUTE_TYPE = 0x00000100;
pub const CKA_ID:             CK_ATTRIBUTE_TYPE = 0x00000102;
pub const CKA_SENSITIVE:      CK_ATTRIBUTE_TYPE = 0x00000103;
pub const CKA_ENCRYPT:        CK_ATTRIBUTE_TYPE = 0x00000104;
pub const CKA_DECRYPT:        CK_ATTRIBUTE_TYPE = 0x00000105;
pub const CKA_WRAP:           CK_ATTRIBUTE_TYPE = 0x00000106;
pub const CKA_UNWRAP:         CK_ATTRIBUTE_TYPE = 0x00000107;
pub const CKA_SIGN:           CK_ATTRIBUTE_TYPE = 0x00000108;
pub const CKA_VERIFY:         CK_ATTRIBUTE_TYPE = 0x0000010A;
pub const CKA_DERIVE:         CK_ATTRIBUTE_TYPE = 0x0000010C;
pub const CKA_EXTRACTABLE:    CK_ATTRIBUTE_TYPE = 0x00000162;
pub const CKA_NEVER_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x00000164;
pub const CKA_ALWAYS_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x00000165;
pub const CKA_EC_PARAMS:      CK_ATTRIBUTE_TYPE = 0x00000180;
pub const CKA_EC_POINT:       CK_ATTRIBUTE_TYPE = 0x00000181;

// ── CK_MECHANISM_TYPE ────────────────────────────────────────────────────────
pub const CKM_ECDSA:          CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA256:   CK_MECHANISM_TYPE = 0x00001044;
pub const CKM_EDDSA:          CK_MECHANISM_TYPE = 0x00001057;

// ── Structs ──────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
pub struct CK_INFO {
    pub cryptoki_version:    CK_VERSION,
    pub manufacturer_id:     [CK_UTF8CHAR; 32], // space-padded
    pub flags:               CK_FLAGS,
    pub library_description: [CK_UTF8CHAR; 32], // space-padded
    pub library_version:     CK_VERSION,
}

#[repr(C)]
pub struct CK_SLOT_INFO {
    pub slot_description: [CK_UTF8CHAR; 64], // space-padded
    pub manufacturer_id:  [CK_UTF8CHAR; 32], // space-padded
    pub flags:            CK_FLAGS,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
}

#[repr(C)]
pub struct CK_TOKEN_INFO {
    pub label:               [CK_UTF8CHAR; 32], // space-padded
    pub manufacturer_id:     [CK_UTF8CHAR; 32], // space-padded
    pub model:               [CK_UTF8CHAR; 16], // space-padded
    pub serial_number:       [CK_CHAR; 16],     // space-padded
    pub flags:               CK_FLAGS,
    pub max_session_count:   CK_ULONG,
    pub session_count:       CK_ULONG,
    pub max_rw_session_count: CK_ULONG,
    pub rw_session_count:    CK_ULONG,
    pub max_pin_len:         CK_ULONG,
    pub min_pin_len:         CK_ULONG,
    pub total_public_memory: CK_ULONG,
    pub free_public_memory:  CK_ULONG,
    pub total_private_memory: CK_ULONG,
    pub free_private_memory: CK_ULONG,
    pub hardware_version:    CK_VERSION,
    pub firmware_version:    CK_VERSION,
    pub utc_time:            [CK_CHAR; 16], // space-padded
}

#[repr(C)]
pub struct CK_SESSION_INFO {
    pub slot_id:        CK_SLOT_ID,
    pub state:          CK_STATE,
    pub flags:          CK_FLAGS,
    pub device_error:   CK_ULONG,
}

#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub attr_type: CK_ATTRIBUTE_TYPE,
    pub value:     *mut std::ffi::c_void,
    pub value_len: CK_ULONG,
}

#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism:        CK_MECHANISM_TYPE,
    pub parameter:        *const std::ffi::c_void,
    pub parameter_len:    CK_ULONG,
}

#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub min_key_size: CK_ULONG,
    pub max_key_size: CK_ULONG,
    pub flags:        CK_FLAGS,
}

/// Helper: write a UTF-8 string into a space-padded fixed-length buffer.
pub fn pad_str(buf: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    for b in &mut buf[n..] {
        *b = b' ';
    }
}

// ── CK_FUNCTION_LIST ─────────────────────────────────────────────────────────
// Each function pointer is Option<unsafe extern "C" fn(...)> so we can fill
// unsupported slots with None.

pub type CK_C_Initialize            = unsafe extern "C" fn(*mut std::ffi::c_void) -> CK_RV;
pub type CK_C_Finalize              = unsafe extern "C" fn(*mut std::ffi::c_void) -> CK_RV;
pub type CK_C_GetInfo               = unsafe extern "C" fn(*mut CK_INFO) -> CK_RV;
pub type CK_C_GetFunctionList       = unsafe extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV;
pub type CK_C_GetSlotList           = unsafe extern "C" fn(CK_BBOOL, *mut CK_SLOT_ID, *mut CK_ULONG) -> CK_RV;
pub type CK_C_GetSlotInfo           = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV;
pub type CK_C_GetTokenInfo          = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV;
pub type CK_C_GetMechanismList      = unsafe extern "C" fn(CK_SLOT_ID, *mut CK_MECHANISM_TYPE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_GetMechanismInfo      = unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV;
pub type CK_C_InitToken             = unsafe extern "C" fn(CK_SLOT_ID, *const CK_UTF8CHAR, CK_ULONG, *const CK_UTF8CHAR) -> CK_RV;
pub type CK_C_InitPIN               = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV;
pub type CK_C_SetPIN                = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_UTF8CHAR, CK_ULONG, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV;
pub type CK_C_OpenSession           = unsafe extern "C" fn(CK_SLOT_ID, CK_FLAGS, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CloseSession          = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CloseAllSessions      = unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV;
pub type CK_C_GetSessionInfo        = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV;
pub type CK_C_GetOperationState     = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SetOperationState     = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Login                 = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, *const CK_UTF8CHAR, CK_ULONG) -> CK_RV;
pub type CK_C_Logout                = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CreateObject          = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_CopyObject            = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_DestroyObject         = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_GetObjectSize         = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_GetAttributeValue     = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
pub type CK_C_SetAttributeValue     = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *const CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
pub type CK_C_FindObjectsInit       = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_ATTRIBUTE, CK_ULONG) -> CK_RV;
pub type CK_C_FindObjects           = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_OBJECT_HANDLE, CK_ULONG, *mut CK_ULONG) -> CK_RV;
pub type CK_C_FindObjectsFinal      = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_EncryptInit           = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Encrypt               = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_EncryptUpdate         = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_EncryptFinal          = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DecryptInit           = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Decrypt               = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DecryptUpdate         = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DecryptFinal          = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DigestInit            = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM) -> CK_RV;
pub type CK_C_Digest                = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DigestUpdate          = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_DigestKey             = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_DigestFinal           = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SignInit              = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Sign                  = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SignUpdate            = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_SignFinal             = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SignRecoverInit       = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_SignRecover           = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_VerifyInit            = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_Verify                = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *const CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyUpdate          = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyFinal           = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_VerifyRecoverInit     = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_VerifyRecover         = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DigestEncryptUpdate   = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DecryptDigestUpdate   = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_SignEncryptUpdate      = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_DecryptVerifyUpdate   = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_GenerateKey           = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_GenerateKeyPair       = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, *const CK_ATTRIBUTE, CK_ULONG, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE, *mut CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_WrapKey               = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, *mut CK_BYTE, *mut CK_ULONG) -> CK_RV;
pub type CK_C_UnwrapKey             = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, *const CK_BYTE, CK_ULONG, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_DeriveKey             = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_MECHANISM, CK_OBJECT_HANDLE, *const CK_ATTRIBUTE, CK_ULONG, *mut CK_OBJECT_HANDLE) -> CK_RV;
pub type CK_C_SeedRandom            = unsafe extern "C" fn(CK_SESSION_HANDLE, *const CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_GenerateRandom        = unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_BYTE, CK_ULONG) -> CK_RV;
pub type CK_C_GetFunctionStatus     = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_CancelFunction        = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type CK_C_WaitForSlotEvent      = unsafe extern "C" fn(CK_FLAGS, *mut CK_SLOT_ID, *mut std::ffi::c_void) -> CK_RV;

#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version:                  CK_VERSION,
    pub C_Initialize:             Option<CK_C_Initialize>,
    pub C_Finalize:               Option<CK_C_Finalize>,
    pub C_GetInfo:                Option<CK_C_GetInfo>,
    pub C_GetFunctionList:        Option<CK_C_GetFunctionList>,
    pub C_GetSlotList:            Option<CK_C_GetSlotList>,
    pub C_GetSlotInfo:            Option<CK_C_GetSlotInfo>,
    pub C_GetTokenInfo:           Option<CK_C_GetTokenInfo>,
    pub C_GetMechanismList:       Option<CK_C_GetMechanismList>,
    pub C_GetMechanismInfo:       Option<CK_C_GetMechanismInfo>,
    pub C_InitToken:              Option<CK_C_InitToken>,
    pub C_InitPIN:                Option<CK_C_InitPIN>,
    pub C_SetPIN:                 Option<CK_C_SetPIN>,
    pub C_OpenSession:            Option<CK_C_OpenSession>,
    pub C_CloseSession:           Option<CK_C_CloseSession>,
    pub C_CloseAllSessions:       Option<CK_C_CloseAllSessions>,
    pub C_GetSessionInfo:         Option<CK_C_GetSessionInfo>,
    pub C_GetOperationState:      Option<CK_C_GetOperationState>,
    pub C_SetOperationState:      Option<CK_C_SetOperationState>,
    pub C_Login:                  Option<CK_C_Login>,
    pub C_Logout:                 Option<CK_C_Logout>,
    pub C_CreateObject:           Option<CK_C_CreateObject>,
    pub C_CopyObject:             Option<CK_C_CopyObject>,
    pub C_DestroyObject:          Option<CK_C_DestroyObject>,
    pub C_GetObjectSize:          Option<CK_C_GetObjectSize>,
    pub C_GetAttributeValue:      Option<CK_C_GetAttributeValue>,
    pub C_SetAttributeValue:      Option<CK_C_SetAttributeValue>,
    pub C_FindObjectsInit:        Option<CK_C_FindObjectsInit>,
    pub C_FindObjects:            Option<CK_C_FindObjects>,
    pub C_FindObjectsFinal:       Option<CK_C_FindObjectsFinal>,
    pub C_EncryptInit:            Option<CK_C_EncryptInit>,
    pub C_Encrypt:                Option<CK_C_Encrypt>,
    pub C_EncryptUpdate:          Option<CK_C_EncryptUpdate>,
    pub C_EncryptFinal:           Option<CK_C_EncryptFinal>,
    pub C_DecryptInit:            Option<CK_C_DecryptInit>,
    pub C_Decrypt:                Option<CK_C_Decrypt>,
    pub C_DecryptUpdate:          Option<CK_C_DecryptUpdate>,
    pub C_DecryptFinal:           Option<CK_C_DecryptFinal>,
    pub C_DigestInit:             Option<CK_C_DigestInit>,
    pub C_Digest:                 Option<CK_C_Digest>,
    pub C_DigestUpdate:           Option<CK_C_DigestUpdate>,
    pub C_DigestKey:              Option<CK_C_DigestKey>,
    pub C_DigestFinal:            Option<CK_C_DigestFinal>,
    pub C_SignInit:               Option<CK_C_SignInit>,
    pub C_Sign:                   Option<CK_C_Sign>,
    pub C_SignUpdate:             Option<CK_C_SignUpdate>,
    pub C_SignFinal:              Option<CK_C_SignFinal>,
    pub C_SignRecoverInit:        Option<CK_C_SignRecoverInit>,
    pub C_SignRecover:            Option<CK_C_SignRecover>,
    pub C_VerifyInit:             Option<CK_C_VerifyInit>,
    pub C_Verify:                 Option<CK_C_Verify>,
    pub C_VerifyUpdate:           Option<CK_C_VerifyUpdate>,
    pub C_VerifyFinal:            Option<CK_C_VerifyFinal>,
    pub C_VerifyRecoverInit:      Option<CK_C_VerifyRecoverInit>,
    pub C_VerifyRecover:          Option<CK_C_VerifyRecover>,
    pub C_DigestEncryptUpdate:    Option<CK_C_DigestEncryptUpdate>,
    pub C_DecryptDigestUpdate:    Option<CK_C_DecryptDigestUpdate>,
    pub C_SignEncryptUpdate:      Option<CK_C_SignEncryptUpdate>,
    pub C_DecryptVerifyUpdate:    Option<CK_C_DecryptVerifyUpdate>,
    pub C_GenerateKey:            Option<CK_C_GenerateKey>,
    pub C_GenerateKeyPair:        Option<CK_C_GenerateKeyPair>,
    pub C_WrapKey:                Option<CK_C_WrapKey>,
    pub C_UnwrapKey:              Option<CK_C_UnwrapKey>,
    pub C_DeriveKey:              Option<CK_C_DeriveKey>,
    pub C_SeedRandom:             Option<CK_C_SeedRandom>,
    pub C_GenerateRandom:         Option<CK_C_GenerateRandom>,
    pub C_GetFunctionStatus:      Option<CK_C_GetFunctionStatus>,
    pub C_CancelFunction:         Option<CK_C_CancelFunction>,
    pub C_WaitForSlotEvent:       Option<CK_C_WaitForSlotEvent>,
}
