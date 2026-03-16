//! Trezor USB HID communication + protobuf encode/decode.
//!
//! Wire protocol: protocol v1, 64-byte HID chunks.
//!
//! Packet layout (what we write — 65 bytes total with hidapi hidraw):
//!   [0]     = 0x00  (report ID for HID v2 / hidraw)
//!   [1]     = '?'   (0x3f, chunk magic)
//!   [2..64] = payload (63 bytes, zero-padded)
//!
//! First chunk payload:
//!   [0..1]  = "##"
//!   [2..3]  = msg_type (big-endian u16)
//!   [4..7]  = data length (big-endian u32)
//!   [8..62] = first 55 bytes of protobuf data
//!
//! Continuation chunk payload:
//!   [0..62] = next 63 bytes of protobuf data

use hidapi::{HidApi, HidDevice};
use prost::Message;
use rusb::UsbContext as _;
use sha2::{Digest, Sha256};
use std::time::Duration;

// Trezor USB identifiers
const TREZOR_VID_T1: u16 = 0x534c;
const TREZOR_PID_T1: u16 = 0x0001;
const TREZOR_VID_T2: u16 = 0x1209;
const TREZOR_PID_T2: u16 = 0x53c1;

// USB bulk transport constants (Trezor T / Safe 3 / Safe 5 WebUSB bridge)
const USB_IFACE:  u8 = 0;
const USB_EP_OUT: u8 = 0x01;
const USB_EP_IN:  u8 = 0x81;
const USB_TIMEOUT: Duration = Duration::from_secs(60);

// Trezor wire message type IDs
const MSG_FAILURE:          u16 = 3;
const MSG_BUTTON_REQUEST:   u16 = 26;
const MSG_BUTTON_ACK:       u16 = 27;
const MSG_PASSPHRASE_REQUEST: u16 = 41;
const MSG_PASSPHRASE_ACK:   u16 = 42;
const MSG_SIGN_IDENTITY:    u16 = 53;
const MSG_SIGNED_IDENTITY:  u16 = 54;

// Prost-generated types from messages-crypto.proto and messages-common.proto.
// Included from $OUT_DIR set by build.rs.
pub mod proto {
    pub mod crypto {
        #![allow(dead_code)]
        include!(concat!(env!("OUT_DIR"), "/hw.trezor.messages.crypto.rs"));
    }
    pub mod common {
        #![allow(dead_code)]
        include!(concat!(env!("OUT_DIR"), "/hw.trezor.messages.common.rs"));
    }
}

#[derive(Debug)]
pub enum TrezorError {
    NoDevice,
    Hid(hidapi::HidError),
    Protocol(String),
    DeviceFailure(String),
    UserCancelled,
}

impl std::fmt::Display for TrezorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDevice        => write!(f, "no Trezor device found"),
            Self::Hid(e)          => write!(f, "HID error: {}", e),
            Self::Protocol(s)     => write!(f, "protocol error: {}", s),
            Self::DeviceFailure(s)=> write!(f, "device failure: {}", s),
            Self::UserCancelled   => write!(f, "cancelled by user"),
        }
    }
}

impl From<hidapi::HidError> for TrezorError {
    fn from(e: hidapi::HidError) -> Self { Self::Hid(e) }
}

// ── Transport abstraction ─────────────────────────────────────────────────────
//
// Trezor One (0x534c:0x0001) uses a HID bridge — we talk to it via hidapi.
// Trezor T / Safe 3 / Safe 5 (0x1209:0x53c1) use a WebUSB bulk bridge on
// interface 0; the only HID interface they expose is FIDO (iface 1, 0xF1D0).

enum Transport {
    Hid(HidDevice),
    Usb(rusb::DeviceHandle<rusb::Context>),
}

// ── Device open ──────────────────────────────────────────────────────────────

fn open_device() -> Result<Transport, TrezorError> {
    // Trezor T / Safe 3 / Safe 5: USB bulk on interface 0.
    if let Ok(ctx) = rusb::Context::new() {
        if let Ok(list) = ctx.devices() {
            for dev in list.iter() {
                let Ok(desc) = dev.device_descriptor() else { continue };
                if desc.vendor_id() != TREZOR_VID_T2 || desc.product_id() != TREZOR_PID_T2 {
                    continue;
                }
                let Ok(handle) = dev.open() else { continue };
                // Detach any kernel driver on the bridge interface (usually none).
                let _ = handle.set_auto_detach_kernel_driver(true);
                if handle.claim_interface(USB_IFACE as u8).is_ok() {
                    return Ok(Transport::Usb(handle));
                }
            }
        }
    }

    // Trezor One: HID bridge.
    let api = HidApi::new()?;
    for info in api.device_list() {
        if info.vendor_id() == TREZOR_VID_T1 && info.product_id() == TREZOR_PID_T1 {
            return Ok(Transport::Hid(info.open_device(&api)?));
        }
    }

    Err(TrezorError::NoDevice)
}

// ── Wire framing ─────────────────────────────────────────────────────────────
//
// Protocol v1: chunks of 63 payload bytes, each prefixed with '?'.
// HID write:  65 bytes = 0x00 (report ID) + '?' + 63 bytes payload
// USB write:  64 bytes = '?' + 63 bytes payload
// Both read:  64 bytes starting with '?'

fn write_message(dev: &Transport, msg_type: u16, data: &[u8]) -> Result<(), TrezorError> {
    let mut stream = Vec::with_capacity(8 + data.len());
    stream.extend_from_slice(b"##");
    stream.extend_from_slice(&msg_type.to_be_bytes());
    stream.extend_from_slice(&(data.len() as u32).to_be_bytes());
    stream.extend_from_slice(data);

    for chunk in stream.chunks(63) {
        match dev {
            Transport::Hid(hid) => {
                let mut packet = [0u8; 65];
                packet[0] = 0x00; // report ID for hidraw
                packet[1] = b'?';
                packet[2..2 + chunk.len()].copy_from_slice(chunk);
                hid.write(&packet)?;
            }
            Transport::Usb(handle) => {
                let mut packet = [0u8; 64];
                packet[0] = b'?';
                packet[1..1 + chunk.len()].copy_from_slice(chunk);
                handle.write_bulk(USB_EP_OUT, &packet, USB_TIMEOUT)
                    .map_err(|e| TrezorError::Protocol(e.to_string()))?;
            }
        }
    }
    Ok(())
}

fn read_message(dev: &Transport) -> Result<(u16, Vec<u8>), TrezorError> {
    let first = read_chunk(dev)?;
    if first[0] != b'?' {
        return Err(TrezorError::Protocol(format!("bad chunk magic: 0x{:02x}", first[0])));
    }
    if &first[1..3] != b"##" {
        return Err(TrezorError::Protocol("missing ## header".into()));
    }
    let msg_type = u16::from_be_bytes([first[3], first[4]]);
    let data_len = u32::from_be_bytes([first[5], first[6], first[7], first[8]]) as usize;

    let mut buf = Vec::with_capacity(data_len);
    buf.extend_from_slice(&first[9..]);

    while buf.len() < data_len {
        let chunk = read_chunk(dev)?;
        if chunk[0] != b'?' {
            return Err(TrezorError::Protocol("bad continuation magic".into()));
        }
        buf.extend_from_slice(&chunk[1..]);
    }
    buf.truncate(data_len);
    Ok((msg_type, buf))
}

fn read_chunk(dev: &Transport) -> Result<[u8; 64], TrezorError> {
    let mut buf = [0u8; 64];
    match dev {
        Transport::Hid(hid) => {
            loop {
                let n = hid.read(&mut buf)?;
                if n > 0 { break; }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Transport::Usb(handle) => {
            handle.read_bulk(USB_EP_IN, &mut buf, USB_TIMEOUT)
                .map_err(|e| TrezorError::Protocol(e.to_string()))?;
        }
    }
    Ok(buf)
}

// ── High-level operations ─────────────────────────────────────────────────────

/// Send a SignIdentity request and wait for the signed response, handling
/// button/passphrase prompts in the loop.  Returns `(pubkey, signature)`.
fn send_sign_identity(
    dev: &Transport,
    req: proto::crypto::SignIdentity,
) -> Result<(Vec<u8>, Vec<u8>), TrezorError> {
    write_message(dev, MSG_SIGN_IDENTITY, &req.encode_to_vec())?;
    loop {
        let (msg_type, msg_bytes) = read_message(dev)?;
        match msg_type {
            MSG_SIGNED_IDENTITY => {
                let resp = proto::crypto::SignedIdentity::decode(msg_bytes.as_slice())
                    .map_err(|e| TrezorError::Protocol(e.to_string()))?;
                return Ok((resp.public_key, resp.signature));
            }
            MSG_BUTTON_REQUEST => {
                let ack = proto::common::ButtonAck {};
                write_message(dev, MSG_BUTTON_ACK, &ack.encode_to_vec())?;
            }
            MSG_PASSPHRASE_REQUEST => {
                let ack = proto::common::PassphraseAck {
                    passphrase: None,
                    on_device: Some(true),
                    ..Default::default()
                };
                write_message(dev, MSG_PASSPHRASE_ACK, &ack.encode_to_vec())?;
            }
            MSG_FAILURE => {
                let fail = proto::common::Failure::decode(msg_bytes.as_slice())
                    .map_err(|e| TrezorError::Protocol(e.to_string()))?;
                if fail.code == Some(4) { return Err(TrezorError::UserCancelled); }
                return Err(TrezorError::DeviceFailure(fail.message.unwrap_or_default()));
            }
            other => return Err(TrezorError::Protocol(
                format!("unexpected message type {}", other))),
        }
    }
}

/// Sign data with a Trezor identity, hashing for ECDSA curves automatically.
///
/// For ECDSA curves (nist256p1, secp256k1), `data` is SHA-256 hashed before
/// being sent as challenge_hidden.  For ed25519, `data` is passed raw.
///
/// Returns `(compressed_pubkey, raw_signature)`.
pub fn sign_identity(
    uri: &str,
    curve: &str,
    data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), TrezorError> {
    let dev = open_device()?;
    let challenge_hidden = if curve == "ed25519" {
        data.to_vec()
    } else {
        Sha256::digest(data).to_vec()
    };
    let req = proto::crypto::SignIdentity {
        identity:         parse_uri(uri),
        challenge_hidden: Some(challenge_hidden),
        challenge_visual: Some(String::new()),
        ecdsa_curve_name: Some(curve.to_string()),
    };
    send_sign_identity(&dev, req)
}

/// Sign with a pre-hashed 32-byte challenge sent verbatim as challenge_hidden.
///
/// Use this from PKCS#11 C_Sign where the caller already controls hashing
/// (CKM_ECDSA passes a pre-hashed digest; CKM_ECDSA_SHA256 hashes in C_Sign
/// before calling here).  Returns only the raw signature bytes.
pub fn sign_identity_raw(
    uri: &str,
    curve: &str,
    hash32: &[u8],
) -> Result<Vec<u8>, TrezorError> {
    let dev = open_device()?;
    let req = proto::crypto::SignIdentity {
        identity:         parse_uri(uri),
        challenge_hidden: Some(hash32.to_vec()),
        challenge_visual: Some(String::new()),
        ecdsa_curve_name: Some(curve.to_string()),
    };
    let (_pubkey, sig) = send_sign_identity(&dev, req)?;
    Ok(sig)
}

/// Get the public key for a URI/curve without signing anything meaningful.
///
/// Uses a deterministic dummy challenge so the key derivation is stable.
pub fn get_public_key(uri: &str, curve: &str) -> Result<Vec<u8>, TrezorError> {
    // Deterministic dummy: SHA-256 of a fixed string. Never all-zeros (Safe 3 rejects that).
    let dummy = Sha256::digest(
        format!("trezor-pkcs11:get-public-key:{}", uri).as_bytes()
    );
    let (pubkey, _sig) = sign_identity(uri, curve, &dummy)?;
    Ok(pubkey)
}

// ── URI parsing ──────────────────────────────────────────────────────────────

fn parse_uri(uri: &str) -> proto::crypto::IdentityType {
    // gpg://user@host:port
    let rest = uri.strip_prefix("gpg://").unwrap_or(uri);
    let (user, host_port) = if let Some(pos) = rest.find('@') {
        (&rest[..pos], &rest[pos + 1..])
    } else {
        ("", rest)
    };
    let (host, port) = if let Some(pos) = host_port.rfind(':') {
        (&host_port[..pos], &host_port[pos + 1..])
    } else {
        (host_port, "")
    };

    proto::crypto::IdentityType {
        proto:  Some("gpg".to_string()),
        user:   Some(user.to_string()),
        host:   Some(host.to_string()),
        port:   if port.is_empty() { None } else { Some(port.to_string()) },
        path:   None,
        index:  Some(0),
    }
}

// ── EC point decompression ────────────────────────────────────────────────────

/// Convert a Trezor compressed public key to an uncompressed SEC1 point.
///
/// Returns a 65-byte buffer `04 || x || y` ready to be DER-wrapped for
/// the PKCS#11 CKA_EC_POINT attribute.
pub fn decompress_pubkey(compressed: &[u8], curve: &str) -> Option<[u8; 65]> {
    if compressed.len() != 33 { return None; }
    match curve {
        "nist256p1" => decompress_p256(compressed),
        "secp256k1" => decompress_k256(compressed),
        _ => None,
    }
}

fn decompress_p256(compressed: &[u8]) -> Option<[u8; 65]> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let pt = p256::PublicKey::from_sec1_bytes(compressed).ok()?;
    let uncompressed = pt.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 { return None; }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Some(out)
}

fn decompress_k256(compressed: &[u8]) -> Option<[u8; 65]> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let pt = k256::PublicKey::from_sec1_bytes(compressed).ok()?;
    let uncompressed = pt.to_encoded_point(false);
    let bytes = uncompressed.as_bytes();
    if bytes.len() != 65 { return None; }
    let mut out = [0u8; 65];
    out.copy_from_slice(bytes);
    Some(out)
}

/// DER OCTET STRING wrapper for CKA_EC_POINT: `04 41 <65-byte uncompressed point>`
pub fn der_octet_string(data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 128, "long-form DER not needed here");
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(0x04);           // OCTET STRING tag
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    out
}

/// DER OID for the named curve, as required by CKA_EC_PARAMS.
///
/// Returns the full DER encoding: `06 <len> <oid bytes>`.
pub fn ec_params_der(curve: &str) -> Option<Vec<u8>> {
    let oid: &[u8] = match curve {
        // P-256 / secp256r1: 1.2.840.10045.3.1.7
        "nist256p1" => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        // secp256k1: 1.3.132.0.10
        "secp256k1" => &[0x2b, 0x81, 0x04, 0x00, 0x0a],
        // Ed25519: 1.3.101.112
        "ed25519"   => &[0x2b, 0x65, 0x70],
        _ => return None,
    };
    let mut out = Vec::with_capacity(2 + oid.len());
    out.push(0x06); // OID tag
    out.push(oid.len() as u8);
    out.extend_from_slice(oid);
    Some(out)
}
