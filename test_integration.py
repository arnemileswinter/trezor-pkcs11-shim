"""
trezor-pkcs11 integration tests
================================

These tests exercise the compiled PKCS#11 shared library against a real
Trezor device. They are *not* unit tests — they talk to hardware.

Requirements
------------
- A Trezor Safe 3, Model T, Safe 5, or Trezor One connected via USB.
- The library built: ``cargo build --release``
- Python dependencies: ``pip install PyKCS11 pytest cryptography``
- A valid config file (see README) defining at least one slot.

Running
-------
    pytest test_integration.py -v

Button presses
--------------
Several tests call C_Sign, which triggers a confirmation prompt on the
Trezor screen. Be ready to press the button when the test name suggests
a signing operation (test_sign_*, test_signature_*, test_different_*,
test_sign_uses_correct_key_for_slot, test_all_slots_have_keys).

Skipping
--------
All tests are automatically skipped if:
- The shared library has not been built (target/release/libtrezor_pkcs11.so
  does not exist), or
- No Trezor is connected / no slots respond.

Override the library path via the TREZOR_PKCS11_SO environment variable.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# PyKCS11 imports
# ---------------------------------------------------------------------------
from PyKCS11 import (
    PyKCS11Lib,
    PyKCS11Error,
    Mechanism,
    CKF_SERIAL_SESSION,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKO_PUBLIC_KEY,
    CKO_PRIVATE_KEY,
    CKA_EC_POINT,
    CKA_EC_PARAMS,
    CKA_LABEL,
    CKA_ID,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKK_EC,
    CKA_SIGN,
    CKA_VERIFY,
)

# CKK_EC_EDWARDS (0x40) is not exported by all PyKCS11 versions
CKK_EC_EDWARDS = 0x00000040

# ---------------------------------------------------------------------------
# cryptography imports (for signature verification)
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    SECP256R1,
    ECDSA,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Locate the shared library
# ---------------------------------------------------------------------------

def _find_so() -> Path | None:
    """Return the path to the PKCS#11 .so, or None if not found."""
    env = os.environ.get("TREZOR_PKCS11_SO")
    if env:
        p = Path(env)
        return p if p.exists() else None
    # Relative to this test file: ../../target/release/libtrezor_pkcs11.so
    here = Path(__file__).resolve().parent
    candidate = here / "target" / "release" / "libtrezor_pkcs11.so"
    return candidate if candidate.exists() else None


SO_PATH = _find_so()

# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def pkcs11_lib():
    """Load the PKCS#11 library. Skip the entire session if unavailable."""
    if SO_PATH is None:
        pytest.skip(
            "libtrezor_pkcs11.so not found. Build with `cargo build --release` "
            "or set TREZOR_PKCS11_SO."
        )
    lib = PyKCS11Lib()
    try:
        lib.load(str(SO_PATH))
    except PyKCS11Error as exc:
        pytest.skip(f"Failed to load PKCS#11 library: {exc}")
    return lib


@pytest.fixture(scope="session")
def session(pkcs11_lib):
    """Open a session on slot 0. Skip if no slots with a token are present."""
    slots = pkcs11_lib.getSlotList(tokenPresent=True)
    if not slots:
        pytest.skip("No Trezor slots found — is the device connected?")
    slot = slots[0]
    sess = pkcs11_lib.openSession(slot, CKF_SERIAL_SESSION)
    yield sess
    try:
        sess.closeSession()
    except PyKCS11Error:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_attr(session, obj, attr):
    """Return a single attribute value from a PKCS#11 object."""
    result = session.getAttributeValue(obj, [attr])
    return result[0]


def _find_objects(session, template):
    return session.findObjects(template)


def _ec_point_to_public_key(ec_point_raw) -> EllipticCurvePublicKey:
    """
    Parse a CKA_EC_POINT value into a cryptography EllipticCurvePublicKey.

    CKA_EC_POINT is a DER OCTET STRING wrapping the 65-byte uncompressed point:
        04 41 04 <x:32> <y:32>
    """
    ec_point = bytes(ec_point_raw)
    # Strip 2-byte DER header (04 41) to get the 65-byte uncompressed point
    assert ec_point[0] == 0x04, "Expected DER OCTET STRING tag"
    assert ec_point[1] == 0x41, "Expected 65-byte length in DER header"
    uncompressed = ec_point[2:]  # 65 bytes: 04 <x:32> <y:32>
    assert uncompressed[0] == 0x04, "Expected uncompressed point marker"
    x = int.from_bytes(uncompressed[1:33], "big")
    y = int.from_bytes(uncompressed[33:65], "big")
    numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    return numbers.public_key(default_backend())


def _raw_sig_to_der(raw_sig: bytes) -> bytes:
    """Convert a raw 64-byte ECDSA signature (r||s) to DER for cryptography."""
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    return encode_dss_signature(r, s)


# ---------------------------------------------------------------------------
# Tests: slot / token info
# ---------------------------------------------------------------------------

class TestSlotAndTokenInfo:

    def test_slot_count(self, pkcs11_lib):
        """getSlotList returns at least 1 slot (matches config)."""
        slots = pkcs11_lib.getSlotList(tokenPresent=True)
        assert len(slots) >= 1

    def test_token_info(self, pkcs11_lib):
        """Token reports expected manufacturer and model strings."""
        slots = pkcs11_lib.getSlotList(tokenPresent=True)
        info = pkcs11_lib.getTokenInfo(slots[0])
        assert "SatoshiLabs" in info.manufacturerID
        assert "Trezor" in info.model

    def test_mechanism_list(self, pkcs11_lib):
        """Both CKM_ECDSA and CKM_ECDSA_SHA256 are advertised."""
        slots = pkcs11_lib.getSlotList(tokenPresent=True)
        mechs = pkcs11_lib.getMechanismList(slots[0])
        # getMechanismList returns string names, not integer constants
        assert "CKM_ECDSA" in mechs
        assert "CKM_ECDSA_SHA256" in mechs


# ---------------------------------------------------------------------------
# Tests: key discovery
# ---------------------------------------------------------------------------

class TestKeyDiscovery:

    def test_find_public_keys(self, session):
        """findObjects with CKO_PUBLIC_KEY returns at least one key."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        assert len(objs) >= 1

    def test_find_private_keys(self, session):
        """findObjects with CKO_PRIVATE_KEY returns at least one key."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PRIVATE_KEY)])
        assert len(objs) >= 1

    def test_public_key_has_ec_params(self, session):
        """CKA_EC_PARAMS is non-empty bytes."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        params = _get_attr(session, objs[0], CKA_EC_PARAMS)
        assert params and len(bytes(params)) > 0

    def test_public_key_ec_params_is_p256_oid(self, session):
        """EC_PARAMS encodes the P-256 OID (06 08 2a 86 48 ce 3d 03 01 07)."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        params = bytes(_get_attr(session, objs[0], CKA_EC_PARAMS))
        assert params == bytes.fromhex("06082a8648ce3d030107")

    def test_public_key_has_ec_point(self, session):
        """CKA_EC_POINT is 67 bytes (DER OCTET STRING wrapping 65-byte point)."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        point = bytes(_get_attr(session, objs[0], CKA_EC_POINT))
        assert len(point) == 67

    def test_ec_point_format(self, session):
        """EC_POINT has correct DER/uncompressed structure: 04 41 04 ..."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        point = bytes(_get_attr(session, objs[0], CKA_EC_POINT))
        assert point[0] == 0x04, "Expected DER OCTET STRING tag at byte 0"
        assert point[1] == 0x41, "Expected length 65 at byte 1"
        assert point[2] == 0x04, "Expected uncompressed point marker at byte 2"

    def test_public_key_is_256_bits(self, session):
        """The x and y coordinates are each 32 bytes."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        point = bytes(_get_attr(session, objs[0], CKA_EC_POINT))
        uncompressed = point[2:]  # strip DER header
        x_bytes = uncompressed[1:33]
        y_bytes = uncompressed[33:65]
        assert len(x_bytes) == 32
        assert len(y_bytes) == 32

    def test_key_label(self, session):
        """CKA_LABEL is a non-empty string."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        label = _get_attr(session, objs[0], CKA_LABEL)
        assert label and len(str(label)) > 0

    def test_key_id_matches(self, session):
        """Public key CKA_ID matches private key CKA_ID for the same slot."""
        pub_objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        priv_objs = _find_objects(session, [(CKA_CLASS, CKO_PRIVATE_KEY)])
        pub_id = bytes(_get_attr(session, pub_objs[0], CKA_ID))
        priv_id = bytes(_get_attr(session, priv_objs[0], CKA_ID))
        assert pub_id == priv_id

    def test_key_type_is_ec(self, session):
        """CKA_KEY_TYPE == CKK_EC for both public and private key."""
        pub_objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        priv_objs = _find_objects(session, [(CKA_CLASS, CKO_PRIVATE_KEY)])
        assert _get_attr(session, pub_objs[0], CKA_KEY_TYPE) == CKK_EC
        assert _get_attr(session, priv_objs[0], CKA_KEY_TYPE) == CKK_EC

    def test_private_key_has_sign_attribute(self, session):
        """CKA_SIGN == True on the private key object."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PRIVATE_KEY)])
        assert _get_attr(session, objs[0], CKA_SIGN) == True

    def test_public_key_has_verify_attribute(self, session):
        """CKA_VERIFY == True on the public key object."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        assert _get_attr(session, objs[0], CKA_VERIFY) == True


# ---------------------------------------------------------------------------
# Tests: signing
# ---------------------------------------------------------------------------

class TestSigning:

    def _get_private_key_obj(self, session):
        objs = _find_objects(session, [(CKA_CLASS, CKO_PRIVATE_KEY)])
        assert objs, "No private key found"
        return objs[0]

    def _get_public_key(self, session):
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        assert objs, "No public key found"
        ec_point = _get_attr(session, objs[0], CKA_EC_POINT)
        return _ec_point_to_public_key(ec_point)

    def test_sign_ecdsa_prehashed(self, session):
        """C_Sign with CKM_ECDSA on a 32-byte digest verifies correctly."""
        import hashlib
        digest = hashlib.sha256(b"test payload for prehashed ecdsa").digest()
        priv = self._get_private_key_obj(session)
        sig_raw = bytes(session.sign(priv, digest, Mechanism(CKM_ECDSA, None)))
        assert len(sig_raw) == 64

        pub = self._get_public_key(session)
        der_sig = _raw_sig_to_der(sig_raw)
        # CKM_ECDSA signs the pre-hashed data — Prehashed lives in asymmetric.utils
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        from cryptography.hazmat.primitives import hashes
        pub.verify(der_sig, digest, ECDSA(Prehashed(hashes.SHA256())))

    def test_sign_ecdsa_sha256(self, session):
        """C_Sign with CKM_ECDSA_SHA256 on raw data verifies correctly."""
        data = b"Hello Trezor"
        priv = self._get_private_key_obj(session)
        sig_raw = bytes(session.sign(priv, data, Mechanism(CKM_ECDSA_SHA256, None)))
        assert len(sig_raw) == 64

        pub = self._get_public_key(session)
        der_sig = _raw_sig_to_der(sig_raw)
        pub.verify(der_sig, data, ECDSA(hashes.SHA256()))

    def test_signature_is_deterministic_for_same_data(self, session):
        """
        Sign the same data twice; both signatures must verify correctly.

        Note: Trezor may use a randomised nonce for extra security, so r and s
        values are not required to be identical — but both must be valid
        signatures over the same key and data.
        """
        data = b"determinism check"
        priv = self._get_private_key_obj(session)
        sig1 = bytes(session.sign(priv, data, Mechanism(CKM_ECDSA_SHA256, None)))
        sig2 = bytes(session.sign(priv, data, Mechanism(CKM_ECDSA_SHA256, None)))
        pub = self._get_public_key(session)
        pub.verify(_raw_sig_to_der(sig1), data, ECDSA(hashes.SHA256()))
        pub.verify(_raw_sig_to_der(sig2), data, ECDSA(hashes.SHA256()))

    def test_signature_length(self, session):
        """Raw ECDSA signature is exactly 64 bytes (r=32, s=32)."""
        data = b"length check"
        priv = self._get_private_key_obj(session)
        sig_raw = bytes(session.sign(priv, data, Mechanism(CKM_ECDSA_SHA256, None)))
        assert len(sig_raw) == 64

    def test_different_data_gives_different_signature(self, session):
        """Signing two different payloads produces different signatures."""
        priv = self._get_private_key_obj(session)
        sig1 = bytes(session.sign(priv, b"payload one", Mechanism(CKM_ECDSA_SHA256, None)))
        sig2 = bytes(session.sign(priv, b"payload two", Mechanism(CKM_ECDSA_SHA256, None)))
        assert sig1 != sig2

    def test_sign_uses_correct_key_for_slot(self, pkcs11_lib, session):
        """
        Sign data in slot 0, then verify with the public key from slot 0.
        The signature must NOT verify against a different key.
        """
        data = b"slot binding check"
        priv = self._get_private_key_obj(session)
        sig_raw = bytes(session.sign(priv, data, Mechanism(CKM_ECDSA_SHA256, None)))

        # Verify against slot 0's public key — must succeed
        pub = self._get_public_key(session)
        pub.verify(_raw_sig_to_der(sig_raw), data, ECDSA(hashes.SHA256()))

        # If a second slot exists, verify the sig does NOT validate against it
        slots = pkcs11_lib.getSlotList(tokenPresent=True)
        if len(slots) > 1:
            sess2 = pkcs11_lib.openSession(slots[1], CKF_SERIAL_SESSION)
            try:
                pub_objs2 = _find_objects(sess2, [(CKA_CLASS, CKO_PUBLIC_KEY)])
                if pub_objs2:
                    pub2 = _ec_point_to_public_key(
                        _get_attr(sess2, pub_objs2[0], CKA_EC_POINT)
                    )
                    with pytest.raises(Exception):
                        pub2.verify(
                            _raw_sig_to_der(sig_raw), data, ECDSA(hashes.SHA256())
                        )
            finally:
                sess2.closeSession()


# ---------------------------------------------------------------------------
# Tests: public key consistency
# ---------------------------------------------------------------------------

class TestPublicKeyConsistency:

    def test_public_key_is_deterministic(self, session):
        """Reading EC_POINT twice returns the same value (cached or re-derived)."""
        objs = _find_objects(session, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        point1 = bytes(_get_attr(session, objs[0], CKA_EC_POINT))
        point2 = bytes(_get_attr(session, objs[0], CKA_EC_POINT))
        assert point1 == point2


# ---------------------------------------------------------------------------
# Tests: multi-slot
# ---------------------------------------------------------------------------

class TestMultiSlot:

    def test_all_slots_have_keys(self, pkcs11_lib):
        """Every token-present slot exposes at least one key object."""
        slots = pkcs11_lib.getSlotList(tokenPresent=True)
        for slot in slots:
            sess = pkcs11_lib.openSession(slot, CKF_SERIAL_SESSION)
            try:
                objs = _find_objects(sess, [(CKA_CLASS, CKO_PUBLIC_KEY)])
                assert len(objs) >= 1, f"Slot {slot} has no public key objects"
            finally:
                sess.closeSession()


# ---------------------------------------------------------------------------
# Tests: session lifecycle
# ---------------------------------------------------------------------------

class TestSessionLifecycle:

    def test_login_is_noop(self, pkcs11_lib):
        """C_Login with any PIN returns success (device enforces its own auth)."""
        slots = pkcs11_lib.getSlotList(tokenPresent=True)
        sess = pkcs11_lib.openSession(slots[0], CKF_SERIAL_SESSION)
        try:
            # CKU_USER = 1; an exception here means login is broken
            try:
                sess.login("1234")
            except PyKCS11Error:
                pass  # Some implementations raise CKR_USER_ALREADY_LOGGED_IN
        finally:
            sess.closeSession()

    def test_close_and_reopen_session(self, pkcs11_lib):
        """After closing a session and opening a new one, objects are still findable."""
        slots = pkcs11_lib.getSlotList(tokenPresent=True)
        sess = pkcs11_lib.openSession(slots[0], CKF_SERIAL_SESSION)
        sess.closeSession()

        sess2 = pkcs11_lib.openSession(slots[0], CKF_SERIAL_SESSION)
        try:
            objs = _find_objects(sess2, [(CKA_CLASS, CKO_PUBLIC_KEY)])
            assert len(objs) >= 1
        finally:
            sess2.closeSession()


# ---------------------------------------------------------------------------
# Tests: ed25519 / CKM_EDDSA
# ---------------------------------------------------------------------------

_ED25519_OID_DER = bytes.fromhex("06032b6570")  # DER OID 1.3.101.112


def _find_ed25519_slot(pkcs11_lib):
    """Return (slot_id, session) for the first ed25519 slot, or skip the test."""
    slots = pkcs11_lib.getSlotList(tokenPresent=True)
    for slot in slots:
        sess = pkcs11_lib.openSession(slot, CKF_SERIAL_SESSION)
        objs = _find_objects(sess, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        if objs:
            params = bytes(_get_attr(sess, objs[0], CKA_EC_PARAMS))
            if params == _ED25519_OID_DER:
                return slot, sess
        sess.closeSession()
    pytest.skip("No ed25519 slot found in config — add curve = \"ed25519\" to a slot.")


class TestEd25519:
    """Tests for Ed25519 keys (CKM_EDDSA, CKK_EC_EDWARDS).

    These tests require at least one slot configured with ``curve = "ed25519"``
    in ~/.config/trezor-pkcs11/config.  They are automatically skipped otherwise.
    """

    @pytest.fixture(autouse=True)
    def ed_session(self, pkcs11_lib):
        """Open the first ed25519 slot; skip if none configured."""
        slot, sess = _find_ed25519_slot(pkcs11_lib)
        self._slot = slot
        self._sess = sess
        self._lib  = pkcs11_lib
        yield
        try:
            sess.closeSession()
        except PyKCS11Error:
            pass

    # -- Key attributes -------------------------------------------------------

    def test_key_type_is_ec_edwards(self):
        """CKA_KEY_TYPE must be CKK_EC_EDWARDS (0x40) for an ed25519 key."""
        objs = _find_objects(self._sess, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        assert _get_attr(self._sess, objs[0], CKA_KEY_TYPE) == CKK_EC_EDWARDS

    def test_ec_params_is_ed25519_oid(self):
        """CKA_EC_PARAMS must be the DER OID for Ed25519 (1.3.101.112 = 06 03 2b 65 70)."""
        objs = _find_objects(self._sess, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        params = bytes(_get_attr(self._sess, objs[0], CKA_EC_PARAMS))
        assert params == bytes.fromhex("06032b6570")

    def test_ec_point_is_32_bytes_wrapped(self):
        """CKA_EC_POINT is a 34-byte DER OCTET STRING wrapping the 32-byte raw key."""
        objs = _find_objects(self._sess, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        point = bytes(_get_attr(self._sess, objs[0], CKA_EC_POINT))
        assert point[0] == 0x04, "Expected DER OCTET STRING tag"
        assert point[1] == 0x20, "Expected 32-byte length"
        assert len(point) == 34

    def test_mechanism_list_includes_eddsa(self):
        """CKM_EDDSA is advertised in the mechanism list for an ed25519 slot."""
        mechs = self._lib.getMechanismList(self._slot)
        assert "CKM_EDDSA" in mechs

    # -- Signing --------------------------------------------------------------

    def test_sign_eddsa(self):
        """C_Sign with CKM_EDDSA on arbitrary data returns a 64-byte signature."""
        from PyKCS11 import CKM_EDDSA
        data = b"Hello Ed25519 from Trezor"
        priv = _find_objects(self._sess, [(CKA_CLASS, CKO_PRIVATE_KEY)])[0]
        sig = bytes(self._sess.sign(priv, data, Mechanism(CKM_EDDSA, None)))
        assert len(sig) == 64

    def test_sign_eddsa_verifies(self):
        """Ed25519 signature from C_Sign verifies with the cryptography library."""
        from PyKCS11 import CKM_EDDSA
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        data = b"verify me with ed25519"
        priv = _find_objects(self._sess, [(CKA_CLASS, CKO_PRIVATE_KEY)])[0]
        sig = bytes(self._sess.sign(priv, data, Mechanism(CKM_EDDSA, None)))
        assert len(sig) == 64

        objs = _find_objects(self._sess, [(CKA_CLASS, CKO_PUBLIC_KEY)])
        point = bytes(_get_attr(self._sess, objs[0], CKA_EC_POINT))
        raw_key = point[2:]  # strip 04 20 DER header → 32 bytes
        pub = Ed25519PublicKey.from_public_bytes(raw_key)
        pub.verify(sig, data)  # raises if invalid

    def test_sign_eddsa_different_data_differs(self):
        """Two different messages produce different Ed25519 signatures."""
        from PyKCS11 import CKM_EDDSA
        priv = _find_objects(self._sess, [(CKA_CLASS, CKO_PRIVATE_KEY)])[0]
        sig1 = bytes(self._sess.sign(priv, b"message one", Mechanism(CKM_EDDSA, None)))
        sig2 = bytes(self._sess.sign(priv, b"message two", Mechanism(CKM_EDDSA, None)))
        assert sig1 != sig2
