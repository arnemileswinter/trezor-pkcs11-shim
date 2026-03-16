# trezor-pkcs11

A PKCS#11 shared library (`libtrezor_pkcs11.so` / `trezor_pkcs11.dll`) that exposes a Trezor hardware wallet as a PKCS#11 token. Any PKCS#11 consumer — `ssh-add`, git commit signing, OpenSSL, browsers — can use the Trezor as an HSM. Keys are derived on-device via SLIP-0013 SignIdentity using `gpg://` URIs. The private key never leaves the device.

## Supported curves

| Curve | Aliases | Supported | Default in example config |
|-------|---------|-----------|---------------------------|
| nist256p1 | P-256, prime256v1 | yes | yes |
| secp256k1 | K-256 | yes | no |
| ed25519 | Ed25519 | yes | no |

`Default in example config = no` means the curve is opt-in, not unsupported.

## Supported mechanisms

| Mechanism | Input | Typical consumer | Supported |
|-----------|-------|------------------|-----------|
| `CKM_ECDSA` | 32-byte pre-hashed digest | OpenSSH (`ssh-add`) | yes |
| `CKM_ECDSA_SHA256` | Raw data (hashed internally) | OpenSSL, git signing | yes |
| `CKM_EDDSA` | Raw data (Ed25519 hashes internally) | OpenSSH, PKCS#11 v3.0 consumers | yes |

## Hardware support

| Device | VID | PID | Transport | Validation status |
|--------|-----|-----|-----------|-------------------|
| Trezor Safe 3 | 0x1209 | 0x53c1 | USB bulk (WebUSB) | tested by maintainer |
| Trezor Model T | 0x1209 | 0x53c1 | USB bulk (WebUSB) | expected to work, community verification wanted |
| Trezor Safe 5 | 0x1209 | 0x53c1 | USB bulk (WebUSB) | expected to work, community verification wanted |
| Trezor One | 0x534c | 0x0001 | HID | expected to work, community verification wanted |

Only Trezor Safe 3 has been tested by the maintainer so far.
If you test with Model T, Safe 5, or Trezor One, please open an issue or PR with results.

## Build

The Trezor protobuf definitions are pulled in as a git submodule. After cloning, initialise it before building:

```bash
git submodule update --init --depth 1
```

### Linux

Install system dependencies:

```bash
sudo apt install libudev-dev libusb-1.0-0-dev protobuf-compiler
```

Then build:

```bash
cargo build --release
# Output: target/release/libtrezor_pkcs11.so
```

### Windows

Build from within a WSL2 terminal (not from a Windows shell like MINGW64). `protoc.exe` cannot access WSL filesystem paths via UNC (`\\wsl.localhost\...`), so running `cargo build` from native Windows against WSL source will fail.

From inside WSL:

```bash
sudo apt install libudev-dev libusb-1.0-0-dev protobuf-compiler
cargo build --release
# Output: target/release/libtrezor_pkcs11.so  (usable from WSL)
```

## Configuration

The library reads a TOML config file to know which PKCS#11 slots to expose and which key identity to use for each.

**Search order:**

1. `$TREZOR_PKCS11_CONF` (environment variable, full path)
2. `$XDG_CONFIG_HOME/trezor-pkcs11/config`
3. `~/.config/trezor-pkcs11/config`
4. `/etc/trezor-pkcs11.conf`

**Example config** (`~/.config/trezor-pkcs11/config`):

```toml
[slot0]
uri   = "gpg://ssh@myhomelab"
label = "ssh-auth"
curve = "nist256p1"

[slot1]
uri   = "gpg://commit@myhomelab"
label = "git-signing"
curve = "nist256p1"
```

Each `[slotN]` section defines one PKCS#11 slot. The `uri` is the SLIP-0013 identity URI passed to the Trezor. The `label` appears in token info and key listings. The `curve` is optional and defaults to `nist256p1`.

## udev rules (Linux)

Without the udev rules the Trezor USB device is owned by root and the library will fail to open it.

**Install rules permanently:**

```bash
sudo cp pkg/51-trezor.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Then re-plug the device.

**Quick workaround for testing** (resets on next plug):

```bash
sudo chmod a+rw /dev/bus/usb/<bus>/<device>
```

## SSH use case

### Load the module into ssh-agent

```bash
# OpenSSH 8.9+ restricts which PKCS#11 modules ssh-agent will load.
# For a development build outside a system library path, start the agent
# with -P to allowlist the directory:
eval $(ssh-agent -P "/path/to/libtrezor_pkcs11.so" -s)
ssh-add -s /path/to/libtrezor_pkcs11.so

# Show the derived public key (ecdsa-sha2-nistp256):
ssh-add -L
```

### Note on OpenSSH 8.9+ path restrictions

By default, `ssh-agent` only loads PKCS#11 modules from system library paths (`/usr/lib*`, `/usr/local/lib*`). Development builds in `target/release/` are outside this allowlist and will be rejected unless you pass `-P` when starting the agent.

The `.deb` package installs the library to `/usr/lib/x86_64-linux-gnu/pkcs11/trezor-pkcs11.so`, which is inside the default allowlist — no `-P` flag needed when using the installed package:

```bash
eval $(ssh-agent -s)
ssh-add -s /usr/lib/x86_64-linux-gnu/pkcs11/trezor-pkcs11.so
ssh-add -L
```

### Authorize the key on a server

```bash
ssh-add -L >> ~/.ssh/authorized_keys   # or append to the remote's authorized_keys
```

Every SSH authentication will require a button press on the Trezor.

## Git commit signing

Git supports PKCS#11 tokens via its SSH signing backend.

```ini
# ~/.gitconfig
[gpg]
    format = ssh
[gpg "ssh"]
    allowedSignersFile = ~/.ssh/allowed_signers
[user]
    signingKey = /usr/lib/x86_64-linux-gnu/pkcs11/trezor-pkcs11.so
[commit]
    gpgsign = true
```

Populate `~/.ssh/allowed_signers` with the output of `ssh-add -L` (prefix each line with `your@email.address `).

Every signed commit will require a button press on the Trezor.

## Packaging

### Debian / Ubuntu .deb

```bash
cargo install cargo-deb
cargo deb
# Output: target/debian/trezor-pkcs11_*.deb
sudo dpkg -i target/debian/trezor-pkcs11_*.deb
```

The package installs the library to `/usr/lib/x86_64-linux-gnu/pkcs11/trezor-pkcs11.so` and the udev rules to `/etc/udev/rules.d/51-trezor.rules`.

## Testing

### Smoke test (no device needed)

```bash
# List slots — works without a Trezor connected:
pkcs11-tool --module target/release/libtrezor_pkcs11.so -L
```

### List keys (device required, prompts on Trezor screen)

```bash
pkcs11-tool --module target/release/libtrezor_pkcs11.so --list-objects
```

### Integration test suite

```bash
pip install PyKCS11 pytest cryptography
pytest test_integration.py -v
```

The integration tests open PKCS#11 sessions and perform real sign operations. Each signing call will require a button press on the Trezor. See `test_integration.py` for the full list of tests.

When at least one slot is configured with `curve = "ed25519"`, the suite also exercises `CKM_EDDSA` and verifies Ed25519 signatures end-to-end.

## Security

- The private key is derived inside the Trezor and **never leaves the device**.
- Every key derivation and signing operation requires **physical confirmation** on the Trezor screen (button press).
- The PKCS#11 PIN (`C_Login`) is a no-op — authentication is enforced by the device itself.
- Key derivation uses [SLIP-0013](https://github.com/satoshilabs/slips/blob/master/slip-0013.md) SignIdentity with `gpg://` URIs, producing a deterministic key per URI.
