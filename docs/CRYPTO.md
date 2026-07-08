# Cryptographic settings

Since v1.2.0 nothing crypto-related is hardcoded: every parameter is shown, configurable and validated in the installer's **"Cryptographic settings"** step, persisted in `/etc/openvpn-manager/config.conf`, and drives both the PKI (easy-rsa) and the generated `server.conf` / client profiles. Even if you accept the defaults untouched, they are displayed before installation and recorded in the config.

## Options and defaults

| Setting | Config key | Default (recommended) | Choices |
|---|---|---|---|
| CA / server / client key type | `PKI_ALGO` + `PKI_CURVE` / `PKI_RSA_BITS` | ECDSA `prime256v1` | ECDSA P-256/P-384/P-521, RSA 2048/3072/4096 |
| Data-channel ciphers | `DATA_CIPHERS` | `AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305` | any colon-list of AES-GCM / CHACHA20-POLY1305 (AEAD only) |
| Fallback data cipher | `DATA_FALLBACK` | `AES-256-GCM` | one cipher from the list (`data-ciphers-fallback`) |
| Minimum TLS version | `TLS_MIN` | `1.2` | `1.2`, `1.3` |
| Control-channel protection | `CONTROL_WRAP` | `tls-crypt` | `tls-crypt`, `tls-auth` (legacy) |
| HMAC / auth digest | `AUTH_DIGEST` | `SHA256` | SHA256 / SHA384 / SHA512 (also used as certificate signature digest) |
| CA validity | `CA_DAYS` | 3650 | 30–7300 days |
| Server cert validity | `SERVER_CERT_DAYS` | 3650 | ≤ CA validity |
| Client cert validity | `CLIENT_CERT_DAYS` | 3650 | ≤ CA validity |
| CRL validity | `CRL_DAYS` | 3650 | 30–7300 days |
| Diffie-Hellman | – | `dh none` + ECDHE (`ecdh-curve`) | fixed by design, see below |
| TLS 1.2 control suites | – | derived: ECDHE-ECDSA or ECDHE-RSA, AES-256-GCM / ChaCha20 | follows the key type |
| TLS 1.3 suites | – | `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256` | fixed modern set |

Presets in the installer: **Recommended modern** (the defaults above), **RSA 4096** (maximum interop with old/exotic clients), **High security** (P-384, AES-256-only, TLS ≥ 1.3, SHA384), plus full **Custom** editing of each item. A reset-to-defaults action is always available, and the summary screen shows warnings for weak or legacy choices (RSA-2048, tls-auth, very long client validity, TLS 1.3 client-compat note).

## RSA vs ECDSA

- **ECDSA** (default): far smaller keys and certificates for equivalent strength (P-256 ≈ RSA-3072), faster handshakes and signing, smaller `.ovpn` files. Supported by every OpenVPN ≥ 2.4 client — on the OS versions this tool targets there is no practical downside.
- **RSA**: the historical default; choose it only if you must interoperate with very old or embedded clients that predate ECDSA support. 2048-bit is the accepted minimum (warned), 3072/4096 recommended if RSA is required.
- Key exchange is **ECDHE in both cases** (`dh none` + `ecdh-curve`): classic DH parameter files (`dh.pem`) are obsolete, slower, and add no security over elliptic-curve DH — that's why there is no dh.pem option.

## tls-crypt vs tls-auth

Both add a pre-shared key on top of TLS, protecting against port scanning, protocol fingerprinting and TLS-stack DoS:

- **`tls-crypt`** (default): *encrypts and authenticates* the whole TLS handshake. The VPN is invisible to scanners; client certificates are never exposed on the wire.
- **`tls-auth`** (legacy): only *authenticates* the handshake (HMAC); the TLS exchange stays visible. Offered solely for interop with legacy setups and warned about when selected. Both modes use the same generated key file (`tls-crypt.key`); client profiles get `<tls-crypt>` or `key-direction 1` + `<tls-auth>` accordingly.

## What is validated

- Menu choices are whitelist-only (AEAD ciphers, known curves, sane day ranges); free-text cipher lists are validated token-by-token; certificate validity can never exceed the CA's.
- After the packages are installed (and before the PKI is generated), the selection is checked against the *installed* binaries: `openvpn --show-ciphers` / `--show-digests` and `openssl ecparam -list_curves`. Unsupported selections offer a reset-to-defaults or abort — never a broken install.
- On every start, `crypto_sanitize` re-validates the persisted values; a missing crypto section (pre-1.2.0 config) or corrupted values fall back to the recommended defaults, logged. Pre-1.2.0 installs are unaffected: the defaults are identical to the previously hardcoded values.

## Changing crypto settings after installation

| Setting | Post-install change | Impact |
|---|---|---|
| Data ciphers, fallback, TLS min, wrap, digest | ✔ `Server configuration → Crypto settings → Runtime` | rewrites `server.conf` (backup), restarts OpenVPN, **all client profiles must be regenerated and redistributed** — old profiles fail to negotiate. Shown as an explicit old→new confirmation; never silent. |
| Validity periods | ✔ `… → Validity` | applies to certificates issued **from now on**; existing certs keep their expiry. |
| Key type (ECDSA/RSA, curve, bits) | ✖ fixed for the PKI's lifetime | requires **Reinstall** (new CA ⇒ every user certificate and profile replaced). The menu explains this instead of attempting it. |

## Ubuntu / Debian compatibility notes

Everything the tool can select is supported by the packaged OpenVPN/OpenSSL on all primary targets (Ubuntu 20.04+ → OpenVPN 2.4.7*/2.5+, Debian 11+ → 2.5+; the tool requires ≥ 2.5 features elsewhere anyway). Specifics:

- `data-ciphers` / `data-ciphers-fallback` need OpenVPN ≥ 2.5 — present everywhere targeted; also avoids the deprecated `cipher` directive that OpenVPN 2.7 (Ubuntu 26.04) warns about.
- TLS 1.3 (`tls-version-min 1.3`, `tls-ciphersuites`) needs OpenSSL ≥ 1.1.1 on **both** ends — fine for the server on all targets; only choose the 1.3 minimum if your *clients* are current.
- Ubuntu 26.04's kernel-accelerated DCO path works with all offered AEAD ciphers (GCM/ChaCha20); that's one more reason CBC ciphers are not offered at all.
