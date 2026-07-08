# Security design

This document explains the security decisions in openvpn-manager, in particular **how TOTP and YubiKey OTP are implemented** and why.

## Threat model summary

Protected against:

- credential theft of a single factor (password OR device) when an MFA mode is active,
- stolen client certificates (revocation via CRL, optional key passphrase, CN↔username binding),
- server port scanning / handshake fingerprinting / TLS DoS (`tls-crypt`),
- secrets leaking through logs, process lists or world-readable files,
- accidental destruction of working config (pre-change backups, default-No confirmations).

Out of scope: a fully compromised server host (root can read the CA key and TOTP secrets by design), malware on the client device, YubiCloud availability.

## TLS / crypto profile

Since v1.2.0 the crypto parameters below are the *recommended defaults* of a configurable, validated crypto section (see [CRYPTO.md](CRYPTO.md)): the installer shows them before anything is generated, only modern whitelisted values can be selected (AEAD ciphers only, no DH files, RSA < 2048 not offered), weak/legacy choices (RSA-2048, `tls-auth`) require an explicit warned confirmation, and the selection is verified against the installed OpenVPN/OpenSSL before the PKI is built.

| Setting | Value | Rationale |
|---|---|---|
| PKI | easy-rsa 3, **ECDSA prime256v1**, CA offline-passwordless on the host | small, fast, modern; matches angristan defaults |
| Data channel | `AES-256-GCM` (+`AES-128-GCM`, `CHACHA20-POLY1305` negotiable) | AEAD only |
| Control channel | `TLS ≥ 1.2`, `TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384` | PFS, no CBC/static-RSA |
| Handshake wrap | `tls-crypt` pre-shared key | hides TLS from scanners, drops junk before TLS work, adds a "poor man's" post-quantum layer for the control channel |
| DH | `dh none` + `ecdh-curve prime256v1` | no legacy finite-field DH |
| HMAC | `auth SHA256` | (relevant for control channel with tls-crypt) |
| Revocation | `crl-verify` — CRL regenerated on each revoke, re-read on every connect | immediate lockout on reconnect |
| Legacy | no `comp-lzo`/compression (VORACLE), no `cipher BF-CBC`, no static keys | disabled entirely, not merely off-by-default |
| Privileges | `user nobody`, `group nogroup/nobody`, `persist-key`, `persist-tun` | daemon drops root after init |

## Password authentication (Mode 2)

- Backend: **PAM** via the stock `openvpn-plugin-auth-pam.so` and a generated `/etc/pam.d/openvpn` service.
- Each VPN user gets a dedicated system account: **no home directory, `nologin` shell, primary group `openvpn-users`**. The PAM stack starts with
  `auth requisite pam_succeed_if.so user ingroup openvpn-users`, so ordinary system accounts cannot log in to the VPN and VPN accounts cannot log in to anything else (no shell).
- Password storage: **only salted hashes in `/etc/shadow`** (whatever the distro's configured crypt is, typically yescrypt/sha512crypt). The tool never writes a plaintext password to disk, log, environment or command line — it is piped from the shell builtin `printf` straight into `chpasswd`, so it never appears in any process argv.
- `auth-nocache` is set in client profiles so OpenVPN clients don't keep credentials in memory longer than needed.

## TOTP (Mode 3) — implementation details

- Module: **`pam_google_authenticator`** (`libpam-google-authenticator`), the de-facto standard PAM TOTP implementation, stacked *after* `pam_unix` — both must succeed.
- Secret generation: 20 bytes from `/dev/urandom`, base32-encoded (RFC 4226-recommended size), written directly in the module's state-file format to `/etc/openvpn-manager/totp/<user>` with `RATE_LIMIT 3 30` (max 3 attempts/30 s), `WINDOW_SIZE 3` (±1 time step of clock skew), `DISALLOW_REUSE` (each code single-use), `TOTP_AUTH`.
- Storage: files are **root-owned, mode `0400`**, referenced from PAM with `user=root secret=/etc/openvpn-manager/totp/${USER}`. The auth-pam plugin performs PAM as root, so secrets are never readable by unprivileged users (including the `nobody` OpenVPN runtime user).
- Enrollment: QR code (`qrencode -t ANSIUTF8`) + base32 secret rendered **once** on a cleared terminal, then cleared again. The provisioning URI and the secret are **never logged**; the log records only "TOTP enabled for user X".
- Transport: the client profile contains `static-challenge "Enter your 6-digit TOTP code" 1`. The OpenVPN client packs *password + code* into a single `SCRV1:` auth payload; the auth-pam plugin unpacks it and answers `pam_unix`'s "Password:" prompt with the password and `pam_google_authenticator`'s "Verification code:" prompt with the OTP (prefix-matched prompt mapping: `password PASSWORD verification OTP`). Requires OpenVPN ≥ 2.5 (client and server).
- Renegotiation: `auth-gen-token 43200` — the server hands the session a one-time token so hourly TLS renegotiations don't re-demand a (long-expired) TOTP code, instead of the insecure alternative `reneg-sec 0`.
- Per-user policy: the optional `nullok` toggle allows accounts without a secret to authenticate with password only — deliberate, visible policy rather than a hidden default.

## YubiKey OTP (Mode 4) — implementation details

**Correctness first:** a Yubico OTP is a 44-character modhex string; the first 12 characters are the key's stable *public ID*, the remaining 32 are an AES-encrypted, monotonically counted one-time block. It changes on **every touch** and must be validated online so the validation service can check the counter (replay protection). It is therefore *never* stored or compared as a static password.

- Module: **`pam_yubico`** (Yubico's official PAM module) in `mode=client` (online validation), stacked after `pam_succeed_if` (and after `pam_unix` in the password+YubiKey mode).
- Validation service: **YubiCloud** with a per-installation API key (`id=` + `key=`; the key HMAC-signs and verifies API responses), or a **self-hosted `yubikey-val`-compatible server** via `urllist=`. The API key is stored only in root-only `0600` files (tool config and the generated PAM file — deliberately not the default `0644` of `/etc/pam.d`).
- Authorization mapping: `authfile=/etc/openvpn-manager/yubikey/authorized_yubikeys` maps `username:publicid[:publicid2…]` — possession of *some* valid YubiKey is not enough; it must be one registered to that specific user. Multiple keys per user = backup key support.
- Registration flow: capture one OTP (hidden input), syntax-validate (modhex), extract the public ID, and verify the OTP against the validation service **before** saving (with an explicit override if the service is unreachable). The test menu item validates a fresh OTP end-to-end. OTP values are single-use; they are never logged (only the public ID, which is not secret, appears in the log).
- Transport: YubiKey-only mode sends the OTP in the password field; password+YubiKey mode uses `static-challenge` exactly like TOTP (`password PASSWORD yubikey OTP` prompt mapping).
- The tool's own API test uses a random `nonce` and verifies `status=OK`, the echoed `otp` and the echoed `nonce` to bind the response to the request.

## Username ↔ certificate binding

With any PAM mode, plain OpenVPN would accept *any* valid certificate combined with *any* valid username/password — factors from different users could be mixed. openvpn-manager closes this by default (`ENFORCE_CN_MATCH=yes`): a minimal `auth-user-pass-verify … via-file` script rejects the login unless the PAM username equals the certificate CN. `via-file` was chosen over `via-env` so the password is **not** exported into the script's environment; the script reads only the username line and logs nothing.

## Secrets & logging policy

Never logged, never echoed into files, never on a command line: passwords, TOTP secrets/URIs, OTP codes, private keys, `.ovpn` contents, YubiCloud API key values. The operations log (`/var/log/openvpn-manager.log`, `0600`) records *events*: "User created", "TOTP enabled for user X", "YubiKey registered for user Y (public id …)", "Firewall rules updated", etc.

Deleted TOTP secrets and temporary passphrase files are removed with `shred -u` where the filesystem makes that meaningful.

## File permission map

| Path | Mode | Owner |
|---|---|---|
| `/etc/openvpn/easy-rsa/pki/private/` | `0700` dir, `0600` files | root |
| `/etc/openvpn/server/*.key`, `server.conf` | `0600` | root |
| `/etc/openvpn/server/crl.pem` | `0644` (required: re-read after privilege drop) | root |
| `/etc/openvpn-manager/` (all subdirs) | `0700` | root |
| `/etc/openvpn-manager/config.conf` | `0600` | root |
| `/etc/openvpn-manager/totp/<user>` | `0400` | root |
| `/etc/openvpn-manager/clients/*.ovpn` | `0600` | root |
| `/etc/pam.d/openvpn` | `0600` (may contain the YubiCloud key) | root |
| `/var/log/openvpn-manager.log` | `0600` | root |

## Safe-change mechanics

- Every file the tool modifies is first copied to `/etc/openvpn-manager/backups/<timestamp>/<original path>`.
- `server.conf`, the client template and the PAM file are **regenerated from persisted state** — no sed-patching drift, re-running the tool is idempotent.
- Destructive actions (reinstall, revoke, uninstall, disabling MFA or CN-matching) require explicit confirmation with **No as the default**, twice for PKI-destroying ones.
- Firewall changes go through the detected backend (firewalld / ufw / raw iptables with a dedicated systemd unit) and only ever add/remove the tool's own clearly-marked rules — existing policies are not flushed or reordered destructively.
- Uninstall produces `/root/openvpn-manager-backup-<ts>.tar.gz` (mode `0600`; contains the PKI — the UI says so explicitly).

## Input validation

All interactive input is validated before use (usernames `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$` and reserved names rejected; ports 1–65535; IPv4 octet-checked; hostnames RFC-shaped; OTPs modhex; API IDs numeric; URLs shape-checked). Usernames flow into filenames, easy-rsa CNs and account names — the single validator guarantees they are shell- and path-safe. The tool's config file is *parsed* against a key whitelist, never `source`d.
