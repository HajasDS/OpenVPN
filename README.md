# openvpn-manager

An interactive, menu-driven terminal tool (whiptail/dialog TUI) to **install, configure and maintain an OpenVPN server** on Linux — with **per-user** certificate, password, **TOTP** and **YubiKey OTP** authentication and global enforcement rules.

Conceptually a successor to [`angristan/openvpn-install`](https://github.com/angristan/openvpn-install): same proven OpenVPN mechanics, but modular, menu-driven, with multi-factor authentication and persistent management state. See [docs/DESIGN.md](docs/DESIGN.md) for the full comparison.

```
┌──────────────── OpenVPN Manager ────────────────┐
│ Service: ACTIVE | vpn.example.com:1194/udp      │
│ Users: 12 | Auth: per-user (3 modes allowed)    │
│                                                 │
│   users      User management                    │
│   auth       Authentication (per-user modes)    │
│   service    Service control                    │
│   settings   Server configuration               │
│   firewall   Firewall / NAT rules               │
│   ...                                           │
└─────────────────────────────────────────────────┘
```

## Supported operating systems

| Tier | OS | Notes |
|---|---|---|
| Primary | Ubuntu 20.04 / 22.04 / 24.04+ | fully targeted |
| Primary | Debian 11 / 12+ | fully targeted |
| Secondary | Fedora, RHEL / Rocky / Alma 8+ | EPEL enabled automatically for PAM modules |
| Secondary | Arch / Manjaro | best effort |
| Best effort | Other apt / dnf / pacman derivatives | warns before continuing |

Requirements: systemd, bash ≥ 4, a TUN device (`/dev/net/tun` — enable it for LXC/containers first), OpenVPN ≥ 2.5 (all supported distros ship it).

## Installation

```bash
git clone https://github.com/HajasDS/OpenVPN.git openvpn-manager
cd openvpn-manager
chmod +x openvpn-manager.sh
sudo ./openvpn-manager.sh
```

Everything else is interactive. The tool detects your distribution and package manager (`apt`, `dnf`, `yum`, `pacman`), installs its own dependencies (including `whiptail` if no TUI backend is present), and walks you through the setup:

1. **Network interface** and **public endpoint** (auto-detected, incl. public-IP lookup behind NAT; manual override supported)
2. **IPv6** in-tunnel support (offered when the host has public IPv6)
3. **Port** and **protocol** (UDP recommended, TCP available)
4. **DNS for clients** (Cloudflare / Google / Quad9 / AdGuard / OpenDNS / system / custom)
5. **Cryptographic settings** — recommended modern defaults (ECDSA P-256, AES-GCM/ChaCha20, TLS ≥ 1.2, `tls-crypt`), RSA-4096 and high-security presets, or full customization (key type, ciphers, TLS min, digests, validity periods); everything reviewed on screen and validated before use — see [docs/CRYPTO.md](docs/CRYPTO.md)
6. **Allowed authentication modes** (multi-select) and the default mode for new users — each user gets their own mode later; see [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)
7. Confirmation summary → packages, PKI, auth policy, server config, IP forwarding, firewall/NAT, service start
8. First VPN user

### Files the tool manages

| Path | Purpose |
|---|---|
| `/etc/openvpn/server/server.conf` | generated server config (never edit by hand — regenerated) |
| `/etc/openvpn/easy-rsa/pki/` | PKI (CA, certs, keys, CRL) |
| `/etc/openvpn-manager/config.conf` | persistent tool configuration (`0600`, example in `examples/`) |
| `/etc/openvpn-manager/clients/*.ovpn` | generated client profiles (`0600`) |
| `/etc/openvpn-manager/totp/<user>` | per-user TOTP secret files (`0400`) |
| `/etc/openvpn-manager/yubikey/authorized_yubikeys` | user → YubiKey public-ID map |
| `/etc/openvpn-manager/backups/<timestamp>/` | automatic pre-change backups |
| `/etc/openvpn/server/auth-policy.conf` | per-user auth policy (usernames + modes, **no secrets**) |
| `/etc/openvpn/server/auth-policy.sh` | fail-closed per-connection policy gate (runs as `nobody`) |
| `/etc/pam.d/openvpn` | generated group-gated PAM stack serving all modes at once |
| `/var/log/openvpn-manager.log` | operations log (never contains secrets) |

## Usage

Run `sudo ./openvpn-manager.sh` any time — it is safe to re-run; it detects the existing installation and opens the management menu:

- **User management** — add users (optional key passphrase), revoke (cert + account + TOTP + YubiKey + profile in one step), list with status flags, regenerate `.ovpn` profiles, set/change VPN passwords.
- **Authentication** — per-user modes (view/change/reset per user), global enforcement rules (multi-select allowed modes, default mode), global features (TOTP/YubiKey packages, validation service), and a full configuration validation report.
- **Service control** — status with live connected-client list, start/stop/restart, journal view.
- **Server configuration** — change port, protocol, client DNS, public endpoint, and crypto settings (runtime crypto changes explain their impact and trigger profile regeneration; key-type changes require a reinstall and the UI says so — [docs/CRYPTO.md](docs/CRYPTO.md)). Config files are regenerated from persisted state, firewall rules are updated, and you're offered a profile regeneration.
- **Firewall / NAT** — view, re-apply or remove the VPN rules.
- **Backups** — every modified file is snapshotted first to a timestamped folder.
- **Uninstall** — full cleanup with a final backup archive in `/root` (see below).

Client `.ovpn` files land in `/etc/openvpn-manager/clients/`. Transfer them over a secure channel (`scp`), then consider deleting them from the server — they contain the user's private key.

## Authentication modes (per user)

A **valid client certificate is always required**. On top of it **every user
has their own mode** — different users with different protection levels
connect to the same server at the same time:

| Mode | Second factor(s) | Client login experience |
|---|---|---|
| Certificate only | — | connects silently |
| Certificate + password | system password (hash in `/etc/shadow`) | username + password prompt |
| Certificate + password + TOTP | password **and** 6-digit TOTP | username + password, then TOTP code prompt |
| Certificate + YubiKey OTP | YubiKey touch | username, password field = key touch |
| Certificate + password + YubiKey | password **and** YubiKey touch | password field = password + key touch (OTP appended) |

**Global enforcement rules** decide which modes are allowed at all
(multi-select). Assignments outside the list are blocked in the UI, and the
policy layer rejects non-compliant logins at every connection attempt.
Selecting exactly one mode (e.g. *password + TOTP*) enforces it for everyone;
shrinking the list shows exactly who becomes non-compliant and offers to
update them on the spot — nobody is silently locked out.

How it works under the hood (full detail in [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md) and [docs/SECURITY.md](docs/SECURITY.md)):

- A fail-closed **policy gate** (`auth-policy.sh`, running unprivileged) decides per certificate CN which factors are required, enforces username = CN and the allowed-modes list. It never sees passwords.
- **One generated PAM stack** serves all modes at once: `pam_succeed_if` group gates (`ovm-password`/`ovm-totp`/`ovm-yubikey`) run only the credential modules matching each user's mode.
- Credential-mode users get a **locked-down system account**: no home, `nologin` shell, `openvpn-users` group; passwords via `chpasswd` (never on a command line), stored only as hashes. Certificate-only users need no account at all.
- Every authentication action **validates its prerequisites first** (packages, PAM plugin, API credentials, user/enrollment state, enforcement rules, file permissions). Anything missing is shown with the reason and one-tap fix options instead of failing or hanging midway — see [docs/PREREQUISITES.md](docs/PREREQUISITES.md).
- `Authentication → Validate authentication configuration` audits the whole chain (policy ↔ groups ↔ accounts ↔ secrets ↔ PAM ↔ server.conf ↔ certificates) as a PASS/WARN/FAIL report.

## TOTP setup guide

Works with Google Authenticator, Microsoft Authenticator, Aegis, Authy, FreeOTP, and any RFC 6238 app.

1. Allow *password + TOTP* under `Authentication → Global enforcement rules`
   (the `libpam-google-authenticator` module is installed on demand).
2. `Authentication → User authentication modes → <user> → Change mode → password + TOTP`.
   A **QR code** is drawn in the terminal during assignment (plus the base32 secret for manual entry). Shown once, never logged, screen cleared afterwards.
3. The user scans it with their authenticator app.
4. Regenerate + redistribute the user's `.ovpn` when prompted.
5. Login = username, password, then the 6-digit code at the challenge prompt.

Per-user actions: **show QR again**, **reset** (new secret, e.g. lost phone), **remove TOTP** (mode change back to password).

## YubiKey OTP setup guide

YubiKey OTP is validated **online** — every touch emits a different one-time code; it is *never* treated as a static password.

1. Choose a validation service in `Authentication → Global authentication features`:
   - **YubiCloud** (default): free API key from <https://upgrade.yubico.com/getapikey/> — needs outbound HTTPS from the server, or
   - **self-hosted** `yubikey-val`-compatible server URL.
2. **Validate a test OTP** to confirm the chain end-to-end.
3. Allow a YubiKey mode under `Global enforcement rules`, then assign it per user — the key is **registered during assignment** (one touch; the tool extracts the 12-char public ID, verifies the OTP online, and stores the `user:publicid` mapping).
4. Redistribute the regenerated profiles.

Login: *YubiKey-only* users just touch the key in the password field; *password + YubiKey* users type the password and touch the key immediately after — the one-time code is appended and the server splits and verifies both (standard pam_yubico flow). Multiple keys per user are supported (backup key).

## Troubleshooting

| Symptom | Check |
|---|---|
| Service won't start | `Service → journal`; the tool shows the journal automatically on failed restarts. Backups of the previous config are under `/etc/openvpn-manager/backups/`. |
| Client connects, no internet | `Firewall → Show rules`; another tool may have flushed them → `Re-apply`. Verify `sysctl net.ipv4.ip_forward` = 1. |
| `AUTH_FAILED` (any mode) | Run `Authentication → Validate authentication configuration` — it audits the whole chain per user. The OpenVPN journal shows `auth-policy: DENY cn=<user> - <reason>` lines for policy-level rejections (no policy entry, mode not allowed, missing credentials, username≠CN). |
| `AUTH_FAILED` (password modes) | User's mode includes a password and `pw:set` in `User management → List`? Username must equal the certificate name. |
| `AUTH_FAILED` (TOTP) | Server *and* phone clock in sync (NTP!). Client profile regenerated after the mode change (needs the `static-challenge` line)? |
| `AUTH_FAILED` (YubiKey) | `Global authentication features → Validate a test OTP`. Outbound HTTPS available? Key registered for exactly this username? password+YubiKey: password typed and key touched in the *same* field, no space? |
| Client prompt asks only for password, not the code | Old `.ovpn` — regenerate the profile after any per-user mode change. |
| Behind NAT | Endpoint must be the *public* IP/DNS name; forward the chosen port (UDP by default) to the server. |
| Container (LXC/Proxmox) | TUN device must be enabled for the container. |

Manager log: `/var/log/openvpn-manager.log` · OpenVPN journal: `journalctl -u openvpn-server@server`

## Security notes

Highlights (full write-up in [docs/SECURITY.md](docs/SECURITY.md)):

- Modern-only crypto: ECDSA P-256 PKI, AES-256-GCM/ChaCha20 data ciphers, TLS ≥ 1.2 with ECDHE, `tls-crypt` (handshake hidden from scanners), CRL checked on every connect. No compression, no legacy options.
- Secrets hygiene: no plaintext passwords anywhere; TOTP secrets `0400` root-only; nothing sensitive is ever logged; deleted secrets are `shred`-ed.
- Strict permissions: keys `0600` in `0700` dirs; config, PAM file and client profiles `0600`.
- Every change first snapshots the affected files; destructive actions require explicit (default-No) confirmation.

## Uninstall

`Main menu → Uninstall`. It stops/disables the service, removes only the firewall rules *it* created, deletes the PKI/config/PAM/TOTP/YubiKey artifacts, removes the managed system accounts, and optionally purges the packages. A restorable backup archive is left at `/root/openvpn-manager-backup-<timestamp>.tar.gz` (contains private keys — keep or delete deliberately).

## Testing

See [docs/TESTING.md](docs/TESTING.md) for the full manual test plan (fresh install, every auth mode end-to-end, revocation, re-run, uninstall) and the syntax/lint CI steps.

## Limitations & future ideas

- One server instance per host (no multi-instance management).
- One YubiKey validation service and one TOTP issuer per server (modes are per-user; the backends are global).
- YubiKey validation needs network access to a validation service (offline YubiKey via challenge-response PAM is not implemented).
- The VPN subnet (`10.8.0.0/24`, `fd42:42:42:42::/112`) is fixed.
- No HA/failover, no LDAP/RADIUS backends (natural next steps: `pam_ldap`, `pam_radius`).
- `nftables`-native backend (currently: firewalld / ufw / iptables).
