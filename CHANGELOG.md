# Changelog

## 1.2.1 — 2026-07-08

### Fixed
- Core packages are installed with `--no-install-recommends` on apt systems. This keeps the smart-card stack (`pcscd`, `opensc`, `libccid`) — which OpenVPN only *recommends* and this tool never uses — off headless servers, eliminating the harmless-but-alarming `pcscd.service` dependency failure that Ubuntu's package ordering prints during installation. If your distro ships it as a hard dependency the flag changes nothing and the message remains cosmetic.

## 1.2.0 — 2026-07-08

### Added
- **Configurable cryptographic settings** (`lib/crypto.sh`, [docs/CRYPTO.md](docs/CRYPTO.md)). New "Cryptographic settings" step in the installer: review the recommended modern defaults, pick a preset (Recommended modern / RSA-4096 / High-security P-384+TLS1.3), or customize each parameter — key type (ECDSA P-256/384/521, RSA 2048–4096), data ciphers + fallback (AEAD whitelist), TLS minimum, `tls-crypt` vs `tls-auth`, HMAC digest, and CA/server/client/CRL validity periods. Nothing crypto-related is hidden or hardcoded anymore; the full selection is shown before installation and persisted in the config file.
- Post-install **crypto menu** under Server configuration: runtime settings (ciphers, TLS min, wrap, digest) changeable with an explicit old→new impact confirmation (server.conf regen + restart + profile regeneration — never silent); validity changes apply to future certificates; key-type changes are explained as requiring a reinstall instead of being attempted.
- **Validation layers**: whitelist-only menus and token-validated custom cipher lists; cert-validity-vs-CA cross checks; post-package-install verification against the actual `openvpn --show-ciphers/--show-digests` and `openssl ecparam -list_curves`, with a reset-to-defaults recovery path; `crypto_sanitize` on every start recovers missing (pre-1.2.0) or corrupted crypto config values.
- Warnings for weak/legacy choices: RSA-2048 and `tls-auth` require explicit default-No confirmation; TLS-1.3-minimum client-compatibility note; >10-year client certificates flagged.

### Changed
- `server.conf` now uses `data-ciphers-fallback` instead of the deprecated `cipher` directive (removes OpenVPN 2.7 deprecation warnings, e.g. on Ubuntu 26.04); client templates use `data-ciphers`. TLS 1.2 control-channel suites are derived from the certificate type (ECDSA/RSA); explicit `tls-ciphersuites` set for TLS 1.3. Client certificates can now have their own validity period (easy-rsa per-issue override).
- Defaults are unchanged from the previously hardcoded values — existing installs upgrade transparently.

## 1.1.0 — 2026-07-08

### Fixed
- **Hang when enabling/registering YubiKey authentication without the global prerequisites in place.** Actions could start executing (package installs, dialogs after plain-terminal output) before their requirements existed, ending in a whiptail dialog waiting for input on a screen it never drew. All authentication workflows are now validation-first and every wait is bounded and cancellable.

### Added
- **Centralized dependency validation** (`lib/checks.sh`): every feature entry point (`auth mode switch`, `YubiKey register/test`, `TOTP generate`, `user add`, `profile regenerate`) calls `require_feature` *before* touching the system. Missing requirements are shown with severity (blocking/warning), the reason they are needed, and a menu of explicit fix actions (install package, configure Yubico API, register a key, generate a secret, fix permissions), plus *Proceed anyway* (warnings only), *Re-check*, and *Return to previous menu*. Structured records, bounded loop, no partial application without confirmation.
- **Config sanitization** (`config_sanitize`): all persisted values are re-validated on every start; corrupted/hand-edited values (port, protocol, auth mode, endpoint, Yubico ID/URL, firewall backend, plugin path) are reset to safe defaults and logged.
- **Partial-installation detection**: remnants of a failed/interrupted install are reported at startup and the Install action is labelled as a repair.
- **No-TTY guard**: with piped stdio or `TERM=dumb` the tool now uses plain prompts instead of whiptail (which would wait forever on an undrawable dialog).
- Documentation: `docs/PREREQUISITES.md` (dependency matrix + validation design), dependency-scenario test plan in `docs/TESTING.md`.

### Security
- Dependency-failure logging uses fixed requirement names only — no OTPs, secrets, API keys, or key material. New warning + one-tap fix for secret files with loose permissions.

## 1.0.1 — 2026-07-08

- Fixed invisible install progress: long-running steps (apt, easy-rsa, firewall, service start) now run on the plain terminal with live output and `[ OK ]`/`[FAIL]` markers (`ui_run`); whiptail `--infobox` quirk worked around via `TERM=ansi`.
- apt runs unmuted with `DPkg::Lock::Timeout=300` (visible, bounded waiting for `unattended-upgrades`).
- easy-rsa and package installs run with stdin closed — unexpected prompts fail loudly instead of hanging.
- Install-path fatal errors converted to error dialogs that return to the menu instead of killing the TUI; install completion shown as plain text with a clean TUI repaint afterwards.

## 1.0.0 — 2026-07-08

- Initial release: interactive whiptail/dialog TUI for installing and managing an OpenVPN server on Ubuntu/Debian (Fedora/RHEL-family and Arch best-effort); ECDSA P-256 PKI with tls-crypt; user lifecycle with `.ovpn` generation; auth modes: certificate / +password (PAM) / +password+TOTP / +YubiKey OTP / +password+YubiKey; firewalld/ufw/iptables backends; pre-change backups; operations log; safe uninstall.
