# Changelog

## 2.0.0 — 2026-07-09

### Added
- **Per-user authentication modes** ([docs/AUTHENTICATION.md](docs/AUTHENTICATION.md)). Every user now has their own mode — certificate-only, password, password+TOTP, YubiKey OTP, or password+YubiKey — and users with different modes connect to the same server at the same time. Architecture: a fail-closed, unprivileged policy gate (`auth-user-pass-verify` script + `auth-user-pass-optional`, policy file with **no secrets**) decides per certificate CN which factors are required and enforces username = CN; one generated PAM stack verifies the credentials, with `pam_succeed_if` group gates (`ovm-password`/`ovm-totp`/`ovm-yubikey`) running only the modules matching each user's mode. Unknown certificates, missing policy files and non-compliant modes are all rejected (fail-closed).
- **Global enforcement rules**: a multi-select allowed-modes list plus a default mode for new users. Assigning a disallowed mode is blocked in the UI (with a one-tap jump to edit the list); the policy layer rejects non-compliant logins at connect time. Shrinking the list shows exactly which users become non-compliant and offers guided updates, an explicit default-No "apply anyway (blocks them)", or cancel — nobody is silently locked out.
- **Per-user authentication screen** (Authentication → User authentication modes, also linked from User management): view/change mode (only allowed modes selectable), quick add/remove factor transitions, set/change password, show/reset TOTP QR, register/replace YubiKey, return to certificate-only, regenerate profile. Mode changes validate everything first, provision prerequisites (account, password, TOTP QR, key registration) before the atomic policy+groups commit, and abort cleanly at any cancelled step.
- **"Validate authentication configuration"** report: audits policy file ↔ config ↔ gate groups ↔ accounts ↔ password states ↔ TOTP secrets ↔ YubiKey registrations ↔ PAM ↔ server.conf ↔ certificates as PASS/WARN/FAIL lines.
- **Automatic migration from the v1.x global mode**: proposes allowed = {old mode} and per-user assignments, downgrading users with incomplete enrollment (listed) so nobody is locked out; nothing changes until confirmed, and declining leaves the running v1 configuration untouched. New users are provisioned per-mode during Add user; the installer gained an allowed-modes step.
- New `lib/policy.sh` (policy store + generated `auth-policy.sh`/`pam-allow-empty.sh`), multi-select (`ui_checklist`) and radiolist UI widgets, `allow_*`/`assign_*` dependency-validation features with an "edit allowed modes" fix action.

### Changed
- **password+YubiKey login format**: the OTP is now typed at the END of the password field (pam_yubico's native append-and-strip flow) instead of a separate challenge prompt — required so both YubiKey modes can coexist; the challenge channel stays reserved for TOTP. Migration offers to regenerate all profiles and v1.x password+YubiKey profiles must be redistributed.
- Certificate-only users no longer need (or get) a system account; accounts of modes without a password factor are password-locked. `server.conf` always carries the policy gate; the PAM plugin line is emitted only when a credential mode is in use.
- Username↔certificate matching is now always enforced by the policy layer (the v1.x toggle was removed); the global TOTP `nullok` toggle is obsolete — enrollment is guaranteed per user at assignment time.
- Legacy config keys `AUTH_MODE`/`TOTP_NULLOK`/`ENFORCE_CN_MATCH` are still parsed (for migration) but no longer drive behaviour.

### Security
- The policy file/script layer contains and logs no secrets; policy denials log the CN and a fixed reason only. Missing PAM plugin with credential modes in use makes OpenVPN fail to start (visible) instead of skipping credential checks. Credentials of one user can never be combined with another user's certificate.

## 1.2.2 — 2026-07-08

### Fixed
- **The missing-requirements screen could be invisible — YubiKey registration appeared to hang.** whiptail/dialog draw message and text boxes on stdout; when a dialog was shown from inside `$(...)` command substitution (as in `require_feature`'s choice capture, or the "invalid input" popups inside `ui_input_validated`), the widget was rendered into the captured variable instead of the terminal and sat waiting for an OK nobody could see. Two-layer fix: display-only widgets (`ui_msg`, `ui_yesno`, `ui_textfile`, `ui_info`) now always draw on the controlling terminal (`/dev/tty`) when stdout is captured, and the requirements info screen is shown outside the capture entirely (only the fd-swap-safe menu runs inside `$(...)`). Registering a YubiKey before enabling/configuring YubiKey support now reliably shows what is missing (PAM module, validation service, global mode) with fix options instead of hanging.
- Plain-mode prompts and pagers print to stderr and tolerate EOF, so no plain-mode path can block or corrupt captured values either.

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
