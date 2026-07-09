# Feature prerequisites & dependency validation

Since v1.1.0 every feature-specific action validates **all** of its prerequisites *before* executing anything. Validation is read-only; when something is missing the tool shows what/why and offers explicit fix actions — it never fails midway, never applies half a change, and never hangs waiting on a dialog that could not be satisfied.

## How it works (design)

Implemented in [`lib/checks.sh`](../lib/checks.sh):

```
feature entry point
   └── require_feature <feature> <user> "<action label>"      # gatekeeper
         └── validate_feature_requirements()                  # dispatcher
               ├── check_password_auth_requirements()         # read-only checks
               ├── check_totp_requirements(context, user)
               ├── check_yubikey_requirements(context, user)
               └── check_certificate_requirements(user)
         ├── show_missing_requirements_dialog()               # what / why / fix
         ├── _requirements_dialog()                           # fix menu
         └── apply_dependency_fix(id)                         # explicit fixes
```

- Each unmet requirement is a **structured record**: `severity|name|description|autofix|recommended action`.
- `severity=blocking` prevents the action; `warning` allows *Proceed anyway*.
- The fix menu is built from the records' `autofix` ids; **Return to previous menu** and **Re-check requirements** are always present, and the loop is bounded (max 15 rounds), so no path can loop or hang.
- After a fix is applied, requirements are re-validated; the action starts only when the list is clean (or only warnings remain and the admin explicitly proceeds).
- Failures are logged as `"<action> blocked: <requirement>"` — never with secrets, OTPs, or key material.

## Prerequisite matrix

| Action (feature id) | Requirement | Severity | Auto-fix |
|---|---|---|---|
| **Allow password mode** (`allow_password`) | `openvpn-plugin-auth-pam.so` present | blocking | – (reinstall openvpn) |
| **Allow password+TOTP** (`allow_password_totp`) | PAM plugin; `pam_google_authenticator.so` | blocking | install package |
| **Allow YubiKey modes** (`allow_yubikey`, `allow_password_yubikey`) | PAM plugin; `pam_yubico.so` | blocking | install package |
| | validation service configured (YubiCloud ID+key *or* self-hosted URL) | warning | configure now |
| **Assign a mode to a user** (`assign_<mode>`) | everything from the matching `allow_*` check | as above | as above |
| | the mode is in the allowed-modes list | blocking | edit allowed modes now |
| | target user exists (valid certificate) | blocking | – (create user first) |
| | YubiKey modes: validation service configured | **blocking** | configure now |
| **Register a YubiKey** (`yubikey_register`) | `pam_yubico.so` installed | blocking | install package |
| | validation service configured | warning | configure now |
| | target user exists (valid certificate) | blocking | – (create user first) |
| | the user's own mode includes YubiKey | warning | – (change the mode after registering) |
| **Test a YubiKey OTP** (`yubikey_test`) | validation service configured; `curl` | blocking | configure now |
| **Generate TOTP secret** (`totp_generate`) | `pam_google_authenticator.so`; user exists | blocking | install package |
| **Add VPN user** (`user_add`) | easy-rsa, CA cert, PKI index, tls-crypt key | blocking | – (Reinstall) |
| **Regenerate client profile** (`profile`) | PKI healthy **and** the user's cert + key exist | blocking | – |
| *(all auth actions)* | secret files are `0600`/`0400` root-only | warning | chmod now |

Notes on deliberate severities:

- **Allowing** a YubiKey mode without a validation service is a *warning* (the service can be configured before the first assignment); **assigning** the mode to a user without one is *blocking* — that user could never log in.
- **Registering a key while the user's mode has no YubiKey** is allowed (warning) — that is the correct order: register first, then switch the user's mode. During a mode assignment the tool registers the key itself, so the warning is suppressed there.
- Enrollment coverage can no longer lock everyone out globally: TOTP secrets and YubiKey registrations are created **during** the per-user assignment, and the enforcement screen lists exactly which users a rule change would block before it is applied.

## Startup-state recovery

Independent of per-action checks, every start of the tool:

- **parses** the config file against a key whitelist (never sourced), then **sanitizes** every value (`config_sanitize`): invalid ports/protocols/auth modes/endpoints/API ids/URLs are reset to safe defaults and the reset is logged — corrupted or hand-edited config cannot crash a code path or feed garbage into commands;
- detects **partial/interrupted installations** (e.g. `server.conf` without a PKI, or config claiming installed while files are gone) and labels the Install menu as a *repair*;
- falls back to **plain-text prompts** when there is no usable terminal (piped stdin/stdout or `TERM=dumb`) so whiptail can never wait for input on a screen it cannot draw.
