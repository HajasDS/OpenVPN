#!/usr/bin/env bash
# =============================================================================
# lib/checks.sh - centralized feature dependency validation
#
# Design (see docs/PREREQUISITES.md):
#   Every feature entry point calls
#       require_feature <feature> <user|""> "<action label>"
#   BEFORE touching the system. Validation is strictly READ-ONLY; fixes run
#   only when the administrator explicitly picks them from the fix menu.
#   The user can always cancel back to the previous menu, the loop is
#   bounded, and nothing is partially applied without confirmation.
#
# Requirement record format (one array element per unmet requirement):
#       "severity|name|description|autofix|recommended action"
#   severity: blocking  - the action cannot run until resolved
#             warning   - the action can proceed, admin decides
#   autofix : an id understood by apply_dependency_fix(), or "-" if none.
#
# Logging: only requirement NAMES and feature labels are logged - never
# secrets, key material or OTP values.
# =============================================================================

REQ_FAILURES=()
REQ_FEATURE=""

req_reset() { REQ_FAILURES=(); }

req_fail() { # req_fail <severity> <name> <description> <autofix|-> <action>
    REQ_FAILURES+=("$1|$2|$3|$4|$5")
}

req_has_blocking() {
    local r
    for r in "${REQ_FAILURES[@]}"; do
        [[ "${r%%|*}" == "blocking" ]] && return 0
    done
    return 1
}

# -----------------------------------------------------------------------------
# Entry point used by every feature
# -----------------------------------------------------------------------------

require_feature() { # require_feature <feature> <user|""> "<action label>" ; 0 = proceed
    local feature="$1" user="$2" label="$3" guard=0 choice r sev name
    while (( guard++ < 15 )); do
        validate_feature_requirements "$feature" "$user"
        (( ${#REQ_FAILURES[@]} == 0 )) && return 0

        if (( guard == 1 )); then
            for r in "${REQ_FAILURES[@]}"; do
                IFS='|' read -r sev name _ <<< "$r"
                log_warn "${label} blocked: ${name} (${sev})"
            done
        fi

        # The info screen is shown OUTSIDE the command substitution below:
        # only the menu (whose fd-swap is capture-safe) runs inside $(...),
        # so no widget can ever end up drawn into a captured variable.
        show_missing_requirements_dialog "$label"
        choice="$(_requirements_fix_menu)" || {
            log_info "${label}: cancelled at requirements check"
            return 1
        }
        case "$choice" in
            proceed)
                log_info "${label}: administrator chose to proceed despite warnings"
                return 0 ;;
            back)
                log_info "${label}: cancelled at requirements check"
                return 1 ;;
            recheck)
                ;;   # loop re-validates
            *)
                apply_dependency_fix "$choice" "$user" || true ;;
        esac
    done
    ui_msg "Aborted" "Requirements were still not met after several attempts.
Returning to the previous menu."
    return 1
}

# -----------------------------------------------------------------------------
# Feature -> requirement mapping
# -----------------------------------------------------------------------------

validate_feature_requirements() { # validate_feature_requirements <feature> <user|"">
    local feature="$1" user="${2:-}"
    REQ_FEATURE="$feature"
    req_reset
    case "$feature" in
        yubikey_register)
            check_yubikey_requirements "register" "$user" ;;
        yubikey_test)
            check_yubikey_requirements "test" "" ;;

        # "allow_<mode>": global prerequisites of making a mode available
        # (enforcement rules / installer / user_add pre-check).
        allow_cert)
            ;;   # certificate-only has no extra prerequisites
        allow_password)
            check_password_auth_requirements ;;
        allow_password_totp)
            check_password_auth_requirements
            check_totp_requirements "allow" "" ;;
        allow_yubikey|allow_password_yubikey)
            check_password_auth_requirements
            check_yubikey_requirements "allow" "" ;;

        # "assign_<mode>": everything needed to give <user> that mode.
        assign_cert)
            _check_mode_allowed "cert"
            _check_user_exists "$user" ;;
        assign_password)
            check_password_auth_requirements
            _check_mode_allowed "password"
            _check_user_exists "$user" ;;
        assign_password_totp)
            check_password_auth_requirements
            check_totp_requirements "assign" "$user"
            _check_mode_allowed "password_totp" ;;
        assign_yubikey|assign_password_yubikey)
            check_password_auth_requirements
            check_yubikey_requirements "assign" "$user"
            _check_mode_allowed "${feature#assign_}" ;;

        totp_generate)
            check_totp_requirements "generate" "$user" ;;
        user_add)
            check_certificate_requirements "" ;;
        profile)
            check_certificate_requirements "$user" ;;
        *)
            log_warn "validate_feature_requirements: unknown feature '${feature}'" ;;
    esac
}

# -----------------------------------------------------------------------------
# Requirement checks (READ-ONLY - they must never change system state)
# -----------------------------------------------------------------------------

check_password_auth_requirements() {
    # Shared base of every PAM-backed mode (password, TOTP, YubiKey).
    local p
    if p="$(find_auth_pam_plugin)"; then
        PLUGIN_PATH="$p"
    else
        req_fail blocking "OpenVPN PAM plugin (openvpn-plugin-auth-pam.so)" \
            "Routes VPN logins to PAM; no password/TOTP/YubiKey mode can work without it." \
            "-" "Reinstall the openvpn package - the plugin ships with it."
    fi
    _check_secret_perms
}

check_totp_requirements() { # check_totp_requirements <context: allow|assign|generate> <user|"">
    local context="$1" user="${2:-}"

    find_pam_module pam_google_authenticator.so || req_fail blocking \
        "TOTP PAM module (pam_google_authenticator)" \
        "Verifies the 6-digit TOTP codes during PAM authentication." \
        "install_totp_pam" "Install the libpam-google-authenticator package."

    case "$context" in
        generate|assign)
            _check_user_exists "$user"
            ;;
        allow)
            ;;   # availability only - enrollment happens per user at assign time
    esac
    _check_secret_perms
}

check_yubikey_requirements() { # check_yubikey_requirements <context: register|test|allow|assign> <user|"">
    local context="$1" user="${2:-}"

    if [[ "$context" != "test" ]]; then
        find_pam_module pam_yubico.so || req_fail blocking \
            "YubiKey PAM module (pam_yubico)" \
            "Validates YubiKey one-time codes during PAM authentication." \
            "install_yubico_pam" "Install the libpam-yubico package."
    fi

    case "$context" in
        register)
            _check_yubico_api warning
            _check_user_exists "$user"
            local umode
            umode="$(policy_user_mode "$user" 2>/dev/null || echo cert)"
            if [[ -z "${OVM_SUPPRESS_MODE_WARN:-}" ]] && ! mode_uses_yubikey "$umode"; then
                req_fail warning "User's authentication mode" \
                    "'${user:-?}' uses '$(auth_mode_label "$umode")'; the key is stored but NOT requested at login until the user's mode includes YubiKey." \
                    "-" "Register the key, then change the mode under Authentication -> User authentication modes."
            fi
            ;;
        test)
            _check_yubico_api blocking
            command -v curl >/dev/null 2>&1 || req_fail blocking \
                "curl" "Needed to reach the OTP validation service over HTTPS." \
                "-" "Install the curl package."
            ;;
        allow)
            # OTPs are useless without a validation service, but it can still
            # be configured before the first user is assigned -> warning here.
            _check_yubico_api warning
            ;;
        assign)
            # An assigned user must actually be able to log in -> blocking.
            _check_yubico_api blocking
            _check_user_exists "$user"
            ;;
    esac
    _check_secret_perms
}

_check_mode_allowed() { # _check_mode_allowed <mode>
    [[ " ${AUTH_ALLOWED_MODES:-cert} " == *" $1 "* ]] && return 0
    req_fail blocking "Mode allowed by enforcement rules" \
        "'$(auth_mode_label "$1")' is not in the allowed-modes list; assigning it would create a user the policy layer blocks at every login." \
        "edit_allowed" "Add the mode under Authentication -> Global enforcement rules."
}

check_certificate_requirements() { # check_certificate_requirements <user|"">
    local user="${1:-}"

    [[ -x "${EASYRSA_DIR}/easyrsa" ]] || req_fail blocking \
        "easy-rsa PKI tool" \
        "Issues and revokes all VPN certificates." \
        "-" "Run Reinstall from the main menu (or install the easy-rsa package and re-run installation)."

    [[ -f "${PKI_DIR}/ca.crt" ]] || req_fail blocking \
        "CA certificate (${PKI_DIR}/ca.crt)" \
        "Every client profile embeds the CA; without it no profile can be built." \
        "-" "The PKI is missing/broken - run Reinstall from the main menu."

    [[ -f "${PKI_DIR}/index.txt" ]] || req_fail blocking \
        "PKI index (${PKI_DIR}/index.txt)" \
        "Tracks issued/revoked certificates; required for user management." \
        "-" "The PKI is missing/broken - run Reinstall from the main menu."

    [[ -s "${OVPN_SERVER_DIR}/tls-crypt.key" ]] || req_fail blocking \
        "tls-crypt key (${OVPN_SERVER_DIR}/tls-crypt.key)" \
        "Embedded in every client profile; clients cannot connect without it." \
        "-" "The server keys are missing - run Reinstall from the main menu."

    if [[ -n "$user" ]]; then
        [[ -f "${PKI_DIR}/issued/${user}.crt" && -f "${PKI_DIR}/private/${user}.key" ]] \
            || req_fail blocking "Certificate/key of user '${user}'" \
                "The user's certificate and private key are needed to build the .ovpn profile." \
                "-" "Revoke the remnants of this user and create the user again."
    fi
}

# --- shared low-level checks ---------------------------------------------------

_check_user_exists() {
    local u="$1"
    if [[ -z "$u" ]] || ! cert_exists "$u"; then
        req_fail blocking "VPN user '${u:-?}'" \
            "The target user must exist as a valid (non-revoked) VPN user." \
            "-" "Create the user first: User management -> Add a new VPN user."
    fi
}

_check_yubico_api() { # _check_yubico_api <severity>
    local sev="$1"
    if [[ -n "$YUBICO_URL" ]]; then
        is_valid_url "$YUBICO_URL" && return 0
        req_fail "$sev" "Self-hosted validation server URL" \
            "The configured URL is not a valid http(s) address." \
            "configure_yubico_api" "Reconfigure the validation service."
        return 0
    fi
    if [[ -n "$YUBICO_ID" || -n "$YUBICO_KEY" ]]; then
        if is_valid_yubico_client_id "${YUBICO_ID:-}" && [[ -n "$YUBICO_KEY" ]]; then
            return 0
        fi
        req_fail "$sev" "YubiCloud API credentials" \
            "Client ID and secret key must both be set to validate OTPs against YubiCloud." \
            "configure_yubico_api" "Reconfigure the YubiCloud API credentials."
        return 0
    fi
    req_fail "$sev" "YubiKey validation service" \
        "YubiKey OTPs change on every touch and must be verified online (YubiCloud or self-hosted); without a service no OTP can be checked." \
        "configure_yubico_api" "Configure YubiCloud API credentials or a self-hosted verify URL."
}

_check_secret_perms() {
    local bad="" f mode
    for f in "$PAM_FILE" "$OVM_CONFIG_FILE" "$OVM_YUBI_AUTHFILE"; do
        [[ -e "$f" ]] || continue
        mode="$(stat -c '%a' "$f" 2>/dev/null)"
        case "$mode" in 600|400) ;; *) bad+=" ${f}(${mode})" ;; esac
    done
    for f in "$OVM_TOTP_DIR"/*; do
        [[ -f "$f" ]] || continue
        mode="$(stat -c '%a' "$f" 2>/dev/null)"
        case "$mode" in 600|400) ;; *) bad+=" ${f}(${mode})" ;; esac
    done
    [[ -z "$bad" ]] && return 0
    req_fail warning "Secret file permissions" \
        "These files may contain credentials and must be root-only:${bad}" \
        "fix_permissions" "Tighten permissions to 0600/0400."
}

# -----------------------------------------------------------------------------
# UI: show what is missing, why, and how it can be fixed
# -----------------------------------------------------------------------------

show_missing_requirements_dialog() { # show_missing_requirements_dialog "<label>"
    local label="$1" r sev name desc fix act text
    text="Requested action:
  ${label}

Requirements not met:
"
    for r in "${REQ_FAILURES[@]}"; do
        IFS='|' read -r sev name desc fix act <<< "$r"
        text+="
  [${sev^^}] ${name}
      Why:  ${desc}
      Next: ${act}
      Automatic fix available: $( [[ "$fix" != "-" ]] && echo yes || echo no )
"
    done
    if req_has_blocking; then
        text+=$'\nBLOCKING items must be resolved before this action can run.'
    else
        text+=$'\nOnly warnings were found - you may proceed anyway.'
    fi
    ui_show_text "Missing requirements" "$text"
}

_requirements_fix_menu() { # prints the chosen action id; rc=1 on cancel
    local r sev name desc fix act id seen
    local -a fix_ids=() items=()
    for r in "${REQ_FAILURES[@]}"; do
        IFS='|' read -r sev name desc fix act <<< "$r"
        [[ "$fix" == "-" ]] && continue
        seen="no"
        for id in "${fix_ids[@]}"; do [[ "$id" == "$fix" ]] && seen="yes"; done
        [[ "$seen" == "no" ]] && fix_ids+=("$fix")
    done
    for id in "${fix_ids[@]}"; do
        items+=("$id" "$(_fix_label "$id")")
    done
    req_has_blocking || items+=("proceed" "Proceed anyway (warnings only)")
    items+=("recheck" "Re-check requirements")
    items+=("back"    "Return to previous menu")

    ui_menu "Missing requirements" "How do you want to continue?" "${items[@]}"
}

_fix_label() {
    case "$1" in
        install_yubico_pam)   echo "Install the YubiKey PAM module now" ;;
        install_totp_pam)     echo "Install the TOTP PAM module now" ;;
        configure_yubico_api) echo "Configure the YubiKey validation service now" ;;
        register_yubikey)     echo "Register a YubiKey for a user now" ;;
        generate_totp)        echo "Generate a TOTP secret for a user now" ;;
        edit_allowed)         echo "Edit the allowed authentication modes now" ;;
        fix_permissions)      echo "Tighten secret file permissions now" ;;
        *)                    echo "$1" ;;
    esac
}

# -----------------------------------------------------------------------------
# Fix actions (each one is explicit, confirmed, logged, and returns to the
# validation loop afterwards - never applied implicitly)
# -----------------------------------------------------------------------------

apply_dependency_fix() { # apply_dependency_fix <id> <user|"">
    local id="$1" user="${2:-}" rc=0
    log_info "Dependency fix selected: ${id}"
    case "$id" in
        install_yubico_pam)
            ui_run "Install YubiKey PAM module (pam_yubico)" pkg_install_yubico; rc=$?
            ui_pause; ui_resume_tui ;;
        install_totp_pam)
            ui_run "Install TOTP PAM module (pam_google_authenticator)" pkg_install_totp; rc=$?
            ui_pause; ui_resume_tui ;;
        configure_yubico_api)
            yubikey_configure_api; rc=$? ;;
        register_yubikey)
            _yubi_pick_user "Register YubiKey" yubikey_register; rc=$? ;;
        generate_totp)
            _totp_pick_user "Enable TOTP" totp_generate; rc=$? ;;
        edit_allowed)
            auth_edit_allowed_modes; rc=$? ;;
        fix_permissions)
            _fix_secret_perms; rc=$? ;;
        *)
            log_warn "Unknown dependency fix id: ${id}"; rc=1 ;;
    esac
    return "$rc"
}

_fix_secret_perms() {
    local f
    for f in "$PAM_FILE" "$OVM_CONFIG_FILE" "$OVM_YUBI_AUTHFILE"; do
        [[ -e "$f" ]] && { chmod 600 "$f"; chown root:root "$f" 2>/dev/null; }
    done
    for f in "$OVM_TOTP_DIR"/*; do
        [[ -f "$f" ]] && { chmod 400 "$f"; chown root:root "$f" 2>/dev/null; }
    done
    log_info "Secret file permissions tightened (0600/0400)"
    ui_msg "Permissions" "Secret file permissions have been tightened."
    return 0
}
