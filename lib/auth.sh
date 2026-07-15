#!/usr/bin/env bash
# =============================================================================
# lib/auth.sh - per-user authentication management + global enforcement
#
# A client certificate is ALWAYS required (verify-client-cert require).
# On top of it EVERY USER has their own mode (stored in the policy file):
#
#   cert              certificate only (no PAM login)
#   password          + system password           (pam_unix, hash in /etc/shadow)
#   password_totp     + password + TOTP           (pam_unix + pam_google_authenticator)
#   yubikey           + YubiKey OTP               (pam_yubico)
#   password_yubikey  + password + YubiKey OTP    (pam_yubico + pam_unix)
#
# HOW MIXED MODES WORK ON ONE SERVER (full detail: docs/AUTHENTICATION.md):
#   1. auth-policy.sh (unprivileged, fail-closed) decides per certificate CN
#      whether credentials are required at all, enforces username == CN and
#      the global allowed-modes list. It never sees passwords.
#   2. ONE generated PAM stack (/etc/pam.d/openvpn) runs only the credential
#      modules matching the user's mode, gated by membership of the
#      ovm-password / ovm-totp / ovm-yubikey groups (pam_succeed_if jumps).
#   3. Certificate-only clients send no credentials (auth-user-pass-optional);
#      the resulting empty PAM login is short-circuited by pam-allow-empty.sh.
#   4. YubiKey OTPs arrive at the END of the password field (pam_yubico
#      try_first_pass verifies and strips them, passing the remaining
#      password to pam_unix); TOTP codes arrive via static-challenge.
# =============================================================================

auth_mode_label() {
    case "${1:-cert}" in
        cert)             echo "Certificate only" ;;
        password)         echo "Certificate + password" ;;
        password_totp)    echo "Certificate + password + TOTP" ;;
        yubikey)          echo "Certificate + YubiKey OTP" ;;
        password_yubikey) echo "Certificate + password + YubiKey OTP" ;;
        *)                echo "unknown" ;;
    esac
}

auth_status_label() { # short main-menu summary of the auth situation
    if ! policy_ready; then
        echo "$(auth_mode_label "${AUTH_MODE:-cert}") (v1 - migration pending)"
        return 0
    fi
    local -a arr=()
    read -r -a arr <<< "${AUTH_ALLOWED_MODES:-cert}"
    if (( ${#arr[@]} == 1 )); then
        auth_mode_label "${arr[0]}"
    else
        echo "per-user (${#arr[@]} modes allowed)"
    fi
}

_mode_is_allowed() { [[ " ${AUTH_ALLOWED_MODES:-cert} " == *" $1 "* ]]; }

_allowed_labels() {
    local m out=""
    for m in ${AUTH_ALLOWED_MODES:-cert}; do
        out+="${out:+, }$(auth_mode_label "$m")"
    done
    printf '%s' "$out"
}

_auth_family_active() { # _auth_family_active password|totp|yubikey
    # True if any allowed mode OR any assigned user mode uses the family.
    local fam="$1" m n
    for m in ${AUTH_ALLOWED_MODES:-cert}; do
        case "$fam" in
            password) mode_uses_password "$m" && return 0 ;;
            totp)     mode_uses_totp "$m"     && return 0 ;;
            yubikey)  mode_uses_yubikey "$m"  && return 0 ;;
        esac
    done
    while read -r n m; do
        [[ -z "$m" ]] && continue
        case "$fam" in
            password) mode_uses_password "$m" && return 0 ;;
            totp)     mode_uses_totp "$m"     && return 0 ;;
            yubikey)  mode_uses_yubikey "$m"  && return 0 ;;
        esac
    done < <(policy_list_users)
    return 1
}

auth_stack_required() { # does server.conf need the PAM plugin at all?
    _auth_family_active password || _auth_family_active totp || _auth_family_active yubikey
}

auth_require_v2() { # gate for menus that need the per-user policy store
    openvpn_is_installed || { ui_msg "Not installed" "Install OpenVPN first."; return 1; }
    policy_ready && return 0
    auth_migrate_v2
}

# -----------------------------------------------------------------------------
# Menus
# -----------------------------------------------------------------------------

auth_menu() {
    auth_require_v2 || return 0
    while true; do
        local choice
        choice="$(ui_menu "Authentication management" \
"Allowed modes: $(_allowed_labels)
Default for new users: $(auth_mode_label "${AUTH_DEFAULT_MODE:-cert}")" \
            "users"    "User authentication modes (per-user settings)" \
            "enforce"  "Global enforcement rules (allowed modes, default)" \
            "features" "Global authentication features (TOTP, YubiKey, PAM)" \
            "validate" "Validate authentication configuration" \
            "viewpam"  "View the generated PAM configuration" \
            "back"     "Back to main menu")" || return 0
        case "$choice" in
            users)    auth_user_menu_pick ;;
            enforce)  auth_enforcement_menu ;;
            features) auth_features_menu ;;
            validate) auth_validate_report ;;
            viewpam)
                if [[ -f "$PAM_FILE" ]]; then
                    ui_textfile "PAM configuration (${PAM_FILE})" "$PAM_FILE"
                else
                    ui_msg "PAM" "No PAM stack is generated (all allowed modes are certificate-only)."
                fi ;;
            back)     return 0 ;;
        esac
    done
}

# --- Per-user authentication screen -------------------------------------------

auth_user_menu_pick() {
    local u
    u="$(user_select "User authentication settings")" || return 0
    auth_user_menu "$u"
}

auth_user_menu() { # auth_user_menu <user>
    local user="$1"
    while true; do
        local mode comp="" choice
        mode="$(policy_user_mode "$user" 2>/dev/null || echo cert)"
        _mode_is_allowed "$mode" || comp=$'\n*** This mode is NOT allowed by the enforcement rules - the user is BLOCKED at login! ***'

        local -a items=( "mode" "Change authentication mode..." )
        case "$mode" in
            password)         items+=( "addtotp" "Add TOTP (-> password + TOTP)" \
                                       "addyk"   "Add YubiKey (-> password + YubiKey)" ) ;;
            password_totp)    items+=( "deltotp" "Remove TOTP requirement (-> password only)" ) ;;
            password_yubikey) items+=( "delyk"   "Remove YubiKey requirement (-> password only)" ) ;;
            yubikey)          items+=( "addpw"   "Add password (-> password + YubiKey)" ) ;;
        esac
        mode_uses_password "$mode" && items+=( "passwd"    "Set / change the VPN password" )
        mode_uses_totp "$mode"     && items+=( "totpqr"    "Show TOTP enrollment QR code again" \
                                               "totpreset" "Reset TOTP secret (new QR code)" )
        mode_uses_yubikey "$mode"  && items+=( "ykreg"     "Register / replace / add a YubiKey" )
        [[ "$mode" != "cert" ]]    && items+=( "cert"      "Return to certificate-only mode" )
        items+=( "regen" "Regenerate the client profile (.ovpn)" \
                 "back"  "Back" )

        choice="$(ui_menu "User: ${user}" \
"Authentication mode: $(auth_mode_label "$mode")${comp}
Enrollment: $(_user_flags "$user")" "${items[@]}")" || return 0

        case "$choice" in
            mode)      auth_pick_mode_for_user "$user" ;;
            addtotp)   user_set_auth_mode "$user" "password_totp" ;;
            addyk)     user_set_auth_mode "$user" "password_yubikey" ;;
            addpw)     user_set_auth_mode "$user" "password_yubikey" ;;
            deltotp)   user_set_auth_mode "$user" "password" ;;
            delyk)     user_set_auth_mode "$user" "password" ;;
            cert)      user_set_auth_mode "$user" "cert" ;;
            passwd)    _set_account_password "$user" ;;
            totpqr)    totp_show "$user" ;;
            totpreset) totp_reset "$user" ;;
            ykreg)     yubikey_register "$user" ;;
            regen)
                require_feature "profile" "$user" \
                    "Regenerate the client profile of '${user}'" || continue
                if build_client_profile "$user"; then
                    ui_msg "Done" "Profile regenerated: ${OVM_CLIENT_DIR}/${user}.ovpn"
                fi ;;
            back)      return 0 ;;
        esac
    done
}

auth_pick_mode_for_user() { # auth_pick_mode_for_user <user>
    local user="$1" cur new m state
    cur="$(policy_user_mode "$user" 2>/dev/null || echo cert)"
    local -a args=()
    for m in "${OVM_AUTH_MODES[@]}"; do
        # only globally allowed modes are selectable (plus the current one)
        _mode_is_allowed "$m" || [[ "$m" == "$cur" ]] || continue
        state="off"; [[ "$m" == "$cur" ]] && state="on"
        args+=("$m" "$(auth_mode_label "$m")" "$state")
    done
    new="$(ui_radiolist "Authentication mode for '${user}'" \
"A valid client certificate is always required. Choose what this user
must present IN ADDITION to it (only globally allowed modes are shown):" \
        "${args[@]}")" || return 0
    [[ -z "$new" || "$new" == "$cur" ]] && return 0
    user_set_auth_mode "$user" "$new"
}

# -----------------------------------------------------------------------------
# The central per-user mode transition
# -----------------------------------------------------------------------------

_account_pw_state() { # -> set|locked|none
    local s
    s="$(passwd -S "$1" 2>/dev/null | awk '{print $2}')"
    case "$s" in
        P|PS)  echo "set" ;;
        L|LK)  echo "locked" ;;
        *)     echo "none" ;;
    esac
}

user_set_auth_mode() { # user_set_auth_mode <user> <mode> [quiet]
    local user="$1" new="$2" quiet="${3:-}"
    local old
    old="$(policy_user_mode "$user" 2>/dev/null || echo cert)"

    if [[ "$new" == "$old" && -z "$quiet" ]]; then
        ui_msg "Authentication" "'${user}' already uses: $(auth_mode_label "$new")"
        return 0
    fi

    # Validate EVERYTHING first (global feature, packages, API, user, cert,
    # enforcement rules) - missing requirements show the fix menu instead of
    # failing or hanging midway.
    require_feature "assign_${new}" "$user" \
        "Set authentication mode of '${user}' to '$(auth_mode_label "$new")'" || return 1

    if [[ -z "$quiet" ]]; then
        local steps=""
        [[ "$new" != "cert" ]] && steps+=$'\n  - ensure a locked-down system account exists'
        mode_uses_password "$new" && steps+=$'\n  - ensure a VPN password is set'
        mode_uses_totp "$new"     && [[ ! -f "${OVM_TOTP_DIR}/${user}" ]] \
            && steps+=$'\n  - generate a TOTP secret (QR code shown once)'
        mode_uses_yubikey "$new"  && ! grep -q "^${user}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null \
            && steps+=$'\n  - register the user'\''s YubiKey (one touch)'
        steps+=$'\n  - update the policy file + PAM gate groups (atomic)'
        steps+=$'\n  - regenerate the user'\''s .ovpn profile (must be redistributed)'
        ui_yesno "Change authentication mode" \
"User:  ${user}
From:  $(auth_mode_label "$old")
To:    $(auth_mode_label "$new")

Steps:${steps}

Existing sessions stay up; the new requirements apply from the next
login. Continue?" || return 0
    fi

    # ---- provision prerequisites (inert until the policy flips below) ------
    if [[ "$new" != "cert" ]]; then
        _ensure_system_account "$user" || return 1
    fi
    if mode_uses_password "$new"; then
        if [[ "$(_account_pw_state "$user")" != "set" ]]; then
            ui_msg "Password required" \
"Mode '$(auth_mode_label "$new")' needs a VPN password for '${user}'.
Set it now (asked twice, never stored in plaintext, never logged)."
            _set_account_password "$user" || {
                log_warn "Auth mode change for ${user} aborted: no password set"
                ui_msg "Aborted" "No password was set - nothing has been changed."
                return 1
            }
        elif [[ -z "$quiet" ]]; then
            ui_yesno "Password" "'${user}' already has a password. Keep it?" \
                || { _set_account_password "$user" || return 1; }
        fi
    fi
    if mode_uses_totp "$new" && [[ ! -f "${OVM_TOTP_DIR}/${user}" ]]; then
        OVM_SUPPRESS_MODE_WARN=1 totp_generate "$user"
        [[ -f "${OVM_TOTP_DIR}/${user}" ]] || {
            log_warn "Auth mode change for ${user} aborted: TOTP enrollment incomplete"
            ui_msg "Aborted" "No TOTP secret was generated - nothing has been changed."
            return 1
        }
    fi
    if mode_uses_yubikey "$new" && ! grep -q "^${user}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null; then
        OVM_SUPPRESS_MODE_WARN=1 yubikey_register "$user"
        grep -q "^${user}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null || {
            log_warn "Auth mode change for ${user} aborted: no YubiKey registered"
            ui_msg "Aborted" "No YubiKey was registered - nothing has been changed."
            return 1
        }
    fi

    # ---- commit: gate groups + account lock state + policy entry -----------
    policy_sync_groups "$user" "$new"
    if [[ "$new" == "cert" ]] || ! mode_uses_password "$new"; then
        # password is not a factor for this mode: lock the account password
        id -u "$user" >/dev/null 2>&1 && usermod -L "$user" 2>/dev/null || true
    fi
    policy_set_user "$user" "$new" || {
        ui_msg "Error" "Could not update the policy file. See ${OVM_LOG_FILE}."
        return 1
    }
    auth_refresh_stack
    log_info "Auth mode for user ${user}: ${old} -> ${new}"

    # ---- optional cleanup of now-unused enrollment data ---------------------
    if mode_uses_totp "$old" && ! mode_uses_totp "$new" && [[ -f "${OVM_TOTP_DIR}/${user}" ]]; then
        ui_yesno "TOTP secret" \
"'${user}' no longer uses TOTP. Delete the stored secret?
(Keep it if you may re-enable TOTP for this user later.)" defaultno \
            && { shred -u "${OVM_TOTP_DIR}/${user}" 2>/dev/null || rm -f "${OVM_TOTP_DIR}/${user}"
                 log_info "TOTP secret removed for ${user} (mode downgrade)"; }
    fi
    if mode_uses_yubikey "$old" && ! mode_uses_yubikey "$new" \
            && grep -q "^${user}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null; then
        ui_yesno "YubiKey registration" \
"'${user}' no longer uses YubiKey OTP. Remove the key registration?
(Keep it if you may re-enable YubiKey for this user later.)" defaultno \
            && { sed -i "/^${user}:/d" "$OVM_YUBI_AUTHFILE"
                 log_info "YubiKey registration removed for ${user} (mode downgrade)"; }
    fi

    if [[ -z "$quiet" ]]; then
        if ui_yesno "Client profile" \
"The .ovpn profile must match the new mode (auth-user-pass /
static-challenge lines). Regenerate '${user}.ovpn' now?"; then
            build_client_profile "$user" \
                && ui_msg "Profile updated" \
"${OVM_CLIENT_DIR}/${user}.ovpn

Distribute the new file to the user over a secure channel.
$(_client_login_hint "$new")"
        fi
    fi
    return 0
}

_client_login_hint() { # one-line reminder of the login procedure per mode
    case "$1" in
        cert)             echo "Login: no username/password - the certificate is enough." ;;
        password)         echo "Login: VPN username + password." ;;
        password_totp)    echo "Login: VPN username + password, then the 6-digit code at the challenge prompt." ;;
        yubikey)          echo "Login: VPN username; in the password field just touch the YubiKey." ;;
        password_yubikey) echo "Login: VPN username; in the password field type the password and IMMEDIATELY touch the YubiKey (the OTP is appended)." ;;
    esac
}

# -----------------------------------------------------------------------------
# Global enforcement rules
# -----------------------------------------------------------------------------

auth_enforcement_menu() {
    while true; do
        local choice viol
        choice="$(ui_menu "Global enforcement rules" \
"Allowed modes: $(_allowed_labels)
Default for new users: $(auth_mode_label "${AUTH_DEFAULT_MODE:-cert}")" \
            "allowed" "Choose the allowed / enforced authentication modes" \
            "default" "Default mode for new users" \
            "check"   "List users violating the current rules" \
            "back"    "Back")" || return 0
        case "$choice" in
            allowed) auth_edit_allowed_modes ;;
            default) auth_pick_default_mode ;;
            check)
                viol="$(policy_noncompliant "${AUTH_ALLOWED_MODES:-cert}")"
                if [[ -z "$viol" ]]; then
                    ui_msg "Compliance" "Every user's mode is within the allowed list."
                else
                    ui_show_text "Non-compliant users (BLOCKED at login)" \
"These users have a mode outside the allowed list and are rejected
by the policy layer when they try to connect:

$(awk '{printf "  %-24s %s\n", $1, $2}' <<< "$viol")

Fix them under: Authentication -> User authentication modes."
                fi ;;
            back)    return 0 ;;
        esac
    done
}

auth_edit_allowed_modes() {
    local m sel cur=" ${AUTH_ALLOWED_MODES:-cert} "
    local -a args=()
    for m in "${OVM_AUTH_MODES[@]}"; do
        args+=("$m" "$(auth_mode_label "$m")" \
               "$([[ "$cur" == *" ${m} "* ]] && echo on || echo off)")
    done
    sel="$(ui_checklist "Allowed authentication modes" \
"Users can only be assigned - and can only log in with - the modes
selected here. Selecting exactly ONE mode enforces it for everyone." \
        "${args[@]}")" || return 0
    if [[ -z "$sel" ]]; then
        ui_msg "Enforcement" "At least one mode must remain allowed - nothing was changed."
        return 0
    fi
    [[ "$sel" == "${AUTH_ALLOWED_MODES:-cert}" ]] && return 0

    # Validate the global features of every NEWLY allowed mode first.
    for m in $sel; do
        [[ "$cur" == *" ${m} "* ]] && continue
        require_feature "allow_${m}" "" \
            "Allow authentication mode '$(auth_mode_label "$m")'" || return 0
    done

    # Compliance impact BEFORE applying anything.
    local viol fixnow="no"
    viol="$(policy_noncompliant "$sel")"
    if [[ -n "$viol" ]]; then
        show_enforcement_impact_dialog "$sel" "$viol"
        local decision
        decision="$(ui_menu "Users become non-compliant" "How do you want to continue?" \
            "update" "Apply the rules and update the listed users NOW" \
            "block"  "Apply the rules anyway - the listed users will be BLOCKED" \
            "cancel" "Cancel - keep the current rules")" || return 0
        case "$decision" in
            cancel) return 0 ;;
            update) fixnow="yes" ;;
            block)
                ui_yesno "Confirm blocking" \
"$(wc -l <<< "$viol") user(s) will be UNABLE to connect until their mode is changed.
Apply the new enforcement rules anyway?" defaultno || return 0 ;;
        esac
    else
        ui_yesno "Apply enforcement rules" \
"New allowed modes:

$(for m in $sel; do echo "  - $(auth_mode_label "$m")"; done)

No existing user violates these rules. Apply?" || return 0
    fi

    AUTH_ALLOWED_MODES="$sel"
    config_set AUTH_ALLOWED_MODES "$AUTH_ALLOWED_MODES"
    if ! _mode_is_allowed "${AUTH_DEFAULT_MODE:-cert}"; then
        AUTH_DEFAULT_MODE="${sel%% *}"
        config_set AUTH_DEFAULT_MODE "$AUTH_DEFAULT_MODE"
    fi
    auth_refresh_stack
    log_info "Enforcement rules updated: allowed modes = ${AUTH_ALLOWED_MODES}"

    if [[ "$fixnow" == "yes" ]]; then
        local name mode
        while read -r name mode; do
            [[ -z "$name" ]] && continue
            ui_msg "Update user" \
"'${name}' currently uses '$(auth_mode_label "$mode")' which is no longer allowed.
Choose a new mode on the next screen."
            auth_pick_mode_for_user "$name"
        done <<< "$viol"
        viol="$(policy_noncompliant "$AUTH_ALLOWED_MODES")"
        if [[ -n "$viol" ]]; then
            ui_show_text "Still non-compliant (BLOCKED at login)" \
"$(awk '{printf "  %-24s %s\n", $1, $2}' <<< "$viol")

These users remain blocked until their mode is updated under
Authentication -> User authentication modes."
        fi
    fi
    ui_msg "Enforcement applied" \
"Allowed modes: $(_allowed_labels)

The policy layer enforces this at every connection attempt."
}

show_enforcement_impact_dialog() { # <new allowed> <violators "name mode" lines>
    local sel="$1" viol="$2"
    ui_show_text "Enforcement impact" \
"New allowed modes:

$(local m; for m in $sel; do echo "  - $(auth_mode_label "$m")"; done)

The following users would violate the new rules. The policy layer
REJECTS every connection of a non-compliant user (fail-closed):

$(awk '{printf "  %-24s currently: %s\n", $1, $2}' <<< "$viol")"
}

auth_pick_default_mode() {
    local m new state
    local -a args=()
    for m in ${AUTH_ALLOWED_MODES:-cert}; do
        state="off"; [[ "$m" == "${AUTH_DEFAULT_MODE:-cert}" ]] && state="on"
        args+=("$m" "$(auth_mode_label "$m")" "$state")
    done
    new="$(ui_radiolist "Default mode for new users" \
        "Preselected when adding a new VPN user:" "${args[@]}")" || return 0
    [[ -z "$new" ]] && return 0
    AUTH_DEFAULT_MODE="$new"
    config_set AUTH_DEFAULT_MODE "$new"
    policy_sync_header
    log_info "Default auth mode for new users: ${new}"
}

# -----------------------------------------------------------------------------
# Global authentication features (availability, packages, validation service)
# -----------------------------------------------------------------------------

auth_features_menu() {
    while true; do
        local pam_state="MISSING" totp_state="not installed" yk_state="not installed"
        find_auth_pam_plugin >/dev/null 2>&1 && pam_state="available"
        find_pam_module pam_google_authenticator.so && totp_state="installed"
        if find_pam_module pam_yubico.so; then
            yk_state="installed, service: not configured"
            [[ -n "$YUBICO_ID" ]]  && yk_state="installed, YubiCloud id ${YUBICO_ID}"
            [[ -n "$YUBICO_URL" ]] && yk_state="installed, self-hosted"
        fi
        local choice
        choice="$(ui_menu "Global authentication features" \
"PAM plugin: ${pam_state} | TOTP: ${totp_state} | YubiKey: ${yk_state}" \
            "totppkg"  "Install the TOTP PAM module (pam_google_authenticator)" \
            "totplist" "List TOTP enrollment status of all users" \
            "ykpkg"    "Install the YubiKey PAM module (pam_yubico)" \
            "ykapi"    "Configure the YubiKey validation service (API key / URL)" \
            "yktest"   "Validate a test YubiKey OTP (checks the whole chain)" \
            "yklist"   "List registered YubiKeys" \
            "ykdel"    "Remove a user's YubiKey registration" \
            "ykhelp"   "YubiKey setup instructions" \
            "back"     "Back")" || return 0
        case "$choice" in
            totppkg)
                ui_run "Install TOTP PAM module" pkg_install_totp
                ui_pause; ui_resume_tui ;;
            totplist) totp_list ;;
            ykpkg)
                ui_run "Install YubiKey PAM module" pkg_install_yubico
                ui_pause; ui_resume_tui ;;
            ykapi)    yubikey_configure_api ;;
            yktest)   yubikey_test ;;
            yklist)   yubikey_list ;;
            ykdel)    _yubi_pick_user "Remove YubiKey" yubikey_unregister ;;
            ykhelp)   yubikey_instructions ;;
            back)     return 0 ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Generated artifacts: PAM stack + server.conf directives
# -----------------------------------------------------------------------------

auth_refresh_stack() {
    # Regenerate every authentication artifact from the persisted state.
    # server.conf is only followed by a restart when it actually changed;
    # policy file, PAM stack and gate groups are re-read on every login.
    write_pam_empty_script
    write_policy_script
    policy_sync_header
    write_pam_file
    local before after
    before="$(md5sum "$OVPN_SERVER_CONF" 2>/dev/null | awk '{print $1}')"
    write_server_conf
    after="$(md5sum "$OVPN_SERVER_CONF" 2>/dev/null | awk '{print $1}')"
    if [[ "$before" != "$after" ]] && svc_is_active; then
        log_info "server.conf changed by an authentication update - restarting OpenVPN"
        svc_restart_checked || true
    fi
    return 0
}

write_pam_file() {
    if ! auth_stack_required; then
        rm -f "$PAM_FILE"
        return 0
    fi
    local yubico_opts="mode=client authfile=${OVM_YUBI_AUTHFILE} try_first_pass"
    [[ -n "$YUBICO_ID" ]]  && yubico_opts+=" id=${YUBICO_ID}"
    [[ -n "$YUBICO_KEY" ]] && yubico_opts+=" key=${YUBICO_KEY}"
    [[ -n "$YUBICO_URL" ]] && yubico_opts+=" urllist=${YUBICO_URL}"

    {
        echo "# Generated by openvpn-manager - per-user gated PAM stack."
        echo "# Do not edit; regenerated on every authentication change."
        echo "# Which credential modules run for a login is decided by the user's"
        echo "# membership of the ovm-* gate groups (= their assigned auth mode)."
        echo "#"
        echo "# 1) certificate-only clients: OpenVPN passes an EMPTY username."
        echo "#    Allow it here - auth-policy.sh has already enforced (fail-closed)"
        echo "#    that only certificate-only users may log in without credentials."
        echo "auth    [success=done default=ignore]   pam_exec.so quiet ${OVM_PAM_EMPTY_SCRIPT}"
        echo "# 2) any real login must belong to a VPN account"
        echo "auth    requisite                       pam_succeed_if.so quiet user ingroup ${VPN_GROUP}"
        if _auth_family_active yubikey; then
            echo "# 3) YubiKey OTP (members of ${OVM_GRP_YUBIKEY}). Runs FIRST: the OTP"
            echo "#    arrives appended to the password field; pam_yubico validates it"
            echo "#    online, strips it, and passes the remainder to pam_unix."
            echo "auth    [success=1 default=ignore]      pam_succeed_if.so quiet user notingroup ${OVM_GRP_YUBIKEY}"
            echo "auth    requisite                       pam_yubico.so ${yubico_opts}"
        fi
        if _auth_family_active password; then
            echo "# 4) system password (members of ${OVM_GRP_PASSWORD})"
            echo "auth    [success=1 default=ignore]      pam_succeed_if.so quiet user notingroup ${OVM_GRP_PASSWORD}"
            echo "auth    requisite                       pam_unix.so try_first_pass"
        fi
        if _auth_family_active totp; then
            echo "# 5) TOTP code (members of ${OVM_GRP_TOTP}), sent via static-challenge"
            echo "auth    [success=1 default=ignore]      pam_succeed_if.so quiet user notingroup ${OVM_GRP_TOTP}"
            # shellcheck disable=SC2016
            echo 'auth    requisite                       pam_google_authenticator.so user=root secret='"${OVM_TOTP_DIR}"'/${USER}'
        fi
        echo "# every gate above passed (or was skipped for this user's mode)"
        echo "auth    required                        pam_permit.so"
        echo "account [success=done default=ignore]   pam_exec.so quiet ${OVM_PAM_EMPTY_SCRIPT}"
        echo "account required                        pam_succeed_if.so quiet user ingroup ${VPN_GROUP}"
    } > "$PAM_FILE"
    # The file can contain the YubiCloud API key -> root-only.
    chmod 600 "$PAM_FILE"
    chown root:root "$PAM_FILE" 2>/dev/null || true
    log_info "PAM stack written (families:$(_auth_family_active password && printf ' password')$(_auth_family_active totp && printf ' totp')$(_auth_family_active yubikey && printf ' yubikey'))"
    return 0
}

auth_server_directives() { # emitted into server.conf by write_server_conf
    echo "# --- authentication: per-user policy (docs/AUTHENTICATION.md) ---"
    echo "# auth-policy.sh enforces (fail-closed, as user nobody) which factors"
    echo "# each certificate must present and that username == CN. It never"
    echo "# reads the password."
    echo "script-security 2"
    echo "auth-user-pass-verify ${OVM_POLICY_SCRIPT} via-file"
    echo "# certificate-only users log in without credentials:"
    echo "auth-user-pass-optional"
    if auth_stack_required; then
        local plugin="${PLUGIN_PATH}"
        [[ -n "$plugin" && -e "$plugin" ]] || plugin="$(find_auth_pam_plugin 2>/dev/null || true)"
        if [[ -z "$plugin" ]]; then
            # Fail closed: a missing plugin must break the service visibly,
            # never let password/OTP logins through unchecked.
            log_error "PAM plugin required but not found - OpenVPN will refuse to start until it is installed"
            plugin="/usr/lib/openvpn/openvpn-plugin-auth-pam.so"
        fi
        echo "# PAM verifies the credentials (per-user gated stack in ${PAM_FILE})."
        echo "# The quoted map answers each PAM prompt from the client's login"
        echo "# fields; the plugin matches each name as a CASE-INSENSITIVE PREFIX"
        echo "# of the prompt ('password' answers 'Password: ', 'yubikey' answers"
        echo "# 'YubiKey for ...'). 'login' answers PAM's username lookup. Keep"
        echo "# this map short: OpenVPN parses at most 16 tokens per plugin line"
        echo "# and a truncated, odd-length map makes the plugin fail to load."
        echo "plugin ${plugin} \"${PAM_SERVICE_NAME} login USERNAME password PASSWORD verification OTP yubikey PASSWORD\""
        echo "# renegotiation token so OTP users are not re-challenged hourly"
        echo "auth-gen-token 43200"
    else
        echo "# all allowed modes are certificate-only: no PAM plugin required"
    fi
}

# -----------------------------------------------------------------------------
# Validation report
# -----------------------------------------------------------------------------

auth_validate_report() {
    local t="" m u
    _v() { t+="$(printf '%-6s %s' "[$1]" "$2")"$'\n'; }

    # global artifacts
    if policy_ready; then
        _v PASS "Policy file exists (${OVM_POLICY_FILE})"
        local hdr
        hdr="$(awk '$1=="allowed" {$1=""; print; exit}' "$OVM_POLICY_FILE")"
        if [[ "$(echo "$hdr" | xargs)" == "${AUTH_ALLOWED_MODES:-cert}" ]]; then
            _v PASS "Policy header matches the configured allowed modes"
        else
            _v FAIL "Policy header (${hdr# }) differs from config (${AUTH_ALLOWED_MODES:-cert}) - re-apply enforcement rules"
        fi
    else
        _v FAIL "Policy file missing - per-user authentication is NOT enforced"
    fi
    [[ -x "$OVM_POLICY_SCRIPT" ]]    && _v PASS "auth-policy.sh present and executable" \
                                     || _v FAIL "auth-policy.sh missing/not executable - ALL logins are rejected"
    [[ -x "$OVM_PAM_EMPTY_SCRIPT" ]] && _v PASS "pam-allow-empty.sh present and executable" \
                                     || _v WARN "pam-allow-empty.sh missing - certificate-only logins may fail"
    if grep -q "auth-user-pass-verify ${OVM_POLICY_SCRIPT}" "$OVPN_SERVER_CONF" 2>/dev/null; then
        _v PASS "server.conf runs the policy gate"
    else
        _v FAIL "server.conf does not reference auth-policy.sh - regenerate it (any auth change does)"
    fi

    if auth_stack_required; then
        if find_auth_pam_plugin >/dev/null 2>&1; then
            _v PASS "OpenVPN PAM plugin available"
        else
            _v FAIL "OpenVPN PAM plugin missing - password/OTP logins fail (reinstall the openvpn package)"
        fi
        [[ -f "$PAM_FILE" ]] && _v PASS "PAM stack generated (${PAM_FILE})" \
                             || _v FAIL "PAM stack missing - run any authentication change to regenerate"
        grep -q "^plugin " "$OVPN_SERVER_CONF" 2>/dev/null \
            && _v PASS "server.conf loads the PAM plugin" \
            || _v FAIL "server.conf lacks the plugin line - credential modes cannot work"
        if _auth_family_active totp; then
            find_pam_module pam_google_authenticator.so \
                && _v PASS "TOTP PAM module installed" \
                || _v FAIL "TOTP PAM module missing - TOTP users fail closed at login"
        fi
        if _auth_family_active yubikey; then
            find_pam_module pam_yubico.so \
                && _v PASS "YubiKey PAM module installed" \
                || _v FAIL "YubiKey PAM module missing - YubiKey users fail closed at login"
            if [[ -n "$YUBICO_URL" || ( -n "$YUBICO_ID" && -n "$YUBICO_KEY" ) ]]; then
                _v PASS "YubiKey validation service configured"
            else
                _v FAIL "No YubiKey validation service - YubiKey OTPs cannot be verified"
            fi
        fi
    else
        _v PASS "All allowed modes are certificate-only (no PAM stack needed)"
    fi

    # per-user state
    local mode acct pw grp want
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        if ! mode="$(policy_user_mode "$u" 2>/dev/null)"; then
            _v FAIL "${u}: valid certificate but NO policy entry - blocked at login (assign a mode)"
            continue
        fi
        _mode_is_allowed "$mode" \
            || _v FAIL "${u}: mode '${mode}' violates the enforcement rules - blocked at login"
        if [[ "$mode" != "cert" ]]; then
            if id -u "$u" >/dev/null 2>&1; then
                if mode_uses_password "$mode"; then
                    pw="$(_account_pw_state "$u")"
                    [[ "$pw" == "set" ]] \
                        || _v FAIL "${u}: mode needs a password but the account password is '${pw}'"
                fi
                want="$(mode_groups "$mode")"
                grp="$(id -nG "$u" 2>/dev/null)"
                for m in $want; do
                    grep -qw "$m" <<< "$grp" \
                        || _v FAIL "${u}: missing PAM gate group '${m}' - re-apply the user's mode"
                done
            else
                _v FAIL "${u}: mode '${mode}' needs a system account but none exists - re-apply the user's mode"
            fi
            if mode_uses_totp "$mode" && [[ ! -f "${OVM_TOTP_DIR}/${u}" ]]; then
                _v FAIL "${u}: TOTP required but no secret enrolled"
            fi
            if mode_uses_yubikey "$mode" && ! grep -q "^${u}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null; then
                _v FAIL "${u}: YubiKey required but no key registered"
            fi
        fi
    done < <(cert_list_valid_clients 2>/dev/null)

    # policy entries without a live certificate
    local name pmode
    while read -r name pmode; do
        [[ -z "$name" ]] && continue
        cert_exists "$name" \
            || _v WARN "${name}: policy entry (${pmode}) but no valid certificate - stale entry, revoke remnants"
    done < <(policy_list_users)

    if grep -q '^\[FAIL\]' <<< "$t"; then
        log_warn "Authentication validation found problems"
    else
        log_info "Authentication validation passed"
    fi
    ui_show_text "Authentication configuration check" \
"${t:-(nothing to check)}
Legend: PASS = ok, WARN = review recommended, FAIL = users affected/blocked."
    unset -f _v
}

auth_repair_prompt_map() {
    # Two defective PAM prompt maps shipped and are repaired at startup:
    #   v2.0.0: 17 tokens - over OpenVPN's 16-token line limit, silently
    #           truncated to an odd list -> plugin init fatal, restart loop.
    #           Signature: '... Yubikey PASSWORD yubikey PASSWORD"'.
    #   v2.0.1: first-letter-dropped names ('ogin', 'assword', ...) - but the
    #           plugin matches names as PREFIXES of the PAM prompts, so no
    #           prompt ever matched -> every credential login failed with
    #           'Conversation error'. Signature: '... ubi PASSWORD erification ...'.
    # The current map ('login USERNAME password PASSWORD ...') matches
    # neither pattern.
    openvpn_is_installed && policy_ready || return 0
    grep -Eq '^plugin .*(Yubikey PASSWORD yubikey PASSWORD"| ubi PASSWORD erification )' \
        "$OVPN_SERVER_CONF" 2>/dev/null || return 0
    log_warn "Defective v2.0.0/v2.0.1 PAM prompt map found in server.conf - repairing"
    auth_refresh_stack
    ui_msg "Configuration repaired" \
"This server carried a defective PAM prompt map from v2.0.0/v2.0.1
(auth plugin failing to load, or every password/OTP login failing
with 'Conversation error').

server.conf has been regenerated with the corrected map."
    if [[ "$INSTALLED" == "yes" ]] && ! svc_is_active; then
        svc_restart_checked || true
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Migration from the v1.x single global mode
# -----------------------------------------------------------------------------

auth_migrate_v2() { # rc 0 = policy store ready afterwards
    policy_ready && return 0
    openvpn_is_installed || return 1

    local legacy="${AUTH_MODE:-cert}" users
    users="$(cert_list_valid_clients 2>/dev/null)"

    # No users yet: adopt the legacy mode silently - nobody can be locked out.
    if [[ -z "$users" ]]; then
        AUTH_ALLOWED_MODES="$legacy"; AUTH_DEFAULT_MODE="$legacy"
        config_set AUTH_ALLOWED_MODES "$AUTH_ALLOWED_MODES"
        config_set AUTH_DEFAULT_MODE "$AUTH_DEFAULT_MODE"
        auth_refresh_stack
        rm -f "$CN_VERIFY_SCRIPT"
        log_info "Migrated to per-user authentication (no users; allowed=${legacy})"
        return 0
    fi

    # Build the per-user proposal, downgrading users whose enrollment is
    # incomplete so nobody is silently locked out.
    local u mode notes="" plan=""
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        mode="$legacy"
        if mode_uses_totp "$mode" && [[ ! -f "${OVM_TOTP_DIR}/${u}" ]]; then
            mode="password"
            notes+="  ${u}: no TOTP secret enrolled -> proposed '${mode}' instead"$'\n'
        fi
        if mode_uses_yubikey "$mode" && ! grep -q "^${u}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null; then
            if mode_uses_password "$mode"; then mode="password"; else mode="cert"; fi
            notes+="  ${u}: no YubiKey registered -> proposed '${mode}' instead"$'\n'
        fi
        if mode_uses_password "$mode" && [[ "$(_account_pw_state "$u")" != "set" ]]; then
            notes+="  ${u}: no usable password set - set one after migration or the user cannot log in"$'\n'
        fi
        plan+="${u} ${mode}"$'\n'
    done <<< "$users"

    ui_show_text "Upgrade to per-user authentication (v2)" \
"This version supports a DIFFERENT authentication mode per user, with
global enforcement rules. Your current global mode:

  $(auth_mode_label "$legacy")

Proposed migration (changeable per user afterwards):

$(awk 'NF {printf "  %-24s -> %s\n", $1, $2}' <<< "$plan")
${notes:+Adjustments made so nobody is locked out:
$notes}
Applying will rewrite the PAM stack and server.conf (backups are
created) and restart OpenVPN. Existing sessions reconnect automatically.$(
    [[ "$legacy" == "password_yubikey" ]] && printf '\n\nNOTE: the password+YubiKey login format changed: the OTP is now\ntyped at the END of the password field (no separate challenge).\nAll password+YubiKey profiles must be regenerated and redistributed.' )"

    if ! ui_yesno "Apply migration" \
"Migrate to per-user authentication now?

(Until migrated, user and authentication management are unavailable.
The running server keeps its current v1 behaviour.)"; then
        log_warn "Per-user authentication migration declined"
        return 1
    fi

    AUTH_ALLOWED_MODES="$legacy"; AUTH_DEFAULT_MODE="$legacy"
    config_set AUTH_ALLOWED_MODES "$AUTH_ALLOWED_MODES"
    config_set AUTH_DEFAULT_MODE "$AUTH_DEFAULT_MODE"

    local name pmode
    while read -r name pmode; do
        [[ -z "$name" ]] && continue
        if [[ "$pmode" != "cert" ]]; then
            _ensure_system_account "$name" || true
            policy_sync_groups "$name" "$pmode"
            mode_uses_password "$pmode" \
                || { id -u "$name" >/dev/null 2>&1 && usermod -L "$name" 2>/dev/null || true; }
        fi
        policy_set_user "$name" "$pmode"
        log_info "Migrated user ${name}: mode ${pmode}"
    done <<< "$plan"

    auth_refresh_stack
    rm -f "$CN_VERIFY_SCRIPT"
    log_info "Migration to per-user authentication complete (allowed=${legacy})"

    if [[ "$legacy" == "password_yubikey" ]]; then
        ui_yesno "Client profiles" \
"The password+YubiKey login format changed (OTP appended to the
password, no separate challenge prompt). Regenerate ALL client
profiles now? They must be redistributed to the users." \
            && user_regenerate_all_profiles
    fi
    ui_msg "Migration complete" \
"Per-user authentication is active.

  Allowed modes: $(_allowed_labels)

Manage users under: Authentication -> User authentication modes."
    return 0
}
