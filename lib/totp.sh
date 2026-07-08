#!/usr/bin/env bash
# =============================================================================
# lib/totp.sh - TOTP (RFC 6238) management via pam_google_authenticator
#
# One secret file per user in /etc/openvpn-manager/totp/<user> (root, 0400),
# written in the pam_google_authenticator state-file format. Secrets are
# generated locally from /dev/urandom.
#
# SECURITY: secrets and provisioning URIs are shown on screen ONCE and are
# never written to the log. The screen is cleared afterwards.
# =============================================================================

totp_menu() {
    while true; do
        local choice
        choice="$(ui_menu "TOTP management" \
            "Server TOTP policy: $( [[ $AUTH_MODE == password_totp ]] && echo "ACTIVE (optional-per-user: ${TOTP_NULLOK})" || echo "inactive (mode: $(auth_mode_label))" )" \
            "generate" "Generate / enable TOTP for a user (shows QR code)" \
            "show"     "Show enrollment QR code again for a user" \
            "reset"    "Reset a user's TOTP (new secret)" \
            "disable"  "Disable TOTP for a user (delete secret)" \
            "list"     "List TOTP status of all users" \
            "nullok"   "Toggle per-user-optional TOTP (now: ${TOTP_NULLOK})" \
            "enable"   "Enable TOTP globally (switch mode to password+TOTP)" \
            "back"     "Back")" || return 0
        case "$choice" in
            generate) _totp_pick_user "Enable TOTP" totp_generate ;;
            show)     _totp_pick_user "Show QR code" totp_show ;;
            reset)    _totp_pick_user "Reset TOTP" totp_reset ;;
            disable)  _totp_pick_user "Disable TOTP" totp_disable ;;
            list)     totp_list ;;
            nullok)   totp_toggle_nullok ;;
            enable)
                if [[ "$AUTH_MODE" == "password_totp" ]]; then
                    ui_msg "TOTP" "Password + TOTP mode is already active."
                else
                    apply_auth_mode "password_totp"
                fi ;;
            back)     return 0 ;;
        esac
    done
}

_totp_pick_user() { # _totp_pick_user "Title" callback
    local name
    name="$(user_select "$1")" || return 0
    "$2" "$name"
}

totp_generate() { # totp_generate <user>
    local user="$1" secret file="${OVM_TOTP_DIR}/$1"

    if [[ -f "$file" ]]; then
        ui_yesno "TOTP exists" \
"'${user}' already has a TOTP secret. Generating a new one will
invalidate the authenticator app entry they use today.

Replace it?" defaultno || return 0
    fi

    if ! find_pam_module pam_google_authenticator.so; then
        ui_run "Install TOTP PAM module (pam_google_authenticator)" pkg_install_totp \
            || { ui_msg "Error" "Could not install the TOTP PAM module. See ${OVM_LOG_FILE}."; return 1; }
    fi

    # 20 random bytes -> 32-char base32 secret (no padding), like RFC 4226 suggests
    secret="$(head -c 20 /dev/urandom | base32 | tr -d '=')"

    umask 077
    {
        printf '%s\n' "$secret"
        printf '" RATE_LIMIT 3 30\n'
        printf '" WINDOW_SIZE 3\n'
        printf '" DISALLOW_REUSE\n'
        printf '" TOTP_AUTH\n'
    } > "$file"
    chmod 400 "$file"
    chown root:root "$file"

    log_info "TOTP enabled for user: ${user}"     # never log the secret
    _totp_display "$user" "$secret"

    if [[ "$AUTH_MODE" != "password_totp" ]]; then
        ui_msg "Note" \
"The secret is stored, but the server is not in 'password + TOTP' mode
yet, so it is not being asked for at login.

Enable it under: Authentication -> Change authentication mode."
    fi
}

totp_show() { # re-display QR from the stored secret
    local user="$1" file="${OVM_TOTP_DIR}/$1" secret
    [[ -f "$file" ]] || { ui_msg "TOTP" "'${user}' has no TOTP secret."; return 0; }
    secret="$(head -n1 "$file")"
    _totp_display "$user" "$secret"
}

totp_reset() {
    local user="$1"
    ui_yesno "Reset TOTP" \
"Generate a NEW secret for '${user}'? Their current authenticator
app entry will stop working immediately." defaultno || return 0
    [[ -f "${OVM_TOTP_DIR}/${user}" ]] && shred -u "${OVM_TOTP_DIR}/${user}" 2>/dev/null
    log_info "TOTP reset requested for user: ${user}"
    totp_generate "$user"
}

totp_disable() {
    local user="$1" file="${OVM_TOTP_DIR}/$1"
    [[ -f "$file" ]] || { ui_msg "TOTP" "'${user}' has no TOTP secret."; return 0; }
    local warn=""
    [[ "$AUTH_MODE" == "password_totp" && "$TOTP_NULLOK" != "yes" ]] && \
        warn=$'\n\nWARNING: TOTP is MANDATORY on this server, so this user will\nnot be able to log in until a new secret is generated.'
    ui_yesno "Disable TOTP" "Delete the TOTP secret of '${user}'?${warn}" defaultno || return 0
    shred -u "$file" 2>/dev/null || rm -f "$file"
    log_info "TOTP disabled for user: ${user}"
    ui_msg "TOTP" "TOTP disabled for '${user}'."
}

totp_list() {
    local u text=""
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        if [[ -f "${OVM_TOTP_DIR}/${u}" ]]; then
            text+="$(printf '%-24s TOTP: enrolled' "$u")"$'\n'
        else
            text+="$(printf '%-24s TOTP: -' "$u")"$'\n'
        fi
    done < <(cert_list_valid_clients)
    [[ -z "$text" ]] && text="(no users)"
    ui_show_text "TOTP status" "$text"
}

totp_toggle_nullok() {
    local new="yes"
    [[ "$TOTP_NULLOK" == "yes" ]] && new="no"
    ui_yesno "Per-user TOTP" \
"$( if [[ $new == yes ]]; then
  echo 'Make TOTP OPTIONAL per user: users WITH a secret must provide a
code, users WITHOUT one log in with password only.'
else
  echo 'Make TOTP MANDATORY for everyone: users without an enrolled
secret will NOT be able to log in.'
fi )

Apply?" || return 0
    TOTP_NULLOK="$new"
    config_set TOTP_NULLOK "$new"
    log_info "TOTP nullok set to ${new}"
    if [[ "$AUTH_MODE" == "password_totp" ]]; then
        write_pam_file
        ui_msg "TOTP" "Policy updated (PAM configuration rewritten). No restart needed."
    fi
}

# -----------------------------------------------------------------------------
# Enrollment display - plain terminal, cleared afterwards, nothing logged
# -----------------------------------------------------------------------------

_totp_display() { # _totp_display <user> <secret>
    local user="$1" secret="$2"
    local issuer uri
    issuer="OpenVPN-$(hostname | tr -cd 'a-zA-Z0-9.-')"
    uri="otpauth://totp/${issuer}:${user}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30"

    clear
    echo "==================================================================="
    echo " TOTP enrollment for VPN user: ${user}"
    echo "==================================================================="
    echo
    echo " Scan the QR code with Google Authenticator, Microsoft"
    echo " Authenticator, Aegis, FreeOTP, Authy or any TOTP app."
    echo
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ANSIUTF8 "$uri" || true
        echo
    else
        echo " (qrencode is not installed - use manual entry below,"
        echo "  or install it for a scannable QR code)"
        echo
        echo " Provisioning URI:"
        echo "   ${uri}"
        echo
    fi
    echo " Manual entry secret (base32): ${secret}"
    echo
    echo " This is shown only now and is NOT logged anywhere."
    echo " At VPN login the user enters: password, then the 6-digit code."
    echo "==================================================================="
    read -rp " Press Enter when the user has enrolled (screen will be cleared) " _
    clear
}
