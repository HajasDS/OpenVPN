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

    require_feature "totp_generate" "$user" \
        "Generate a TOTP secret for user '${user}'" || return 0

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

    local umode
    umode="$(policy_user_mode "$user" 2>/dev/null || echo cert)"
    if [[ -z "${OVM_SUPPRESS_MODE_WARN:-}" ]] && ! mode_uses_totp "$umode"; then
        ui_msg "Note" \
"The secret is stored, but '${user}' uses mode '$(auth_mode_label "$umode")',
so no TOTP code is requested at login yet.

Change it under: Authentication -> User authentication modes."
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
    local user="$1" file="${OVM_TOTP_DIR}/$1" umode warn=""
    [[ -f "$file" ]] || { ui_msg "TOTP" "'${user}' has no TOTP secret."; return 0; }
    umode="$(policy_user_mode "$user" 2>/dev/null || echo cert)"
    mode_uses_totp "$umode" && \
        warn=$'\n\nWARNING: this user'\''s mode REQUIRES a TOTP code - they will NOT\nbe able to log in until a new secret is generated or their mode is\nchanged (Authentication -> User authentication modes).'
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
    read -rp " Press Enter when the user has enrolled (screen will be cleared) " _ || true
    clear
}
