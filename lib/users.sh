#!/usr/bin/env bash
# =============================================================================
# lib/users.sh - VPN user lifecycle: add, revoke, list, client profiles,
# passwords, system accounts
#
# Rule: a VPN user = client certificate (CN) + (for non-cert auth modes)
# a locked-down system account with the same name, primary group VPN_GROUP,
# shell nologin. Passwords are stored ONLY as hashes in /etc/shadow.
# =============================================================================

user_menu() {
    while true; do
        local choice
        choice="$(ui_menu "User management" \
            "Auth mode: $(auth_mode_label)   Users: $(cert_list_valid_clients | wc -l)" \
            "add"      "Add a new VPN user" \
            "list"     "List users and their status" \
            "revoke"   "Revoke a user (certificate + access)" \
            "regen"    "Regenerate a client profile (.ovpn)" \
            "regenall" "Regenerate ALL client profiles" \
            "passwd"   "Set / change a user's VPN password" \
            "show"     "Show where a user's .ovpn profile is stored" \
            "back"     "Back to main menu")" || return 0
        case "$choice" in
            add)      user_add ;;
            list)     user_list ;;
            revoke)   user_revoke ;;
            regen)    user_regenerate_profile ;;
            regenall) user_regenerate_all_profiles ;;
            passwd)   user_set_password ;;
            show)     user_show_profile_path ;;
            back)     return 0 ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Selection helper
# -----------------------------------------------------------------------------

user_select() { # user_select "Title" -> prints chosen username
    local title="$1" u
    local -a items=()
    while IFS= read -r u; do
        [[ -n "$u" ]] && items+=("$u" "$(_user_flags "$u")")
    done < <(cert_list_valid_clients)
    if (( ${#items[@]} == 0 )); then
        ui_msg "$title" "There are no active VPN users yet."
        return 1
    fi
    ui_menu "$title" "Select a user:" "${items[@]}"
}

_user_flags() { # short status string for menus
    local u="$1" f=""
    _has_system_account "$u" && f+="account "
    [[ -f "${OVM_TOTP_DIR}/${u}" ]] && f+="TOTP "
    grep -q "^${u}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null && f+="YubiKey "
    printf '%s' "${f:-certificate only}"
}

_has_system_account() { id -u "$1" >/dev/null 2>&1; }

_is_vpn_account() { # true if the account's primary group is VPN_GROUP
    local u="$1" gid vgid
    gid="$(id -g "$u" 2>/dev/null)" || return 1
    vgid="$(getent group "$VPN_GROUP" 2>/dev/null | cut -d: -f3)" || return 1
    [[ -n "$vgid" && "$gid" == "$vgid" ]]
}

# -----------------------------------------------------------------------------
# Add user
# -----------------------------------------------------------------------------

user_add() {
    # PKI must be healthy before we try to issue anything (covers partially
    # installed / interrupted setups).
    require_feature "user_add" "" "Add a new VPN user" || return 0

    local name
    name="$(ui_input_validated "New VPN user" \
        "Username (letters, digits, '-', '_'; max 32 chars):" "" \
        is_valid_username \
        "Invalid username. Allowed: a-z A-Z 0-9 - _ (must start alphanumeric, not 'server*').")" \
        || return 0

    if cert_exists "$name"; then
        ui_msg "User exists" "A valid certificate for '${name}' already exists."
        return 0
    fi
    if _has_system_account "$name" && ! _is_vpn_account "$name"; then
        ui_yesno "Existing system account" \
"'${name}' already exists as a REGULAR system account on this server.

With password authentication enabled, this person could log in to the
VPN with their existing system password.

Use this existing account for the VPN anyway?" defaultno || return 0
    fi

    # Optional passphrase on the client private key
    local passfile=""
    if ui_yesno "Private key" \
"Protect the client's private key with a passphrase?

The user will have to type it every time the VPN connects.
Recommended for laptops that may be lost or stolen." defaultno; then
        local kp
        kp="$(ui_password_confirmed "Key passphrase" "Passphrase for ${name}'s private key")" || return 0
        passfile="$(mktemp)"
        chmod 600 "$passfile"
        printf '%s' "$kp" > "$passfile"
    fi

    ui_info "Issuing certificate for ${name}..."
    if ! cert_create_client "$name" "$passfile"; then
        [[ -n "$passfile" ]] && shred -u "$passfile" 2>/dev/null
        ui_msg "Error" "Certificate creation failed. See ${OVM_LOG_FILE}."
        return 1
    fi
    [[ -n "$passfile" ]] && shred -u "$passfile" 2>/dev/null
    log_info "User created: ${name}"

    # System account + credentials for the active auth mode
    if [[ "$AUTH_MODE" != "cert" ]]; then
        _ensure_system_account "$name" || return 1
        case "$AUTH_MODE" in
            password|password_totp|password_yubikey)
                _set_account_password "$name" || true ;;
        esac
        case "$AUTH_MODE" in
            password_totp)
                if [[ "$TOTP_NULLOK" == "yes" ]]; then
                    ui_yesno "TOTP" "Generate a TOTP secret for '${name}' now?
(Per-user TOTP is optional on this server.)" \
                        && totp_generate "$name"
                else
                    ui_msg "TOTP required" "TOTP is mandatory on this server. A secret will be generated now."
                    totp_generate "$name"
                fi ;;
        esac
        case "$AUTH_MODE" in
            yubikey|password_yubikey)
                ui_msg "YubiKey required" "This server requires YubiKey OTP. Register '${name}'s key now."
                yubikey_register "$name" ;;
        esac
    fi

    build_client_profile "$name"
    ui_msg "User added" \
"VPN user '${name}' is ready.

Client profile (transfer it over a SECURE channel, then consider
deleting it from the server):

  ${OVM_CLIENT_DIR}/${name}.ovpn"
}

_ensure_system_account() {
    local name="$1"
    groupadd -f "$VPN_GROUP"
    if _has_system_account "$name"; then
        # add VPN group membership if missing
        _is_vpn_account "$name" || usermod -aG "$VPN_GROUP" "$name"
        return 0
    fi
    if useradd -M -N -g "$VPN_GROUP" -s "$NOLOGIN_SHELL" -c "openvpn-manager VPN user" "$name"; then
        log_info "System account created for VPN user: ${name} (nologin, group ${VPN_GROUP})"
        return 0
    fi
    log_error "useradd failed for ${name}"
    ui_msg "Error" "Could not create the system account for '${name}'."
    return 1
}

_set_account_password() {
    local name="$1" pw
    pw="$(ui_password_confirmed "VPN password" "Password for VPN user '${name}'")" || return 1
    # printf is a shell builtin -> the password never appears in any argv/proc list.
    if printf '%s:%s\n' "$name" "$pw" | chpasswd; then
        log_info "Password set for user: ${name}"
        return 0
    fi
    log_error "chpasswd failed for ${name}"
    ui_msg "Error" "Setting the password failed (check password policy / pam configuration)."
    return 1
}

user_set_password() {
    [[ "$AUTH_MODE" == "cert" ]] && {
        ui_msg "Not applicable" "The server is in certificate-only mode; there are no VPN passwords."
        return 0
    }
    local name
    name="$(user_select "Change password")" || return 0
    _has_system_account "$name" || _ensure_system_account "$name" || return 1
    _set_account_password "$name"
}

# -----------------------------------------------------------------------------
# Revoke / remove
# -----------------------------------------------------------------------------

user_revoke() {
    local name
    name="$(user_select "Revoke user")" || return 0

    ui_yesno "Revoke '${name}'" \
"This will immediately and permanently:
  - revoke the certificate (existing sessions are cut on reconnect)
  - delete the system account and password (if managed by this tool)
  - delete the TOTP secret and YubiKey registration
  - delete the stored .ovpn profile

Revoke VPN user '${name}'?" defaultno || return 0

    ui_info "Revoking ${name}..."
    cert_revoke_client "$name" || { ui_msg "Error" "Revocation failed. See ${OVM_LOG_FILE}."; return 1; }

    if _has_system_account "$name"; then
        if _is_vpn_account "$name"; then
            userdel "$name" >/dev/null 2>&1 || true
            log_info "System account removed: ${name}"
        else
            gpasswd -d "$name" "$VPN_GROUP" >/dev/null 2>&1 || true
            log_info "Removed ${name} from ${VPN_GROUP} (pre-existing account kept)"
        fi
    fi

    [[ -f "${OVM_TOTP_DIR}/${name}" ]] && shred -u "${OVM_TOTP_DIR}/${name}" 2>/dev/null
    [[ -f "$OVM_YUBI_AUTHFILE" ]] && sed -i "/^${name}:/d" "$OVM_YUBI_AUTHFILE"
    rm -f "${OVM_CLIENT_DIR}/${name}.ovpn"

    log_info "User revoked: ${name}"
    ui_msg "Revoked" "User '${name}' has been revoked. Active sessions end at their next TLS renegotiation or reconnect; restart OpenVPN from the Service menu to disconnect them immediately."
}

# -----------------------------------------------------------------------------
# Listing
# -----------------------------------------------------------------------------

user_list() {
    local u text="" pwstate
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        pwstate="-"
        if _has_system_account "$u"; then
            pwstate="$(passwd -S "$u" 2>/dev/null | awk '{print $2}')"
            case "$pwstate" in
                P|PS) pwstate="set" ;;
                L|LK) pwstate="locked" ;;
                NP)   pwstate="EMPTY!" ;;
            esac
        fi
        text+="$(printf '%-20s pw:%-8s %s | expires: %s' \
            "$u" "$pwstate" "$(_user_flags "$u")" "$(cert_expiry "$u")")"$'\n'
    done < <(cert_list_valid_clients)
    [[ -z "$text" ]] && text="(no active users)"
    ui_show_text "VPN users  —  auth mode: $(auth_mode_label)" "$text"
}

user_show_profile_path() {
    local name
    name="$(user_select "Client profile")" || return 0
    if [[ -f "${OVM_CLIENT_DIR}/${name}.ovpn" ]]; then
        ui_msg "Profile location" \
"${OVM_CLIENT_DIR}/${name}.ovpn

Copy it to the user's device over a secure channel (scp/sftp),
e.g. from the client machine:

  scp root@${ENDPOINT}:${OVM_CLIENT_DIR}/${name}.ovpn .

The file contains the user's private key - treat it like a password."
    else
        ui_yesno "Missing profile" "No stored .ovpn for '${name}'. Generate it now?" \
            && build_client_profile "$name" \
            && ui_msg "Done" "Created ${OVM_CLIENT_DIR}/${name}.ovpn"
    fi
}

# -----------------------------------------------------------------------------
# Client profile (.ovpn) generation
# -----------------------------------------------------------------------------

build_client_profile() { # build_client_profile <name>
    local name="$1"
    local crt="${PKI_DIR}/issued/${name}.crt"
    local key="${PKI_DIR}/private/${name}.key"
    local out="${OVM_CLIENT_DIR}/${name}.ovpn"

    [[ -f "$crt" && -f "$key" ]] || { log_error "Missing cert/key for ${name}"; return 1; }
    [[ -f "$OVM_TEMPLATE_FILE" ]] || write_client_template

    umask 077
    {
        cat "$OVM_TEMPLATE_FILE"
        case "$AUTH_MODE" in
            password)
                echo "auth-user-pass" ;;
            password_totp)
                echo "auth-user-pass"
                echo 'static-challenge "Enter your 6-digit TOTP code" 1' ;;
            yubikey)
                echo "# Login: username = VPN username, password = touch your YubiKey"
                echo "auth-user-pass" ;;
            password_yubikey)
                echo "auth-user-pass"
                echo 'static-challenge "Insert and touch your YubiKey" 1' ;;
        esac
        echo "<ca>"
        cat "${PKI_DIR}/ca.crt"
        echo "</ca>"
        echo "<cert>"
        openssl x509 -in "$crt"
        echo "</cert>"
        echo "<key>"
        cat "$key"
        echo "</key>"
        if [[ "$CONTROL_WRAP" == "tls-crypt" ]]; then
            echo "<tls-crypt>"
            cat "${OVPN_SERVER_DIR}/tls-crypt.key"
            echo "</tls-crypt>"
        else
            echo "key-direction 1"
            echo "<tls-auth>"
            cat "${OVPN_SERVER_DIR}/tls-crypt.key"
            echo "</tls-auth>"
        fi
    } > "$out"
    chmod 600 "$out"
    log_info "Client profile generated: ${name}.ovpn (auth mode: ${AUTH_MODE})"
}

user_regenerate_profile() {
    local name
    name="$(user_select "Regenerate profile")" || return 0
    require_feature "profile" "$name" \
        "Regenerate the client profile of '${name}'" || return 0
    if build_client_profile "$name"; then
        ui_msg "Done" "Profile regenerated:
${OVM_CLIENT_DIR}/${name}.ovpn"
    else
        ui_msg "Error" "Profile generation failed. See ${OVM_LOG_FILE}."
    fi
}

user_regenerate_all_profiles() {
    local u n=0
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        build_client_profile "$u" && n=$((n+1))
    done < <(cert_list_valid_clients)
    log_info "Regenerated ${n} client profiles"
    ui_msg "Profiles regenerated" "${n} client profile(s) rebuilt in ${OVM_CLIENT_DIR}.

Distribute the new files to the users."
}
