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
    auth_require_v2 || return 0
    while true; do
        local choice
        choice="$(ui_menu "User management" \
            "Users: $(cert_list_valid_clients | wc -l)   Default mode: $(auth_mode_label "${AUTH_DEFAULT_MODE:-cert}")" \
            "add"      "Add a new VPN user" \
            "list"     "List users and their status" \
            "auth"     "Per-user authentication settings" \
            "revoke"   "Revoke a user (certificate + access)" \
            "regen"    "Regenerate a client profile (.ovpn)" \
            "regenall" "Regenerate ALL client profiles" \
            "passwd"   "Set / change a user's VPN password" \
            "show"     "Show where a user's .ovpn profile is stored" \
            "back"     "Back to main menu")" || return 0
        case "$choice" in
            add)      user_add ;;
            list)     user_list ;;
            auth)     auth_user_menu_pick ;;
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

_user_flags() { # short status string for menus: "mode | enrollment"
    local u="$1" f="" m
    m="$(policy_user_mode "$u" 2>/dev/null || echo "-")"
    _has_system_account "$u" && f+="account "
    [[ -f "${OVM_TOTP_DIR}/${u}" ]] && f+="TOTP "
    grep -q "^${u}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null && f+="YubiKey "
    printf '%s | %s' "$m" "${f:-cert only}"
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
    auth_require_v2 || return 0
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

    # Pick the authentication mode BEFORE issuing anything, and validate its
    # global prerequisites (packages, API, enforcement) up front.
    local mode="${AUTH_DEFAULT_MODE:-cert}"
    local -a marr=()
    read -r -a marr <<< "${AUTH_ALLOWED_MODES:-cert}"
    if (( ${#marr[@]} > 1 )); then
        local m state
        local -a args=()
        for m in "${marr[@]}"; do
            state="off"; [[ "$m" == "$mode" ]] && state="on"
            args+=("$m" "$(auth_mode_label "$m")" "$state")
        done
        mode="$(ui_radiolist "Authentication mode for '${name}'" \
            "A certificate is always issued. What must this user present in addition?" \
            "${args[@]}")" || return 0
        [[ -z "$mode" ]] && mode="${AUTH_DEFAULT_MODE:-cert}"
    fi
    require_feature "allow_${mode}" "" \
        "Add user '${name}' with mode '$(auth_mode_label "$mode")'" || return 0

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

    # Provision credentials + policy entry for the chosen mode. If the admin
    # aborts halfway (e.g. cancels the password prompt), fall back to a safe
    # certificate-only entry so the user is never left in a blocked
    # no-policy state.
    if ! user_set_auth_mode "$name" "$mode" quiet; then
        if _mode_is_allowed "cert"; then
            policy_set_user "$name" "cert"
            auth_refresh_stack
            ui_msg "Mode not applied" \
"Provisioning for '$(auth_mode_label "$mode")' was not completed.
'${name}' was saved as CERTIFICATE-ONLY instead - change it later under
Authentication -> User authentication modes."
        else
            policy_set_user "$name" "$mode"
            auth_refresh_stack
            ui_msg "Enrollment incomplete" \
"'${name}' is stored with mode '$(auth_mode_label "$mode")' but the
enrollment is incomplete - the user CANNOT log in yet. Finish it under
Authentication -> User authentication modes."
        fi
    fi

    build_client_profile "$name"
    ui_msg "User added" \
"VPN user '${name}' is ready.
Mode: $(auth_mode_label "$(policy_user_mode "$name" 2>/dev/null || echo cert)")

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
    local name mode
    name="$(user_select "Change password")" || return 0
    mode="$(policy_user_mode "$name" 2>/dev/null || echo cert)"
    if ! mode_uses_password "$mode"; then
        ui_msg "Not applicable" \
"'${name}' uses mode '$(auth_mode_label "$mode")' - it has no VPN password.
Change the mode first under Authentication -> User authentication modes."
        return 0
    fi
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
            local g
            for g in "$VPN_GROUP" "$OVM_GRP_PASSWORD" "$OVM_GRP_TOTP" "$OVM_GRP_YUBIKEY"; do
                gpasswd -d "$name" "$g" >/dev/null 2>&1 || true
            done
            log_info "Removed ${name} from VPN groups (pre-existing account kept)"
        fi
    fi

    policy_remove_user "$name"
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
    local u text="" pwstate mode comp
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        mode="$(policy_user_mode "$u" 2>/dev/null || echo "NO-POLICY!")"
        comp=""
        [[ "$mode" == "NO-POLICY!" ]] || _mode_is_allowed "$mode" || comp=" [BLOCKED by enforcement]"
        pwstate="-"
        if _has_system_account "$u"; then
            pwstate="$(passwd -S "$u" 2>/dev/null | awk '{print $2}')"
            case "$pwstate" in
                P|PS) pwstate="set" ;;
                L|LK) pwstate="locked" ;;
                NP)   pwstate="EMPTY!" ;;
            esac
        fi
        text+="$(printf '%-20s %-18s pw:%-8s expires: %s%s' \
            "$u" "$mode" "$pwstate" "$(cert_expiry "$u")" "$comp")"$'\n'
    done < <(cert_list_valid_clients)
    [[ -z "$text" ]] && text="(no active users)"
    ui_show_text "VPN users  —  allowed modes: $(_allowed_labels)" "$text"
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

    local mode
    mode="$(policy_user_mode "$name" 2>/dev/null || echo cert)"

    umask 077
    {
        cat "$OVM_TEMPLATE_FILE"
        case "$mode" in
            cert)
                echo "# certificate-only login: no username/password required" ;;
            password)
                echo "# Login: VPN username + password"
                echo "auth-user-pass" ;;
            password_totp)
                echo "# Login: VPN username + password, then the 6-digit code"
                echo "auth-user-pass"
                echo 'static-challenge "Enter your 6-digit TOTP code" 1' ;;
            yubikey)
                echo "# Login: username = VPN username; password field = touch your YubiKey"
                echo "auth-user-pass" ;;
            password_yubikey)
                echo "# Login: username = VPN username; in the password field type the"
                echo "# password and IMMEDIATELY touch the YubiKey (its one-time code is"
                echo "# appended to the end - the server splits and verifies both)."
                echo "auth-user-pass" ;;
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
    log_info "Client profile generated: ${name}.ovpn (auth mode: ${mode})"
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
