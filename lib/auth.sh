#!/usr/bin/env bash
# =============================================================================
# lib/auth.sh - authentication mode management
#
# A client certificate is ALWAYS required (verify-client-cert require).
# On top of that, one of five modes:
#
#   cert              certificate only (no PAM)
#   password          + system password           (pam_unix, hash in /etc/shadow)
#   password_totp     + password + TOTP           (pam_unix + pam_google_authenticator)
#   yubikey           + YubiKey OTP               (pam_yubico)
#   password_yubikey  + password + YubiKey OTP    (pam_unix + pam_yubico)
#
# OpenVPN side: openvpn-plugin-auth-pam.so with a prompt-mapping string.
# The plugin answers PAM prompts by case-insensitive prefix match:
#   "password"     -> pam_unix        ("Password: ")
#   "verification" -> google-auth     ("Verification code: ")
#   "yubikey"      -> pam_yubico      ("YubiKey for `user': ")
# PASSWORD/OTP come from the client's auth-user-pass + static-challenge
# (SCRV1), so two factors travel in one auth request. Requires OpenVPN >= 2.5.
#
# ENFORCE_CN_MATCH additionally rejects logins where the PAM username does
# not equal the certificate CN (prevents cross-user credential mixing).
# =============================================================================

auth_mode_label() {
    case "${1:-$AUTH_MODE}" in
        cert)             echo "Certificate only" ;;
        password)         echo "Certificate + password" ;;
        password_totp)    echo "Certificate + password + TOTP" ;;
        yubikey)          echo "Certificate + YubiKey OTP" ;;
        password_yubikey) echo "Certificate + password + YubiKey OTP" ;;
        *)                echo "unknown" ;;
    esac
}

auth_menu() {
    while true; do
        local choice
        choice="$(ui_menu "Authentication" "Active mode: $(auth_mode_label)" \
            "mode"    "Change authentication mode" \
            "totp"    "TOTP management (secrets, QR codes)" \
            "yubikey" "YubiKey management (registration, API)" \
            "cnmatch" "Username must match certificate: ${ENFORCE_CN_MATCH}" \
            "viewpam" "View the generated PAM configuration" \
            "back"    "Back to main menu")" || return 0
        case "$choice" in
            mode)    auth_change_mode ;;
            totp)    totp_menu ;;
            yubikey) yubikey_menu ;;
            cnmatch) auth_toggle_cn_match ;;
            viewpam)
                if [[ -f "$PAM_FILE" ]]; then
                    ui_textfile "PAM configuration (${PAM_FILE})" "$PAM_FILE"
                else
                    ui_msg "PAM" "No PAM file exists (certificate-only mode)."
                fi ;;
            back)    return 0 ;;
        esac
    done
}

auth_change_mode() {
    local new
    new="$(ui_menu "Authentication mode" \
"A valid client certificate is always required. Choose what is
required IN ADDITION to it:" \
        "cert"             "Nothing - certificate only" \
        "password"         "Password" \
        "password_totp"    "Password + TOTP code (Google Authenticator etc.)" \
        "yubikey"          "YubiKey OTP" \
        "password_yubikey" "Password + YubiKey OTP")" || return 0

    [[ "$new" == "$AUTH_MODE" ]] && { ui_msg "Authentication" "That mode is already active."; return 0; }

    ui_yesno "Switch authentication mode" \
"Switching to: $(auth_mode_label "$new")

This will:
  - rewrite ${PAM_FILE} and server.conf (backups are created)
  - restart OpenVPN (active clients reconnect automatically)
  - require regenerating and redistributing all .ovpn profiles

Continue?" || return 0

    apply_auth_mode "$new"
}

apply_auth_mode() { # apply_auth_mode <mode>
    local new="$1"

    # --- prerequisites --------------------------------------------------------
    if [[ "$new" != "cert" ]]; then
        if ! PLUGIN_PATH="$(find_auth_pam_plugin)"; then
            ui_msg "Error" "openvpn-plugin-auth-pam.so not found. Is OpenVPN installed correctly?"
            return 1
        fi
        config_set PLUGIN_PATH "$PLUGIN_PATH"
        groupadd -f "$VPN_GROUP"
    fi
    case "$new" in
        password_totp)
            if ! find_pam_module pam_google_authenticator.so; then
                ui_run "Install TOTP PAM module (pam_google_authenticator)" pkg_install_totp \
                    || { ui_resume_tui; ui_msg "Error" "Could not install the TOTP PAM module. See ${OVM_LOG_FILE}."; return 1; }
            fi ;;
        yubikey|password_yubikey)
            if ! find_pam_module pam_yubico.so; then
                ui_run "Install YubiKey PAM module (pam_yubico)" pkg_install_yubico \
                    || { ui_resume_tui; ui_msg "Error" "Could not install the YubiKey PAM module. See ${OVM_LOG_FILE}."; return 1; }
            fi
            if [[ -z "$YUBICO_ID" && -z "$YUBICO_URL" ]]; then
                ui_msg "YubiKey API required" \
"YubiKey OTP validation needs either a YubiCloud API key
(free at https://upgrade.yubico.com/getapikey/) or a self-hosted
validation server URL. Configure it now."
                yubikey_configure_api || return 1
            fi ;;
    esac
    ui_resume_tui   # a package install above may have scrolled the screen

    # --- apply -----------------------------------------------------------------
    backup_file "$PAM_FILE"
    AUTH_MODE="$new"
    config_set AUTH_MODE "$AUTH_MODE"
    write_pam_file
    write_cn_verify_script
    write_server_conf          # picks up auth_server_directives for the new mode
    write_client_template
    log_info "Authentication mode changed to: ${AUTH_MODE}"

    [[ "$new" != "cert" ]] && auth_backfill_accounts

    svc_restart_checked || return 1
    ui_yesno "Client profiles" \
"Client profiles must match the new mode (auth-user-pass /
static-challenge lines). Regenerate all .ovpn files now?" \
        && user_regenerate_all_profiles
}

auth_backfill_accounts() {
    # After enabling password/OTP auth, every existing cert user needs a
    # system account (and usually a password).
    local u missing=""
    while IFS= read -r u; do
        [[ -n "$u" ]] && ! _has_system_account "$u" && missing+="${u}"$'\n'
    done < <(cert_list_valid_clients)
    [[ -z "$missing" ]] && return 0

    ui_yesno "Existing users" \
"These users have certificates but no login account yet:

${missing}
They cannot connect in the new mode until an account (and password,
if applicable) exists. Create the accounts now?" || return 0

    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        _ensure_system_account "$u" || continue
        case "$AUTH_MODE" in
            password|password_totp|password_yubikey)
                ui_yesno "Password" "Set a password for '${u}' now?" \
                    && _set_account_password "$u" ;;
        esac
    done <<< "$missing"
}

auth_toggle_cn_match() {
    local new="yes"
    [[ "$ENFORCE_CN_MATCH" == "yes" ]] && new="no"
    if [[ "$new" == "no" ]]; then
        ui_yesno "Disable CN matching" \
"Currently a user can only authenticate with the username that matches
their own certificate. Disabling this allows any valid certificate to
be combined with any valid username/password.

Disabling is NOT recommended. Disable anyway?" defaultno || return 0
    fi
    ENFORCE_CN_MATCH="$new"
    config_set ENFORCE_CN_MATCH "$new"
    write_cn_verify_script
    write_server_conf
    log_info "ENFORCE_CN_MATCH set to ${new}"
    svc_restart_checked
}

# -----------------------------------------------------------------------------
# Generated artifacts
# -----------------------------------------------------------------------------

auth_server_directives() { # emitted into server.conf by write_server_conf
    if [[ "$AUTH_MODE" == "cert" ]]; then
        echo "# authentication: client certificate only"
        return 0
    fi
    local pairs=""
    case "$AUTH_MODE" in
        password)         pairs="login USERNAME password PASSWORD" ;;
        password_totp)    pairs="login USERNAME password PASSWORD verification OTP" ;;
        yubikey)          pairs="login USERNAME yubikey PASSWORD" ;;
        password_yubikey) pairs="login USERNAME password PASSWORD yubikey OTP" ;;
    esac
    echo "# --- authentication: $(auth_mode_label) ---"
    echo "plugin ${PLUGIN_PATH} \"${PAM_SERVICE_NAME} ${pairs}\""
    echo "# renegotiation token so OTP users are not re-challenged hourly"
    echo "auth-gen-token 43200"
    if [[ "$ENFORCE_CN_MATCH" == "yes" ]]; then
        echo "script-security 2"
        echo "auth-user-pass-verify ${CN_VERIFY_SCRIPT} via-file"
    fi
}

write_pam_file() {
    [[ "$AUTH_MODE" == "cert" ]] && { rm -f "$PAM_FILE"; return 0; }

    local yubico_opts=""
    if [[ "$AUTH_MODE" == "yubikey" || "$AUTH_MODE" == "password_yubikey" ]]; then
        yubico_opts="mode=client authfile=${OVM_YUBI_AUTHFILE}"
        [[ -n "$YUBICO_ID" ]]  && yubico_opts+=" id=${YUBICO_ID}"
        [[ -n "$YUBICO_KEY" ]] && yubico_opts+=" key=${YUBICO_KEY}"
        [[ -n "$YUBICO_URL" ]] && yubico_opts+=" urllist=${YUBICO_URL}"
    fi

    local nullok=""
    [[ "$TOTP_NULLOK" == "yes" ]] && nullok=" nullok"

    {
        echo "# Generated by openvpn-manager - mode: ${AUTH_MODE}"
        echo "# Do not edit; regenerated on every authentication change."
        echo "auth    requisite   pam_succeed_if.so quiet user ingroup ${VPN_GROUP}"
        case "$AUTH_MODE" in
            password)
                echo "auth    required    pam_unix.so"
                ;;
            password_totp)
                echo "auth    required    pam_unix.so"
                # shellcheck disable=SC2016
                echo 'auth    required    pam_google_authenticator.so user=root secret='"${OVM_TOTP_DIR}"'/${USER}'"${nullok}"
                ;;
            yubikey)
                echo "auth    required    pam_yubico.so ${yubico_opts}"
                ;;
            password_yubikey)
                echo "auth    required    pam_unix.so"
                echo "auth    required    pam_yubico.so ${yubico_opts}"
                ;;
        esac
        echo "account required    pam_unix.so"
    } > "$PAM_FILE"
    # The file can contain the YubiCloud API key -> root-only.
    chmod 600 "$PAM_FILE"
    chown root:root "$PAM_FILE"
    log_info "PAM configuration written for mode ${AUTH_MODE}"
}

write_cn_verify_script() {
    if [[ "$ENFORCE_CN_MATCH" != "yes" || "$AUTH_MODE" == "cert" ]]; then
        rm -f "$CN_VERIFY_SCRIPT"
        return 0
    fi
    mkdir -p "$OVPN_SERVER_DIR"
    cat > "$CN_VERIFY_SCRIPT" <<'EOF'
#!/bin/sh
# openvpn-manager: reject logins where the username does not match the
# certificate common name. Called by OpenVPN (auth-user-pass-verify via-file).
# $1 = temp file whose first line is the username. Nothing is logged here.
[ -n "$1" ] && [ -r "$1" ] || exit 1
u="$(head -n1 "$1")"
[ -n "$u" ] && [ "$u" = "$common_name" ] && exit 0
exit 1
EOF
    chmod 755 "$CN_VERIFY_SCRIPT"
}
