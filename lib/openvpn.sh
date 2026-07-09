#!/usr/bin/env bash
# =============================================================================
# lib/openvpn.sh - installation wizard, server.conf / client template
# generation, server settings changes, uninstall
#
# server.conf and the client template are ALWAYS regenerated from the
# persisted configuration (single source of truth), so setting changes and
# auth-mode changes cannot drift from each other.
# =============================================================================

readonly SYSCTL_FILE="/etc/sysctl.d/99-openvpn-manager.conf"

openvpn_is_installed() {
    [[ -f "$OVPN_SERVER_CONF" && -d "$PKI_DIR" ]]
}

openvpn_partial_state() {
    # Detects remnants of a failed/interrupted installation. Prints a short
    # description and returns 0 if partial artifacts exist, 1 otherwise.
    openvpn_is_installed && return 1
    local bits=""
    [[ -f "$OVPN_SERVER_CONF" ]] && bits+=" server.conf"
    [[ -d "$PKI_DIR" ]] && bits+=" PKI"
    [[ "$INSTALLED" == "yes" ]] && bits+=" config-says-installed"
    systemctl is-enabled "$OVPN_SERVICE" >/dev/null 2>&1 && bits+=" service-unit"
    [[ -n "$bits" ]] || return 1
    printf 'Incomplete installation detected (found:%s).' "$bits"
}

# -----------------------------------------------------------------------------
# Interactive installation wizard
# -----------------------------------------------------------------------------

install_wizard() {
    if openvpn_is_installed; then
        ui_yesno "Reinstall OpenVPN" \
"OpenVPN is already installed by this tool.

Reinstalling will DESTROY the current PKI: every existing user
certificate and client profile will stop working permanently.

A backup of /etc/openvpn will be created first.

Continue with a full reinstall?" defaultno || return 0
        ui_yesno "Are you absolutely sure?" \
            "Last confirmation: wipe the PKI and reinstall OpenVPN?" defaultno || return 0
        log_warn "Reinstall requested - existing configuration will be replaced"
        _uninstall_core_quiet
    fi

    check_tun_device

    # ---- Gather settings -----------------------------------------------------
    local nic endpoint local_ip public_ip ipv6 port proto

    nic="$(detect_default_nic)"
    nic="$(ui_input_validated "Network interface" \
        "Public network interface (used for NAT):" "${nic:-eth0}" \
        _valid_nic "Interface not found on this system.")" || return 0

    local_ip="$(detect_local_ipv4 "$nic")"
    endpoint="$local_ip"
    if [[ -z "$endpoint" ]] || is_private_ipv4 "$endpoint"; then
        ui_info "Detecting public IP address..."
        public_ip="$(detect_public_ipv4 || true)"
        [[ -n "$public_ip" ]] && endpoint="$public_ip"
    fi
    endpoint="$(ui_input_validated "Public endpoint" \
"IP address or DNS name clients will connect to.
(Behind NAT? Enter the public IP / DNS name here.)" \
        "$endpoint" is_valid_endpoint \
        "Enter a valid IPv4/IPv6 address or DNS hostname.")" || return 0

    ipv6="no"
    if host_has_ipv6; then
        ui_yesno "IPv6" "This host appears to have public IPv6 connectivity.

Enable IPv6 inside the VPN tunnel as well?" \
            && ipv6="yes"
    fi

    port="$(ui_input_validated "Port" "OpenVPN listening port:" "1194" \
        is_valid_port "Port must be a number between 1 and 65535.")" || return 0

    proto="$(ui_menu "Protocol" "Select the transport protocol:" \
        "udp" "UDP - recommended (faster)" \
        "tcp" "TCP - only if UDP is blocked (e.g. restrictive networks)")" || return 0

    _choose_dns || return 0   # sets DNS1 DNS2 DNS_LABEL

    # Cryptographic settings: review/customize BEFORE anything is generated.
    crypto_install_menu || return 0

    # Allowed authentication modes (per-user; changeable later).
    _choose_auth_modes || return 0   # sets WIZ_ALLOWED WIZ_DEFAULT

    ui_yesno "Confirm installation" \
"Ready to install with these settings:

  Endpoint:   ${endpoint}:${port}/${proto}
  Interface:  ${nic}
  VPN subnet: ${VPN_CIDR4}$( [[ $ipv6 == yes ]] && printf ' + %s' "$VPN_SUBNET6" )
  DNS:        ${DNS_LABEL} (${DNS1}${DNS2:+, ${DNS2}})
  Crypto:     $(crypto_short_desc)
  Auth modes: ${WIZ_ALLOWED} (default: ${WIZ_DEFAULT}; per-user, changeable later)

Proceed?" || return 0

    # ---- Persist settings, then build everything from them --------------------
    ENDPOINT="$endpoint" PORT="$port" PROTOCOL="$proto"
    IPV6_ENABLED="$ipv6" NIC="$nic"
    AUTH_ALLOWED_MODES="$WIZ_ALLOWED" AUTH_DEFAULT_MODE="$WIZ_DEFAULT"
    config_set ENDPOINT "$ENDPOINT";     config_set PORT "$PORT"
    config_set PROTOCOL "$PROTOCOL";     config_set IPV6_ENABLED "$IPV6_ENABLED"
    config_set NIC "$NIC"
    config_set AUTH_ALLOWED_MODES "$AUTH_ALLOWED_MODES"
    config_set AUTH_DEFAULT_MODE "$AUTH_DEFAULT_MODE"
    config_set DNS1 "$DNS1"; config_set DNS2 "$DNS2"; config_set DNS_LABEL "$DNS_LABEL"
    crypto_persist

    log_info "Installation started (endpoint=${ENDPOINT} port=${PORT}/${PROTOCOL} ipv6=${IPV6_ENABLED})"

    # From here on we work on the PLAIN terminal with live output, so the
    # admin always sees what is happening (package downloads can take a
    # while and may briefly wait for an apt/dnf lock).
    clear 2>/dev/null || true
    printf '=== openvpn-manager: installing OpenVPN ===\n'
    printf 'Live output below. Operations log: %s\n' "$OVM_LOG_FILE"

    if ! ui_run "Refresh package metadata" pkg_refresh; then
        ui_pause; ui_resume_tui
        ui_msg "Installation failed" "Could not refresh package metadata.
Check network connectivity and the output above."
        return 1
    fi
    if ! ui_run "Install packages (openvpn, easy-rsa, openssl, curl)" pkg_install_core; then
        ui_pause; ui_resume_tui
        ui_msg "Installation failed" "Package installation failed.
See the output above and ${OVM_LOG_FILE}."
        return 1
    fi
    # PAM modules for the allowed OTP families (best-effort: assignments
    # re-validate and offer installation again if these fail here).
    if [[ " ${AUTH_ALLOWED_MODES} " == *" password_totp "* ]]; then
        ui_run "Install TOTP PAM module (pam_google_authenticator)" pkg_install_totp || true
    fi
    if [[ " ${AUTH_ALLOWED_MODES} " == *" yubikey "* || " ${AUTH_ALLOWED_MODES} " == *" password_yubikey "* ]]; then
        ui_run "Install YubiKey PAM module (pam_yubico)" pkg_install_yubico || true
    fi
    if ! ui_run "Validate crypto settings against installed OpenVPN/OpenSSL" crypto_validate_runtime; then
        ui_pause; ui_resume_tui
        if ui_yesno "Unsupported crypto settings" \
"The installed OpenVPN/OpenSSL does not support part of the selected
crypto configuration (details in ${OVM_LOG_FILE}).

Reset to the recommended modern defaults and continue?"; then
            crypto_set_defaults
            crypto_persist
        else
            return 1
        fi
    fi
    if ! ui_run "Generate PKI and certificates ($(crypto_key_type_desc))" pki_init; then
        ui_pause; ui_resume_tui
        ui_msg "Installation failed" "PKI generation failed. See ${OVM_LOG_FILE}."
        return 1
    fi

    ui_run "Write authentication policy (per-user modes)" _install_auth_artifacts
    ui_run "Write server configuration" write_server_conf
    ui_run "Write client profile template" write_client_template
    ui_run "Enable IP forwarding (sysctl)" write_sysctl

    if ! ui_run "Configure firewall / NAT rules" firewall_apply; then
        ui_resume_tui
        ui_msg "Installation failed" "Firewall configuration failed. See ${OVM_LOG_FILE}."
        return 1
    fi

    mkdir -p /var/log/openvpn
    systemctl daemon-reload
    svc_enable
    ui_run "Start OpenVPN service" systemctl restart "$OVPN_SERVICE"
    sleep 1

    # Completion is printed as PLAIN text (like the steps above) so it is
    # always visible, then we cleanly hand control back to the TUI menus.
    if svc_is_active; then
        config_set INSTALLED "yes"; INSTALLED="yes"
        log_info "Installation finished successfully"
        printf '\n=== Installation complete ===\n'
        printf '  OpenVPN is installed and RUNNING (systemd: %s).\n' "$OVPN_SERVICE"
        printf '  It keeps running in the background after you exit this tool.\n\n'
        printf '  Firewall backend: %s\n' "$FIREWALL_BACKEND"
        printf '  Server config:    %s\n' "$OVPN_SERVER_CONF"
        printf '  Client profiles:  %s\n' "$OVM_CLIENT_DIR"
        printf '  Manager log:      %s\n' "$OVM_LOG_FILE"
        ui_pause "Press Enter to return to the menu..."
        ui_resume_tui
        if ui_yesno "Add user" "OpenVPN is running. Add the first VPN user now?"; then
            user_add
        fi
    else
        log_error "OpenVPN failed to start after installation"
        printf '\n=== OpenVPN failed to start ===\n'
        journalctl -u "$OVPN_SERVICE" --no-pager -n 30 2>/dev/null
        ui_pause "Press Enter to return to the menu..."
        ui_resume_tui
    fi
    return 0
}

_valid_nic() { ip link show "$1" >/dev/null 2>&1; }

_choose_auth_modes() { # sets WIZ_ALLOWED (space-separated) + WIZ_DEFAULT
    local sel
    sel="$(ui_checklist "Allowed authentication modes" \
"Every user always needs a client certificate. Select which modes users
MAY be assigned - each user gets their own mode later. TOTP/YubiKey
PAM modules are installed automatically if selected here." \
        "cert"             "Certificate only" on \
        "password"         "Certificate + password" off \
        "password_totp"    "Certificate + password + TOTP" off \
        "yubikey"          "Certificate + YubiKey OTP" off \
        "password_yubikey" "Certificate + password + YubiKey OTP" off)" || return 1
    [[ -z "$sel" ]] && sel="cert"
    WIZ_ALLOWED="$sel"
    WIZ_DEFAULT="${sel%% *}"
    local -a arr=()
    read -r -a arr <<< "$sel"
    if (( ${#arr[@]} > 1 )); then
        local m state
        local -a args=()
        for m in "${arr[@]}"; do
            state="off"; [[ "$m" == "$WIZ_DEFAULT" ]] && state="on"
            args+=("$m" "$(auth_mode_label "$m")" "$state")
        done
        WIZ_DEFAULT="$(ui_radiolist "Default mode for new users" \
            "Preselected when adding a VPN user (changeable per user):" \
            "${args[@]}")" || return 1
        [[ -z "$WIZ_DEFAULT" ]] && WIZ_DEFAULT="${arr[0]}"
    fi
    return 0
}

_install_auth_artifacts() {
    # Policy file (header only - users are added later), the two helper
    # scripts and, if any credential mode is allowed, the PAM stack.
    groupadd -f "$VPN_GROUP"
    write_pam_empty_script \
        && write_policy_script \
        && policy_sync_header \
        && write_pam_file
}

_choose_dns() {
    local choice
    choice="$(ui_menu "DNS for VPN clients" "Resolver pushed to connected clients:" \
        "cloudflare" "Cloudflare (1.1.1.1) - recommended" \
        "google"     "Google (8.8.8.8)" \
        "quad9"      "Quad9 (9.9.9.9) - malware blocking" \
        "adguard"    "AdGuard DNS (94.140.14.14) - ad blocking" \
        "opendns"    "OpenDNS (208.67.222.222)" \
        "system"     "This server's own resolvers" \
        "custom"     "Custom DNS servers")" || return 1
    case "$choice" in
        cloudflare) DNS1="1.1.1.1";        DNS2="1.0.0.1";           DNS_LABEL="Cloudflare" ;;
        google)     DNS1="8.8.8.8";        DNS2="8.8.4.4";           DNS_LABEL="Google" ;;
        quad9)      DNS1="9.9.9.9";        DNS2="149.112.112.112";   DNS_LABEL="Quad9" ;;
        adguard)    DNS1="94.140.14.14";   DNS2="94.140.15.15";      DNS_LABEL="AdGuard" ;;
        opendns)    DNS1="208.67.222.222"; DNS2="208.67.220.220";    DNS_LABEL="OpenDNS" ;;
        system)
            local resolv="/etc/resolv.conf"
            [[ -f /run/systemd/resolve/resolv.conf ]] && resolv="/run/systemd/resolve/resolv.conf"
            DNS1="$(awk '/^nameserver/ && $2 !~ /^127\./ {print $2; exit}' "$resolv")"
            DNS2="$(awk '/^nameserver/ && $2 !~ /^127\./ {print $2}' "$resolv" | sed -n 2p)"
            DNS_LABEL="system"
            if [[ -z "$DNS1" ]]; then
                ui_msg "DNS" "No usable system resolver found; falling back to Cloudflare."
                DNS1="1.1.1.1"; DNS2="1.0.0.1"; DNS_LABEL="Cloudflare"
            fi ;;
        custom)
            DNS1="$(ui_input_validated "Custom DNS" "Primary DNS server:" "" \
                is_valid_dns_ip "Enter a valid IPv4 or IPv6 address.")" || return 1
            DNS2="$(ui_input "Custom DNS" "Secondary DNS server (optional):" "")" || DNS2=""
            if [[ -n "$DNS2" ]] && ! is_valid_dns_ip "$DNS2"; then
                ui_msg "DNS" "Secondary DNS invalid - it will be skipped."
                DNS2=""
            fi
            DNS_LABEL="custom" ;;
    esac
    return 0
}

# -----------------------------------------------------------------------------
# Config generation (from persisted settings)
# -----------------------------------------------------------------------------

write_server_conf() {
    backup_file "$OVPN_SERVER_CONF"

    local listen_proto="$PROTOCOL"
    [[ "$IPV6_ENABLED" == "yes" ]] && listen_proto="${PROTOCOL}6"

    {
        echo "# Generated by openvpn-manager v${OVM_VERSION} - do not edit manually."
        echo "# Regenerated on every settings/auth change; edits will be lost."
        echo "port ${PORT}"
        echo "proto ${listen_proto}"
        echo "dev tun"
        echo
        echo "user nobody"
        echo "group ${NOGROUP}"
        echo "persist-key"
        echo "persist-tun"
        echo "keepalive 10 120"
        echo
        echo "topology subnet"
        echo "server ${VPN_SUBNET4} ${VPN_MASK4}"
        echo "ifconfig-pool-persist ipp.txt"
        if [[ "$IPV6_ENABLED" == "yes" ]]; then
            echo "server-ipv6 ${VPN_SUBNET6}"
            echo "push \"redirect-gateway def1 bypass-dhcp ipv6\""
            echo "push \"route-ipv6 2000::/3\""
        else
            echo "push \"redirect-gateway def1 bypass-dhcp\""
        fi
        echo "push \"dhcp-option DNS ${DNS1}\""
        [[ -n "$DNS2" ]] && echo "push \"dhcp-option DNS ${DNS2}\""
        echo
        echo "# --- TLS / crypto (from persisted settings: $(crypto_short_desc)) ---"
        echo "ca ca.crt"
        echo "cert ${SERVER_NAME}.crt"
        echo "key ${SERVER_NAME}.key"
        echo "dh none"
        echo "ecdh-curve $(crypto_ecdh_curve)"
        if [[ "$CONTROL_WRAP" == "tls-crypt" ]]; then
            echo "tls-crypt tls-crypt.key"
        else
            echo "# legacy tls-auth mode (same key file, HMAC-only)"
            echo "tls-auth tls-crypt.key 0"
        fi
        echo "crl-verify crl.pem"
        echo "verify-client-cert require"
        echo "auth ${AUTH_DIGEST}"
        echo "data-ciphers ${DATA_CIPHERS}"
        echo "data-ciphers-fallback ${DATA_FALLBACK}"
        echo "tls-server"
        echo "tls-version-min ${TLS_MIN}"
        if [[ "$TLS_MIN" != "1.3" ]]; then
            echo "tls-cipher $(crypto_tls_cipher_list)"
        fi
        echo "tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
        echo
        auth_server_directives
        echo
        echo "status ${OVPN_STATUS_LOG}"
        echo "verb 3"
        [[ "$PROTOCOL" == "udp" ]] && echo "explicit-exit-notify 1"
    } > "$OVPN_SERVER_CONF"
    chmod 600 "$OVPN_SERVER_CONF"
    log_info "server.conf regenerated (allowed auth modes: ${AUTH_ALLOWED_MODES:-cert})"
}

write_client_template() {
    {
        echo "client"
        echo "proto ${PROTOCOL}"
        echo "remote ${ENDPOINT} ${PORT}"
        echo "dev tun"
        echo "resolv-retry infinite"
        echo "nobind"
        echo "persist-key"
        echo "persist-tun"
        echo "remote-cert-tls server"
        echo "verify-x509-name ${SERVER_NAME} name"
        echo "auth ${AUTH_DIGEST}"
        echo "auth-nocache"
        echo "data-ciphers ${DATA_CIPHERS}"
        echo "tls-client"
        echo "tls-version-min ${TLS_MIN}"
        echo "ignore-unknown-option block-outside-dns"
        echo "setenv opt block-outside-dns  # Windows DNS-leak protection"
        echo "verb 3"
        [[ "$PROTOCOL" == "udp" ]] && echo "explicit-exit-notify"
    } > "$OVM_TEMPLATE_FILE"
    chmod 600 "$OVM_TEMPLATE_FILE"
}

write_sysctl() {
    backup_file "$SYSCTL_FILE"
    {
        echo "# Generated by openvpn-manager"
        echo "net.ipv4.ip_forward = 1"
        [[ "$IPV6_ENABLED" == "yes" ]] && echo "net.ipv6.conf.all.forwarding = 1"
    } > "$SYSCTL_FILE"
    sysctl -p "$SYSCTL_FILE" >/dev/null
}

# -----------------------------------------------------------------------------
# Settings changes (regenerate from config, reapply firewall, restart)
# -----------------------------------------------------------------------------

server_settings_menu() {
    while true; do
        local choice
        choice="$(ui_menu "Server configuration" \
"Current: ${ENDPOINT}:${PORT}/${PROTOCOL}  DNS: ${DNS_LABEL}  IPv6: ${IPV6_ENABLED}" \
            "port"     "Change listening port (now: ${PORT})" \
            "proto"    "Change protocol (now: ${PROTOCOL})" \
            "dns"      "Change client DNS (now: ${DNS_LABEL})" \
            "endpoint" "Change public endpoint (now: ${ENDPOINT})" \
            "crypto"   "Crypto settings ($(crypto_key_type_desc), ${CONTROL_WRAP}, TLS>=${TLS_MIN})" \
            "view"     "View current server.conf" \
            "back"     "Back to main menu")" || return 0
        case "$choice" in
            crypto) crypto_post_install_menu ;;
            port)
                local new
                new="$(ui_input_validated "Port" "New listening port:" "$PORT" \
                    is_valid_port "Port must be 1-65535.")" || continue
                [[ "$new" == "$PORT" ]] && continue
                firewall_remove
                PORT="$new"; config_set PORT "$PORT"
                _regen_and_restart refresh_firewall regen_profiles ;;
            proto)
                local new
                new="$(ui_menu "Protocol" "Select protocol:" \
                    "udp" "UDP (recommended)" "tcp" "TCP")" || continue
                [[ "$new" == "$PROTOCOL" ]] && continue
                firewall_remove
                PROTOCOL="$new"; config_set PROTOCOL "$PROTOCOL"
                _regen_and_restart refresh_firewall regen_profiles ;;
            dns)
                _choose_dns || continue
                config_set DNS1 "$DNS1"; config_set DNS2 "$DNS2"; config_set DNS_LABEL "$DNS_LABEL"
                _regen_and_restart ;;
            endpoint)
                local new
                new="$(ui_input_validated "Endpoint" "Public IP or DNS name for clients:" \
                    "$ENDPOINT" is_valid_endpoint "Invalid address/hostname.")" || continue
                ENDPOINT="$new"; config_set ENDPOINT "$ENDPOINT"
                write_client_template
                ui_msg "Endpoint changed" "The endpoint only affects client profiles."
                _offer_regen_profiles ;;
            view) ui_textfile "server.conf" "$OVPN_SERVER_CONF" ;;
            back) return 0 ;;
        esac
    done
}

_regen_and_restart() { # args may include: refresh_firewall regen_profiles
    write_server_conf
    write_client_template
    local a
    for a in "$@"; do
        [[ "$a" == "refresh_firewall" ]] && firewall_apply
    done
    svc_restart_checked || true
    for a in "$@"; do
        [[ "$a" == "regen_profiles" ]] && _offer_regen_profiles
    done
    log_info "Server settings updated (${ENDPOINT}:${PORT}/${PROTOCOL} dns=${DNS_LABEL})"
}

_offer_regen_profiles() {
    ui_yesno "Client profiles" \
"Connection settings changed. Existing .ovpn files still point to the
old settings.

Regenerate all client profiles now?" && user_regenerate_all_profiles
}

# -----------------------------------------------------------------------------
# Uninstall
# -----------------------------------------------------------------------------

uninstall_wizard() {
    openvpn_is_installed || { ui_msg "Uninstall" "OpenVPN does not appear to be installed."; return 0; }

    ui_yesno "Uninstall OpenVPN" \
"This will:
  - stop and disable the OpenVPN service
  - remove firewall/NAT rules added by this tool
  - remove /etc/openvpn (PKI, certificates, keys)
  - remove VPN system accounts (group ${VPN_GROUP})
  - remove PAM/TOTP/YubiKey configuration created by this tool

A full encrypted-permission backup archive will be saved to /root first,
so the setup can be restored manually if needed.

Existing system firewall configuration NOT created by this tool
will not be touched. Continue?" defaultno || return 0

    ui_yesno "Final confirmation" "Really uninstall OpenVPN now?" defaultno || return 0

    local archive="/root/openvpn-manager-backup-${RUN_STAMP}.tar.gz"
    ui_info "Creating backup archive..."
    tar -czf "$archive" -C / etc/openvpn etc/openvpn-manager 2>/dev/null || true
    chmod 600 "$archive"
    log_info "Uninstall backup created: ${archive} (contains private keys - kept root-only)"

    _uninstall_core_quiet

    local purge="no"
    if ui_yesno "Packages" "Also remove the installed packages (openvpn, easy-rsa, PAM modules)?" defaultno; then
        purge="yes"
        pkg_remove openvpn easy-rsa
        pkg_remove libpam-google-authenticator google-authenticator \
                   libpam-yubico pam_yubico 2>/dev/null || true
    fi

    config_set INSTALLED "no"; INSTALLED="no"
    log_info "Uninstall finished (packages removed: ${purge})"
    ui_msg "Uninstall complete" \
"OpenVPN has been removed.

Backup archive (contains private keys, keep it safe or delete it):
  ${archive}

Manager log kept at: ${OVM_LOG_FILE}"
}

_uninstall_core_quiet() {
    # Shared by uninstall and reinstall. No prompts here.
    systemctl stop "$OVPN_SERVICE"    >/dev/null 2>&1 || true
    systemctl disable "$OVPN_SERVICE" >/dev/null 2>&1 || true

    firewall_remove

    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true

    # Remove VPN system accounts we created (primary group = VPN_GROUP only).
    if getent group "$VPN_GROUP" >/dev/null 2>&1; then
        local gid u
        gid="$(getent group "$VPN_GROUP" | cut -d: -f3)"
        while IFS=: read -r u _ _ ugid _; do
            if [[ "$ugid" == "$gid" ]]; then
                userdel "$u" >/dev/null 2>&1 || true
                log_info "Removed VPN system account: $u"
            fi
        done < /etc/passwd
        groupdel "$VPN_GROUP" >/dev/null 2>&1 || true
    fi

    rm -f "$PAM_FILE"
    local g
    for g in "$OVM_GRP_PASSWORD" "$OVM_GRP_TOTP" "$OVM_GRP_YUBIKEY"; do
        groupdel "$g" >/dev/null 2>&1 || true
    done
    rm -rf /etc/openvpn
    rm -rf /var/log/openvpn
    # Wipe secrets and client material managed by this tool
    find "$OVM_TOTP_DIR" -type f -exec shred -u {} + 2>/dev/null || rm -rf "${OVM_TOTP_DIR:?}"/* 2>/dev/null || true
    rm -rf "${OVM_CLIENT_DIR:?}"/* 2>/dev/null || true
    rm -f "$OVM_YUBI_AUTHFILE" "$OVM_TEMPLATE_FILE"
    log_info "Core OpenVPN configuration removed"
}
