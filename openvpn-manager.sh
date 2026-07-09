#!/usr/bin/env bash
# =============================================================================
#  openvpn-manager - interactive OpenVPN server installer & manager
#
#  Menu-driven (whiptail/dialog) tool to install, configure and maintain an
#  OpenVPN server with certificate, password, TOTP and YubiKey OTP
#  authentication. Primary targets: Ubuntu and Debian; also runs on the
#  Fedora/RHEL family and Arch.
#
#  Usage:   sudo ./openvpn-manager.sh
#
#  Conceptually inspired by angristan/openvpn-install (MIT); reimplemented
#  as a modular project. See docs/DESIGN.md.
# =============================================================================

set -o pipefail
set -u
umask 077

OVM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OVM_ROOT

for _mod in common os ui packages certs firewall service crypto policy openvpn users auth totp yubikey checks; do
    # shellcheck source=/dev/null
    source "${OVM_ROOT}/lib/${_mod}.sh" \
        || { printf 'FATAL: cannot load lib/%s.sh\n' "${_mod}" >&2; exit 1; }
done
unset _mod

# -----------------------------------------------------------------------------

status_summary() {
    local svc="not installed" fw="${FIREWALL_BACKEND:-—}" users
    if openvpn_is_installed; then
        svc="$(systemctl is-active "$OVPN_SERVICE" 2>/dev/null || echo unknown)"
    fi
    users="$(cert_list_valid_clients 2>/dev/null | wc -l)"
    printf 'Service: %s | %s:%s/%s | Users: %s | Auth: %s | FW: %s' \
        "${svc^^}" "${ENDPOINT:-—}" "${PORT}" "${PROTOCOL}" \
        "$users" "$(auth_status_label)" "$fw"
}

firewall_menu() {
    while true; do
        local choice
        choice="$(ui_menu "Firewall / NAT" "Backend: ${FIREWALL_BACKEND:-not configured}" \
            "show"    "Show active VPN firewall rules" \
            "reapply" "Re-apply rules (repair after external changes)" \
            "remove"  "Remove VPN firewall rules (VPN traffic will stop!)" \
            "back"    "Back to main menu")" || return 0
        case "$choice" in
            show)    ui_show_text "Firewall rules (${FIREWALL_BACKEND:-?})" "$(firewall_show_rules)" ;;
            reapply)
                ui_yesno "Re-apply" "Remove and re-add the VPN firewall/NAT rules now?" || continue
                firewall_remove
                firewall_apply
                ui_msg "Firewall" "Rules re-applied (backend: ${FIREWALL_BACKEND})." ;;
            remove)
                ui_yesno "Remove rules" \
"Clients will lose internet access through the VPN until the rules
are re-applied. Remove the rules now?" defaultno || continue
                firewall_remove
                ui_msg "Firewall" "VPN firewall rules removed." ;;
            back)    return 0 ;;
        esac
    done
}

logs_menu() {
    while true; do
        local choice
        choice="$(ui_menu "Logs" "Log files never contain passwords, OTPs or keys." \
            "manager" "openvpn-manager log (operations audit)" \
            "journal" "OpenVPN service journal (last 100 lines)" \
            "status"  "OpenVPN status log (connected clients)" \
            "back"    "Back to main menu")" || return 0
        case "$choice" in
            manager) ui_show_text "openvpn-manager.log (last 200 lines)" \
                         "$(tail -n 200 "$OVM_LOG_FILE" 2>/dev/null)" ;;
            journal) ui_show_text "OpenVPN journal" \
                         "$(journalctl -u "$OVPN_SERVICE" --no-pager -n 100 2>/dev/null)" ;;
            status)  ui_show_text "Connected clients" "$(svc_connected_clients)" ;;
            back)    return 0 ;;
        esac
    done
}

backups_menu() {
    local list
    list="$(list_backups)"
    [[ -z "$list" ]] && list="(no backups yet)"
    ui_show_text "Configuration backups" \
"Before every modification the affected files are copied to a
timestamped folder under:

  ${OVM_BACKUP_DIR}

Available backup sets:

${list}

To restore manually: copy the file back to its original location
(the folder structure below the timestamp mirrors '/'), then restart
OpenVPN from the Service menu."
}

main_menu() {
    while true; do
        local choice
        if ! openvpn_is_installed; then
            local not_installed_text="OpenVPN is not installed on this system yet."
            local partial
            if partial="$(openvpn_partial_state)"; then
                not_installed_text="${partial}
Choose Install to repair - remnants are backed up and replaced."
                log_warn "Partial installation detected at startup"
            fi
            choice="$(ui_menu "OpenVPN Manager" \
                "$not_installed_text" \
                "install" "Install OpenVPN server (guided setup)" \
                "logs"    "View manager log" \
                "exit"    "Exit")" || exit 0
            case "$choice" in
                install) install_wizard ;;
                logs)    logs_menu ;;
                exit)    exit 0 ;;
            esac
            continue
        fi

        choice="$(ui_menu "OpenVPN Manager" "$(status_summary)" \
            "users"     "User management  (add / revoke / list / profiles)" \
            "auth"      "Authentication   (per-user modes, enforcement, 2FA)" \
            "service"   "Service control  (status, restart, journal)" \
            "settings"  "Server configuration  (port, protocol, DNS, endpoint)" \
            "firewall"  "Firewall / NAT rules" \
            "logs"      "Logs" \
            "backups"   "Configuration backups" \
            "reinstall" "Reinstall OpenVPN (new PKI!)" \
            "uninstall" "Uninstall OpenVPN" \
            "exit"      "Exit")" || exit 0

        case "$choice" in
            users)     user_menu ;;
            auth)      auth_menu ;;
            service)   service_menu ;;
            settings)  server_settings_menu ;;
            firewall)  firewall_menu ;;
            logs)      logs_menu ;;
            backups)   backups_menu ;;
            reinstall) install_wizard ;;
            uninstall) uninstall_wizard ;;
            exit)      exit 0 ;;
        esac
    done
}

# -----------------------------------------------------------------------------

main() {
    require_bash
    require_root
    detect_os
    init_dirs
    config_load
    config_sanitize
    crypto_sanitize
    ui_init

    log_info "openvpn-manager v${OVM_VERSION} started on ${OS_NAME}"

    if [[ "$OS_SUPPORT" == "besteffort" ]]; then
        ui_yesno "Unverified distribution" \
"${OS_NAME} is not one of the primary tested targets
(Ubuntu 20.04+/Debian 11+). The tool will try its best.

Continue at your own risk?" defaultno || exit 0
    fi

    # v1.x installs carry a single global auth mode - offer the upgrade to
    # per-user authentication once, before entering the menus.
    if openvpn_is_installed && ! policy_ready; then
        auth_migrate_v2 || log_warn "Per-user authentication migration postponed"
    fi

    main_menu
}

main "$@"
