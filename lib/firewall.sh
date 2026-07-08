#!/usr/bin/env bash
# =============================================================================
# lib/firewall.sh - NAT / firewall rules for the VPN
#
# Three backends, chosen automatically to avoid breaking existing setups:
#   firewalld - if firewalld is running (RHEL family default)
#   ufw       - if ufw is active (Ubuntu default when enabled)
#   iptables  - otherwise: own rule scripts + a systemd oneshot unit,
#               never touching distribution persistence mechanisms
#
# The active backend is persisted so removal always mirrors what was applied.
# =============================================================================

readonly FW_UNIT="/etc/systemd/system/openvpn-manager-iptables.service"
readonly FW_ADD_SCRIPT="${OVM_FW_DIR}/add-rules.sh"
readonly FW_DEL_SCRIPT="${OVM_FW_DIR}/remove-rules.sh"
readonly UFW_MARK_BEGIN="# BEGIN OPENVPN-MANAGER NAT (do not edit)"
readonly UFW_MARK_END="# END OPENVPN-MANAGER NAT"

firewall_detect_backend() {
    if command -v firewall-cmd >/dev/null 2>&1 \
            && systemctl is-active --quiet firewalld 2>/dev/null; then
        printf 'firewalld'
    elif command -v ufw >/dev/null 2>&1 \
            && ufw status 2>/dev/null | grep -q '^Status: active'; then
        printf 'ufw'
    else
        printf 'iptables'
    fi
}

firewall_apply() {
    # Uses globals: PORT PROTOCOL NIC IPV6_ENABLED
    FIREWALL_BACKEND="$(firewall_detect_backend)"
    config_set FIREWALL_BACKEND "$FIREWALL_BACKEND"
    log_info "Applying firewall rules via backend: ${FIREWALL_BACKEND} (port ${PORT}/${PROTOCOL}, nic ${NIC})"
    case "$FIREWALL_BACKEND" in
        firewalld) _fw_firewalld_apply ;;
        ufw)       _fw_ufw_apply ;;
        iptables)  _fw_iptables_apply ;;
    esac
}

firewall_remove() {
    local backend="${FIREWALL_BACKEND:-$(firewall_detect_backend)}"
    log_info "Removing firewall rules (backend: ${backend})"
    case "$backend" in
        firewalld) _fw_firewalld_remove ;;
        ufw)       _fw_ufw_remove ;;
        iptables)  _fw_iptables_remove ;;
    esac
}

firewall_show_rules() { # prints current rules for the status viewer
    case "${FIREWALL_BACKEND:-iptables}" in
        firewalld)
            firewall-cmd --list-all 2>/dev/null
            echo
            firewall-cmd --zone=trusted --list-all 2>/dev/null ;;
        ufw)
            ufw status verbose 2>/dev/null
            echo
            grep -A8 "$UFW_MARK_BEGIN" /etc/ufw/before.rules 2>/dev/null || true ;;
        iptables)
            echo "--- filter table (openvpn related) ---"
            iptables -S 2>/dev/null | grep -Ei 'tun|'"${PORT:-1194}" || true
            echo "--- nat table ---"
            iptables -t nat -S POSTROUTING 2>/dev/null || true ;;
    esac
}

# --- firewalld ----------------------------------------------------------------

_fw_firewalld_apply() {
    local runtime
    for runtime in "" "--permanent"; do
        # shellcheck disable=SC2086
        firewall-cmd $runtime --add-port="${PORT}/${PROTOCOL}" >/dev/null
        firewall-cmd $runtime --add-masquerade >/dev/null
        firewall-cmd $runtime --zone=trusted --add-source="${VPN_CIDR4}" >/dev/null
        if [[ "$IPV6_ENABLED" == "yes" ]]; then
            firewall-cmd $runtime --zone=trusted --add-source="${VPN_SUBNET6}" >/dev/null
        fi
    done
}

_fw_firewalld_remove() {
    local runtime
    for runtime in "" "--permanent"; do
        # shellcheck disable=SC2086
        firewall-cmd $runtime --remove-port="${PORT}/${PROTOCOL}" >/dev/null 2>&1 || true
        firewall-cmd $runtime --remove-masquerade >/dev/null 2>&1 || true
        firewall-cmd $runtime --zone=trusted --remove-source="${VPN_CIDR4}" >/dev/null 2>&1 || true
        firewall-cmd $runtime --zone=trusted --remove-source="${VPN_SUBNET6}" >/dev/null 2>&1 || true
    done
}

# --- ufw ------------------------------------------------------------------------

_fw_ufw_apply() {
    backup_file /etc/ufw/before.rules

    ufw allow "${PORT}/${PROTOCOL}" >/dev/null
    ufw route allow in on tun0 out on "$NIC" >/dev/null

    _fw_ufw_strip_nat_block /etc/ufw/before.rules
    local tmp
    tmp="$(mktemp)"
    {
        echo "$UFW_MARK_BEGIN"
        echo "*nat"
        echo ":POSTROUTING ACCEPT [0:0]"
        echo "-A POSTROUTING -s ${VPN_CIDR4} -o ${NIC} -j MASQUERADE"
        echo "COMMIT"
        echo "$UFW_MARK_END"
        cat /etc/ufw/before.rules
    } > "$tmp"
    cat "$tmp" > /etc/ufw/before.rules
    rm -f "$tmp"

    if [[ "$IPV6_ENABLED" == "yes" && -f /etc/ufw/before6.rules ]]; then
        backup_file /etc/ufw/before6.rules
        _fw_ufw_strip_nat_block /etc/ufw/before6.rules
        tmp="$(mktemp)"
        {
            echo "$UFW_MARK_BEGIN"
            echo "*nat"
            echo ":POSTROUTING ACCEPT [0:0]"
            echo "-A POSTROUTING -s ${VPN_SUBNET6} -o ${NIC} -j MASQUERADE"
            echo "COMMIT"
            echo "$UFW_MARK_END"
            cat /etc/ufw/before6.rules
        } > "$tmp"
        cat "$tmp" > /etc/ufw/before6.rules
        rm -f "$tmp"
    fi

    ufw reload >/dev/null
}

_fw_ufw_strip_nat_block() { # remove our marked NAT block from a ufw rules file
    local file="$1"
    [[ -f "$file" ]] || return 0
    sed -i "\|^${UFW_MARK_BEGIN}\$|,\|^${UFW_MARK_END}\$|d" "$file"
}

_fw_ufw_remove() {
    ufw delete allow "${PORT}/${PROTOCOL}" >/dev/null 2>&1 || true
    ufw route delete allow in on tun0 out on "$NIC" >/dev/null 2>&1 || true
    _fw_ufw_strip_nat_block /etc/ufw/before.rules
    _fw_ufw_strip_nat_block /etc/ufw/before6.rules
    ufw reload >/dev/null 2>&1 || true
}

# --- raw iptables + systemd oneshot unit -----------------------------------------

_fw_iptables_apply() {
    local ipt ip6t
    ipt="$(command -v iptables)" || { log_error "iptables binary not found"; return 1; }
    ip6t="$(command -v ip6tables || true)"

    mkdir -p "$OVM_FW_DIR"

    cat > "$FW_ADD_SCRIPT" <<EOF
#!/bin/sh
# Generated by openvpn-manager - adds VPN firewall/NAT rules
${ipt} -t nat -I POSTROUTING 1 -s ${VPN_CIDR4} -o ${NIC} -j MASQUERADE
${ipt} -I INPUT 1 -i tun0 -j ACCEPT
${ipt} -I FORWARD 1 -i ${NIC} -o tun0 -j ACCEPT
${ipt} -I FORWARD 1 -i tun0 -o ${NIC} -j ACCEPT
${ipt} -I INPUT 1 -i ${NIC} -p ${PROTOCOL} --dport ${PORT} -j ACCEPT
EOF

    cat > "$FW_DEL_SCRIPT" <<EOF
#!/bin/sh
# Generated by openvpn-manager - removes VPN firewall/NAT rules
${ipt} -t nat -D POSTROUTING -s ${VPN_CIDR4} -o ${NIC} -j MASQUERADE
${ipt} -D INPUT -i tun0 -j ACCEPT
${ipt} -D FORWARD -i ${NIC} -o tun0 -j ACCEPT
${ipt} -D FORWARD -i tun0 -o ${NIC} -j ACCEPT
${ipt} -D INPUT -i ${NIC} -p ${PROTOCOL} --dport ${PORT} -j ACCEPT
EOF

    if [[ "$IPV6_ENABLED" == "yes" && -n "$ip6t" ]]; then
        cat >> "$FW_ADD_SCRIPT" <<EOF
${ip6t} -t nat -I POSTROUTING 1 -s ${VPN_SUBNET6} -o ${NIC} -j MASQUERADE
${ip6t} -I INPUT 1 -i tun0 -j ACCEPT
${ip6t} -I FORWARD 1 -i ${NIC} -o tun0 -j ACCEPT
${ip6t} -I FORWARD 1 -i tun0 -o ${NIC} -j ACCEPT
${ip6t} -I INPUT 1 -i ${NIC} -p ${PROTOCOL} --dport ${PORT} -j ACCEPT
EOF
        cat >> "$FW_DEL_SCRIPT" <<EOF
${ip6t} -t nat -D POSTROUTING -s ${VPN_SUBNET6} -o ${NIC} -j MASQUERADE
${ip6t} -D INPUT -i tun0 -j ACCEPT
${ip6t} -D FORWARD -i ${NIC} -o tun0 -j ACCEPT
${ip6t} -D FORWARD -i tun0 -o ${NIC} -j ACCEPT
${ip6t} -D INPUT -i ${NIC} -p ${PROTOCOL} --dport ${PORT} -j ACCEPT
EOF
    fi

    chmod 750 "$FW_ADD_SCRIPT" "$FW_DEL_SCRIPT"

    cat > "$FW_UNIT" <<EOF
[Unit]
Description=openvpn-manager firewall rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${FW_ADD_SCRIPT}
ExecStop=${FW_DEL_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now openvpn-manager-iptables.service \
        || { log_error "Failed to enable the iptables rules service"; return 1; }
}

_fw_iptables_remove() {
    systemctl disable --now openvpn-manager-iptables.service >/dev/null 2>&1 || true
    rm -f "$FW_UNIT" "$FW_ADD_SCRIPT" "$FW_DEL_SCRIPT"
    systemctl daemon-reload
}
