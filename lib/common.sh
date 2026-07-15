#!/usr/bin/env bash
# =============================================================================
# lib/common.sh - constants, logging, config persistence, backups, validation
# Part of openvpn-manager. Sourced by openvpn-manager.sh; not standalone.
#
# SECURITY NOTE: log() must NEVER receive passwords, OTP codes, TOTP secrets,
# private keys or client profile contents. Log operational events only.
# =============================================================================

readonly OVM_VERSION="2.0.2"

# --- Paths -------------------------------------------------------------------
# ":=" pattern: production values are unchanged, but the test suites can
# pre-set any path to a sandbox location before sourcing this file.
: "${OVM_ETC_DIR:=/etc/openvpn-manager}"
: "${OVM_CONFIG_FILE:=${OVM_ETC_DIR}/config.conf}"
: "${OVM_LOG_FILE:=/var/log/openvpn-manager.log}"
: "${OVM_BACKUP_DIR:=${OVM_ETC_DIR}/backups}"
: "${OVM_CLIENT_DIR:=${OVM_ETC_DIR}/clients}"
: "${OVM_TOTP_DIR:=${OVM_ETC_DIR}/totp}"
: "${OVM_YUBI_DIR:=${OVM_ETC_DIR}/yubikey}"
: "${OVM_YUBI_AUTHFILE:=${OVM_YUBI_DIR}/authorized_yubikeys}"
: "${OVM_TEMPLATE_FILE:=${OVM_ETC_DIR}/client-template.txt}"
: "${OVM_FW_DIR:=${OVM_ETC_DIR}/firewall}"

: "${OVPN_DIR:=/etc/openvpn}"
: "${OVPN_SERVER_DIR:=/etc/openvpn/server}"
: "${OVPN_SERVER_CONF:=${OVPN_SERVER_DIR}/server.conf}"
: "${OVPN_STATUS_LOG:=/var/log/openvpn/status.log}"
: "${OVPN_SERVICE:=openvpn-server@server}"

: "${EASYRSA_DIR:=/etc/openvpn/easy-rsa}"
: "${PKI_DIR:=${EASYRSA_DIR}/pki}"

: "${PAM_SERVICE_NAME:=openvpn}"
: "${PAM_FILE:=/etc/pam.d/openvpn}"
: "${VPN_GROUP:=openvpn-users}"
: "${CN_VERIFY_SCRIPT:=${OVPN_SERVER_DIR}/verify-cn.sh}"   # legacy (v1.x), removed on migration

readonly OVM_ETC_DIR OVM_CONFIG_FILE OVM_LOG_FILE OVM_BACKUP_DIR \
         OVM_CLIENT_DIR OVM_TOTP_DIR OVM_YUBI_DIR OVM_YUBI_AUTHFILE \
         OVM_TEMPLATE_FILE OVM_FW_DIR \
         OVPN_DIR OVPN_SERVER_DIR OVPN_SERVER_CONF OVPN_STATUS_LOG OVPN_SERVICE \
         EASYRSA_DIR PKI_DIR PAM_SERVICE_NAME PAM_FILE VPN_GROUP CN_VERIFY_SCRIPT

# --- VPN network constants ---------------------------------------------------
readonly VPN_SUBNET4="10.8.0.0"
readonly VPN_MASK4="255.255.255.0"
readonly VPN_CIDR4="10.8.0.0/24"
readonly VPN_SUBNET6="fd42:42:42:42::/112"

# Timestamp for this run's backups (one backup dir per run)
RUN_STAMP="$(date +%Y%m%d-%H%M%S)"

# Keys allowed in the persistent config file. config_load() only assigns
# variables from this whitelist, so a tampered config file cannot clobber
# arbitrary shell variables (PATH, IFS, ...).
readonly -a OVM_CONFIG_KEYS=(
    INSTALLED ENDPOINT PORT PROTOCOL IPV6_ENABLED NIC
    DNS1 DNS2 DNS_LABEL
    SERVER_NAME AUTH_MODE TOTP_NULLOK ENFORCE_CN_MATCH
    AUTH_ALLOWED_MODES AUTH_DEFAULT_MODE
    YUBICO_ID YUBICO_KEY YUBICO_URL
    FIREWALL_BACKEND PLUGIN_PATH
    PKI_ALGO PKI_CURVE PKI_RSA_BITS
    DATA_CIPHERS DATA_FALLBACK TLS_MIN CONTROL_WRAP AUTH_DIGEST
    CA_DAYS SERVER_CERT_DAYS CLIENT_CERT_DAYS CRL_DAYS
)

# The five supported per-user authentication modes (a client certificate is
# always required on top; see docs/AUTHENTICATION.md).
readonly -a OVM_AUTH_MODES=(cert password password_totp yubikey password_yubikey)

is_valid_auth_mode() {
    local m
    for m in "${OVM_AUTH_MODES[@]}"; do [[ "$m" == "$1" ]] && return 0; done
    return 1
}
mode_uses_password() { [[ "$1" == password || "$1" == password_totp || "$1" == password_yubikey ]]; }
mode_uses_totp()     { [[ "$1" == password_totp ]]; }
mode_uses_yubikey()  { [[ "$1" == yubikey || "$1" == password_yubikey ]]; }

# =============================================================================
# Logging
# =============================================================================

log() { # log <LEVEL> <message...>  -- NEVER pass secrets
    local level="$1"; shift
    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*" \
        >> "$OVM_LOG_FILE" 2>/dev/null || true
}
log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_error() { log "ERROR" "$@"; }

die() {
    log_error "$*"
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

# =============================================================================
# Environment checks / initialisation
# =============================================================================

require_root() {
    [[ ${EUID} -eq 0 ]] || die "This tool must be run as root (try: sudo $0)"
}

require_bash() {
    [[ -n ${BASH_VERSION:-} ]] || die "This tool requires bash."
    [[ ${BASH_VERSINFO[0]} -ge 4 ]] || die "This tool requires bash >= 4."
}

check_tun_device() {
    if [[ ! -e /dev/net/tun ]]; then
        die "/dev/net/tun is not available. If this is a container, enable the TUN device for it first."
    fi
}

init_dirs() {
    local d
    umask 077
    for d in "$OVM_ETC_DIR" "$OVM_BACKUP_DIR" "$OVM_CLIENT_DIR" \
             "$OVM_TOTP_DIR" "$OVM_YUBI_DIR" "$OVM_FW_DIR"; do
        mkdir -p "$d"
        chmod 700 "$d"
    done
    touch "$OVM_LOG_FILE"
    chmod 600 "$OVM_LOG_FILE"
}

# =============================================================================
# Persistent configuration (key=value, root-only file)
# =============================================================================

config_set() { # config_set KEY VALUE
    local key="$1" value="$2" tmp
    [[ $key =~ ^[A-Z0-9_]+$ ]] || { log_error "config_set: invalid key '$key'"; return 1; }
    value="${value//$'\n'/ }"   # keep the file strictly one line per key
    touch "$OVM_CONFIG_FILE"
    chmod 600 "$OVM_CONFIG_FILE"
    tmp="$(mktemp "${OVM_ETC_DIR}/.config.XXXXXX")" || return 1
    grep -v "^${key}=" "$OVM_CONFIG_FILE" > "$tmp" 2>/dev/null || true
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$OVM_CONFIG_FILE"
}

config_get() { # config_get KEY -> prints value, rc=1 if absent
    local line
    line="$(grep -m1 "^${1}=" "$OVM_CONFIG_FILE" 2>/dev/null)" || return 1
    printf '%s' "${line#*=}"
}

config_load() {
    # Parse (never source) the config file; assign whitelisted keys only.
    local line key value k
    [[ -r "$OVM_CONFIG_FILE" ]] || return 0
    while IFS= read -r line; do
        [[ $line =~ ^([A-Z0-9_]+)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
        for k in "${OVM_CONFIG_KEYS[@]}"; do
            if [[ $k == "$key" ]]; then
                printf -v "$key" '%s' "$value"
                break
            fi
        done
    done < "$OVM_CONFIG_FILE"
}

# Defaults for config-backed globals (overridden by config_load)
INSTALLED="no"
ENDPOINT=""
PORT="1194"
PROTOCOL="udp"
IPV6_ENABLED="no"
NIC=""
DNS1="" DNS2="" DNS_LABEL=""
SERVER_NAME=""
AUTH_MODE="cert"            # legacy (v1.x global mode) - read for migration only
TOTP_NULLOK="no"            # legacy (v1.x) - superseded by per-user modes
ENFORCE_CN_MATCH="yes"      # v2: always enforced by the policy layer
AUTH_ALLOWED_MODES=""       # space-separated; set by installer/migration
AUTH_DEFAULT_MODE="cert"    # preselected mode when adding a new user
YUBICO_ID="" YUBICO_KEY="" YUBICO_URL=""
FIREWALL_BACKEND=""
PLUGIN_PATH=""
# Crypto defaults = the "recommended modern" preset (see lib/crypto.sh and
# docs/CRYPTO.md); shown and changeable in the installer, never hidden.
PKI_ALGO="ec"
PKI_CURVE="prime256v1"
PKI_RSA_BITS="4096"
DATA_CIPHERS="AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
DATA_FALLBACK="AES-256-GCM"
TLS_MIN="1.2"
CONTROL_WRAP="tls-crypt"
AUTH_DIGEST="SHA256"
CA_DAYS="3650"
SERVER_CERT_DAYS="3650"
CLIENT_CERT_DAYS="3650"
CRL_DAYS="3650"

config_sanitize() {
    # Recover safely from a hand-edited, truncated or corrupted config file:
    # every loaded value is re-validated and reset to a safe default if bad,
    # so no code path ever operates on undefined/garbage settings.
    local fixed=""
    is_valid_port "$PORT" || { fixed+=" PORT"; PORT="1194"; }
    [[ "$PROTOCOL" == "udp" || "$PROTOCOL" == "tcp" ]] || { fixed+=" PROTOCOL"; PROTOCOL="udp"; }
    is_valid_auth_mode "$AUTH_MODE" || { fixed+=" AUTH_MODE"; AUTH_MODE="cert"; }
    if [[ -n "$AUTH_ALLOWED_MODES" ]]; then
        local m cleaned=""
        for m in $AUTH_ALLOWED_MODES; do
            is_valid_auth_mode "$m" && cleaned+="${cleaned:+ }${m}"
        done
        [[ "$cleaned" == "$AUTH_ALLOWED_MODES" ]] || fixed+=" AUTH_ALLOWED_MODES"
        AUTH_ALLOWED_MODES="${cleaned:-cert}"
    fi
    if ! is_valid_auth_mode "$AUTH_DEFAULT_MODE" \
            || { [[ -n "$AUTH_ALLOWED_MODES" ]] \
                 && [[ " ${AUTH_ALLOWED_MODES} " != *" ${AUTH_DEFAULT_MODE} "* ]]; }; then
        fixed+=" AUTH_DEFAULT_MODE"
        AUTH_DEFAULT_MODE="${AUTH_ALLOWED_MODES%% *}"
        [[ -n "$AUTH_DEFAULT_MODE" ]] || AUTH_DEFAULT_MODE="cert"
    fi
    [[ "$IPV6_ENABLED" == "yes" ]] || IPV6_ENABLED="no"
    [[ "$TOTP_NULLOK" == "yes" ]] || TOTP_NULLOK="no"
    ENFORCE_CN_MATCH="yes"   # v2: the auth-policy layer always enforces CN=username
    [[ "$INSTALLED" == "yes" ]] || INSTALLED="no"
    if [[ -n "$ENDPOINT" ]] && ! is_valid_endpoint "$ENDPOINT"; then
        fixed+=" ENDPOINT"; ENDPOINT=""
    fi
    if [[ -n "$YUBICO_ID" ]] && ! is_valid_yubico_client_id "$YUBICO_ID"; then
        fixed+=" YUBICO_ID"; YUBICO_ID=""
    fi
    if [[ -n "$YUBICO_URL" ]] && ! is_valid_url "$YUBICO_URL"; then
        fixed+=" YUBICO_URL"; YUBICO_URL=""
    fi
    case "$FIREWALL_BACKEND" in ""|firewalld|ufw|iptables) ;; *) fixed+=" FIREWALL_BACKEND"; FIREWALL_BACKEND="" ;; esac
    if [[ -n "$PLUGIN_PATH" && ! -e "$PLUGIN_PATH" ]]; then
        fixed+=" PLUGIN_PATH"; PLUGIN_PATH=""
    fi
    [[ -n "$fixed" ]] && log_warn "Config sanitized - invalid values were reset:${fixed}"
    return 0
}

# =============================================================================
# Backups
# =============================================================================

backup_file() { # backup_file /path/to/file  -> copies into per-run backup dir
    local f="$1" dest
    [[ -e "$f" ]] || return 0
    dest="${OVM_BACKUP_DIR}/${RUN_STAMP}$(dirname "$f")"
    mkdir -p "$dest"
    cp -a "$f" "${dest}/"
    chmod -R go-rwx "${OVM_BACKUP_DIR}/${RUN_STAMP}"
    log_info "Backed up $f -> ${dest}/"
}

list_backups() {
    ls -1 "$OVM_BACKUP_DIR" 2>/dev/null || true
}

# =============================================================================
# Input validation
# All interactive input MUST pass through one of these before being used in
# a command, a config file or a filename.
# =============================================================================

is_valid_username() {
    # Also used as certificate CN and system account name.
    [[ $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$ ]] || return 1
    [[ $1 != server* ]] || return 1      # reserved for the server certificate
    [[ $1 != root && $1 != nobody ]] || return 1
    return 0
}

is_valid_port() {
    [[ $1 =~ ^[0-9]{1,5}$ ]] || return 1
    (( $1 >= 1 && $1 <= 65535 ))
}

is_valid_ipv4() {
    local ip="$1" x
    local -a o
    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a o <<< "$ip"
    for x in "${o[@]}"; do (( 10#$x <= 255 )) || return 1; done
    return 0
}

is_valid_ipv6() {
    [[ $1 =~ ^[0-9a-fA-F:]{2,45}$ ]] && [[ $1 == *:* ]]
}

is_valid_hostname() {
    [[ ${#1} -le 253 ]] || return 1
    [[ $1 =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]
}

is_valid_endpoint() { # public IPv4, IPv6 or DNS name
    is_valid_ipv4 "$1" || is_valid_ipv6 "$1" || is_valid_hostname "$1"
}

is_valid_dns_ip() {
    is_valid_ipv4 "$1" || is_valid_ipv6 "$1"
}

is_private_ipv4() {
    [[ $1 =~ ^10\. ]] && return 0
    [[ $1 =~ ^192\.168\. ]] && return 0
    [[ $1 =~ ^169\.254\. ]] && return 0
    [[ $1 =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
    return 1
}

is_valid_yubikey_otp() {
    # YubiKey OTP: modhex, 32-48 chars (public id 0-16 chars + 32 char OTP part)
    [[ $1 =~ ^[cbdefghijklnrtuv]{32,48}$ ]]
}

is_valid_yubico_client_id() {
    [[ $1 =~ ^[0-9]{1,10}$ ]]
}

is_valid_url() {
    [[ $1 =~ ^https?://[a-zA-Z0-9._~:/?#@!$\&\'()*+,\;=%-]+$ ]]
}
