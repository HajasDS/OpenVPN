#!/usr/bin/env bash
# =============================================================================
# lib/packages.sh - package installation per package manager
# =============================================================================

# Output stays VISIBLE on purpose (shown live via ui_run). The lock timeout
# keeps apt from hanging forever behind unattended-upgrades on fresh boots.
pkg_refresh() {
    log_info "Refreshing package metadata (${PKG_MANAGER})"
    case "$PKG_MANAGER" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -q -o DPkg::Lock::Timeout=300 ;;
        dnf)    dnf makecache --refresh || true ;;
        yum)    yum makecache || true ;;
        pacman) pacman -Sy --noconfirm ;;
    esac
}

pkg_install() { # pkg_install pkg1 pkg2 ... (fails if any package fails)
    log_info "Installing packages: $*"
    case "$PKG_MANAGER" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
                    -o DPkg::Lock::Timeout=300 "$@" </dev/null ;;
        dnf)    dnf install -y "$@" </dev/null ;;
        yum)    yum install -y "$@" </dev/null ;;
        pacman) pacman -S --noconfirm --needed "$@" </dev/null ;;
    esac
}

pkg_install_best_effort() { # install each package individually, ignore failures
    local p
    for p in "$@"; do
        pkg_install "$p" >/dev/null 2>&1 || log_warn "Optional package not installed: $p"
    done
}

pkg_remove() {
    log_info "Removing packages: $*"
    case "$PKG_MANAGER" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y -qq "$@" || true ;;
        dnf)    dnf remove -y -q "$@" || true ;;
        yum)    yum remove -y -q "$@" || true ;;
        pacman) pacman -Rns --noconfirm "$@" || true ;;
    esac
}

ensure_epel() {
    # google-authenticator / pam_yubico live in EPEL on RHEL clones.
    is_rhel_family || return 0
    [[ "$OS_ID" == "fedora" ]] && return 0
    if ! rpm -q epel-release >/dev/null 2>&1; then
        log_info "Enabling EPEL repository"
        pkg_install epel-release || log_warn "Could not install epel-release automatically."
    fi
}

pkg_install_ui_tool() {
    case "$PKG_MANAGER" in
        apt)    pkg_refresh && pkg_install whiptail ;;
        dnf|yum) pkg_install newt ;;
        pacman) pkg_install libnewt ;;
    esac
}

pkg_install_core() {
    # openvpn + easy-rsa + tooling needed by every install
    local -a pkgs=(openvpn easy-rsa openssl ca-certificates curl)
    log_info "Installing core packages: ${pkgs[*]}"
    case "$PKG_MANAGER" in
        apt)
            # --no-install-recommends keeps the smart-card stack (pcscd,
            # opensc, libccid) off headless servers: openvpn only recommends
            # it, nothing in this tool uses it, and its postinst ordering
            # prints a scary (harmless) pcscd.service failure during install.
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
                -o DPkg::Lock::Timeout=300 --no-install-recommends \
                "${pkgs[@]}" </dev/null ;;
        *)
            pkg_install "${pkgs[@]}" ;;
    esac || return 1
    # iptables is only required for the raw-iptables firewall backend
    command -v iptables >/dev/null 2>&1 || pkg_install_best_effort iptables
}

pkg_install_totp() {
    ensure_epel
    case "$PKG_MANAGER" in
        apt)    pkg_install libpam-google-authenticator ;;
        dnf|yum) pkg_install google-authenticator ;;
        pacman) pkg_install libpam-google-authenticator ;;
    esac
    pkg_install_best_effort qrencode
    find_pam_module pam_google_authenticator.so || {
        log_error "pam_google_authenticator.so not found after installation"
        return 1
    }
}

pkg_install_yubico() {
    ensure_epel
    case "$PKG_MANAGER" in
        apt)    pkg_install libpam-yubico ;;
        dnf|yum) pkg_install pam_yubico ;;
        pacman) pkg_install yubico-pam || pkg_install_best_effort yubico-pam ;;
    esac
    find_pam_module pam_yubico.so || {
        log_error "pam_yubico.so not found after installation"
        return 1
    }
}
