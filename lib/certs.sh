#!/usr/bin/env bash
# =============================================================================
# lib/certs.sh - easy-rsa 3 PKI management (ECDSA / prime256v1)
#
# SECURITY: everything under pki/private is chmod 600 inside a 700 directory.
# easy-rsa output goes to the manager log; it contains file paths, never keys.
# =============================================================================

run_easyrsa() { # run_easyrsa [EXTRA_ENV...] -- <easyrsa args...>
    (
        cd "$EASYRSA_DIR" || exit 1
        export EASYRSA_PKI="$PKI_DIR"
        export EASYRSA_ALGO="ec"
        export EASYRSA_CURVE="prime256v1"
        export EASYRSA_CA_EXPIRE=3650
        export EASYRSA_CERT_EXPIRE=3650
        export EASYRSA_CRL_DAYS=3650
        export EASYRSA_BATCH=1
        # stdin closed: if easy-rsa ever tries to prompt, it must fail
        # loudly instead of hanging on an invisible question
        ./easyrsa "$@" < /dev/null
    ) >> "$OVM_LOG_FILE" 2>&1
}

pki_setup_easyrsa_dir() {
    local src
    mkdir -p "$EASYRSA_DIR"
    chmod 700 "$EASYRSA_DIR"
    if [[ -x "${EASYRSA_DIR}/easyrsa" ]]; then
        return 0
    fi
    src="$(find_easyrsa)" || { log_error "easy-rsa not found (is the easy-rsa package installed?)"; return 1; }
    if [[ -d "$(dirname "$src")/x509-types" ]]; then
        cp -a "$(dirname "$src")/." "$EASYRSA_DIR/"
    else
        ln -sf "$src" "${EASYRSA_DIR}/easyrsa"
    fi
    [[ -x "${EASYRSA_DIR}/easyrsa" ]] || chmod +x "${EASYRSA_DIR}/easyrsa"
}

pki_init() {
    # Creates a brand new PKI. Destroys any existing one (caller must confirm).
    local rand
    pki_setup_easyrsa_dir || return 1
    rand="$(openssl rand -hex 6)"
    SERVER_NAME="server_${rand}"

    log_info "Initialising new PKI (server certificate: ${SERVER_NAME})"
    rm -rf "$PKI_DIR"

    run_easyrsa init-pki \
        || { log_error "easy-rsa init-pki failed"; return 1; }
    EASYRSA_REQ_CN="ca_${rand}" run_easyrsa build-ca nopass \
        || { log_error "easy-rsa build-ca failed"; return 1; }
    run_easyrsa build-server-full "$SERVER_NAME" nopass \
        || { log_error "easy-rsa build-server-full failed"; return 1; }
    run_easyrsa gen-crl \
        || { log_error "easy-rsa gen-crl failed"; return 1; }

    chmod 700 "${PKI_DIR}/private"
    find "${PKI_DIR}/private" -type f -exec chmod 600 {} +

    # Must stay 755: the daemon re-reads crl.pem and runs the CN-verify
    # script AFTER dropping privileges to 'nobody'. Secrets inside are 0600.
    mkdir -p "$OVPN_SERVER_DIR"
    chmod 755 "$OVPN_SERVER_DIR"

    # tls-crypt pre-shared key: hides the TLS handshake, blocks port scans/DoS
    openvpn --genkey secret "${OVPN_SERVER_DIR}/tls-crypt.key" 2>/dev/null \
        || openvpn --genkey --secret "${OVPN_SERVER_DIR}/tls-crypt.key"
    [[ -s "${OVPN_SERVER_DIR}/tls-crypt.key" ]] \
        || { log_error "tls-crypt key generation failed"; return 1; }
    chmod 600 "${OVPN_SERVER_DIR}/tls-crypt.key"

    pki_install_server_files
    crl_install
    config_set SERVER_NAME "$SERVER_NAME"
}

pki_install_server_files() {
    cp -f "${PKI_DIR}/ca.crt"                          "${OVPN_SERVER_DIR}/ca.crt"
    cp -f "${PKI_DIR}/issued/${SERVER_NAME}.crt"       "${OVPN_SERVER_DIR}/${SERVER_NAME}.crt"
    cp -f "${PKI_DIR}/private/${SERVER_NAME}.key"      "${OVPN_SERVER_DIR}/${SERVER_NAME}.key"
    chmod 644 "${OVPN_SERVER_DIR}/ca.crt" "${OVPN_SERVER_DIR}/${SERVER_NAME}.crt"
    chmod 600 "${OVPN_SERVER_DIR}/${SERVER_NAME}.key"
}

crl_install() {
    # The CRL is re-read on every client connect by the (unprivileged) daemon,
    # so unlike keys it must stay world-readable.
    cp -f "${PKI_DIR}/crl.pem" "${OVPN_SERVER_DIR}/crl.pem"
    chmod 644 "${OVPN_SERVER_DIR}/crl.pem"
}

cert_exists() { # cert_exists <name> -> true if a valid (V) cert with this CN exists
    [[ -f "${PKI_DIR}/index.txt" ]] || return 1
    awk -F'\t' -v cn="/CN=$1" '$1=="V" && index($NF, cn) {found=1} END {exit !found}' \
        "${PKI_DIR}/index.txt"
}

cert_create_client() { # cert_create_client <name> [passfile]
    local name="$1" passfile="${2:-}"
    if [[ -n "$passfile" ]]; then
        EASYRSA_PASSOUT="file:${passfile}" EASYRSA_PASSIN="file:${passfile}" \
            run_easyrsa build-client-full "$name" \
            || { log_error "Certificate creation failed for user '$name'"; return 1; }
    else
        run_easyrsa build-client-full "$name" nopass \
            || { log_error "Certificate creation failed for user '$name'"; return 1; }
    fi
    find "${PKI_DIR}/private" -type f -exec chmod 600 {} +
    log_info "Client certificate issued: $name"
}

cert_revoke_client() { # cert_revoke_client <name>
    local name="$1"
    run_easyrsa revoke "$name"  || { log_error "Revocation failed for '$name'"; return 1; }
    run_easyrsa gen-crl         || { log_error "CRL regeneration failed"; return 1; }
    crl_install
    log_info "Certificate revoked and CRL updated: $name"
}

cert_list_valid_clients() {
    # Prints one CN per line for every valid, non-server client certificate.
    [[ -f "${PKI_DIR}/index.txt" ]] || return 0
    awk -F'\t' '$1=="V" {
        n = $NF
        sub(/.*\/CN=/, "", n)
        print n
    }' "${PKI_DIR}/index.txt" | grep -v "^${SERVER_NAME}$" | grep -v '^ca_' || true
}

cert_expiry() { # cert_expiry <name> -> "YYYY-MM-DD" or empty
    local crt="${PKI_DIR}/issued/${1}.crt"
    [[ -f "$crt" ]] || return 0
    openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2
}
