#!/usr/bin/env bash
# =============================================================================
# lib/crypto.sh - cryptographic settings: presets, menus, validation,
# persistence (see docs/CRYPTO.md)
#
# All crypto parameters live in the persisted config and drive BOTH the PKI
# (easy-rsa env in lib/certs.sh) and the generated server.conf / client
# template (lib/openvpn.sh). Nothing crypto-related is hardcoded any more;
# the recommended defaults are visible, reviewable and changeable during
# installation, and safely changeable (with impact warnings) afterwards.
#
# Post-install rules:
#   - runtime settings (data ciphers, fallback, TLS min, control-channel
#     wrap, auth digest): changeable; requires server.conf regen, service
#     restart, and regenerating ALL client profiles - never done silently.
#   - validity periods: changeable; apply to certificates issued in the
#     future only.
#   - key type (ECDSA/RSA, curve, bits): fixed for the life of the PKI;
#     changing it requires a full reinstall (new CA -> all certs replaced).
# =============================================================================

readonly OVM_CIPHERS_ALLOWED="AES-256-GCM AES-128-GCM AES-192-GCM CHACHA20-POLY1305"
readonly OVM_CURVES_ALLOWED="prime256v1 secp384r1 secp521r1"
readonly OVM_RSA_BITS_ALLOWED="2048 3072 4096"
readonly OVM_DIGESTS_ALLOWED="SHA256 SHA384 SHA512"
readonly OVM_DAYS_MIN=30
readonly OVM_DAYS_MAX=7300

# -----------------------------------------------------------------------------
# Presets
# -----------------------------------------------------------------------------

crypto_set_defaults() { # "Recommended modern" preset
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
}

crypto_preset_rsa4096() {
    crypto_set_defaults
    PKI_ALGO="rsa"
    PKI_RSA_BITS="4096"
}

crypto_preset_high() { # P-384, AES-256 only, TLS 1.3, SHA384
    crypto_set_defaults
    PKI_CURVE="secp384r1"
    DATA_CIPHERS="AES-256-GCM:CHACHA20-POLY1305"
    TLS_MIN="1.3"
    AUTH_DIGEST="SHA384"
}

crypto_persist() {
    config_set PKI_ALGO "$PKI_ALGO";           config_set PKI_CURVE "$PKI_CURVE"
    config_set PKI_RSA_BITS "$PKI_RSA_BITS";   config_set DATA_CIPHERS "$DATA_CIPHERS"
    config_set DATA_FALLBACK "$DATA_FALLBACK"; config_set TLS_MIN "$TLS_MIN"
    config_set CONTROL_WRAP "$CONTROL_WRAP";   config_set AUTH_DIGEST "$AUTH_DIGEST"
    config_set CA_DAYS "$CA_DAYS";             config_set SERVER_CERT_DAYS "$SERVER_CERT_DAYS"
    config_set CLIENT_CERT_DAYS "$CLIENT_CERT_DAYS"; config_set CRL_DAYS "$CRL_DAYS"
    log_info "Crypto settings saved: $(crypto_short_desc)"
}

# -----------------------------------------------------------------------------
# Validators / sanitization
# -----------------------------------------------------------------------------

_crypto_in_list() { # _crypto_in_list <value> <space separated list>
    local v="$1" x
    for x in $2; do [[ "$x" == "$v" ]] && return 0; done
    return 1
}

is_valid_cipher_list() { # colon separated, every token from the whitelist
    local list="$1" c
    [[ -n "$list" ]] || return 1
    for c in ${list//:/ }; do
        _crypto_in_list "$c" "$OVM_CIPHERS_ALLOWED" || return 1
    done
    return 0
}

is_valid_days() {
    [[ $1 =~ ^[0-9]{1,5}$ ]] && (( $1 >= OVM_DAYS_MIN && $1 <= OVM_DAYS_MAX ))
}

crypto_sanitize() {
    # Recover from a config file with a missing or corrupted crypto section:
    # any invalid value falls back to the recommended default (logged).
    local fixed=""
    [[ "$PKI_ALGO" == "ec" || "$PKI_ALGO" == "rsa" ]] || { fixed+=" PKI_ALGO"; PKI_ALGO="ec"; }
    _crypto_in_list "$PKI_CURVE" "$OVM_CURVES_ALLOWED"   || { fixed+=" PKI_CURVE"; PKI_CURVE="prime256v1"; }
    _crypto_in_list "$PKI_RSA_BITS" "$OVM_RSA_BITS_ALLOWED" || { fixed+=" PKI_RSA_BITS"; PKI_RSA_BITS="4096"; }
    is_valid_cipher_list "$DATA_CIPHERS" || { fixed+=" DATA_CIPHERS"; DATA_CIPHERS="AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"; }
    _crypto_in_list "$DATA_FALLBACK" "${DATA_CIPHERS//:/ }" || { fixed+=" DATA_FALLBACK"; DATA_FALLBACK="${DATA_CIPHERS%%:*}"; }
    [[ "$TLS_MIN" == "1.2" || "$TLS_MIN" == "1.3" ]] || { fixed+=" TLS_MIN"; TLS_MIN="1.2"; }
    [[ "$CONTROL_WRAP" == "tls-crypt" || "$CONTROL_WRAP" == "tls-auth" ]] || { fixed+=" CONTROL_WRAP"; CONTROL_WRAP="tls-crypt"; }
    _crypto_in_list "$AUTH_DIGEST" "$OVM_DIGESTS_ALLOWED" || { fixed+=" AUTH_DIGEST"; AUTH_DIGEST="SHA256"; }
    is_valid_days "$CA_DAYS"          || { fixed+=" CA_DAYS"; CA_DAYS="3650"; }
    is_valid_days "$SERVER_CERT_DAYS" || { fixed+=" SERVER_CERT_DAYS"; SERVER_CERT_DAYS="3650"; }
    is_valid_days "$CLIENT_CERT_DAYS" || { fixed+=" CLIENT_CERT_DAYS"; CLIENT_CERT_DAYS="3650"; }
    is_valid_days "$CRL_DAYS"         || { fixed+=" CRL_DAYS"; CRL_DAYS="3650"; }
    # certificates must never outlive the CA
    (( SERVER_CERT_DAYS <= CA_DAYS )) || { fixed+=" SERVER_CERT_DAYS>CA"; SERVER_CERT_DAYS="$CA_DAYS"; }
    (( CLIENT_CERT_DAYS <= CA_DAYS )) || { fixed+=" CLIENT_CERT_DAYS>CA"; CLIENT_CERT_DAYS="$CA_DAYS"; }
    [[ -n "$fixed" ]] && log_warn "Crypto settings sanitized - invalid values reset:${fixed}"
    return 0
}

crypto_validate_runtime() {
    # Called once the openvpn/openssl binaries exist: verify the selection is
    # actually supported by the installed versions. Read-only.
    local ok=0 c
    if command -v openvpn >/dev/null 2>&1; then
        for c in ${DATA_CIPHERS//:/ } "$DATA_FALLBACK"; do
            openvpn --show-ciphers 2>/dev/null | grep -qiE "^${c} " \
                || { log_error "Cipher not supported by installed OpenVPN: ${c}"; ok=1; }
        done
        openvpn --show-digests 2>/dev/null | grep -qiE "^${AUTH_DIGEST} " \
            || { log_error "Digest not supported by installed OpenVPN: ${AUTH_DIGEST}"; ok=1; }
    fi
    if [[ "$PKI_ALGO" == "ec" ]] && command -v openssl >/dev/null 2>&1; then
        openssl ecparam -list_curves 2>/dev/null | grep -q "$PKI_CURVE" \
            || { log_error "Curve not supported by installed OpenSSL: ${PKI_CURVE}"; ok=1; }
    fi
    return "$ok"
}

# -----------------------------------------------------------------------------
# Derived server.conf values
# -----------------------------------------------------------------------------

crypto_ecdh_curve() { # ECDHE curve for the TLS key exchange (also with RSA certs)
    [[ "$PKI_ALGO" == "ec" ]] && printf '%s' "$PKI_CURVE" || printf 'prime256v1'
}

crypto_tls_cipher_list() { # TLS<=1.2 control-channel suites, matching the cert type
    if [[ "$PKI_ALGO" == "ec" ]]; then
        printf 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
    else
        printf 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
    fi
}

# -----------------------------------------------------------------------------
# Display helpers
# -----------------------------------------------------------------------------

crypto_key_type_desc() {
    if [[ "$PKI_ALGO" == "ec" ]]; then
        printf 'ECDSA %s' "$PKI_CURVE"
    else
        printf 'RSA %s-bit' "$PKI_RSA_BITS"
    fi
}

crypto_short_desc() {
    printf '%s | %s | TLS>=%s | %s | %s' \
        "$(crypto_key_type_desc)" "$DATA_CIPHERS" "$TLS_MIN" "$CONTROL_WRAP" "$AUTH_DIGEST"
}

crypto_summary_text() {
    cat <<EOF
CA / certificate key type:   $(crypto_key_type_desc)
  (CA, server and client certificates all use this key type)
Data-channel ciphers:        ${DATA_CIPHERS}
Fallback data cipher:        ${DATA_FALLBACK}
Minimum TLS version:         ${TLS_MIN}
Control-channel TLS suites:  $( [[ "$TLS_MIN" == "1.3" ]] && echo "TLS 1.3 defaults (AES-256-GCM / CHACHA20)" || crypto_tls_cipher_list )
Control-channel protection:  ${CONTROL_WRAP}
HMAC/auth digest:            ${AUTH_DIGEST}
Diffie-Hellman:              none (ECDHE key exchange, curve $(crypto_ecdh_curve))
CA validity:                 ${CA_DAYS} days
Server certificate validity: ${SERVER_CERT_DAYS} days
Client certificate validity: ${CLIENT_CERT_DAYS} days
CRL validity:                ${CRL_DAYS} days
$(crypto_warnings_text)
EOF
}

crypto_warnings_text() { # non-empty only if something deserves a warning
    local w=""
    [[ "$CONTROL_WRAP" == "tls-auth" ]] && \
        w+=$'\nWARNING: tls-auth only authenticates the handshake; tls-crypt also\n         encrypts it (hides the VPN from scanners). Prefer tls-crypt.'
    [[ "$PKI_ALGO" == "rsa" && "$PKI_RSA_BITS" == "2048" ]] && \
        w+=$'\nWARNING: RSA 2048 is the acceptable minimum today; prefer 3072/4096\n         or ECDSA for new installations.'
    [[ "$TLS_MIN" == "1.3" ]] && \
        w+=$'\nNOTE: TLS 1.3 minimum requires reasonably current OpenVPN/OpenSSL on\n      every client device.'
    (( CLIENT_CERT_DAYS > 3650 )) && \
        w+=$'\nWARNING: client certificates valid for more than 10 years are risky.'
    printf '%s' "$w"
}

# -----------------------------------------------------------------------------
# Install-time menu (before anything is generated)
# -----------------------------------------------------------------------------

crypto_install_menu() { # rc 0 = settings accepted, 1 = cancel installation step
    local choice
    while true; do
        choice="$(ui_menu "Cryptographic settings" \
            "Current: $(crypto_short_desc)" \
            "continue" "Use these settings and continue" \
            "view"     "View full crypto settings (with warnings)" \
            "preset"   "Choose a preset (modern / RSA-4096 / high-security)" \
            "custom"   "Customize individual settings" \
            "reset"    "Reset to recommended defaults" \
            "back"     "Back (cancel installation)")" || return 1
        case "$choice" in
            continue) return 0 ;;
            view)     ui_show_text "Crypto settings review" "$(crypto_summary_text)" ;;
            preset)   _crypto_preset_menu ;;
            custom)   crypto_customize_menu ;;
            reset)    crypto_set_defaults
                      ui_msg "Crypto" "Settings reset to the recommended modern defaults." ;;
            back)     return 1 ;;
        esac
    done
}

_crypto_preset_menu() {
    local p
    p="$(ui_menu "Crypto presets" "Select a base configuration:" \
        "modern" "Recommended modern: ECDSA P-256, AES-GCM/ChaCha20, TLS>=1.2, tls-crypt" \
        "rsa"    "RSA 4096-bit: maximum client compatibility, larger/slower keys" \
        "high"   "High security: ECDSA P-384, AES-256 only, TLS>=1.3, SHA384")" || return 0
    case "$p" in
        modern) crypto_set_defaults ;;
        rsa)    crypto_preset_rsa4096 ;;
        high)   crypto_preset_high ;;
    esac
    ui_show_text "Preset applied" "$(crypto_summary_text)"
}

# -----------------------------------------------------------------------------
# Customization
# -----------------------------------------------------------------------------

crypto_customize_menu() {
    local choice
    while true; do
        choice="$(ui_menu "Customize crypto settings" "$(crypto_short_desc)" \
            "keytype"  "Certificate key type      (now: $(crypto_key_type_desc))" \
            "ciphers"  "Data-channel ciphers      (now: ${DATA_CIPHERS})" \
            "fallback" "Fallback data cipher      (now: ${DATA_FALLBACK})" \
            "tlsmin"   "Minimum TLS version       (now: ${TLS_MIN})" \
            "wrap"     "Control-channel wrap      (now: ${CONTROL_WRAP})" \
            "digest"   "HMAC/auth digest          (now: ${AUTH_DIGEST})" \
            "validity" "Validity periods          (CA ${CA_DAYS}d / srv ${SERVER_CERT_DAYS}d / client ${CLIENT_CERT_DAYS}d / CRL ${CRL_DAYS}d)" \
            "back"     "Done")" || return 0
        case "$choice" in
            keytype)  _crypto_pick_keytype ;;
            ciphers)  _crypto_pick_ciphers ;;
            fallback) _crypto_pick_fallback ;;
            tlsmin)   _crypto_pick_tlsmin ;;
            wrap)     _crypto_pick_wrap ;;
            digest)   _crypto_pick_digest ;;
            validity) _crypto_pick_validity ;;
            back)     return 0 ;;
        esac
    done
}

_crypto_pick_keytype() {
    local k
    k="$(ui_menu "Certificate key type" \
"Used for the CA, the server and every client certificate.
ECDSA: small, fast, modern. RSA: larger, best legacy compatibility." \
        "ec-p256"  "ECDSA prime256v1 (P-256) - recommended" \
        "ec-p384"  "ECDSA secp384r1 (P-384) - stronger, slightly slower" \
        "ec-p521"  "ECDSA secp521r1 (P-521) - strongest, least common" \
        "rsa-4096" "RSA 4096-bit" \
        "rsa-3072" "RSA 3072-bit" \
        "rsa-2048" "RSA 2048-bit (acceptable minimum - not recommended)")" || return 0
    case "$k" in
        ec-p256)  PKI_ALGO="ec"; PKI_CURVE="prime256v1" ;;
        ec-p384)  PKI_ALGO="ec"; PKI_CURVE="secp384r1" ;;
        ec-p521)  PKI_ALGO="ec"; PKI_CURVE="secp521r1" ;;
        rsa-4096) PKI_ALGO="rsa"; PKI_RSA_BITS="4096" ;;
        rsa-3072) PKI_ALGO="rsa"; PKI_RSA_BITS="3072" ;;
        rsa-2048)
            ui_yesno "Weak choice" \
"RSA 2048 is the bare minimum by today's standards and will need
replacement sooner than the alternatives. Use it anyway?" defaultno \
                || return 0
            PKI_ALGO="rsa"; PKI_RSA_BITS="2048" ;;
    esac
}

_crypto_pick_ciphers() {
    local c
    c="$(ui_menu "Data-channel ciphers" \
"Negotiated in order; all are modern AEAD ciphers. GCM is
hardware-accelerated on most CPUs (AES-NI); ChaCha20 is faster on
small ARM devices without AES acceleration." \
        "default" "AES-256-GCM : AES-128-GCM : CHACHA20-POLY1305 (recommended)" \
        "aes-cha" "AES-256-GCM : CHACHA20-POLY1305" \
        "aes256"  "AES-256-GCM only (strictest)" \
        "chacha"  "CHACHA20-POLY1305 : AES-256-GCM (ARM-first)" \
        "custom"  "Enter a custom colon-separated list")" || return 0
    case "$c" in
        default) DATA_CIPHERS="AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305" ;;
        aes-cha) DATA_CIPHERS="AES-256-GCM:CHACHA20-POLY1305" ;;
        aes256)  DATA_CIPHERS="AES-256-GCM" ;;
        chacha)  DATA_CIPHERS="CHACHA20-POLY1305:AES-256-GCM" ;;
        custom)
            local list
            list="$(ui_input_validated "Custom cipher list" \
"Colon-separated AEAD ciphers. Allowed:
${OVM_CIPHERS_ALLOWED// /, }" \
                "$DATA_CIPHERS" is_valid_cipher_list \
                "Invalid list - only these AEAD ciphers are allowed: ${OVM_CIPHERS_ALLOWED}")" \
                || return 0
            DATA_CIPHERS="$list" ;;
    esac
    # keep the fallback consistent with the new list
    _crypto_in_list "$DATA_FALLBACK" "${DATA_CIPHERS//:/ }" || DATA_FALLBACK="${DATA_CIPHERS%%:*}"
}

_crypto_pick_fallback() {
    local -a items=()
    local c
    for c in ${DATA_CIPHERS//:/ }; do
        items+=("$c" "Use ${c} when a client cannot negotiate")
    done
    c="$(ui_menu "Fallback data cipher" \
        "Used for clients that do not send a cipher negotiation list." \
        "${items[@]}")" || return 0
    DATA_FALLBACK="$c"
}

_crypto_pick_tlsmin() {
    local t
    t="$(ui_menu "Minimum TLS version" "For the OpenVPN control channel:" \
        "1.2" "TLS 1.2 minimum - recommended, compatible" \
        "1.3" "TLS 1.3 minimum - strictest; requires current clients")" || return 0
    TLS_MIN="$t"
}

_crypto_pick_wrap() {
    local w
    w="$(ui_menu "Control-channel protection" \
"Both use a pre-shared key on top of TLS:
tls-crypt encrypts AND authenticates the handshake (hides the VPN,
blocks scanners/DoS); tls-auth only authenticates it (legacy)." \
        "tls-crypt" "tls-crypt - recommended" \
        "tls-auth"  "tls-auth - legacy interop only")" || return 0
    if [[ "$w" == "tls-auth" ]]; then
        ui_yesno "Deprecated choice" \
"tls-auth leaves the TLS handshake visible to network scanners.
Only choose it if you must interoperate with a legacy setup.
Use tls-auth anyway?" defaultno || return 0
    fi
    CONTROL_WRAP="$w"
}

_crypto_pick_digest() {
    local d
    d="$(ui_menu "HMAC/auth digest" \
"Used for control-channel HMAC and certificate signatures.
(AEAD data ciphers carry their own integrity protection.)" \
        "SHA256" "SHA-256 - recommended" \
        "SHA384" "SHA-384" \
        "SHA512" "SHA-512")" || return 0
    AUTH_DIGEST="$d"
}

_crypto_pick_validity() {
    local ca srv cli crl
    while true; do
        ca="$(ui_input_validated "Validity" "CA validity in days (${OVM_DAYS_MIN}-${OVM_DAYS_MAX}):" \
            "$CA_DAYS" is_valid_days "Enter a number of days between ${OVM_DAYS_MIN} and ${OVM_DAYS_MAX}.")" || return 0
        srv="$(ui_input_validated "Validity" "Server certificate validity in days:" \
            "$SERVER_CERT_DAYS" is_valid_days "Enter a number of days between ${OVM_DAYS_MIN} and ${OVM_DAYS_MAX}.")" || return 0
        cli="$(ui_input_validated "Validity" "Client certificate validity in days:" \
            "$CLIENT_CERT_DAYS" is_valid_days "Enter a number of days between ${OVM_DAYS_MIN} and ${OVM_DAYS_MAX}.")" || return 0
        crl="$(ui_input_validated "Validity" "CRL validity in days:" \
            "$CRL_DAYS" is_valid_days "Enter a number of days between ${OVM_DAYS_MIN} and ${OVM_DAYS_MAX}.")" || return 0
        if (( srv > ca || cli > ca )); then
            ui_msg "Invalid combination" \
"Certificates cannot be valid longer than the CA itself
(CA: ${ca} days). Please adjust the values."
            continue
        fi
        CA_DAYS="$ca"; SERVER_CERT_DAYS="$srv"; CLIENT_CERT_DAYS="$cli"; CRL_DAYS="$crl"
        return 0
    done
}

# -----------------------------------------------------------------------------
# Post-install menu (existing server: explain impact, never change silently)
# -----------------------------------------------------------------------------

crypto_post_install_menu() {
    local choice
    while true; do
        choice="$(ui_menu "Crypto settings (installed server)" \
            "$(crypto_short_desc)" \
            "view"     "View full crypto settings" \
            "runtime"  "Change runtime settings (ciphers, TLS min, wrap, digest)" \
            "validity" "Change validity periods (applies to future certificates)" \
            "keytype"  "Key type: $(crypto_key_type_desc) (fixed - explain)" \
            "back"     "Back")" || return 0
        case "$choice" in
            view)    ui_show_text "Crypto settings" "$(crypto_summary_text)" ;;
            runtime) _crypto_post_runtime_change ;;
            validity)
                local old_ca="$CA_DAYS" old_s="$SERVER_CERT_DAYS" old_c="$CLIENT_CERT_DAYS" old_r="$CRL_DAYS"
                _crypto_pick_validity
                if [[ "$CA_DAYS $SERVER_CERT_DAYS $CLIENT_CERT_DAYS $CRL_DAYS" != "$old_ca $old_s $old_c $old_r" ]]; then
                    crypto_persist
                    ui_msg "Saved" \
"Validity periods updated. They apply to certificates issued from
now on; existing certificates keep their original expiry
(the CA itself keeps its original ${old_ca}-day validity)."
                fi ;;
            keytype)
                ui_msg "Key type is fixed" \
"The key type ($(crypto_key_type_desc)) is baked into the CA and every
issued certificate. Changing it requires a NEW PKI:

  Main menu -> Reinstall OpenVPN

That invalidates every existing user certificate - all users need
new .ovpn profiles afterwards." ;;
            back)    return 0 ;;
        esac
    done
}

_crypto_post_runtime_change() {
    # Snapshot -> edit -> show diff impact -> confirm -> apply everywhere.
    local before after
    before="$(crypto_short_desc)"
    local old_ciphers="$DATA_CIPHERS" old_fb="$DATA_FALLBACK" old_tls="$TLS_MIN" \
          old_wrap="$CONTROL_WRAP" old_digest="$AUTH_DIGEST"

    local choice
    while true; do
        choice="$(ui_menu "Runtime crypto settings" "$(crypto_short_desc)" \
            "ciphers"  "Data-channel ciphers      (now: ${DATA_CIPHERS})" \
            "fallback" "Fallback data cipher      (now: ${DATA_FALLBACK})" \
            "tlsmin"   "Minimum TLS version       (now: ${TLS_MIN})" \
            "wrap"     "Control-channel wrap      (now: ${CONTROL_WRAP})" \
            "digest"   "HMAC/auth digest          (now: ${AUTH_DIGEST})" \
            "apply"    "Apply changes..." \
            "cancel"   "Discard changes")" || choice="cancel"
        case "$choice" in
            ciphers)  _crypto_pick_ciphers ;;
            fallback) _crypto_pick_fallback ;;
            tlsmin)   _crypto_pick_tlsmin ;;
            wrap)     _crypto_pick_wrap ;;
            digest)   _crypto_pick_digest ;;
            apply)
                after="$(crypto_short_desc)"
                if [[ "$after" == "$before" ]]; then
                    ui_msg "Crypto" "Nothing changed."
                    return 0
                fi
                ui_yesno "Apply crypto changes" \
"Old: ${before}
New: ${after}

Applying will:
  - regenerate server.conf (backup created) and restart OpenVPN
  - require regenerating ALL client .ovpn profiles: profiles with the
    old settings will FAIL to connect until replaced

Certificates are NOT touched by these settings. Apply now?" defaultno || continue
                crypto_persist
                write_server_conf
                write_client_template
                svc_restart_checked || true
                _offer_regen_profiles
                return 0 ;;
            cancel)
                DATA_CIPHERS="$old_ciphers"; DATA_FALLBACK="$old_fb"; TLS_MIN="$old_tls"
                CONTROL_WRAP="$old_wrap"; AUTH_DIGEST="$old_digest"
                return 0 ;;
        esac
    done
}
