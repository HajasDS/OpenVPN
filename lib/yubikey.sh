#!/usr/bin/env bash
# =============================================================================
# lib/yubikey.sh - YubiKey OTP management via pam_yubico
#
# A YubiKey OTP is a 44-character modhex string that changes on every touch:
# the first 12 characters are the key's stable PUBLIC ID, the remaining 32
# are the AES-encrypted one-time part. It is validated ONLINE against
# YubiCloud (or a self-hosted validation server) - it is NEVER treated as a
# static password.
#
# user -> key mapping lives in /etc/openvpn-manager/yubikey/authorized_yubikeys
# in pam_yubico authfile format:   username:publicid1[:publicid2...]
#
# SECURITY: OTP values are single-use and are never logged. The YubiCloud
# API key is stored only in root-only files (config + pam file, both 0600).
# =============================================================================

readonly YUBICO_DEFAULT_API="https://api.yubico.com/wsapi/2.0/verify"

_yubi_pick_user() {
    local name
    name="$(user_select "$1")" || return 0
    "$2" "$name"
}

# -----------------------------------------------------------------------------
# Validation service configuration
# -----------------------------------------------------------------------------

yubikey_configure_api() {
    local kind
    kind="$(ui_menu "Validation service" "How should OTPs be validated?" \
        "cloud" "YubiCloud (Yubico's free service; needs an API key)" \
        "self"  "Self-hosted validation server (yubikey-val or compatible)")" || return 1

    case "$kind" in
        cloud)
            ui_msg "YubiCloud API key" \
"Get a free API key at:  https://upgrade.yubico.com/getapikey/
(You need any YubiKey OTP once to request it.)

You will receive a numeric Client ID and a base64 Secret Key."
            local id key
            id="$(ui_input_validated "YubiCloud" "Client ID (numeric):" "$YUBICO_ID" \
                is_valid_yubico_client_id "The client ID is a number.")" || return 1
            key="$(ui_password "YubiCloud" "Secret key (base64; input hidden)")" || return 1
            if [[ ! $key =~ ^[A-Za-z0-9+/=]{16,64}$ ]]; then
                ui_msg "Invalid key" "That does not look like a base64 API key."
                return 1
            fi
            YUBICO_ID="$id"; YUBICO_KEY="$key"; YUBICO_URL=""
            ;;
        self)
            local url id
            url="$(ui_input_validated "Validation server" \
                "Verify URL (e.g. https://val.example.com/wsapi/2.0/verify):" \
                "$YUBICO_URL" is_valid_url "Enter a valid http(s) URL.")" || return 1
            id="$(ui_input_validated "Validation server" "Client ID (use 1 if unsure):" \
                "${YUBICO_ID:-1}" is_valid_yubico_client_id "Numeric ID required.")" || return 1
            YUBICO_URL="$url"; YUBICO_ID="$id"; YUBICO_KEY=""
            ;;
    esac

    config_set YUBICO_ID "$YUBICO_ID"
    config_set YUBICO_KEY "$YUBICO_KEY"
    config_set YUBICO_URL "$YUBICO_URL"
    log_info "YubiKey validation service configured (id=${YUBICO_ID}, self-hosted=$([[ -n $YUBICO_URL ]] && echo yes || echo no))"

    # PAM references id/key/url -> rewrite if any YubiKey mode is in use
    if [[ -f "$PAM_FILE" ]] && _auth_family_active yubikey; then
        write_pam_file
    fi
    ui_msg "Saved" "Validation service configured. PAM re-reads it on the next login (no restart needed)."
    return 0
}

# -----------------------------------------------------------------------------
# Registration / removal / listing
# -----------------------------------------------------------------------------

yubikey_register() { # yubikey_register <user>
    local user="$1" otp pubid

    # Validate everything (PAM module, API config, user, global mode) BEFORE
    # asking for an OTP - missing prerequisites show a fix menu instead of
    # failing or hanging midway.
    require_feature "yubikey_register" "$user" \
        "Register a YubiKey for user '${user}'" || return 0

    otp="$(ui_password "Register YubiKey" \
"Insert ${user}'s YubiKey and touch it once.
(The OTP appears as typed keystrokes; input is hidden.)")" || return 0
    otp="${otp//[[:space:]]/}"

    if ! is_valid_yubikey_otp "$otp"; then
        ui_msg "Invalid OTP" \
"That was not a valid YubiKey OTP (expected 32-48 modhex characters:
c b d e f g h i j k l n r t u v).

Make sure the keyboard layout is US-like and try again."
        return 1
    fi

    pubid="${otp:0:$(( ${#otp} - 32 ))}"
    if [[ -z "$pubid" ]]; then
        ui_msg "Unsupported key" "This OTP has no public ID part; per-user mapping is not possible with it."
        return 1
    fi

    # Optional but recommended: verify the OTP online before saving
    if [[ -n "$YUBICO_ID" || -n "$YUBICO_URL" ]]; then
        ui_info "Validating OTP against the validation service..."
        if ! _yubico_verify "$otp"; then
            ui_yesno "Validation failed" \
"The validation service did NOT accept this OTP.
(Wrong API credentials, no network, or the key is not known
to this validation service.)

Register the key anyway?" defaultno || return 1
        fi
    else
        ui_msg "Note" "No validation service configured yet - the key will be registered without an online check."
    fi

    umask 077
    touch "$OVM_YUBI_AUTHFILE"
    chmod 600 "$OVM_YUBI_AUTHFILE"

    local existing
    existing="$(grep -m1 "^${user}:" "$OVM_YUBI_AUTHFILE" || true)"
    if [[ -n "$existing" ]]; then
        if [[ "$existing" == *":${pubid}"* ]]; then
            ui_msg "Already registered" "This YubiKey is already registered for '${user}'."
            return 0
        fi
        local action
        action="$(ui_menu "Existing registration" "'${user}' already has a YubiKey." \
            "add"     "Add this key as an ADDITIONAL key" \
            "replace" "REPLACE the existing key(s) with this one")" || return 0
        if [[ "$action" == "add" ]]; then
            sed -i "s|^${user}:.*|&:${pubid}|" "$OVM_YUBI_AUTHFILE"
        else
            sed -i "s|^${user}:.*|${user}:${pubid}|" "$OVM_YUBI_AUTHFILE"
        fi
    else
        printf '%s:%s\n' "$user" "$pubid" >> "$OVM_YUBI_AUTHFILE"
    fi

    log_info "YubiKey registered for user: ${user} (public id: ${pubid})"
    ui_msg "YubiKey registered" \
"YubiKey with public ID '${pubid}' is now registered for '${user}'.

At VPN login the user touches the key when prompted - every touch
produces a different one-time code."
}

yubikey_unregister() {
    local user="$1"
    if ! grep -q "^${user}:" "$OVM_YUBI_AUTHFILE" 2>/dev/null; then
        ui_msg "YubiKey" "'${user}' has no registered YubiKey."
        return 0
    fi
    local warn="" umode
    umode="$(policy_user_mode "$user" 2>/dev/null || echo cert)"
    mode_uses_yubikey "$umode" && \
        warn=$'\n\nWARNING: this user'\''s mode REQUIRES a YubiKey OTP - they will not\nbe able to log in afterwards until a key is registered again or their\nmode is changed.'
    ui_yesno "Remove YubiKey" "Remove all YubiKey registrations of '${user}'?${warn}" defaultno || return 0
    sed -i "/^${user}:/d" "$OVM_YUBI_AUTHFILE"
    log_info "YubiKey registration removed for user: ${user}"
    ui_msg "YubiKey" "Registration removed."
}

yubikey_list() {
    local text=""
    if [[ -s "$OVM_YUBI_AUTHFILE" ]]; then
        text="$(awk -F: '{printf "%-24s keys: %s\n", $1, NF-1}' "$OVM_YUBI_AUTHFILE")"
    fi
    [[ -z "$text" ]] && text="(no YubiKeys registered)"
    ui_show_text "Registered YubiKeys" "$text"
}

# -----------------------------------------------------------------------------
# Online validation (test + registration check)
# -----------------------------------------------------------------------------

yubikey_test() {
    require_feature "yubikey_test" "" "Validate a test YubiKey OTP" || return 0
    local otp
    otp="$(ui_password "Test OTP" "Touch the YubiKey to emit a test OTP (input hidden)")" || return 0
    otp="${otp//[[:space:]]/}"
    is_valid_yubikey_otp "$otp" || { ui_msg "Invalid" "Not a valid modhex OTP string."; return 1; }

    ui_info "Contacting validation service..."
    if _yubico_verify "$otp"; then
        log_info "YubiKey test OTP validated successfully (public id: ${otp:0:$(( ${#otp} - 32 ))})"
        ui_msg "Success" "The validation service accepted the OTP.
The full validation chain works."
    else
        log_warn "YubiKey test OTP validation failed"
        ui_msg "Failed" \
"The OTP was rejected or the service was unreachable.

Checklist:
  - API client ID / secret key correct?
  - Server has outbound HTTPS access?
  - Each OTP is single-use: touch the key again for a fresh one."
        return 1
    fi
}

_yubico_verify() { # _yubico_verify <otp> ; returns 0 if status=OK. Never logs the OTP.
    local otp="$1" nonce url resp
    nonce="$(openssl rand -hex 16)"
    url="${YUBICO_URL:-$YUBICO_DEFAULT_API}"
    resp="$(curl -fsS --max-time 15 -G \
        --data-urlencode "id=${YUBICO_ID:-1}" \
        --data-urlencode "otp=${otp}" \
        --data-urlencode "nonce=${nonce}" \
        "$url" 2>/dev/null)" || return 1
    # Bind the response to our request: same otp, same nonce, status OK.
    grep -q "^status=OK" <<< "$(tr -d '\r' <<< "$resp")" || return 1
    grep -q "otp=${otp}"     <<< "$resp" || return 1
    grep -q "nonce=${nonce}" <<< "$resp" || return 1
    return 0
}

yubikey_instructions() {
    ui_show_text "YubiKey OTP - how it works and how to set it up" \
"HOW IT WORKS
  A YubiKey OTP is NOT a static password. Every touch generates a new
  44-character one-time code (first 12 chars = the key's public ID,
  the rest changes every time). The server sends the code to a
  validation service (YubiCloud or self-hosted) which decrypts it and
  confirms it is genuine and has never been used before.

SERVER SETUP
  1. Authentication -> Global authentication features ->
     Configure the YubiKey validation service
     - YubiCloud: get a free API key at
       https://upgrade.yubico.com/getapikey/
     - or point it at your own yubikey-val server.
  2. 'Validate a test OTP' to confirm the whole chain.
  3. Allow a YubiKey mode under Global enforcement rules.
  4. Assign the mode per user (Authentication -> User authentication
     modes) - the key is registered during assignment (one touch).
  5. Distribute the regenerated .ovpn profiles.

CLIENT LOGIN
  - Mode 'certificate + YubiKey': username = VPN username,
    password field = just touch the YubiKey.
  - Mode 'certificate + password + YubiKey': in the password field
    type the password and IMMEDIATELY touch the key - the one-time
    code is appended to the end and the server splits and verifies
    both parts (standard pam_yubico flow).

REQUIREMENTS
  - The VPN server needs outbound HTTPS to the validation service.
  - Keys must be registered (user -> public ID mapping) before login."
}
