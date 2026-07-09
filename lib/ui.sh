#!/usr/bin/env bash
# =============================================================================
# lib/ui.sh - terminal UI wrappers (whiptail preferred, dialog fallback,
# plain-text fallback for consoles without either).
#
# All ui_* functions return 0 on OK/Yes and non-zero on Cancel/No/ESC.
# Selection results are printed on stdout.
# =============================================================================

UI_TOOL="plain"
OVM_BACKTITLE=""

ui_init() {
    OVM_BACKTITLE="OpenVPN Manager v${OVM_VERSION}  —  $(hostname)"
    # No usable terminal (piped stdin/stdout, TERM=dumb)? whiptail/dialog
    # would draw nothing and wait for input forever - use plain prompts.
    if [[ ! -t 0 || ! -t 1 || "${TERM:-dumb}" == "dumb" ]]; then
        UI_TOOL="plain"
        log_info "UI backend: plain (no interactive terminal detected)"
        return 0
    fi
    if command -v whiptail >/dev/null 2>&1; then
        UI_TOOL="whiptail"
    elif command -v dialog >/dev/null 2>&1; then
        UI_TOOL="dialog"
    else
        # Try to install whiptail/newt; fall back to plain prompts.
        printf 'No TUI backend found - installing whiptail...\n'
        if pkg_install_ui_tool; then
            if command -v whiptail >/dev/null 2>&1; then UI_TOOL="whiptail"
            elif command -v dialog >/dev/null 2>&1; then UI_TOOL="dialog"
            fi
        fi
    fi
    log_info "UI backend: ${UI_TOOL}"
}

_ui_height() { # _ui_height "text" -> reasonable box height
    local lines
    lines="$(printf '%s\n' "$1" | wc -l)"
    local h=$(( lines + 7 ))
    (( h < 9 ))  && h=9
    (( h > 22 )) && h=22
    printf '%s' "$h"
}

_ui_display() { # _ui_display <cmd...>
    # Run a DISPLAY-ONLY widget (msgbox/textbox/infobox/yesno) so it always
    # draws on the real terminal. whiptail/dialog render their UI on stdout;
    # when a helper is called inside $(...) command substitution, stdout is
    # captured and the widget becomes an invisible box waiting for input
    # forever. Redirect drawing to the controlling terminal in that case.
    if [[ -t 1 ]]; then
        "$@"
    elif [[ -w /dev/tty ]]; then
        "$@" > /dev/tty
    else
        "$@" >&2
    fi
}

# --- Message / confirmation ---------------------------------------------------

ui_msg() { # ui_msg "Title" "Text"
    local title="$1" text="$2"
    case "$UI_TOOL" in
        plain)
            printf '\n== %s ==\n%s\n' "$title" "$text" >&2
            read -rp "[Enter to continue] " _ || true ;;
        *)
            _ui_display "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                --msgbox "$text" "$(_ui_height "$text")" 74 ;;
    esac
}

ui_yesno() { # ui_yesno "Title" "Question" [defaultno]
    local title="$1" text="$2" defno="${3:-}"
    case "$UI_TOOL" in
        plain)
            local ans def="y/N"
            [[ -z "$defno" ]] && def="Y/n"
            printf '\n== %s ==\n%s\n' "$title" "$text" >&2
            read -rp "Confirm? [$def] " ans || return 1
            if [[ -z "$ans" ]]; then
                [[ -z "$defno" ]]
            else
                [[ $ans =~ ^[Yy] ]]
            fi ;;
        *)
            local -a flags=()
            [[ -n "$defno" ]] && flags+=(--defaultno)
            _ui_display "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                "${flags[@]}" --yesno "$text" "$(_ui_height "$text")" 74 ;;
    esac
}

ui_info() { # non-blocking progress note
    local text="$1"
    case "$UI_TOOL" in
        plain)
            printf '... %s\n' "$text" >&2 ;;
        whiptail)
            # newt quirk: whiptail --infobox draws nothing on xterm-like
            # terminals unless TERM is downgraded for the call
            _ui_display env TERM=ansi whiptail --backtitle "$OVM_BACKTITLE" \
                --title "Working" --infobox "$text" 7 70 ;;
        *)
            _ui_display "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "Working" \
                --infobox "$text" 7 70 ;;
    esac
}

ui_run() { # ui_run "label" cmd [args...]
    # Run a long/observable step on the PLAIN terminal so the admin sees the
    # real output live (package managers, easy-rsa, systemd). Returns the
    # command's exit code; prints an OK/FAIL marker line.
    local label="$1"; shift
    printf '\n==> %s\n' "$label"
    log_info "STEP: ${label}"
    if "$@"; then
        printf '    [ OK ] %s\n' "$label"
        return 0
    fi
    local rc=$?
    printf '    [FAIL] %s (exit %d) - details: %s\n' "$label" "$rc" "$OVM_LOG_FILE"
    log_error "STEP failed (exit ${rc}): ${label}"
    return "$rc"
}

ui_pause() { # plain "press Enter" prompt (used after ui_run phases)
    printf '\n%s' "${1:-Press Enter to continue...}" >&2
    read -r _ || true
}

ui_resume_tui() {
    # Call after a block of plain ui_run output before returning to the
    # whiptail/dialog menus. whiptail/newt does NOT reliably repaint after a
    # program has scrolled the screen, which looks like a hang on an
    # invisible dialog. A full clear resets the scroll region so the next
    # dialog draws correctly.
    [[ "$UI_TOOL" == "plain" ]] && return 0
    clear 2>/dev/null || printf '\033[2J\033[H'
    return 0
}

# --- Input --------------------------------------------------------------------

ui_input() { # ui_input "Title" "Prompt" ["default"] -> stdout
    local title="$1" text="$2" def="${3:-}"
    case "$UI_TOOL" in
        plain)
            local val
            printf '\n== %s ==\n' "$title" >&2
            read -rp "$text [$def]: " val || return 1   # EOF = cancel, never loop
            [[ -z "$val" ]] && val="$def"
            printf '%s' "$val" ;;
        *)
            "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                --inputbox "$text" 11 74 "$def" 3>&1 1>&2 2>&3 ;;
    esac
}

ui_input_validated() { # ui_input_validated "Title" "Prompt" "default" validator_fn "error text"
    local title="$1" text="$2" def="$3" validator="$4" errmsg="$5" val
    while true; do
        val="$(ui_input "$title" "$text" "$def")" || return 1
        if "$validator" "$val"; then
            printf '%s' "$val"
            return 0
        fi
        ui_msg "Invalid input" "$errmsg"
    done
}

ui_password() { # ui_password "Title" "Prompt" -> stdout (input hidden)
    local title="$1" text="$2"
    case "$UI_TOOL" in
        plain)
            local val
            printf '\n== %s ==\n' "$title" >&2
            read -rsp "$text: " val || { printf '\n' >&2; return 1; }
            printf '\n' >&2
            printf '%s' "$val" ;;
        *)
            "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                --passwordbox "$text" 11 74 3>&1 1>&2 2>&3 ;;
    esac
}

ui_password_confirmed() { # asks twice, verifies match & minimum length
    local title="$1" prompt="$2" minlen="${3:-8}" p1 p2
    while true; do
        p1="$(ui_password "$title" "$prompt (min. ${minlen} characters)")" || return 1
        if (( ${#p1} < minlen )); then
            ui_msg "Too short" "The password must be at least ${minlen} characters long."
            continue
        fi
        p2="$(ui_password "$title" "Repeat to confirm")" || return 1
        if [[ "$p1" == "$p2" ]]; then
            printf '%s' "$p1"
            return 0
        fi
        ui_msg "Mismatch" "The two entries did not match. Please try again."
    done
}

# --- Menus --------------------------------------------------------------------

ui_menu() { # ui_menu "Title" "Text" tag1 "item1" tag2 "item2" ... -> selected tag
    local title="$1" text="$2"; shift 2
    case "$UI_TOOL" in
        plain)
            local -a tags=() items=()
            while (( $# >= 2 )); do tags+=("$1"); items+=("$2"); shift 2; done
            printf '\n== %s ==\n%s\n' "$title" "$text" >&2
            local i
            for i in "${!tags[@]}"; do
                printf '  %-12s %s\n' "${tags[$i]})" "${items[$i]}" >&2
            done
            local choice
            read -rp "Choice (empty = cancel): " choice
            [[ -z "$choice" ]] && return 1
            for i in "${!tags[@]}"; do
                if [[ "${tags[$i]}" == "$choice" ]]; then
                    printf '%s' "$choice"
                    return 0
                fi
            done
            return 1 ;;
        *)
            local n=$(( $# / 2 ))
            (( n > 12 )) && n=12
            "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                --menu "$text" 22 76 "$n" "$@" 3>&1 1>&2 2>&3 ;;
    esac
}

ui_checklist() { # ui_checklist "Title" "Text" tag item on|off ... -> selected tags (space-separated)
    local title="$1" text="$2"; shift 2
    case "$UI_TOOL" in
        plain)
            local -a tags=() items=() states=()
            while (( $# >= 3 )); do tags+=("$1"); items+=("$2"); states+=("$3"); shift 3; done
            local i choice found guard=0
            while (( guard++ < 50 )); do
                printf '\n== %s ==\n%s\n' "$title" "$text" >&2
                for i in "${!tags[@]}"; do
                    printf '  [%s] %-18s %s\n' \
                        "$([[ ${states[$i]} == on ]] && echo x || echo ' ')" \
                        "${tags[$i]}" "${items[$i]}" >&2
                done
                read -rp "Type a name to toggle it, Enter = accept, q = cancel: " choice || return 1
                [[ -z "$choice" ]] && break
                [[ "$choice" == "q" ]] && return 1
                found="no"
                for i in "${!tags[@]}"; do
                    if [[ "${tags[$i]}" == "$choice" ]]; then
                        found="yes"
                        [[ "${states[$i]}" == "on" ]] && states[$i]="off" || states[$i]="on"
                    fi
                done
                [[ "$found" == "no" ]] && printf 'No such item: %s\n' "$choice" >&2
            done
            local out=""
            for i in "${!tags[@]}"; do
                [[ "${states[$i]}" == "on" ]] && out+="${out:+ }${tags[$i]}"
            done
            printf '%s' "$out" ;;
        *)
            local n=$(( $# / 3 )) sel
            (( n > 10 )) && n=10
            sel="$("$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                --checklist "$text" 20 76 "$n" "$@" 3>&1 1>&2 2>&3)" || return 1
            # whiptail quotes each selected tag; dialog does not - normalize.
            printf '%s' "$(tr -d '"' <<< "$sel")" ;;
    esac
}

ui_radiolist() { # ui_radiolist "Title" "Text" tag item on|off ... -> selected tag
    local title="$1" text="$2"; shift 2
    case "$UI_TOOL" in
        plain)
            local -a args=()
            local tag item state
            while (( $# >= 3 )); do
                tag="$1" item="$2" state="$3"; shift 3
                [[ "$state" == "on" ]] && item+=" (current)"
                args+=("$tag" "$item")
            done
            ui_menu "$title" "$text" "${args[@]}" ;;
        *)
            local n=$(( $# / 3 ))
            (( n > 10 )) && n=10
            "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                --radiolist "$text" 20 76 "$n" "$@" 3>&1 1>&2 2>&3 ;;
    esac
}

# --- Text viewers ---------------------------------------------------------------

ui_textfile() { # ui_textfile "Title" /path/to/file
    local title="$1" file="$2"
    case "$UI_TOOL" in
        plain)
            {
                printf '\n== %s ==\n' "$title"
                cat -- "$file"
            } >&2
            read -rp "[Enter to continue] " _ || true ;;
        *)
            _ui_display "$UI_TOOL" --backtitle "$OVM_BACKTITLE" --title "$title" \
                --scrolltext --textbox "$file" 24 78 ;;
    esac
}

ui_show_text() { # ui_show_text "Title" "multi-line text"  (non-secret content only)
    local title="$1" text="$2" tmp
    tmp="$(mktemp)" || return 1
    printf '%s\n' "$text" > "$tmp"
    ui_textfile "$title" "$tmp"
    rm -f "$tmp"
}
