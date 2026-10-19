#!/system/bin/sh
# Read-only process and Binder checks. No mount or service-start operations.

process_token() {
    # After removing pid and (comm), starttime is field 20.
    sed 's/^.*) //' "$PROC_ROOT/$1/stat" 2>/dev/null | awk '{print $20}'
}

process_alive() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "$PROC_ROOT/$1/stat" ] || return 1
    process_state=$(sed 's/^.*) //' "$PROC_ROOT/$1/stat" | awk '{print $1}')
    case "$process_state" in ''|Z|X) return 1 ;; esac
}

check_identity() {
    process_alive "$1" || { CHECK_STATE=PROCESS_EXITED; return 1; }
    check_token=$(process_token "$1")
    check_exe=$(readlink "$PROC_ROOT/$1/exe" 2>/dev/null)
    check_context=$(cat "$PROC_ROOT/$1/attr/current" 2>/dev/null)
    check_status=$(cat "$PROC_ROOT/$1/status" 2>/dev/null)
    log "identity pid=$1 starttime=$check_token exe=$check_exe context=$check_context"
    printf '%s\n' "$check_status" | grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Amb)):' >>"$ATTEMPT_LOG"
    case "$check_exe" in "$BIN"|"$MODDIR/system/odm/bin/mosey_server") ;; *) CHECK_STATE=IDENTITY_ERROR; return 1 ;; esac
    [ "$check_context" = 'u:r:mosey_server:s0' ] || { CHECK_STATE=IDENTITY_ERROR; return 1; }
    # Require all real/effective/saved/filesystem IDs and all four capability sets.
    if ! printf '%s\n' "$check_status" | awk '
        /^Uid:/ { uid=(NF==5 && $2==1000 && $3==1000 && $4==1000 && $5==1000) }
        /^Gid:/ { gid=(NF==5 && $2==1000 && $3==1000 && $4==1000 && $5==1000) }
        /^Groups:/ { for(i=2;i<=NF;i++) if($i==3003) inet=1 }
        /^CapInh:/ { inh=($2=="0000000000003000") }
        /^CapPrm:/ { prm=($2=="0000000000003000") }
        /^CapEff:/ { eff=($2=="0000000000003000") }
        /^CapAmb:/ { amb=($2=="0000000000003000") }
        END { exit !(uid && gid && inet && inh && prm && eff && amb) }'; then
        CHECK_STATE=IDENTITY_ERROR; return 1
    fi
    if [ -z "$check_token" ] || [ "$check_token" != "$(process_token "$1")" ] || ! process_alive "$1"; then
        CHECK_STATE=PROCESS_CHANGED; return 1
    fi
    CHECK_STATE=IDENTITY_OK
}

check_binder() {
    # listServices does not lazily start an absent service. Keep raw output + rc.
    timeout 5 service list >"$ATTEMPT_DIR/binder.txt" 2>&1
    binder_rc=$?
    log "binder_query_rc=$binder_rc snapshot=$ATTEMPT_DIR/binder.txt"
    [ "$binder_rc" -eq 0 ] || { CHECK_STATE=BINDER_QUERY_FAILED; return 1; }
    grep -Eq '^Found [0-9]+ services:' "$ATTEMPT_DIR/binder.txt" \
        || { CHECK_STATE=BINDER_QUERY_FAILED; return 1; }
    if awk -v name="$SERVICE_NAME:" '$2==name {found=1} END {exit !found}' "$ATTEMPT_DIR/binder.txt"; then
        CHECK_STATE=REGISTERED; return 0
    fi
    CHECK_STATE=BINDER_NOT_REGISTERED
    return 1
}

verify_running() {
    verify_pid=$1
    verify_token=$(process_token "$verify_pid")
    verify_i=0
    while [ "$verify_i" -lt 5 ]; do
        check_identity "$verify_pid" || return 1
        [ "$verify_token" = "$(process_token "$verify_pid")" ] \
            || { CHECK_STATE=PROCESS_CHANGED; return 1; }
        if check_binder; then
            check_identity "$verify_pid" || return 1
            [ "$verify_token" = "$(process_token "$verify_pid")" ] \
                || { CHECK_STATE=PROCESS_CHANGED; return 1; }
            CHECK_STATE=REGISTERED
            return 0
        fi
        [ "$CHECK_STATE" = BINDER_QUERY_FAILED ] && return 1
        verify_i=$((verify_i + 1))
        [ "$verify_i" -ge 5 ] || sleep 1
    done
    return 1
}
