#!/system/bin/sh
# Internal one-shot worker. Public callers use control.sh; no PID/package input.
MODDIR=${0%/*}
PATH=/system/bin:/system/xbin
LC_ALL=C
export PATH LC_ALL
unset LD_PRELOAD LD_LIBRARY_PATH MOSEY_REGISTRATION_COMPAT
umask 077
set -f
. "$MODDIR/control-common.sh"
control_environment >/dev/null || exit 1
[ "$#" = 1 ] || exit 64
OP_ID=$1
case "$OP_ID" in ''|*[!a-zA-Z0-9-]*) exit 64 ;; esac
control_prepare && control_owner_read && [ "$lock_id" = "$OP_ID" ] && [ "$lock_phase" = starting ] || exit 1
control_private_file "$CONTROL_ROOT/operation" || exit 1
read -r op_schema op_boot recorded_id OP_COMMAND op_state op_reason OP_STARTED OP_DEADLINE op_extra <"$CONTROL_ROOT/operation"
[ "$op_schema" = 1 ] && [ "$op_boot" = "$CONTROL_BOOT" ] && [ "$recorded_id" = "$OP_ID" ] \
    && [ "$op_state" = running ] && [ -z "$op_extra" ] || exit 1
case "$OP_COMMAND" in start|stop|restart) ;; *) exit 64 ;; esac
case "$OP_STARTED:$OP_DEADLINE" in *[!0-9:]*|:*|*:) exit 64 ;; esac
[ "$CONTROL_NOW" -lt "$OP_DEADLINE" ] || exit 1
control_write_owner active || exit 1
trap control_unlock 0
trap 'control_operation_write unconfirmed WORKER_INTERRUPTED; exit 1' 1 2 15
control_done() {
    control_operation_write "$1" "$2"
    mosey_event operation "$OP_COMMAND:$1:$2"
    exit "$3"
}
control_remaining() {
    remaining_now=$(control_now)
    case "$remaining_now" in ''|*[!0-9]*) return 1 ;; esac
    remaining=$((OP_DEADLINE-remaining_now))
    [ "$remaining" -gt 0 ]
}
control_sample() {
    sample_now=$(control_now)
    case "$sample_now" in ''|*[!0-9]*) echo Unknown; return ;; esac
    sample_remaining=$((sample_deadline-sample_now-1))
    [ "$sample_remaining" -gt 0 ] || { echo Unknown; return; }
    STATUS_TIMEOUT=5
    [ "$sample_remaining" -ge 5 ] || STATUS_TIMEOUT=$sample_remaining
    mosey_status_sample
}
control_stop() {
    stop_started=$(control_now)
    stop_deadline=$((stop_started+30))
    [ "$stop_deadline" -le "$OP_DEADLINE" ] || stop_deadline=$OP_DEADLINE
    sample_deadline=$stop_deadline
    initial=$(control_sample)
    [ "$initial" != Stopped ] || return 0
    control_owned || { stop_reason=OWNERSHIP_UNVERIFIED; return 1; }
    stop_pid=$owned_pid; stop_token=$owned_token
    "$CONTROL_HELPER" terminate
    terminate_rc=$?
    if [ "$terminate_rc" != 0 ]; then
        case "$terminate_rc" in 69) stop_reason=PIDFD_UNAVAILABLE ;; 66) stop_reason=OWNERSHIP_CHANGED ;; *) stop_reason=TERM_NOT_SENT ;; esac
        return 1
    fi
    while control_remaining; do
        stop_now=$(control_now)
        [ "$stop_now" -lt "$stop_deadline" ] || break
        # Another process is never signalled. A reused PID is a change, not exit.
        if registration_alive "$stop_pid"; then
            [ "$(registration_token "$stop_pid")" = "$stop_token" ] || { stop_reason=PROCESS_REPLACED; return 1; }
        fi
        current=$(control_sample)
        if registration_alive "$stop_pid" && [ "$(registration_token "$stop_pid")" != "$stop_token" ]; then
            stop_reason=PROCESS_REPLACED; return 1
        fi
        if [ "$current" = Stopped ] && ! registration_alive "$stop_pid"; then
            rm -f "$CONTROL_ROOT/owned"
            return 0
        fi
        if [ "$current" = Unknown ]; then
            stop_now=$(control_now)
            if [ "$stop_now" -ge "$((stop_deadline-1))" ]; then stop_reason=STOP_TIMEOUT; return 1; fi
            stop_reason=STATE_UNCONFIRMED; return 1
        fi
        sleep 1
    done
    stop_reason=STOP_TIMEOUT
    return 1
}
if [ "$CONTROL_MOUNT_OK" != true ]; then control_done failed MOUNT_NAMESPACE_UNVERIFIED 1; fi
mosey_event operation "$OP_COMMAND:running:BEGIN"
if [ "$OP_COMMAND" = stop ] || [ "$OP_COMMAND" = restart ]; then
    if ! control_stop; then control_done failed "$stop_reason" 1; fi
    [ "$OP_COMMAND" != stop ] || control_done succeeded STOPPED 0
fi
control_remaining || control_done unconfirmed DEADLINE_EXCEEDED 1
sample_deadline=$OP_DEADLINE
before=$(control_sample)
if [ "$before" = Running ] && control_owned; then control_done succeeded ALREADY_RUNNING 0; fi
[ "$before" = Stopped ] || control_done failed EXISTING_PROCESS_OR_BINDER 1
control_remaining || control_done unconfirmed DEADLINE_EXCEEDED 1
[ "$remaining" -le 180 ] || remaining=180
[ ! -L "$CONTROL_ROOT/start-result" ] || control_done failed STATE_WRITE_FAILED 1
[ ! -e "$CONTROL_ROOT/start-result" ] || control_private_file "$CONTROL_ROOT/start-result" || control_done failed STATE_WRITE_FAILED 1
start_result_tmp=$(mktemp "$CONTROL_ROOT/.start-result.XXXXXX") || control_done failed STATE_WRITE_FAILED 1
"$CONTROL_HELPER" run-start "$remaining" >"$start_result_tmp" 2>&1
start_rc=$?
# Replace the directory entry; never truncate/follow an existing result link.
if ! control_replace "$start_result_tmp" "$CONTROL_ROOT/start-result"; then
    rm -f "$start_result_tmp"
    control_done unconfirmed STATE_WRITE_FAILED 1
fi
[ "$start_rc" != 124 ] || control_done unconfirmed START_TIMEOUT 1
control_remaining || control_done unconfirmed DEADLINE_EXCEEDED 1
if [ "$start_rc" = 0 ] && control_owned && [ "$(control_sample)" = Running ]; then
    control_remaining || control_done unconfirmed DEADLINE_EXCEEDED 1
    control_done succeeded RUNNING 0
fi
start_reason=$(sed -n 's/^RESULT=//p' "$CONTROL_ROOT/start-result" | tail -n 1)
case "$start_reason" in ''|*[!A-Z0-9_]*) start_reason=START_UNCONFIRMED ;; esac
control_done failed "$start_reason" 1
