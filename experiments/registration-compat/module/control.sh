#!/system/bin/sh
MODDIR=${0%/*}
PATH=/system/bin:/system/xbin
LC_ALL=C
export PATH LC_ALL
unset LD_PRELOAD LD_LIBRARY_PATH MOSEY_REGISTRATION_COMPAT
umask 077
set -f
. "$MODDIR/control-common.sh"
control_environment || exit 1
[ "$#" = 1 ] || { control_error INVALID_COMMAND; exit 64; }
case "$1" in
    capabilities)
        control_header
        printf '"ok":true,"commands":["capabilities","status","start","stop","restart"],"timeouts":{"status":10,"start":180,"stop":30,"restart":210},"mountNamespaceVerified":%s}\n' "$CONTROL_MOUNT_OK"
        ;;
    status)
        native_state=$(mosey_status_sample)
        is_owned=false
        control_owned && is_owned=true
        control_header
        printf '"ok":true,"state":"%s","owned":%s,"bootId":"%s","sampledElapsed":%s,"mountNamespaceVerified":%s,"lastOperation":' \
            "$native_state" "$is_owned" "$CONTROL_BOOT" "$CONTROL_NOW" "$CONTROL_MOUNT_OK"
        control_operation_json
        printf '}\n'
        ;;
    start|stop|restart)
        [ "$CONTROL_MOUNT_OK" = true ] || { control_error MOUNT_NAMESPACE_UNVERIFIED; exit 1; }
        [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] && [ ! -e "$MODDIR/update" ] \
            || { control_error MODULE_INACTIVE; exit 1; }
        [ -x "$CONTROL_HELPER" ] || { control_error CONTROL_HELPER_UNAVAILABLE; exit 1; }
        control_prepare || { control_error PRIVATE_STATE_UNAVAILABLE; exit 1; }
        OP_COMMAND=$1
        OP_STARTED=$CONTROL_NOW
        case "$OP_COMMAND" in start) OP_BUDGET=180 ;; stop) OP_BUDGET=30 ;; restart) OP_BUDGET=210 ;; esac
        OP_DEADLINE=$((OP_STARTED + OP_BUDGET))
        submit_token=$(registration_token "$$")
        case "$submit_token" in ''|*[!0-9]*) control_error CALLER_LIFETIME_UNAVAILABLE; exit 1 ;; esac
        OP_ID="$CONTROL_BOOT-$CONTROL_NOW-$$-$submit_token"
        control_lock || { control_error OPERATION_BUSY_OR_UNTRUSTED_LOCK; exit 1; }
        if ! control_operation_write running ACCEPTED; then
            control_unlock; control_error STATE_WRITE_FAILED; exit 1
        fi
        # libsu/root-shell shutdown cannot hang up this worker. Its donor gets
        # another session so neither this worker nor its budget owns its life.
        setsid sh "$MODDIR/control-worker.sh" "$OP_ID" </dev/null >/dev/null 2>&1 &
        worker_launch=$!
        if [ -z "$worker_launch" ]; then
            control_operation_write failed WORKER_LAUNCH_FAILED
            control_unlock; control_error WORKER_LAUNCH_FAILED; exit 1
        fi
        control_header
        printf '"ok":true,"operation":'
        control_operation_json
        printf '}\n'
        ;;
    *) control_error INVALID_COMMAND; exit 64 ;;
esac
