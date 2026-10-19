#!/system/bin/sh
# Installed module runtime only. Publishes passive snapshots, never restarts Mosey.
MODDIR=${0%/*}
PROC_ROOT=/proc
BIN=/odm/bin/mosey_server
SERVICE_NAME=com.google.android.moseyservice.IMoseyService/default
KSUD=/data/adb/ksud
PATH=/system/bin:/system/xbin
LC_ALL=C
export PATH LC_ALL
unset LD_PRELOAD LD_LIBRARY_PATH MOSEY_REGISTRATION_COMPAT
umask 077
set -f
# shellcheck source=registration-checks.sh
. "$MODDIR/registration-checks.sh"
# shellcheck source=status-checks.sh
. "$MODDIR/status-checks.sh"

status_boot=$(cat "$PROC_ROOT/sys/kernel/random/boot_id" 2>/dev/null)
status_start=$(registration_token "$$")
[ -n "$status_boot" ] && [ -n "$status_start" ] || exit 1
STATUS_OWNER="$status_boot:$$:$status_start"
# A new service invocation replaces ownership atomically. Previous observers
# retire at their next check; stale owners after SIGKILL never block a new one.
owner_tmp=$(mktemp "$MODDIR/.status-owner.XXXXXX") || exit 1
printf '%s\n' "$STATUS_OWNER" >"$owner_tmp" || { rm -f "$owner_tmp"; exit 1; }
mv -f "$owner_tmp" "$MODDIR/.status-owner" || { rm -f "$owner_tmp"; exit 1; }
# shellcheck disable=SC2329 # Called via the EXIT trap.
status_cleanup() {
    if mosey_status_owns; then
        mosey_status_publish Unknown
    fi
}
trap status_cleanup 0
trap 'exit 0' 1 2 15
while mosey_status_owns; do
    [ "$(cat "$PROC_ROOT/sys/kernel/random/boot_id" 2>/dev/null)" = "$status_boot" ] || break
    if [ -e "$MODDIR/disable" ] || [ -e "$MODDIR/remove" ] || [ -e "$MODDIR/update" ]; then
        # These flags concern next boot, not proof the native service stopped.
        current_status=Unknown
    else
        current_status=$(mosey_status_sample)
    fi
    mosey_status_owns || break
    # Reassert temporary config each round so an older observer finishing an
    # in-flight publish cannot leave a stale value. Unchanged legacy props are
    # never rewritten. The ownership record need not be removed on exit.
    mosey_status_publish "$current_status"
    if [ "${previous_status:-}" != "$current_status" ]; then
        if [ -f "$MODDIR/event-log.sh" ]; then
            . "$MODDIR/event-log.sh"
            mosey_event status "$current_status" || :
        fi
        previous_status=$current_status
    fi
    sleep 30
done
