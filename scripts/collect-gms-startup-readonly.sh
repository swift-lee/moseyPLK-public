#!/system/bin/sh
# Review on the host, then stream via an already authorized root shell's stdin.
# The host must first confirm exactly one target and the expected boot/user.
# Start BEFORE asking the user to restart GMS; this never starts/stops an app.

capture_seconds=${MOSEY_CAPTURE_SECONDS:-180}
case "$capture_seconds" in
    ''|*[!0-9]*|????*) printf 'Invalid capture duration\n' >&2; exit 2 ;;
esac
if [ "$capture_seconds" -lt 1 ] || [ "$capture_seconds" -gt 300 ]; then
    printf 'Capture duration must be 1..300 seconds\n' >&2
    exit 2
fi
[ "$(id -u)" = 0 ] || exit 3
[ "$(getprop ro.product.model)" = PLK110 ] || exit 4
current_user=$(timeout -k 1 5 am get-current-user)
user_query_rc=$?
if [ "$user_query_rc" -ne 0 ]; then
    printf 'CURRENT_USER_QUERY_FAILED rc=%s\n' "$user_query_rc" >&2
    exit 5
fi
[ "$current_user" = 0 ] || exit 5

date '+%Y-%m-%dT%H:%M:%S%z'
printf '\nBOOT_ID_AND_UPTIME\n'
cat /proc/sys/kernel/random/boot_id /proc/uptime
printf '\nMAIN_BUFFER_CAPACITY\n'
timeout -k 1 5 logcat -b main -g
capacity_query_rc=$?
if [ "$capacity_query_rc" -ne 0 ]; then
    printf 'MAIN_BUFFER_CAPACITY_FAILED rc=%s\n' "$capacity_query_rc" >&2
    exit 6
fi
# READY means the bounded reader is about to start, not a subscription ACK.
printf '\nSTARTUP_CAPTURE_READY duration=%s\n' "$capture_seconds"
# -T 1 follows new records; no buffer resize, clear, property or file writes.
# Output is captured only on the host. The timeout ends the reader, not apps.
timeout -k 1 "$capture_seconds" logcat -b main -b system -b events -b crash \
    -v threadtime -T 1 'MoseyClientCompat:I' 'MoseyGmsDiag:I' \
    'NearbySharing:I' 'ActivityManager:I' 'am_proc_start:I' \
    'am_proc_died:I' 'am_kill:I' 'wm_resume_activity:I' '*:S'
capture_rc=$?
printf '\nSTARTUP_CAPTURE_END reader_rc=%s\n' "$capture_rc"
date '+%Y-%m-%dT%H:%M:%S%z'
case "$capture_rc" in
    0|124) exit 0 ;;
    *) exit "$capture_rc" ;;
esac
