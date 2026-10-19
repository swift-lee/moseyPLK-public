#!/system/bin/sh
# Detached pipe owner: outlives UI and the finite registration observer.
LOGROOT=/data/adb/mosey-plk110-cn/registration-compat
BIN=/odm/bin/mosey_server
LIBRARY=/odm/lib64/libmosey_registration_compat.so
LAUNCHER=/vendor/bin/mosey_launcher
PATH=/system/bin:/system/xbin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH MOSEY_REGISTRATION_COMPAT
umask 077
set -f
[ "$#" = 1 ] && [ "$(id -u)" = 0 ] || exit 64
OUT=$1
case "$OUT" in "$LOGROOT"/*) ;; *) exit 64 ;; esac
[ ! -L "$OUT" ] && [ -d "$OUT" ] && [ "$(stat -c '%u:%a' "$OUT")" = 0:700 ] || exit 64
trap '' 1
# The donor receives an anonymous pipe, never an adb_data_file descriptor.
# The ksu consumer keeps draining even after the log storage limit is reached.
# A separate ksu supervisor records the exact wait status of this child.
(
    trap - 0 1 2 15
    # shellcheck disable=SC2016 # Expansions belong to the child shell.
    sh -c '
        token=$(sed "s/^.*) //" "/proc/$$/stat" | awk "{print \$20}")
        [ -n "$token" ] || exit 90
        printf "%s %s\n" "$$" "$token" >"$1/child.txt"
        LD_PRELOAD="$2"; MOSEY_REGISTRATION_COMPAT=1
        export LD_PRELOAD MOSEY_REGISTRATION_COMPAT
        exec "$3" "$4"
    ' sh "$OUT" "$LIBRARY" "$LAUNCHER" "$BIN"
    daemon_rc=$?
    printf 'DAEMON_EXIT_CODE=%s\n' "$daemon_rc" >"$OUT/daemon-exit.txt"
) </dev/null 2>&1 | (
    trap - 0 1 2 15
    awk 'BEGIN {bytes=0; limit=1048576}
        {if(bytes+length($0)+1<=limit) {print; bytes+=length($0)+1; fflush()}
         else if(!truncated) {
             remaining=limit-bytes
             if(remaining>1) print substr($0,1,remaining-1)
             print "MOSEY_LOG_TRUNCATED=1"; fflush(); truncated=1; bytes=limit
         }}
    ' >"$OUT/daemon.log"
) 2>"$OUT/consumer-error.txt"
