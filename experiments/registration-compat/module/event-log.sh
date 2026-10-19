#!/system/bin/sh
# Best-effort fixed-token events; logging failure never changes service behavior.
EVENT_ROOT=/data/adb/mosey-plk110-cn/events
mosey_event() (
    case "$1:$2" in *[!a-zA-Z0-9_:.-]*|:*|*:) exit 0 ;; esac
    timeout -k 1 1 log -t KernelSU "[moseyPLK.service] $1 $2" >/dev/null 2>&1 || :
    umask 077
    [ ! -L "$EVENT_ROOT" ] || exit 0
    # shellcheck disable=SC2174 # umask 077 also protects newly created parents.
    mkdir -m 0700 -p "$EVENT_ROOT" 2>/dev/null || exit 0
    [ "$(stat -c '%u:%a' "$EVENT_ROOT" 2>/dev/null)" = 0:700 ] || exit 0
    # Non-blocking lock. A crashed logger may suppress file logging, but never
    # service control. Each event also has its independently bounded logcat copy.
    mkdir "$EVENT_ROOT/.lock" 2>/dev/null || exit 0
    trap 'rmdir "$EVENT_ROOT/.lock" 2>/dev/null' 0
    for event_file in "$EVENT_ROOT/events.log" "$EVENT_ROOT/events.log.1" "$EVENT_ROOT/events.log.2"; do
        [ ! -L "$event_file" ] || exit 0
        if [ -e "$event_file" ]; then
            [ -f "$event_file" ] && [ "$(stat -c '%u:%a' "$event_file" 2>/dev/null)" = 0:600 ] || exit 0
        fi
    done
    event_line="$(date +%s) [moseyPLK.service] $1 $2"
    event_size=0
    [ ! -e "$EVENT_ROOT/events.log" ] || event_size=$(stat -c %s "$EVENT_ROOT/events.log" 2>/dev/null)
    case "$event_size" in ''|*[!0-9]*) exit 0 ;; esac
    if [ "$((event_size+${#event_line}+1))" -gt 1048576 ]; then
        rm -f "$EVENT_ROOT/events.log.2"
        [ ! -e "$EVENT_ROOT/events.log.1" ] || mv "$EVENT_ROOT/events.log.1" "$EVENT_ROOT/events.log.2" || exit 0
        [ ! -e "$EVENT_ROOT/events.log" ] || mv "$EVENT_ROOT/events.log" "$EVENT_ROOT/events.log.1" || exit 0
    fi
    printf '%s\n' "$event_line" >>"$EVENT_ROOT/events.log" 2>/dev/null || :
    exit 0
)
