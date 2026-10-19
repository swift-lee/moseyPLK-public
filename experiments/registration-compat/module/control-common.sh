#!/system/bin/sh
# shellcheck disable=SC2034,SC2153 # Shared caller variables and input/output records.
# Fixed-path helpers. Never source persisted state or evaluate caller text.
CONTROL_ROOT=/data/adb/mosey-plk110-cn/control
PROC_ROOT=/proc
BIN=/odm/bin/mosey_server
SERVICE_NAME=com.google.android.moseyservice.IMoseyService/default
CONTROL_HELPER="$MODDIR/mosey_service_control"
. "$MODDIR/registration-checks.sh"
. "$MODDIR/status-checks.sh"
. "$MODDIR/event-log.sh"

control_now() { awk '{print int($1)}' "$PROC_ROOT/uptime" 2>/dev/null; }
control_boot() { tr -cd 'a-zA-Z0-9-' <"$PROC_ROOT/sys/kernel/random/boot_id" 2>/dev/null; }
control_header() {
    printf '{"schema":1,"moduleId":"moseyPLK.service","version":"%s","versionCode":%s,' "$CONTROL_VERSION" "$CONTROL_VERSION_CODE"
}
control_error() {
    control_header
    printf '"ok":false,"reason":"%s"}\n' "$1"
}
control_environment() {
    CONTROL_VERSION=$(sed -n 's/^version=v\{0,1\}//p' "$MODDIR/module.prop")
    CONTROL_VERSION_CODE=$(sed -n 's/^versionCode=//p' "$MODDIR/module.prop")
    case "$CONTROL_VERSION" in ''|*[!0-9.]*) CONTROL_VERSION=unknown ;; esac
    case "$CONTROL_VERSION_CODE" in ''|*[!0-9]*) CONTROL_VERSION_CODE=0 ;; esac
    [ "$(id -u)" = 0 ] || { control_error ROOT_REQUIRED; return 1; }
    [ "$(cat "$PROC_ROOT/self/attr/current" 2>/dev/null)" = u:r:ksu:s0 ] \
        || { control_error CALLER_CONTEXT_UNVERIFIED; return 1; }
    CONTROL_BOOT=$(control_boot)
    CONTROL_NOW=$(control_now)
    case "$CONTROL_BOOT:$CONTROL_NOW" in :*|*:|*[!a-zA-Z0-9:-]*) control_error CLOCK_UNAVAILABLE; return 1 ;; esac
    if ! command -v timeout >/dev/null 2>&1 || ! command -v setsid >/dev/null 2>&1; then
        control_error TOOLS_UNAVAILABLE; return 1
    fi
    # Status may run in a private namespace, but controls cannot. No setns/mount.
    CONTROL_MOUNT_OK=false
    control_self_ns=$(readlink "$PROC_ROOT/self/ns/mnt" 2>/dev/null)
    control_init_ns=$(readlink "$PROC_ROOT/1/ns/mnt" 2>/dev/null)
    if [ -n "$control_self_ns" ] && [ "$control_self_ns" = "$control_init_ns" ]; then CONTROL_MOUNT_OK=true; fi
}
control_prepare() {
    [ ! -L "$CONTROL_ROOT" ] || return 1
    # shellcheck disable=SC2174 # umask 077 also protects newly created parents.
    if [ ! -e "$CONTROL_ROOT" ]; then mkdir -m 0700 -p "$CONTROL_ROOT" || return 1; fi
    [ -d "$CONTROL_ROOT" ] && [ "$(stat -c '%u:%a' "$CONTROL_ROOT" 2>/dev/null)" = 0:700 ]
}
control_private_file() {
    [ ! -L "$1" ] && [ -f "$1" ] && [ "$(stat -c '%u:%a' "$1" 2>/dev/null)" = 0:600 ]
}
control_replace() {
    # mv treats a symlink to a directory as a directory unless -T is available.
    # Avoid that portability trap; root-only parents rule out untrusted races.
    [ ! -L "$2" ] || return 1
    [ ! -e "$2" ] || control_private_file "$2" || return 1
    chmod 0600 "$1" && mv -f "$1" "$2"
}
control_owner_read() {
    control_private_file "$CONTROL_ROOT/lock/owner" || return 1
    read -r lock_schema lock_boot lock_pid lock_token lock_id lock_phase lock_time lock_extra <"$CONTROL_ROOT/lock/owner"
    [ "$lock_schema" = 1 ] && [ -z "$lock_extra" ] || return 1
    case "$lock_pid:$lock_token:$lock_time" in *[!0-9:]*|:*|*::*|*:) return 1 ;; esac
    case "$lock_id" in ''|*[!a-zA-Z0-9-]*) return 1 ;; esac
    case "$lock_phase" in starting|active) ;; *) return 1 ;; esac
}
control_owner_alive() {
    [ "$lock_boot" = "$CONTROL_BOOT" ] && registration_alive "$lock_pid" \
        && [ "$(registration_token "$lock_pid")" = "$lock_token" ]
}
control_lock() {
    if ! mkdir -m 0700 "$CONTROL_ROOT/lock" 2>/dev/null; then
        [ ! -L "$CONTROL_ROOT/lock" ] && [ "$(stat -c '%u:%a' "$CONTROL_ROOT/lock" 2>/dev/null)" = 0:700 ] || return 1
        # A single reaper serializes stale-owner recovery. Unknown/malformed
        # ownership remains locked; it is never interpreted as permission.
        mkdir -m 0700 "$CONTROL_ROOT/reaper" 2>/dev/null || return 1
        if ! control_owner_read || control_owner_alive || \
            { [ "$lock_boot" = "$CONTROL_BOOT" ] && [ "$((CONTROL_NOW-lock_time))" -lt 10 ]; }; then
            rmdir "$CONTROL_ROOT/reaper" 2>/dev/null; return 1
        fi
        if ! mv "$CONTROL_ROOT/lock" "$CONTROL_ROOT/reaper/stale" 2>/dev/null; then
            rmdir "$CONTROL_ROOT/reaper" 2>/dev/null; return 1
        fi
        rm -f "$CONTROL_ROOT/reaper/stale/owner"
        rmdir "$CONTROL_ROOT/reaper/stale" "$CONTROL_ROOT/reaper" 2>/dev/null || return 1
        mkdir -m 0700 "$CONTROL_ROOT/lock" 2>/dev/null || return 1
    fi
    control_write_owner starting
}
control_write_owner() {
    control_own_token=$(registration_token "$$")
    case "$control_own_token" in ''|*[!0-9]*) return 1 ;; esac
    control_owner_tmp=$(mktemp "$CONTROL_ROOT/lock/.owner.XXXXXX") || return 1
    printf '1 %s %s %s %s %s %s\n' "$CONTROL_BOOT" "$$" "$control_own_token" "$OP_ID" "$1" "$CONTROL_NOW" >"$control_owner_tmp" \
        && control_replace "$control_owner_tmp" "$CONTROL_ROOT/lock/owner"
}
control_unlock() {
    if control_owner_read && [ "$lock_id" = "$OP_ID" ] && [ "$lock_pid" = "$$" ]; then
        rm -f "$CONTROL_ROOT/lock/owner"
        rmdir "$CONTROL_ROOT/lock" 2>/dev/null
    fi
}
control_operation_write() {
    operation_tmp=$(mktemp "$CONTROL_ROOT/.operation.XXXXXX") || return 1
    printf '1 %s %s %s %s %s %s %s\n' "$CONTROL_BOOT" "$OP_ID" "$OP_COMMAND" "$1" "$2" "$OP_STARTED" "$OP_DEADLINE" >"$operation_tmp" \
        && control_replace "$operation_tmp" "$CONTROL_ROOT/operation"
}
control_operation_json() {
    if ! control_private_file "$CONTROL_ROOT/operation"; then printf null; return; fi
    read -r op_schema op_boot op_id op_command op_state op_reason op_started op_deadline op_extra <"$CONTROL_ROOT/operation"
    if [ "$op_schema" != 1 ] || [ "$op_boot" != "$CONTROL_BOOT" ] || [ -n "$op_extra" ]; then printf null; return; fi
    case "$op_id:$op_reason" in *[!a-zA-Z0-9_:-]*|:*|*:) printf null; return ;; esac
    case "$op_started:$op_deadline" in *[!0-9:]*|:*|*:) printf null; return ;; esac
    case "$op_command" in start|stop|restart) ;; *) printf null; return ;; esac
    case "$op_state" in running|succeeded|failed|unconfirmed) ;; *) printf null; return ;; esac
    if [ "$op_state" = running ]; then
        if [ "$CONTROL_NOW" -ge "$op_deadline" ]; then
            op_state=unconfirmed; op_reason=DEADLINE_EXCEEDED
        elif ! control_owner_read || [ "$lock_id" != "$op_id" ] || \
            { ! control_owner_alive && [ "$((CONTROL_NOW-op_started))" -ge 10 ]; }; then
            op_state=unconfirmed; op_reason=WORKER_NOT_RUNNING
        fi
    fi
    printf '{"id":"%s","command":"%s","state":"%s","reason":"%s","startedElapsed":%s,"deadlineElapsed":%s}' \
        "$op_id" "$op_command" "$op_state" "$op_reason" "$op_started" "$op_deadline"
}
control_owned() {
    control_private_file "$CONTROL_ROOT/owned" || return 1
    read -r owned_schema owned_boot owned_pid owned_token owned_dev owned_ino owned_extra <"$CONTROL_ROOT/owned"
    [ "$owned_schema" = 1 ] && [ "$owned_boot" = "$CONTROL_BOOT" ] && [ -z "$owned_extra" ] || return 1
    case "$owned_pid:$owned_token:$owned_dev:$owned_ino" in *[!0-9:]*|:*|*::*|*:) return 1 ;; esac
    registration_identity "$owned_pid" "$owned_token" || return 1
    [ "$(stat -Lc '%d:%i' "$PROC_ROOT/$owned_pid/exe" 2>/dev/null)" = "$owned_dev:$owned_ino" ] || return 1
    [ "$(stat -Lc '%d:%i' "$BIN" 2>/dev/null)" = "$owned_dev:$owned_ino" ]
}
