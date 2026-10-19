#!/system/bin/sh
# A finite registration experiment; the external provider owns all mounts.
MODDIR=${0%/*}
LOGROOT=/data/adb/mosey-plk110-cn/registration-compat
PROC_ROOT=/proc
BIN=/odm/bin/mosey_server
# shellcheck disable=SC2034 # Used by the sourced read-only Binder checker.
SERVICE_NAME=com.google.android.moseyservice.IMoseyService/default
PATH=/system/bin:/system/xbin
LC_ALL=C
export PATH LC_ALL
unset LD_PRELOAD LD_LIBRARY_PATH MOSEY_REGISTRATION_COMPAT
umask 077
set -f
case "$1" in service|control) origin=$1 ;; *) echo 'Invalid registration origin'; exit 64 ;; esac
registration_budget_seconds=${2:-180}
case "$registration_budget_seconds" in ''|*[!0-9]*) exit 64 ;; esac
[ "$registration_budget_seconds" -ge 1 ] && [ "$registration_budget_seconds" -le 180 ] || exit 64
registration_started=$(awk '{print int($1)}' "$PROC_ROOT/uptime" 2>/dev/null)
case "$registration_started" in ''|*[!0-9]*) exit 1 ;; esac
registration_deadline=$((registration_started+registration_budget_seconds))
mkdir -p "$LOGROOT" || exit 1
boot_id=$(tr -cd 'a-zA-Z0-9-' <"$PROC_ROOT/sys/kernel/random/boot_id" 2>/dev/null)
[ -n "$boot_id" ] || boot_id=unknown
OUT=$(mktemp -d "$LOGROOT/$boot_id-$(date +%Y%m%dT%H%M%S)-$origin-XXXXXX") || exit 1
LOCK="$LOGROOT/lock-$boot_id"
lock_owned=0
# shellcheck disable=SC2329 # Invoked through the EXIT trap.
cleanup() {
    if [ "$lock_owned" = 1 ] && [ "$(cat "$LOCK/record" 2>/dev/null)" = "$OUT" ]; then
        rm -f "$LOCK/owner" "$LOCK/record"
        rmdir "$LOCK" 2>/dev/null
    fi
}
finish() {
    if [ -n "${owned_pid:-}" ]; then
        {
            printf 'OWNED_PID=%s\nOWNED_STARTTIME=%s\n' "$owned_pid" "$owned_token"
            printf 'CURRENT_STARTTIME=%s\n' "$(registration_token "$owned_pid")"
            readlink "$PROC_ROOT/$owned_pid/exe" "$PROC_ROOT/$owned_pid/ns/mnt" 2>/dev/null
            cat "$PROC_ROOT/$owned_pid/attr/current" "$PROC_ROOT/$owned_pid/status" 2>/dev/null
            grep -E 'libmosey_(registration_compat|daemon_ffi)\.so' "$PROC_ROOT/$owned_pid/maps" 2>/dev/null
        } >"$OUT/process.txt"
        if [ -f "$OUT/daemon.log" ]; then
            if registration_shim_success "$OUT/daemon.log" "$owned_pid"; then
                shim_state=SHIM_PLATFORM_REGISTRATION_OK
            else
                shim_state=$(registration_shim_failure "$OUT/daemon.log" "$owned_pid")
            fi
            printf 'SHIM_SNAPSHOT_STATE=%s\n' "$shim_state" >>"$OUT/context.txt"
        fi
    fi
    printf 'RESULT=%s\n' "$1" >"$OUT/result.txt"
    if [ -f "$MODDIR/event-log.sh" ]; then
        . "$MODDIR/event-log.sh"
        mosey_event startup "$1" || :
    fi
    printf 'RESULT=%s\nRecords: %s\n' "$1" "$OUT"
    exit "$2"
}
registration_budget() {
    budget_now=$(awk '{print int($1)}' "$PROC_ROOT/uptime" 2>/dev/null)
    case "$budget_now" in ''|*[!0-9]*) finish READINESS_CLOCK_UNAVAILABLE 1 ;; esac
    [ "$budget_now" -lt "$registration_deadline" ] || finish START_TIMEOUT 1
}
trap cleanup 0
trap 'finish INTERRUPTED 1' 1 2 15
# shellcheck source=/dev/null
. "$MODDIR/registration-checks.sh"
caller_context=$(tr -d '\000\n' <"$PROC_ROOT/self/attr/current" 2>/dev/null)
{
    date
    printf 'ORIGIN=%s\nBOOT_ID=%s\nCALLER_CONTEXT=%s\n' "$origin" "$boot_id" "$caller_context"
    id
    printf 'CALLER_MNT='; readlink "$PROC_ROOT/self/ns/mnt"
} >"$OUT/context.txt" 2>&1
[ "$(id -u)" = 0 ] || finish ROOT_REQUIRED 1
[ "$caller_context" = 'u:r:ksu:s0' ] || finish CALLER_CONTEXT_UNVERIFIED 1
command -v timeout >/dev/null 2>&1 || finish TIMEOUT_UNAVAILABLE 1
if [ "$origin" = control ]; then
    . "$MODDIR/control-common.sh"
    control_environment >/dev/null || finish CONTROL_CALLER_UNVERIFIED 1
    control_owner_read && control_owner_alive && [ "$lock_phase" = active ] \
        || finish CONTROL_LOCK_UNVERIFIED 1
else
    if ! mkdir "$LOCK" 2>/dev/null; then
        cat "$LOCK/owner" "$LOCK/record" >"$OUT/lock-owner.txt" 2>&1
        finish ATTEMPT_LOCKED 1
    fi
    lock_owned=1
    printf '%s\n' "$OUT" >"$LOCK/record"
    printf 'PID=%s\nSTARTTIME=%s\n' "$$" "$(registration_token "$$")" >"$LOCK/owner"
fi

# Check current, init, and the exact current system_server mount views. Do not
# try to move mounts between namespaces when late root only has a private view.
mounted_paths='odm/bin/mosey_server
odm/lib64/libmosey_daemon_ffi.so
odm/etc/init/mosey.rc
odm/etc/vintf/manifest/manifest_mosey.xml
system_ext/priv-app/MoseyApp/MoseyApp.apk
system_ext/etc/permissions/privapp-permissions-com.google.android.mosey.xml
system_ext/etc/default-permissions/default-permissions-com.google.android.mosey.xml
vendor/bin/mosey_launcher
odm/bin/mosey_load_probe
odm/lib64/libmosey_load_probe.so
odm/lib64/libmosey_registration_compat.so'
verify_mount_view() {
    view=$1
    if [ "$view" = self ]; then prefix=; else prefix="$PROC_ROOT/$view/root"; fi
    printf 'VIEW_PID=%s MNT=%s\n' "$view" "$(readlink "$PROC_ROOT/$view/ns/mnt" 2>/dev/null)" >>"$OUT/context.txt"
    for rel in $mounted_paths; do
        expected=$(awk -v path="system/$rel" '$2==path {n++; value=$1} END {if(n==1) print value}' "$MODDIR/payload.sha256")
        actual=$(sha256sum "$prefix/$rel" 2>/dev/null); actual=${actual%% *}
        printf 'VIEW=%s PATH=/%s EXPECTED=%s ACTUAL=%s\n' "$view" "$rel" "$expected" "$actual" >>"$OUT/mounts.txt"
        if [ "${#expected}" != 64 ] || [ "$actual" != "$expected" ]; then
            readiness_state=DEFERRED_MOUNT_HASH_MISMATCH; return 1
        fi
        case "$rel" in
            odm/bin/*) label=u:object_r:mosey_server_exec:s0 ;;
            odm/etc/*) label=u:object_r:vendor_configs_file:s0 ;;
            system_ext/*) label=u:object_r:system_file:s0 ;;
            *) label=u:object_r:vendor_file:s0 ;;
        esac
        case "$(ls -Z "$prefix/$rel" 2>/dev/null)" in
            *"$label"*) ;;
            *) readiness_state=DEFERRED_MOUNT_LABEL_MISMATCH; return 1 ;;
        esac
    done
}
# A hard-boot private root view needs the user's normal soft restart. Waiting
# for system_server cannot repair an init view that lacks these module files.
for view in self 1; do
    verify_mount_view "$view" || finish "$readiness_state" 1
done

# During a soft restart service.sh can precede the new system_server and a
# responsive servicemanager by several seconds. Wait only for readiness, never
# restart any process. Monotonic uptime bounds the wait; package and Binder
# queries are independently bounded.
ready_started=$(awk '{print int($1)}' "$PROC_ROOT/uptime" 2>/dev/null)
[ -n "$ready_started" ] || finish READINESS_CLOCK_UNAVAILABLE 1
ready_i=0
ready=0
while [ "$ready_i" -lt 60 ]; do
    registration_budget
    readiness_state=DEFERRED_SYSTEM_SERVER_UNAVAILABLE
    system_pids=$(pidof system_server 2>/dev/null)
    # shellcheck disable=SC2086
    set -- $system_pids
    if [ "$#" = 1 ]; then
        system_pid=$1
        system_token=$(registration_token "$system_pid")
        if [ -n "$system_token" ] && registration_alive "$system_pid" && verify_mount_view "$system_pid"; then
            timeout -k 1 8 dumpsys package com.google.android.mosey >"$OUT/package.txt" 2>&1
            package_rc=$?
            readiness_state=DEFERRED_PACKAGE_QUERY_FAILED
            if [ "$package_rc" = 0 ]; then
                readiness_state=DEFERRED_SYSTEM_APP_NOT_READY
                if registration_system_app "$OUT/package.txt"; then
                    readiness_state=DEFERRED_SYSTEM_SERVER_CHANGED
                    if [ "$(pidof system_server 2>/dev/null)" = "$system_pid" ] \
                        && [ "$(registration_token "$system_pid")" = "$system_token" ] \
                        && registration_alive "$system_pid"; then
                        readiness_state=DEFERRED_BINDER_QUERY_FAILED
                        # Reuse one bounded snapshot path across retries; the
                        # context log and READINESS_RETRIES preserve timing.
                        registration_binder readiness
                        readiness_binder_rc=$?
                        case "$readiness_binder_rc" in
                            0|1)
                                readiness_state=DEFERRED_SYSTEM_SERVER_CHANGED
                                if [ "$(pidof system_server 2>/dev/null)" = "$system_pid" ] \
                                    && [ "$(registration_token "$system_pid")" = "$system_token" ] \
                                    && registration_alive "$system_pid"; then
                                    ready=1
                                    break
                                fi
                                ;;
                        esac
                    fi
                fi
            fi
        fi
    fi
    ready_i=$((ready_i + 1))
    ready_now=$(awk '{print int($1)}' "$PROC_ROOT/uptime" 2>/dev/null)
    [ -n "$ready_now" ] || finish READINESS_CLOCK_UNAVAILABLE 1
    [ "$((ready_now - ready_started))" -lt 60 ] || break
    [ "$ready_i" -ge 60 ] || sleep 1
done
printf 'READINESS_RETRIES=%s\n' "$ready_i" >>"$OUT/context.txt"
[ "$ready" = 1 ] || finish "$readiness_state" 1

pids=$(pidof mosey_server 2>/dev/null)
if [ -n "$pids" ]; then
    printf 'EXISTING_PIDS=%s\n' "$pids" >>"$OUT/context.txt"
    registration_binder existing
    printf 'EXISTING_BINDER_CHECK_RC=%s\n' "$?" >>"$OUT/context.txt"
    finish EXISTING_PROCESS_NOT_STARTED 1
fi
registration_binder before
binder_before=$?
case "$binder_before" in
    0) finish EXISTING_BINDER_NOT_STARTED 1 ;;
    1) ;;
    *) finish BINDER_QUERY_FAILED 1 ;;
esac

# A successful record from an earlier boot or caller is never accepted here.
registration_budget
sh "$MODDIR/load-probe.sh" service >"$OUT/loading-gate.txt" 2>&1
gate_rc=$?
printf 'LOADING_GATE_RC=%s\n' "$gate_rc" >>"$OUT/context.txt"
[ "$gate_rc" = 0 ] || finish LOADING_GATE_FAILED 1
awk -F= 'BEGIN {want[1]="BASELINE_IDENTITY_OK"; want[2]="PRELOAD_OK"; want[3]="PROBE_PRELOAD_CONFIRMED"}
    $1=="RESULT" {n++; if(NF!=2 || $2!=want[n]) bad=1} END {exit !(n==3 && !bad)}' \
    "$OUT/loading-gate.txt" || finish LOADING_GATE_UNVERIFIED 1
if [ "$(pidof system_server 2>/dev/null)" != "$system_pid" ] \
    || [ "$(registration_token "$system_pid")" != "$system_token" ] \
    || ! registration_alive "$system_pid"; then finish DEFERRED_SYSTEM_SERVER_CHANGED 1; fi
[ -z "$(pidof mosey_server 2>/dev/null)" ] || finish EXISTING_PROCESS_NOT_STARTED 1
registration_binder ready
case "$?" in 0) finish EXISTING_BINDER_NOT_STARTED 1 ;; 1) ;; *) finish BINDER_QUERY_FAILED 1 ;; esac
if [ "$(pidof system_server 2>/dev/null)" != "$system_pid" ] \
    || [ "$(registration_token "$system_pid")" != "$system_token" ] \
    || ! registration_alive "$system_pid"; then finish DEFERRED_SYSTEM_SERVER_CHANGED 1; fi

registration_budget

# Give the donor, its pipe consumer and wait-status supervisor their own
# session before launch. Neither UI closure nor the start budget owns them.
setsid sh "$MODDIR/donor-supervisor.sh" "$OUT" </dev/null >/dev/null 2>&1 &
printf 'SUPERVISOR_PID=%s\n' "$!" >>"$OUT/context.txt"

# At most 15 observation rounds; each service-list call is independently bounded.
i=0
while [ "$i" -lt 15 ]; do
    registration_budget
    if [ -r "$OUT/child.txt" ]; then
        read -r owned_pid owned_token extra <"$OUT/child.txt"
        [ -z "$extra" ] || finish CHILD_RECORD_INVALID 1
        case "$owned_pid:$owned_token" in
            *[!0-9:]*|:*|*:) finish CHILD_RECORD_INVALID 1 ;;
        esac
        if ! registration_alive "$owned_pid"; then
            # The supervisor may still be writing its wait status; do not infer
            # a Binder error code from a Unix exit status.
            [ -r "$OUT/daemon-exit.txt" ] || sleep 1
            finish DONOR_PROCESS_EXITED 1
        fi
        [ "$(registration_token "$owned_pid")" = "$owned_token" ] || finish OWNED_PROCESS_CHANGED 1
        if [ "$(readlink "$PROC_ROOT/$owned_pid/exe" 2>/dev/null)" = "$BIN" ]; then
            if ! registration_identity "$owned_pid" "$owned_token"; then
                # Identity is not verified, so do not signal a PID based only
                # on its name or starttime. Preserve the evidence for inspection.
                finish DONOR_IDENTITY_FAILED 1
            fi
            # Only a freshly launched, fully verified instance becomes owned.
            # This also records an unregistered donor so an explicit stop can
            # target it later. No pre-existing process is adopted.
            if [ -f "$MODDIR/control-common.sh" ]; then
                CONTROL_ROOT=/data/adb/mosey-plk110-cn/control
                if [ ! -L "$CONTROL_ROOT" ] && [ -d "$CONTROL_ROOT" ] \
                    && [ "$(stat -c '%u:%a' "$CONTROL_ROOT" 2>/dev/null)" = 0:700 ]; then
                    [ ! -L "$CONTROL_ROOT/owned" ] || finish OWNERSHIP_WRITE_FAILED 1
                    if [ -e "$CONTROL_ROOT/owned" ]; then
                        [ -f "$CONTROL_ROOT/owned" ] && [ "$(stat -c '%u:%a' "$CONTROL_ROOT/owned" 2>/dev/null)" = 0:600 ] \
                            || finish OWNERSHIP_WRITE_FAILED 1
                    fi
                    owned_identity=$(stat -Lc '%d %i' "$PROC_ROOT/$owned_pid/exe" 2>/dev/null)
                    owned_tmp=$(mktemp "$CONTROL_ROOT/.owned.XXXXXX") || finish OWNERSHIP_WRITE_FAILED 1
                    if ! { printf '1 %s %s %s %s\n' "$boot_id" "$owned_pid" "$owned_token" "$owned_identity" >"$owned_tmp" \
                        && chmod 0600 "$owned_tmp" && mv -f "$owned_tmp" "$CONTROL_ROOT/owned"; }; then
                        rm -f "$owned_tmp"
                        finish OWNERSHIP_WRITE_FAILED 1
                    fi
                fi
            fi
            if registration_shim_success "$OUT/daemon.log" "$owned_pid"; then
                registration_binder "after-$i"
                case "$?" in
                    0)
                        sleep 2
                        registration_identity "$owned_pid" "$owned_token" || finish OWNED_PROCESS_CHANGED 1
                        registration_binder confirmed
                        case "$?" in 0) ;; 1) finish BINDER_DISAPPEARED 1 ;; *) finish BINDER_QUERY_FAILED 1 ;; esac
                        registration_identity "$owned_pid" "$owned_token" || finish OWNED_PROCESS_CHANGED 1
                        registration_shim_success "$OUT/daemon.log" "$owned_pid" || finish SHIM_REGISTRATION_UNCONFIRMED 1
                        printf 'OWNED_PID=%s\nOWNED_STARTTIME=%s\n' "$owned_pid" "$owned_token" >>"$OUT/context.txt"
                        finish SHIM_REGISTERED_PROCESS_RUNNING 0 ;;
                    1) ;;
                    *) finish BINDER_QUERY_FAILED 1 ;;
                esac
            fi
        fi
    fi
    i=$((i + 1))
    [ "$i" -ge 15 ] || sleep 1
done
if [ -z "${owned_pid:-}" ]; then finish CHILD_RECORD_MISSING 1; fi
registration_alive "$owned_pid" || finish DONOR_PROCESS_EXITED 1
finish "$(registration_shim_failure "$OUT/daemon.log" "$owned_pid")" 1
