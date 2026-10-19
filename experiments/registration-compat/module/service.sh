#!/system/bin/sh
# Boot registration owns the shared control lock, but uses the readiness-aware
# service path directly. An early Binder status timeout must not skip startup.
MODDIR=${0%/*}
PATH=/system/bin:/system/xbin
LC_ALL=C
export PATH LC_ALL
unset LD_PRELOAD LD_LIBRARY_PATH MOSEY_REGISTRATION_COMPAT
umask 077
set -f
setsid sh "$MODDIR/status-monitor.sh" </dev/null >/dev/null 2>&1 &
. "$MODDIR/control-common.sh"
boot_fail() {
    mosey_event startup "$1"
    printf 'RESULT=%s\n' "$1"
    exit 1
}
control_environment >/dev/null || boot_fail BOOT_CONTROL_ENVIRONMENT_UNAVAILABLE
control_prepare || boot_fail PRIVATE_STATE_UNAVAILABLE
boot_token=$(registration_token "$$")
case "$boot_token" in ''|*[!0-9]*) boot_fail CALLER_LIFETIME_UNAVAILABLE ;; esac
OP_ID="$CONTROL_BOOT-$CONTROL_NOW-$$-$boot_token"
control_lock || boot_fail OPERATION_BUSY_OR_UNTRUSTED_LOCK
trap control_unlock 0
trap 'exit 1' 1 2 15
control_write_owner active || boot_fail STATE_WRITE_FAILED
sh "$MODDIR/registration-compat.sh" service 180
exit $?
