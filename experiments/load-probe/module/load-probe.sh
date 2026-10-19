#!/system/bin/sh
# Only user-space diagnostics. External mount provider supplies every mount.
# Runs two short-lived probes through the original launcher; no donor/Binder calls.
MODDIR=${0%/*}
LOGROOT=/data/adb/mosey-plk110-cn/load-probe
PROBE=/odm/bin/mosey_load_probe
LIBRARY=/odm/lib64/libmosey_load_probe.so
LAUNCHER=/vendor/bin/mosey_launcher
PROC_ROOT=/proc
PATH=/system/bin:/system/xbin
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH
umask 077
set -f
case "$1" in service|action) origin=$1 ;; *) echo 'Invalid probe origin'; exit 64 ;; esac
mkdir -p "$LOGROOT" || exit 1
boot_id=$(tr -cd 'a-zA-Z0-9-' <"$PROC_ROOT/sys/kernel/random/boot_id" 2>/dev/null)
[ -n "$boot_id" ] || boot_id=unknown
OUT=$(mktemp -d "$LOGROOT/$boot_id-$(date +%Y%m%dT%H%M%S)-$origin-XXXXXX") || exit 1
caller_context=$(tr -d '\000\n' <"$PROC_ROOT/self/attr/current" 2>/dev/null)
finish() {
    printf 'RESULT=%s\n' "$1" >"$OUT/result.txt"
    printf 'RESULT=%s\nRecords: %s\n' "$1" "$OUT"
    exit "$2"
}
verified_probe() {
    # Require one complete, internally consistent result from probe main.
    awk -F= -v mode="$2" -v executable="$PROBE" '
        BEGIN {
            required["PROBE_SCHEMA"]="1"; required["MODE"]=mode
            required["EXE"]=executable; required["IDENTITY_OK"]="1"
            required["READ_ERROR_MASK"]="0"; required["EXIT_CODE"]="0"
            required["RESULT"]=(mode=="baseline" ? "BASELINE_IDENTITY_OK" : "PRELOAD_OK")
            if (mode=="preload") {
                required["MARKER_FOUND"]="1"; required["MARKER_ORIGIN_EXPECTED"]="1"
                required["MARKER_INITIALIZED"]="1"; required["LD_PRELOAD_EXPECTED"]="1"
            }
        }
        $1 in required { count[$1]++; if (NF!=2 || $2!=required[$1]) bad=1 }
        END {
            for (key in required) if (count[key]!=1) bad=1
            exit bad
        }' "$1"
}
{
    date
    printf 'ORIGIN=%s\nBOOT_ID=%s\n' "$origin" "$boot_id"
    id
    printf 'CALLER_CONTEXT=%s\n' "$caller_context"
    printf 'CALLER_MNT='; readlink "$PROC_ROOT/self/ns/mnt"
    cat "$PROC_ROOT/uptime"
    for p in 1 $(pidof servicemanager system_server 2>/dev/null); do
        echo "VIEW_PID=$p"
        cat "$PROC_ROOT/$p/stat" 2>/dev/null
        readlink "$PROC_ROOT/$p/ns/mnt" 2>/dev/null
        for f in "$PROBE" "$LIBRARY" "$LAUNCHER"; do
            ls -lZ "$PROC_ROOT/$p/root$f" 2>/dev/null
        done
    done
} >"$OUT/context.txt" 2>&1
[ "$(id -u)" = 0 ] || finish ROOT_REQUIRED 1
[ "$caller_context" = 'u:r:ksu:s0' ] || finish CALLER_CONTEXT_UNVERIFIED 1
command -v timeout >/dev/null 2>&1 || finish TIMEOUT_UNAVAILABLE 1

# Fixed payloads only; never use a module-directory executable fallback.
i=0
while [ "$i" -lt 60 ]; do
    [ -x "$PROBE" ] && [ -r "$LIBRARY" ] && [ -x "$LAUNCHER" ] && break
    sleep 1
    i=$((i + 1))
done
printf 'MOUNT_WAIT_SECONDS=%s\n' "$i" >>"$OUT/context.txt"
[ -x "$PROBE" ] && [ -r "$LIBRARY" ] && [ -x "$LAUNCHER" ] || finish FILES_NOT_READY 1
for f in "$PROBE" "$LIBRARY" "$LAUNCHER"; do
    expected=$(awk -v path="system$f" '$2==path {print $1}' "$MODDIR/payload.sha256")
    actual=$(sha256sum "$f" 2>/dev/null); actual=${actual%% *}
    printf 'PATH=%s EXPECTED=%s ACTUAL=%s\n' "$f" "$expected" "$actual" >>"$OUT/context.txt"
    [ "${#expected}" = 64 ] && [ "$expected" = "$actual" ] || finish PAYLOAD_MISMATCH 1
done
case "$(ls -Z "$PROBE")" in *u:object_r:mosey_server_exec:s0*) ;; *) finish PROBE_LABEL_MISMATCH 1 ;; esac
case "$(ls -Z "$LIBRARY")" in *u:object_r:vendor_file:s0*) ;; *) finish LIBRARY_LABEL_MISMATCH 1 ;; esac
case "$(ls -Z "$LAUNCHER")" in *u:object_r:vendor_file:s0*) ;; *) finish LAUNCHER_LABEL_MISMATCH 1 ;; esac

echo 'Running baseline identity probe (no Binder or network operations).'
# The enforcing donor domain may write a ksu pipe but not adb_data_file.
# Capture through that pipe; only the parent ksu shell writes the log file.
baseline_output=$(timeout -k 1 8 "$LAUNCHER" "$PROBE" baseline 2>&1)
baseline_rc=$?
printf '%s\n' "$baseline_output" >"$OUT/baseline.txt"
printf 'BASELINE_SHELL_RC=%s\n' "$baseline_rc" >>"$OUT/context.txt"
cat "$OUT/baseline.txt"
[ "$baseline_rc" = 0 ] || finish BASELINE_FAILED 1
verified_probe "$OUT/baseline.txt" baseline || finish BASELINE_UNVERIFIED 1

echo 'Running preload probe through the same original launcher.'
# Set LD_PRELOAD only after timeout/sh have started. The marker is also loaded
# by the launcher, so only the probe main's dlsym+dladdr result is accepted.
# shellcheck disable=SC2016 # Positional arguments belong to the child shell.
preload_output=$(timeout -k 1 8 sh -c 'LD_PRELOAD="$1"; export LD_PRELOAD; exec "$2" "$3" preload' \
    sh "$LIBRARY" "$LAUNCHER" "$PROBE" 2>&1)
preload_rc=$?
printf '%s\n' "$preload_output" >"$OUT/preload.txt"
printf 'PRELOAD_SHELL_RC=%s\n' "$preload_rc" >>"$OUT/context.txt"
cat "$OUT/preload.txt"
if [ "$preload_rc" = 0 ] && verified_probe "$OUT/preload.txt" preload; then
    finish PROBE_PRELOAD_CONFIRMED 0
fi
if [ "$preload_rc" = 11 ] && grep -qx 'RESULT=PRELOAD_NOT_LOADED' "$OUT/preload.txt" \
    && grep -qx 'AT_SECURE=1' "$OUT/preload.txt"; then
    finish PRELOAD_BLOCKED_AT_SECURE 1
fi
finish PRELOAD_UNCONFIRMED 1
