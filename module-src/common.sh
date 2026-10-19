#!/system/bin/sh
# Install-time checks only; not used by the runtime launcher. The caller sets MODDIR.
# shellcheck disable=SC2034
MOSEY_LOGDIR=/data/adb/mosey-plk110-cn

mosey_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*"
}

mosey_check_prop() {
    actual_prop=$(getprop "$1")
    if [ "$actual_prop" != "$2" ]; then
        mosey_log "MISMATCH property $1: expected=[$2] actual=[$actual_prop]"
        return 1
    fi
    mosey_log "OK property $1=[$actual_prop]"
}

mosey_check_target() {
    target_props_ok=true
    mosey_check_prop ro.product.model PLK110 || target_props_ok=false
    mosey_check_prop ro.build.version.sdk 36 || target_props_ok=false
    mosey_check_prop ro.product.cpu.abi arm64-v8a || target_props_ok=false
    # Firmware version is diagnostic; reviewed Mosey prerequisites are the gate.
    for prop in ro.build.version.incremental ro.build.display.id ro.build.display.id.show ro.build.version.ota; do
        mosey_log "INFO property $prop=[$(getprop "$prop")]"
    done
    [ "$target_props_ok" = true ] || return 1
    # shellcheck source=compatibility.sh
    . "$MODDIR/compatibility.sh"
    mosey_check_compatibility
}

mosey_check_payload() {
    (cd "$MODDIR" && sha256sum -c payload.sha256)
}

mosey_check_conflicts() {
    while read -r expected rel; do
        case "$rel" in system/*) dest="/${rel#system/}" ;; *) continue ;; esac
        # A clean first install adds missing files only. An active identical
        # version is accepted during an update; a differing file is a conflict.
        if [ -e "$dest" ] || [ -L "$dest" ]; then
            actual=$(sha256sum "$dest" 2>/dev/null)
            actual=${actual%% *}
            if [ "$actual" != "$expected" ]; then
                mosey_log "CONFLICT: $dest"
                return 1
            fi
        fi
    done < "$MODDIR/payload.sha256"
}
