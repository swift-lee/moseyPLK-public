#!/system/bin/sh
# Passive native-service snapshots; no registration, app calls or log parsing.
# The caller supplies MODDIR, PROC_ROOT, BIN, SERVICE_NAME and KSUD.

mosey_status_sample() {
    status_pids=$(pidof mosey_server 2>/dev/null)
    status_pid_rc=$?
    case "$status_pid_rc:$status_pids" in
        1:) ;;
        0:*) [ -n "$status_pids" ] || { echo Unknown; return; } ;;
        *) echo Unknown; return ;;
    esac
    # Do not interpret a pidof failure, multiple PIDs or an unrelated executable
    # as a stopped/running donor. Disable glob expansion in the caller.
    # shellcheck disable=SC2086
    set -- $status_pids
    [ "$#" -le 1 ] || { echo Unknown; return; }
    status_pid=${1:-}
    if [ -n "$status_pid" ]; then
        case "$status_pid" in *[!0-9]*) echo Unknown; return ;; esac
        status_token=$(registration_token "$status_pid")
        case "$status_token" in ''|*[!0-9]*) echo Unknown; return ;; esac
        registration_identity "$status_pid" "$status_token" 2>/dev/null \
            || { echo Unknown; return; }
    fi
    # listServices is passive: it does not lazily start an absent service.
    if ! status_binder=$(timeout -k 1 "${STATUS_TIMEOUT:-5}" service list 2>/dev/null); then
        echo Unknown; return
    fi
    status_registration=$(printf '%s\n' "$status_binder" | awk -v name="$SERVICE_NAME:" '
        NR==1 {if($0 !~ /^Found [0-9]+ services:$/) bad=1; expected=$2; next}
        {if(NF!=3 || $1 !~ /^[0-9]+$/ || $1!=entries || $2 !~ /:$/ || $3 !~ /^\[[^][]*\]$/) bad=1; entries++}
        $2==name {count++; if($3=="[com.google.android.moseyservice.IMoseyService]") valid++}
        END {
            if(bad || entries!=expected) print "unknown"
            else if(!count) print "absent"
            else if(count==1 && valid==1) print "present"
            else print "unknown"
        }')
    status_after=$(pidof mosey_server 2>/dev/null)
    status_after_rc=$?
    if [ -z "$status_pid" ]; then
        if [ "$status_after_rc" = 1 ] && [ -z "$status_after" ] \
            && [ "$status_registration" = absent ]; then
            echo Stopped
        else
            echo Unknown
        fi
        return
    fi
    # Recheck the same process lifetime after the bounded Binder snapshot.
    if [ "$status_after_rc" != 0 ] || [ "$status_after" != "$status_pids" ] \
        || ! registration_identity "$status_pid" "$status_token" 2>/dev/null; then
        echo Unknown; return
    fi
    case "$status_registration" in
        present) echo Running ;;
        absent) echo Unregistered ;;
        *) echo Unknown ;;
    esac
}

mosey_status_owns() {
    [ -f "$MODDIR/module.prop" ] \
        && [ "$(cat "$MODDIR/.status-owner" 2>/dev/null)" = "$STATUS_OWNER" ] \
        && grep -qxF 'id=moseyPLK.service' "$MODDIR/module.prop"
}

mosey_status_publish() {
    case "$1" in Running|Stopped|Unregistered|Unknown) ;; *) return 1 ;; esac
    mosey_status_owns || return 1
    case "$1" in Running) status_emoji=🟢 ;; Stopped) status_emoji=🔴 ;; Unregistered) status_emoji=🟡 ;; Unknown) status_emoji=⚪ ;; esac
    status_description="[$status_emoji $1] Native Mosey service for PLK110."
    # Recent KernelSU keeps the override in boot-scoped temporary config. Older
    # managers read module.prop; update only its description, in the same dir.
    if KSU_MODULE=moseyPLK.service timeout -k 1 5 "$KSUD" module config set \
        --temp override.description "$status_description" >/dev/null 2>&1; then
        return 0
    fi
    grep -qxF "description=$status_description" "$MODDIR/module.prop" && return 0
    status_tmp=$(mktemp "$MODDIR/.status-prop.XXXXXX") || return 1
    if ! awk -v description="$status_description" '
        /^description=/ {print "description=" description; count++; next}
        {print}
        END {if(count!=1) exit 1}' "$MODDIR/module.prop" >"$status_tmp" \
        || ! chmod 0644 "$status_tmp" || ! mosey_status_owns \
        || ! mv -f "$status_tmp" "$MODDIR/module.prop"; then
        rm -f "$status_tmp"
        return 1
    fi
}
