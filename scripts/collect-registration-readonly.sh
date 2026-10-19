#!/system/bin/sh
# Read already-created records over an authorized root shell; stdout only.
# Do not use Action or the registration entrypoint as a read-only collector.
date
id
cat /proc/sys/kernel/random/boot_id /proc/uptime
getprop ro.build.display.id
printf '\nNATIVE_MODULES\n'
for module_root in /data/adb/modules /data/adb/modules_update; do
    for module_id in moseyPLK.service mosey-plk110-cn; do
        module_path="$module_root/$module_id"
        [ -f "$module_path/module.prop" ] || continue
        printf '\nMODULE_PATH=%s\n' "$module_path"
        cat "$module_path/module.prop"
    done
done
printf '\nCURRENT_PROCESSES\n'
# shellcheck disable=SC2009
ps -AZ | grep -E 'mosey|servicemanager|system_server|lspd'
printf '\nPASSIVE_BINDER_LIST\n'
timeout -k 1 5 service list | grep -E '^Found |mosey'
printf '\nCURRENT_PACKAGE\n'
timeout -k 1 8 dumpsys package com.google.android.mosey | grep -E 'codePath=|versionName=|flags=\[|privateFlags=|disabledComponents:|ExternalSharingService'
printf '\nREGISTRATION_RECORDS\n'
for directory in /data/adb/mosey-plk110-cn/registration-compat/*; do
    [ -d "$directory" ] || continue
    printf '\nRECORD=%s\n' "$directory"
    for name in result.txt context.txt child.txt daemon-exit.txt owner record; do
        [ -f "$directory/$name" ] || continue
        printf 'FILE=%s\n' "$name"
        cat "$directory/$name"
    done
    if [ -f "$directory/daemon.log" ]; then
        printf 'DAEMON_LOG_TAIL\n'
        tail -n 100 "$directory/daemon.log"
    fi
done
printf '\nCURRENT_DONOR_IDENTITY\n'
for pid in $(pidof mosey_server 2>/dev/null); do
    printf 'PID=%s\n' "$pid"
    cat "/proc/$pid/stat" "/proc/$pid/attr/current"
    readlink "/proc/$pid/exe" "/proc/$pid/ns/mnt"
    grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Amb)):' "/proc/$pid/status"
    grep -E 'mosey|libbinder' "/proc/$pid/maps"
done
printf '\nDECLARATION_QUERY\n'
# Exact transaction verified from this libbinder binary. Never guess after OTA.
binder_hash=$(sha256sum /system/lib64/libbinder.so)
binder_hash=${binder_hash%% *}
if [ "$binder_hash" = 297aad352eee9b522677e0568ca1ab69d67e8baba4c34a9c329fc7064cfae5a6 ]; then
    timeout -k 1 5 service call manager 9 s16 com.google.android.moseyservice.IMoseyService/default
else
    printf 'SKIPPED: libbinder changed; re-verify read-only transaction ABI.\n'
fi
printf '\nEND_READ_ONLY_COLLECTION\n'
