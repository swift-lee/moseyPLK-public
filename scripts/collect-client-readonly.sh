#!/system/bin/sh
# Stream via the existing authorized root shell; no staging or execution of apps.
date
id
cat /proc/sys/kernel/random/boot_id /proc/uptime
getprop ro.build.display.id
printf '\nCURRENT_USER\n'
timeout -k 1 5 am get-current-user
user_query_rc=$?
if [ "$user_query_rc" -ne 0 ]; then
    printf 'CURRENT_USER_QUERY_FAILED rc=%s\n' "$user_query_rc"
fi
printf '\nCURRENT_PROCESSES\n'
# shellcheck disable=SC2009
ps -AZ | grep -E 'mosey|com.google.android.gms|servicemanager|system_server|lspd'
printf '\nNATIVE_MODULE\n'
for module_root in /data/adb/modules /data/adb/modules_update; do
    for module_id in moseyPLK.service mosey-plk110-cn; do
        module_path="$module_root/$module_id"
        [ -f "$module_path/module.prop" ] || continue
        printf '\nMODULE_PATH=%s\n' "$module_path"
        cat "$module_path/module.prop"
    done
done
printf '\nPASSIVE_BINDER_LIST\n'
timeout -k 1 5 service list | grep -E '^Found |mosey'
printf '\nCLIENT_MODULE_PACKAGE_FULL\n'
timeout -k 1 8 dumpsys package moseyPLK.client
printf '\nLEGACY_CLIENT_MODULE_PACKAGE_FULL\n'
timeout -k 1 8 dumpsys package top.netkumiko.moseyclientcompat
printf '\nGMS_PACKAGE_FULL\n'
# Keep the active package separate from the hidden system APK and user states.
timeout -k 1 8 dumpsys package com.google.android.gms
printf '\nMOSEY_PACKAGE_FULL\n'
# Preserve active/hidden sections and User headings; do not conflate users.
timeout -k 1 8 dumpsys package com.google.android.mosey
printf '\nCLIENT_HOOK_LOG\n'
# A small ring buffer can lose attach-time events before this snapshot.
# Use collect-gms-startup-readonly.sh BEFORE a user-triggered process restart.
# -d reads existing records; never clears buffers or triggers the application.
timeout -k 1 8 logcat -d -b all -v threadtime -t 3000 'MoseyClientCompat:I' 'MoseyGmsDiag:I' '*:S'
printf '\nLOG_BUFFER_CAPACITY\n'
timeout -k 1 5 logcat -b main -g
capacity_query_rc=$?
if [ "$capacity_query_rc" -ne 0 ]; then
    printf 'MAIN_BUFFER_CAPACITY_FAILED rc=%s\n' "$capacity_query_rc"
fi
printf '\nNATIVE_IDENTITY\n'
for pid in $(pidof mosey_server 2>/dev/null); do
    printf 'PID=%s\n' "$pid"
    cat "/proc/$pid/stat" "/proc/$pid/attr/current"
    readlink "/proc/$pid/exe" "/proc/$pid/ns/mnt"
    grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Amb)):' "/proc/$pid/status"
    grep -E 'mosey|libbinder' "/proc/$pid/maps"
done
printf '\nEND_CLIENT_READ_ONLY\n'
