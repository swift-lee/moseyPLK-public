#!/system/bin/sh
# Stream over an already-authorized root shell. No phone-side output files.
# Do not run module Action/service.sh to perform a read-only check.
date
printf '\nBOOT\n'
cat /proc/sys/kernel/random/boot_id /proc/uptime
printf '\nVERSIONS\n'
getprop ro.build.display.id
getprop ro.build.version.sdk
for module_root in /data/adb/modules /data/adb/modules_update; do
    for module_id in moseyPLK.service mosey-plk110-cn; do
        module_path="$module_root/$module_id"
        [ -f "$module_path/module.prop" ] || continue
        printf '\nMODULE_PATH=%s\n' "$module_path"
        cat "$module_path/module.prop"
    done
done
printf '\nPROCESSES\n'
# Preserve SELinux contexts and full process columns.
# shellcheck disable=SC2009
ps -AZ | grep -E 'mosey|servicemanager|system_server|lspd'
printf '\nBINDER_LIST (does not start services)\n'
timeout 5 service list | grep -E '^Found |mosey'
printf '\nINIT_STATE\n'
getprop init.svc.mosey_server
printf '\nPACKAGE\n'
timeout 10 dumpsys package com.google.android.mosey | grep -E 'codePath=|versionName=|flags=\[|privateFlags=\['
printf '\nRULE_SYNTAX (parse only)\n'
for module_root in /data/adb/modules /data/adb/modules_update; do
    for module_id in moseyPLK.service mosey-plk110-cn; do
        module_path="$module_root/$module_id"
        [ -f "$module_path/sepolicy.rule" ] || continue
        printf '\nMODULE_PATH=%s\n' "$module_path"
        /data/adb/ksud sepolicy check "$module_path/sepolicy.rule"
        printf 'rule_check_rc=%s\n' "$?"
    done
done
printf '\nMOUNT_VIEWS\n'
for pid in 1 $(pidof servicemanager system_server mosey_server 2>/dev/null); do
    printf '\nPID=%s\n' "$pid"
    cat "/proc/$pid/stat" "/proc/$pid/attr/current"
    readlink "/proc/$pid/ns/mnt" "/proc/$pid/exe"
    grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Amb)):' "/proc/$pid/status"
    grep -E ' /odm(/| )| /system_ext(/| )| /vendor/bin(/| )' "/proc/$pid/mountinfo"
    for path in \
        /odm/bin/mosey_server /odm/lib64/libmosey_daemon_ffi.so \
        /odm/etc/init/mosey.rc /odm/etc/vintf/manifest/manifest_mosey.xml \
        /system_ext/etc/permissions/privapp-permissions-com.google.android.mosey.xml \
        /system_ext/etc/default-permissions/default-permissions-com.google.android.mosey.xml \
        /system_ext/priv-app/MoseyApp/MoseyApp.apk /vendor/bin/mosey_launcher; do
        ls -lZ "/proc/$pid/root$path"
        sha256sum "/proc/$pid/root$path"
    done
done
printf '\nRECENT_STARTUP_INDEX (historical lines require matching boot ID)\n'
tail -n 50 /data/adb/mosey-plk110-cn/service.log
printf '\nRECENT_CRASHES (may include older attempts)\n'
logcat -b crash -d -t 200 | grep -E 'mosey|Timestamp:|Abort message|SIGABRT'
printf '\nKERNEL_REJECTIONS (may include earlier attempts)\n'
dmesg | grep -E 'mosey|VINTF' | tail -n 80
printf '\nDeclaration recognition is NOT established by file visibility or service list.\n'
