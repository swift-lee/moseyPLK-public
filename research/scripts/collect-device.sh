#!/system/bin/sh
# Read-only diagnostics. Run on the phone as root; redirect stdout to a file.
# Does not start services, change properties, grant permissions, or install anything.
echo '=== identity ==='
id
date
uname -a
getenforce
for prop in ro.product.model ro.product.device ro.build.version.incremental ro.build.version.sdk ro.build.version.security_patch ro.boot.verifiedbootstate init.svc.mosey_server; do
    echo "$prop=$(getprop "$prop")"
done
echo '=== packages ==='
for pkg in com.google.android.mosey com.google.android.gms com.android.vending; do
    pm path "$pkg"
    dumpsys package "$pkg" | grep -E 'versionCode=|versionName=|codePath=|pkgFlags=|privateFlags=|enabled=|mosey|ACCESS_NEARBY_SHARE_API|granted='
done
echo '=== interfaces and kernel modules ==='
ls -ld /sys/class/ieee80211/* /sys/class/net/* 2>/dev/null
cat /sys/module/wonder/parameters/physical_name 2>/dev/null
cat /proc/modules | grep -E 'wonder|cnss|qca_cld3|mac80211|cfg80211'
ip -details link show
if command -v iw >/dev/null 2>&1; then iw dev; iw phy; fi
echo '=== declared files and labels ==='
ls -lZ /odm/bin/mosey_server /odm/lib64/libmosey_daemon_ffi.so /odm/etc/init/mosey.rc /odm/etc/vintf/manifest/manifest_mosey.xml /system_ext/priv-app/MoseyApp/MoseyApp.apk 2>/dev/null
cat /odm/etc/init/mosey.rc /odm/etc/vintf/manifest/manifest_mosey.xml 2>/dev/null
echo '=== registered services and process identity ==='
service list | grep -i mosey
ps -AZ | grep -i mosey
for pid in $(pidof mosey_server 2>/dev/null); do
    cat "/proc/$pid/attr/current"
    grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapAmb):' "/proc/$pid/status"
done
echo '=== target policy hashes ==='
sha256sum /vendor/etc/selinux/vendor_sepolicy.cil /vendor/etc/selinux/vendor_file_contexts /vendor/etc/selinux/vendor_service_contexts /system_ext/etc/selinux/system_ext_sepolicy.cil /system_ext/etc/selinux/system_ext_seapp_contexts 2>/dev/null
echo '=== application configuration ==='
grep -n 'mosey' /my_product/etc/config/app_v2.xml /my_stock/etc/config/app_v2.xml /system_ext/etc/sysconfig/hidden-api-whitelist-ext.xml 2>/dev/null
echo '=== relevant recent kernel messages ==='
dmesg 2>/dev/null | grep -iE 'wonder|mosey|avc:.*(mosey|wonder)' | tail -100
