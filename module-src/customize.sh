#!/system/bin/sh
SKIPUNZIP=0
REPLACE=""
REMOVE=""
export SKIPUNZIP REPLACE REMOVE

[ "$BOOTMODE" = true ] || abort '! Install from the root manager in Android, not recovery.'
[ "$KSU" = true ] || abort '! This reference-launcher build requires KernelSU.'
MODDIR=$MODPATH
# shellcheck source=common.sh
. "$MODDIR/common.sh"

ui_print '- Target: OnePlus 15 PLK110 / Android 16 / reviewed Mosey prerequisites'
mosey_check_target || abort '! Target check failed. See MISMATCH or UNREADABLE lines above; save this install log.'
mosey_check_payload || abort '! Module payload checksum mismatch.'
mosey_check_conflicts || abort '! Conflicting Mosey installation. Remove it and reboot first.'
# Parse only; KernelSU is responsible for applying module rules at runtime.
[ -x /data/adb/ksud ] || abort '! Cannot locate ksud to validate module rule syntax.'
/data/adb/ksud sepolicy check "$MODDIR/sepolicy.rule" > "$MODDIR/policy-check.log" 2>&1
policy_check_rc=$?
cat "$MODDIR/policy-check.log"
[ "$policy_check_rc" -eq 0 ] || abort '! Module rule syntax rejected by ksud; policy was not applied by this check.'
ui_print '- Rule syntax accepted; effective domain transition still requires runtime verification.'
[ -d /odm ] && [ -d /system_ext ] || abort '! Missing ODM or system_ext partition.'
grep -q 'mosey_server_exec' /vendor/etc/selinux/vendor_file_contexts || abort '! Missing native file context.'
grep -q 'name=com.google.android.mosey' /system_ext/etc/selinux/system_ext_seapp_contexts || abort '! Missing application domain.'

# Labels on the module layer are inherited by the merged filesystem.
set_perm_recursive "$MODDIR" 0 0 0755 0644
set_perm_recursive "$MODDIR/system/odm" 0 0 0755 0644 u:object_r:vendor_file:s0
set_perm_recursive "$MODDIR/system/odm/etc" 0 0 0755 0644 u:object_r:vendor_configs_file:s0
set_perm "$MODDIR/system/odm/bin/mosey_server" 0 0 0755 u:object_r:mosey_server_exec:s0
set_perm_recursive "$MODDIR/system/system_ext" 0 0 0755 0644 u:object_r:system_file:s0
set_perm_recursive "$MODDIR/system/vendor" 0 0 0755 0644 u:object_r:vendor_file:s0
set_perm "$MODDIR/system/vendor/bin/mosey_launcher" 0 0 0755 u:object_r:vendor_file:s0
case "$(ls -Z "$MODDIR/system/odm/bin/mosey_server")" in
    *u:object_r:mosey_server_exec:s0*) ;;
    *) abort '! Could not apply the donor executable label.' ;;
esac
case "$(ls -Z "$MODDIR/system/system_ext/priv-app/MoseyApp/MoseyApp.apk")" in
    *u:object_r:system_file:s0*) ;;
    *) abort '! Could not apply the APK label.' ;;
esac
for script in common.sh compatibility.sh startup-checks.sh service.sh action.sh uninstall.sh collect-device.sh; do
    set_perm "$MODDIR/$script" 0 0 0755
done
# Standard module layout: mounting belongs to the installed mount provider.
rm -f "$MODDIR/skip_mount"
ui_print '- Standard system/odm and system/system_ext layout for the installed external mount provider.'
ui_print '- Seven OxygenOS files remain byte-identical to the donor.'
ui_print '- No donor APK/native/kernel/GMS patch; equivalent SELinux launcher transitions in KernelSU syntax included.'
ui_print '- Uses the original Z Fold6 launcher after KernelSU loads; no InjectRC or boot-stage marker.'
ui_print '- With GhostLock, activate KernelSU after boot, then verify module mounts and logs.'
ui_print '- Logs: /data/adb/mosey-plk110-cn/'
