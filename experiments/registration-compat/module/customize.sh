#!/system/bin/sh
# Install checks and labels apply only to the staged module directory.
# A renamed module is a separate installation, not an in-place update. Even
# disabled or pending-removal legacy modules must disappear after a reboot.
for legacy_module in /data/adb/modules/mosey-plk110-cn /data/adb/modules_update/mosey-plk110-cn; do
    if [ -e "$legacy_module" ] || [ -L "$legacy_module" ]; then
        abort '! Uninstall the old mosey-plk110-cn module and reboot before installing moseyPLK.service.'
    fi
done
# shellcheck source=/dev/null
. "$MODPATH/customize-base.sh"
set_perm "$MODPATH/system/odm/bin/mosey_load_probe" 0 0 0755 u:object_r:mosey_server_exec:s0
for library in libmosey_load_probe.so libmosey_registration_compat.so; do
    set_perm "$MODPATH/system/odm/lib64/$library" 0 0 0644 u:object_r:vendor_file:s0
done
for script in load-probe.sh registration-compat.sh registration-checks.sh status-monitor.sh status-checks.sh control.sh control-common.sh control-worker.sh donor-supervisor.sh event-log.sh collect-registration-readonly.sh; do
    set_perm "$MODPATH/$script" 0 0 0755
done
case "$(ls -Z "$MODPATH/system/odm/bin/mosey_load_probe")" in
    *u:object_r:mosey_server_exec:s0*) ;;
    *) abort '! Could not apply the probe executable label.' ;;
esac
set_perm "$MODPATH/mosey_service_control" 0 0 0755
ui_print '- Native service with explicit root-only control from moseyPLK Client.'
ui_print '- Requires system-visible mounts and the loading probe to pass first.'
ui_print '- The original donor files, Fold6 launcher and six policy rules are preserved.'
ui_print '- No client hook or sharing-component change is included.'
ui_print '- Manager description: passive Mosey status, sampled every 30 seconds. No Action button.'
ui_print '- Results: /data/adb/mosey-plk110-cn/registration-compat/'
