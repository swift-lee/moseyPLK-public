#!/system/bin/sh
# Reuse the reviewed v0.4.1 installation checks and six policy statements.
# shellcheck source=/dev/null
. "$MODPATH/customize-base.sh"
set_perm "$MODPATH/system/odm/bin/mosey_load_probe" 0 0 0755 u:object_r:mosey_server_exec:s0
set_perm "$MODPATH/system/odm/lib64/libmosey_load_probe.so" 0 0 0644 u:object_r:vendor_file:s0
set_perm "$MODPATH/load-probe.sh" 0 0 0755
case "$(ls -Z "$MODPATH/system/odm/bin/mosey_load_probe")" in
    *u:object_r:mosey_server_exec:s0*) ;;
    *) abort '! Could not apply the probe executable label.' ;;
esac
ui_print '- LOAD PROBE EXPERIMENT: service and Action run two finite diagnostic processes.'
ui_print '- This variant does not start Mosey or change Binder registration.'
ui_print '- Original donors and Fold6 launcher are preserved; two probe files are added.'
ui_print '- Results: /data/adb/mosey-plk110-cn/load-probe/'
