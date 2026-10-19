#!/system/bin/sh
MODDIR=${0%/*}
LOGDIR=/data/adb/mosey-plk110-cn
umask 077
mkdir -p "$LOGDIR"
sh "$MODDIR/collect-device.sh" > "$LOGDIR/diagnostics.txt" 2>&1
echo "Diagnostics: $LOGDIR/diagnostics.txt"
echo '--- Reference launcher startup ---'
tail -n 12 "$LOGDIR/service.log" 2>/dev/null
echo 'Disabling/removing the module requires a reboot to clear managed mounts; late-loaded KernelSU must be activated again afterward.'
