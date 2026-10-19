#!/system/bin/sh
# Experimental variant: run the loading gate only, never start the donor daemon.
MODDIR=${0%/*}
exec sh "$MODDIR/load-probe.sh" service
