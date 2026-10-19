#!/system/bin/sh
# Manager Action intentionally repeats the same finite loading experiment.
MODDIR=${0%/*}
exec sh "$MODDIR/load-probe.sh" action
