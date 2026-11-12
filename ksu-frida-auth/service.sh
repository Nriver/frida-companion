#!/system/bin/sh

MODDIR=${0%/*}
DATA=/data/adb/frida-auth

(
    i=0
    while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ "$i" -lt 150 ]; do
        sleep 2
        i=$((i + 1))
    done

    [ -x "$MODDIR/bin/frida-auth" ] || exit 0

    "$MODDIR/bin/frida-auth" ensure
    "$MODDIR/bin/frida-auth" resolve

    if [ "$(cat "$DATA/autostart" 2>/dev/null)" = "1" ]; then
        "$MODDIR/bin/frida-auth" start
    fi
) &

exit 0
