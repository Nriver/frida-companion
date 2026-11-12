#!/system/bin/sh

# Stop any running frida-server and remove runtime state.
# The module directory itself is removed by KernelSU.
for p in $(ps -A -o PID,ARGS 2>/dev/null | grep '[f]rida-server' | awk '{print $1}'); do
    kill -9 "$p" 2>/dev/null
done
for p in $(ps -A -o PID,ARGS 2>/dev/null | grep '[l]ogcat -b crash -B' | awk '{print $1}'); do
    kill -9 "$p" 2>/dev/null
done

rm -rf /data/adb/frida-auth
