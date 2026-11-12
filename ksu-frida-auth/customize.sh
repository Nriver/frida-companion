#!/system/bin/sh

SKIPMOUNT=true
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=true

# Compatibility shims for managers that don't expose Magisk installer helpers.
command -v ui_print >/dev/null 2>&1 || ui_print() { echo "$1"; }
command -v set_perm >/dev/null 2>&1 || set_perm() {
    chown "$2:$3" "$1" 2>/dev/null
    chmod "$4" "$1" 2>/dev/null
}
command -v set_perm_recursive >/dev/null 2>&1 || set_perm_recursive() {
    chown -R "$2:$3" "$1" 2>/dev/null
    find "$1" -type d -exec chmod "$4" {} + 2>/dev/null
    find "$1" -type f -exec chmod "$5" {} + 2>/dev/null
}

ui_print "- Installing Frida Auth"

set_perm_recursive "$MODPATH/bin" 0 0 0755 0644
set_perm_recursive "$MODPATH/lib" 0 0 0755 0644
set_perm "$MODPATH/bin/frida-auth" 0 0 0755
set_perm "$MODPATH/customize.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755
set_perm "$MODPATH/module.prop" 0 0 0644
set_perm "$MODPATH/sepolicy.rule" 0 0 0644

# Persistent runtime data (survives module updates)
mkdir -p /data/adb/frida-auth 2>/dev/null
[ -f /data/adb/frida-auth/allow.list ] || : > /data/adb/frida-auth/allow.list
chmod 0600 /data/adb/frida-auth/allow.list 2>/dev/null

ui_print "- Open the module WebUI to choose authorized apps"
ui_print "- Remember to start frida-server from the WebUI (shim must be loaded)"
