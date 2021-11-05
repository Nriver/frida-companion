# frida-companion
User-friendly frida automation

# Feature

1. Check frida update on startup.

2. Automatically detect device type and download the corresponding frida-server. Then try to push and run on your device.

# Install

1. install python dependencies

```
pip3 install -r requirements.txt
```

2. install other tools
depends on your system
```
sudo pacman -S xz
```

xz: for decompress frida executables from github

3. modify `settings.py`

# How to use
run `main.py` (for now).
