# frida-companion

!!! Project is still under development, not production ready, yet 😄 !!!

User-friendly frida automation platform. Made with 😍 and ✌️.

# Feature

1. Check frida update on startup.

2. Automatically detect device type and download the corresponding frida-server. Then try to push and run on your
   device. Support multiple device types.

# Install

1. install python dependencies

```
pip3 install -r requirements.txt
```

2. install other tools depends on your system

```
sudo pacman -S xz
```

xz: for decompress frida executables from github

3. modify `settings.py`

# How to use

(for now)
check device is working
```python test.py```
start server
```python main.py```
