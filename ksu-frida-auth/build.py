#!/usr/bin/env python3
"""Build the frida-auth KernelSU module.

Compiles the LD_PRELOAD shim for all Android ABIs with the NDK and packages
the module into dist/frida-auth-<version>.zip.
"""

import os
import platform
import re
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))

ABIS = {
    "arm64-v8a": "aarch64-linux-android21",
    "armeabi-v7a": "armv7a-linux-androideabi21",
    "x86_64": "x86_64-linux-android21",
    "x86": "i686-linux-android21",
}

HOST_BY_SYSTEM = {
    "Linux": "linux-x86_64",
    "Darwin": "darwin-x86_64",
    "Windows": "windows-x86_64",
}

EXEC_FILES = {"customize.sh", "service.sh", "uninstall.sh", "bin/frida-auth"}
SKIP_DIRS = {"src", "dist", "__pycache__", ".git"}


def find_ndk():
    for var in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        path = os.environ.get(var)
        if path and os.path.isdir(path):
            return path

    sdk = os.path.expanduser("~/Android/Sdk/ndk")
    if os.path.isdir(sdk):
        def key(name):
            return [int(part) for part in re.findall(r"\d+", name)]

        versions = sorted(os.listdir(sdk), key=key, reverse=True)
        for version in versions:
            candidate = os.path.join(sdk, version)
            if os.path.isdir(candidate):
                return candidate

    raise SystemExit("NDK not found. Set ANDROID_NDK_HOME or install under ~/Android/Sdk/ndk")


def build_shim(ndk):
    host = HOST_BY_SYSTEM.get(platform.system())
    if host is None:
        raise SystemExit("Unsupported host platform: %s" % platform.system())

    cc_dir = os.path.join(ndk, "toolchains", "llvm", "prebuilt", host, "bin")
    src = os.path.join(ROOT, "src", "frida_auth.c")
    if not os.path.isfile(src):
        raise SystemExit("missing source: %s" % src)

    built = []
    for abi, triple in ABIS.items():
        compiler = os.path.join(cc_dir, triple + "-clang")
        if not os.path.exists(compiler) and os.path.exists(compiler + ".cmd"):
            compiler += ".cmd"
        if not os.path.exists(compiler):
            print("skip %s: compiler not found (%s)" % (abi, compiler))
            continue

        out_dir = os.path.join(ROOT, "lib", abi)
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, "libfrida_auth.so")

        command = [
            compiler,
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-o",
            out,
            src,
            "-llog",
            "-ldl",
        ]
        print("[build] %s" % abi)
        subprocess.check_call(command)
        built.append(abi)

    if not built:
        raise SystemExit("no ABI was built")

    return built


def read_version():
    with open(os.path.join(ROOT, "module.prop"), "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("version="):
                return line.split("=", 1)[1].strip()
    return "0.0.0"


def add_file(archive, source, arcname, mode):
    info = zipfile.ZipInfo(arcname)
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    with open(source, "rb") as handle:
        archive.writestr(info, handle.read())


def package():
    version = read_version()
    dist = os.path.join(ROOT, "dist")
    os.makedirs(dist, exist_ok=True)
    output = os.path.join(dist, "frida-auth-%s.zip" % version)

    files = []
    for current, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            if name.endswith(".zip") or name.endswith(".pyc") or name == "build.py":
                continue
            path = os.path.join(current, name)
            arcname = os.path.relpath(path, ROOT).replace(os.sep, "/")
            files.append((path, arcname))

    files.sort(key=lambda item: item[1])

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, arcname in files:
            mode = 0o755 if arcname in EXEC_FILES else 0o644
            add_file(archive, path, arcname, mode)

    print("[zip] %s (%d files)" % (output, len(files)))
    return output


def main():
    ndk = find_ndk()
    print("[ndk] %s" % ndk)
    built = build_shim(ndk)
    print("[abi] %s" % ", ".join(built))
    package()


if __name__ == "__main__":
    main()
