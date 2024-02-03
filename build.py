#!/usr/bin/env python3
import argparse
import glob
import lzma
import multiprocessing
import os
import os.path as op
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import textwrap
import urllib.request
from zipfile import ZipFile

def color_print(code, str):
    if no_color:
        print(str)
    else:
        str = str.replace("\n", f"\033[0m\n{code}")
        print(f"{code}{str}\033[0m")

def error(str):
    color_print("\033[41;39m", f"\n! {str}\n")
    sys.exit(1)

def header(str):
    color_print("\033[44;39m", f"\n{str}\n")

def vprint(str):
    if args.verbose:
        print(str)

is_windows = os.name == "nt"
EXE_EXT = ".exe" if is_windows else ""

no_color = False
if is_windows:
    try:
        import colorama
        colorama.init()
    except ImportError:
        # We can't do ANSI color codes in terminal on Windows without colorama
        no_color = True

# Environment checks
if not sys.version_info >= (3, 8):
    error("Requires Python 3.8+")

if "ANDROID_SDK_ROOT" not in os.environ:
    error("Please set Android SDK path to environment variable ANDROID_SDK_ROOT!")

if shutil.which("sccache") is not None:
    os.environ["RUSTC_WRAPPER"] = "sccache"
    os.environ["NDK_CCACHE"] = "sccache"
    os.environ["CARGO_INCREMENTAL"] = "0"
if shutil.which("ccache") is not None:
    os.environ["NDK_CCACHE"] = "ccache"

cpu_count = multiprocessing.cpu_count()
os_name = platform.system().lower()

archs = ["armeabi-v7a", "x86", "arm64-v8a", "x86_64"]
triples = [
    "armv7a-linux-androideabi",
    "i686-linux-android",
    "aarch64-linux-android",
    "x86_64-linux-android",
]
default_targets = ["magisk", "magiskinit", "magiskboot", "magiskpolicy", "busybox"]
support_targets = default_targets + ["resetprop"]
rust_targets = ["magisk", "magiskinit", "magiskboot", "magiskpolicy"]

sdk_path = os.environ["ANDROID_SDK_ROOT"]
ndk_root = op.join(sdk_path, "ndk")
ndk_path = op.join(ndk_root, "magisk")
ndk_build = op.join(ndk_path, "ndk-build")
rust_bin = op.join(ndk_path, "toolchains", "rust", "bin")
llvm_bin = op.join(
    ndk_path, "toolchains", "llvm", "prebuilt", f"{os_name}-x86_64", "bin"
)
cargo = op.join(rust_bin, "cargo" + EXE_EXT)
gradlew = op.join(".", "gradlew" + (".bat" if is_windows else ""))
adb_path = op.join(sdk_path, "platform-tools", "adb" + EXE_EXT)
native_gen_path = op.realpath(op.join("native", "out", "generated"))

# Global vars
config = {}
STDOUT = None
build_tools = None

def mv(source, target):
    try:
        shutil.move(source, target)
        vprint(f"mv {source} -> {target}")
    except:
        pass

def cp(source, target):
    try:
        shutil.copyfile(source, target)
        vprint(f"cp {source} -> {target}")
    except:
        pass

def rm(file):
    try:
        os.remove(file)
        vprint(f"rm {file}")
    except FileNotFoundError as e:
        pass

def rm_on_error(func, path, _):
    try:
        os.chmod(path, stat.S_IWRITE)
        os.unlink(path)
    except FileNotFoundError as e:
        pass

def rm_rf(path):
    vprint(f"rm -rf {path}")
    shutil.rmtree(path, ignore_errors=False, onerror=rm_on_error)

def mkdir(path, mode=0o755):
    try:
        os.mkdir(path, mode)
    except:
        pass

def mkdir_p(path, mode=0o755):
    os.makedirs(path, mode, exist_ok=True)

def execv(cmd, env=None):
    return subprocess.run(cmd, stdout=STDOUT, env=env)

def system(cmd):
    return subprocess.run(cmd, shell=True, stdout=STDOUT)

def cmd_out(cmd, env=None):
    return (
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        .stdout.strip()
        .decode("utf-8")
    )

def xz(data):
    return lzma.compress(data, preset=9, check=lzma.CHECK_NONE)

def parse_props(file):
    props = {}
    with open(file, "r") as f:
        for line in [l.strip(" \t\r\n") for l in f]:
            if line.startswith("#") or len(line) == 0:
                continue
            prop = line.split("=")
            if len(prop) != 2:
                continue
            value = prop[1].strip(" \t\r\n")
            if len(value) == 0:
                continue
            props[prop[0].strip(" \t\r\n")] = value
    return props

def load_config(args):
    commit_hash = cmd_out(["git", "rev-parse", "--short=8", "HEAD"])

    # Default values
    config["version"] = commit_hash
    config["versionCode"] = 1000000
    config["outdir"] = "out"

    # Load prop files
    if op.exists(args.config):
        config.update(parse_props(args.config))

    if op.exists("gradle.properties"):
        for key, value in parse_props("gradle.properties").items():
            if key.startswith("magisk."):
                config[key[7:]] = value

    try:
        config["versionCode"] = int(config["versionCode"])
    except ValueError:
        error('Config error: "versionCode" is required to be an integer')

    mkdir_p(config["outdir"])
    global STDOUT
    STDOUT = None if args.verbose else subprocess.DEVNULL

def clean_elf():
    if is_windows:
        elf_cleaner = op.join("tools", "elf-cleaner.exe")
    else:
        elf_cleaner = op.join("native", "out", "elf-cleaner")
        if not op.exists(elf_cleaner):
            execv(
                [
                    "gcc",
                    '-DPACKAGE_NAME="termux-elf-cleaner"',
                    '-DPACKAGE_VERSION="2.1.1"',
                    '-DCOPYRIGHT="Copyright (C) 2022 Termux."',
                    "tools/termux-elf-cleaner/elf-cleaner.cpp",
                    "tools/termux-elf-cleaner/arghandling.c",
                    "-o",
                    elf_cleaner,
                ]
            )

    if not op.exists(elf_cleaner):
        error("Failed to build elf-cleaner!")

    vprint(f"Checking {native_gen_path}")
    for arch in archs:
        for file in glob.iglob(op.join(native_gen_path, arch, "*.so")):
            execv([elf_cleaner, file])

def ndk_build_jobs():
    if is_windows:
        # Windows doesn't like too many parallel processes
        return cpu_count // 2
    return cpu_count

def download(url, file):
    vprint(f"Downloading {url} -> {file}")
    urllib.request.urlretrieve(url, file)

def unzip(file, dest):
    with ZipFile(file, "r") as zip_ref:
        zip_ref.extractall(dest)

def download_and_extract(url, dest):
    zip_file = op.join(config["outdir"], op.basename(url))
    download(url, zip_file)
    unzip(zip_file, dest)

def download_android_tools():
    if not op.exists(gradlew):
        error("gradlew not found! Please make sure you have cloned the repository correctly.")
    
    header("Downloading Android tools")
    execv([gradlew, "dependencies"])

def check_android_sdk():
    if not op.exists(adb_path):
        error("adb not found! Please make sure you have Android SDK installed and added to your PATH.")
    
    if not os.environ.get("ANDROID_HOME"):
        error("ANDROID_HOME environment variable is not set. Please set it to your Android SDK path.")

def check_android_build_tools():
    try:
        build_tools = cmd_out([gradlew, "project-properties"]).splitlines()[-1]
        vprint(f"ANDROID_BUILD_TOOLS_VERSION: {build_tools}")
    except Exception as e:
        error("Failed to determine Android Build Tools version.")
    
    if not op.exists(op.join(
        sdk_path,
        "build-tools",
        build_tools,
        "zipalign" + EXE_EXT,
    )):
        header("Installing Android Build Tools")
        execv(
            [
                sdk_path,
                "tools/bin/sdkmanager" + EXE_EXT,
                f"build-tools;{build_tools}",
            ]
        )

def download_and_extract_ndk():
    header("Downloading NDK")
    if not op.exists(ndk_build):
        download_and_extract(
            f"https://dl.google.com/android/repository/android-ndk-{config['ndk_version']}-linux-{os_name}-x86_64.zip",
            ndk_path,
        )

def download_and_extract_rust():
    header("Downloading Rust")
    if not op.exists(cargo):
        download_and_extract(
            f"https://static.rust-lang.org/rustup/archive/1.21.1/{os_name}/rustup-init{EXE_EXT}",
            config["outdir"],
        )
        execv([config["outdir"] + "/rustup-init" + EXE_EXT, "-y", "--default-toolchain", "none"])
        execv([config["outdir"] + "/.cargo/bin/rustup" + EXE_EXT, "toolchain", "install", "nightly"])
        execv([cargo, "install", "cargo-audit"])

def build_magisk():
    header("Building Magisk")
    execv([cargo, "build", "--release"])

def build_magisk_init():
    header("Building MagiskInit")
    execv([cargo, "build", "--release", "--manifest-path", "magiskinit/Cargo.toml"])

def build_magisk_boot():
    header("Building MagiskBoot")
    execv([cargo, "build", "--release", "--manifest-path", "magiskboot/Cargo.toml"])

def build_magisk_policy():
    header("Building MagiskPolicy")
    execv([cargo, "build", "--release", "--manifest-path", "magiskpolicy/Cargo.toml"])

def build_busybox():
    header("Building Busybox")
    ndk_build_busybox = op.join(ndk_path, "ndk-build-busybox")
    execv(
        [
            "make",
            "CC=clang",
            "LDFLAGS=-static",
            "ARCH=arm",
            "CROSS_COMPILE=armv7a-linux-androideabi-",
            "-C",
            "busybox",
        ]
    )

def build_resetprop():
    header("Building Resetprop")
    execv(
        [
            ndk_build,
            "-C",
            "resetprop",
            "NDK_PROJECT_PATH=.",
            "NDK_APPLICATION_MK=Application.mk",
            f"-j{ndk_build_jobs()}",
            "APP_OPTIM=release",
            "APP_ABI=arm64-v8a",
        ]
    )

def create_flashable_zip():
    header("Creating Flashable ZIP")
    magisk_file = op.join(config["outdir"], "magisk", "release", "magisk.apk")
    magiskinit_file = op.join(config["outdir"], "magiskinit", "release", "magiskinit")
    magiskboot_file = op.join(config["outdir"], "magiskboot", "release", "magiskboot")
    magiskpolicy_file = op.join(config["outdir"], "magiskpolicy", "release", "magiskpolicy")
    busybox_file = op.join("busybox", "busybox")
    resetprop_file = op.join("resetprop", "libs", "arm64-v8a", "resetprop")

    zip_name = f"Magisk-v{config['version']}.zip"
    zip_path = op.join(config["outdir"], zip_name)

    with ZipFile(zip_path, "w") as zip_file:
        zip_file.write(magisk_file, "system/priv-app/MagiskManager/MagiskManager.apk")
        zip_file.write(magiskinit_file, "magiskinit")
        zip_file.write(magiskboot_file, "magiskboot")
        zip_file.write(magiskpolicy_file, "magiskpolicy")
        zip_file.write(busybox_file, "system/xbin/busybox")
        zip_file.write(resetprop_file, "system/xbin/resetprop")

    vprint(f"ZIP created: {zip_path}")

def main():
    parser = argparse.ArgumentParser(description="Build Magisk from source.")
    subparsers = parser.add_subparsers(help="Sub-commands")

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increase output verbosity"
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        default="magisk_build.config",
        help="Specify config file (default: magisk_build.config)",
    )

    download_parser = subparsers.add_parser(
        "download", help="Download necessary dependencies"
    )
    download_parser.set_defaults(func=download_android_tools)

    check_parser = subparsers.add_parser(
        "check", help="Check if required tools and dependencies are present"
    )
    check_parser.set_defaults(func=check_android_sdk)

    build_parser = subparsers.add_parser(
        "build", help="Build Magisk and related components"
    )
    build_parser.set_defaults(func=build_magisk)
    build_parser.set_defaults(func=build_magisk_init)
    build_parser.set_defaults(func=build_magisk_boot)
    build_parser.set_defaults(func=build_magisk_policy)
    build_parser.set_defaults(func=build_resetprop)
build_parser.set_defaults(func=build_resetprop)

clean_parser = subparsers.add_parser(
    "clean", help="Clean up build artifacts"
)
clean_parser.set_defaults(func=clean_elf)

args = parser.parse_args()
load_config(args)

if hasattr(args, "func"):
    args.func()
else:
    parser.print_help()
if name == "main":
main()
