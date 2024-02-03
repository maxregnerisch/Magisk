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


def color_print(code, string):
    if no_color:
        print(string)
    else:
        string = string.replace("\n", f"\033[0m\n{code}")
        print(f"{code}{string}\033[0m")


def error(string):
    color_print("\033[41;39m", f"\n! {string}\n")
    sys.exit(1)


def header(string):
    color_print("\033[44;39m", f"\n{string}\n")


def vprint(string):
    if args.verbose:
        print(string)


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
ndk_build = op.join(ndk_path, "build")

# Other methods...

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Magisk build script")
    parser.set_defaults(function=lambda x: None)
    parser.add_argument(
        "-r", "--release", action="store_true", help="compile in release mode"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument(
        "-c",
        "--config",
        default="config.prop",
        help="custom config file (default: config.prop)",
    )
    subparsers = parser.add_subparsers(title="actions")

    all_parser = subparsers.add_parser("all", help="build everything")
    all_parser.set_defaults(function=build_all)

    binary_parser = subparsers.add_parser("binary", help="build binaries")
    binary_parser.add_argument(
        "target",
        nargs="*",
        help=f"{', '.join(support_targets)}, or empty for defaults ({', '.join(default_targets)})",
    )
    binary_parser.set_defaults(function=build_binary)

    cargo_parser = subparsers.add_parser(
        "cargo", help="run cargo with proper environment"
    )
    cargo_parser.add_argument("commands", nargs=argparse.REMAINDER)
    cargo_parser.set_defaults(function=run_cargo_command)

    app_parser = subparsers.add_parser("app", help="build the Magisk app")
    app_parser.set_defaults(function=build_application)

    stub_parser = subparsers.add_parser("stub", help="build the stub app")
    stub_parser.set_defaults(function=build_stub)

    avd_parser = subparsers.add_parser(
        "emulator", help="setup AVD for development"
    )
    avd_parser.add_argument(
        "-s", "--skip", action="store_true", help="skip building binaries and the app"
    )
    avd_parser.set_defaults(function=setup_avd)

    avd_patch_parser = subparsers.add_parser(
        "avd_patch", help="patch AVD ramdisk.img"
    )
    avd_patch_parser.add_argument("ramdisk", help="path to ramdisk.img")
    avd_patch_parser.add_argument(
        "-s", "--skip", action="store_true", help="skip building binaries and the app"
    )
    avd_patch_parser.set_defaults(function=patch_avd_ramdisk)

    clean_parser = subparsers.add_parser("clean", help="cleanup")
    clean_parser.add_argument(
        "target",
        nargs="*",
        help="native, cpp, rust, java, or empty to clean all",
    )
    clean_parser.set_defaults(function=cleanup)

    ndk_parser = subparsers.add_parser("ndk", help="setup Magisk NDK")
    ndk_parser.set_defaults(function=setup_ndk)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    arguments = parser.parse_args()
    load_config(arguments)

    # Call corresponding functions
    arguments.function(arguments)
