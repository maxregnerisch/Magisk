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
    # Removing a read-only file on Windows will get "WindowsError: [Error 5] Access is denied"
    # Clear the "read-only" bit and retry
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



import lzma
import subprocess
import os
import shutil

def compress_data(data):
    return lzma.compress(data, preset=9, check=lzma.CHECK_NONE)

def parse_props(file):
    props = {}
    with open(file, "r") as f:
        for line in [l.strip() for l in f]:
            if line.startswith("#") or len(line) == 0:
                continue
            prop = line.split("=")
            if len(prop) != 2:
                continue
            value = prop[1].strip()
            if len(value) == 0:
                continue
            props[prop[0].strip()] = value
    return props

def load_config(args):
    commit_hash = subprocess.check_output(["git", "rev-parse", "--short=8", "HEAD"]).decode().strip()

    # Default values
    config = {}
    config["version"] = commit_hash
    config["versionCode"] = 1000000
    config["outdir"] = "out"

    # Load prop files
    if os.path.exists(args.config):
        config.update(parse_props(args.config))

    if os.path.exists("gradle.properties"):
        for key, value in parse_props("gradle.properties").items():
            if key.startswith("magisk."):
                config[key[7:]] = value

    try:
        config["versionCode"] = int(config["versionCode"])
    except ValueError:
        raise ValueError('Config error: "versionCode" is required to be an integer')

    os.makedirs(config["outdir"], exist_ok=True)
    global STDOUT
    STDOUT = None if args.verbose else subprocess.DEVNULL

def clean_elf():
    is_windows = os.name == "nt"
    if is_windows:
        elf_cleaner = os.path.join("tools", "elf-cleaner.exe")
    else:
        elf_cleaner = os.path.join("native", "out", "elf-cleaner")
        if not os.path.exists(elf_cleaner):
            subprocess.run([
                "gcc",
                '-DPACKAGE_NAME="termux-elf-cleaner"',
                '-DPACKAGE_VERSION="2.1.1"',
                '-DCOPYRIGHT="Copyright (C) 2022 Termux."',
                "tools/termux-elf-cleaner/elf-cleaner.cpp",
                "tools/termux-elf-cleaner/arghandling.c",
                "-o",
                elf_cleaner,
            ])
    args = [elf_cleaner, "--api-level", "23"]
    args.extend(
        os.path.join("native", "out", arch, bin)
        for arch in archs
        for bin in ["magisk", "magiskpolicy"]
    )
    subprocess.run(args)

def run_ndk_build(flags):
    os.chdir("native")
    flags = f'NDK_PROJECT_PATH=. NDK_APPLICATION_MK=src/Application.mk {flags}'
    proc = subprocess.run(f"{ndk_build} {flags} -j{cpu_count}", shell=True)
    if proc.returncode != 0:
        raise Exception("Build binary failed!")
    os.chdir("..")
    for arch in archs:
        for tgt in support_targets + ["libinit-ld.so"]:
            source = os.path.join("native", "libs", arch, tgt)
            target = os.path.join("native", "out", arch, tgt)
            shutil.move(source, target)

def run_cargo(cmds, triple="aarch64-linux-android"):
    env = os.environ.copy()
    rust_bin = "/path/to/rust/bin"  # Replace with the actual path to the Rust bin directory
    llvm_bin = "/path/to/llvm/bin"  # Replace with the actual path to the LLVM bin directory
    cargo = os.path.join(rust_bin, "cargo")
    env["PATH"] = f'{rust_bin}{os.pathsep}{env["PATH"]}'
    env["CARGO_BUILD_RUSTC"] = os.path.join(rust_bin, "rustc")
    env["RUSTFLAGS"] = f"-Clinker-plugin-lto -Zthreads={min(8, cpu_count)}"
    env["TARGET_CC"] = os.path.join(llvm_bin, "clang")
    env["TARGET_CFLAGS"] = f"--target={triple}23"
    return subprocess.run([cargo, *cmds], env=env)

def run_cargo_build(args):
    native_out = os.path.join("..", "out")
    os.makedirs(native_out, exist_ok=True)

    targets = set(args.target) & set(rust_targets)
    if "resetprop" in args.target:
        targets.add("magisk")

    if len(targets) == 0:
        return

    # Start building the actual build commands
    cmds = ["build", "-p", ""]
    rust_out = "debug"
    if args.release:
        cmds.append("-r")
        rust_out = "release"
    if not args.verbose:
        cmds.append("-q")

    cmds.append("--target")
    cmds.append("")

    for arch, triple in zip(archs, triples):
        rust_triple = (
            "thumbv7neon-linux-androideabi" if triple.startswith("armv7") else triple
        )
        cmds[-1] = rust_triple

        for target in targets:
            cmds[2] = target
            proc = run_cargo(cmds, triple)
            if proc.returncode != 0:
                raise Exception("Build binary failed!")

        arch_out = os.path.join(native_out, arch)
        os.makedirs(arch_out, exist_ok=True)
        for tgt in targets:
            source = os.path.join("target", rust_triple, rust_out, f"lib{tgt}.a")
            target = os.path.join(arch_out, f"lib{tgt}-rs.a")
            shutil.move(source, target)
import os
import subprocess
import textwrap
import shutil

def run_cargo_cmd(args):
    global STDOUT
    STDOUT = None
    if len(args.commands) >= 1 and args.commands[0] == "--":
        args.commands = args.commands[1:]
    os.chdir(os.path.join("native", "src"))
    run_cargo(args.commands)
    os.chdir(os.path.join("..", ".."))

def write_if_diff(file_name, text):
    do_write = True
    if os.path.exists(file_name):
        with open(file_name, "r") as f:
            orig = f.read()
        do_write = orig != text
    if do_write:
        with open(file_name, "w") as f:
            f.write(text)

def binary_dump(src, var_name, compressor=xz):
    out_str = f"constexpr unsigned char {var_name}[] = {{"
    for i, c in enumerate(compressor(src.read())):
        if i % 16 == 0:
            out_str += "\n"
        out_str += f"0x{c:02X},"
    out_str += "\n}};\n"
    return out_str

def dump_bin_header(args):
    native_gen_path = "native_gen"
    os.makedirs(native_gen_path, exist_ok=True)
    for arch in archs:
        preload = os.path.join("native", "out", arch, "libinit-ld.so")
        with open(preload, "rb") as src:
            text = binary_dump(src, "init_ld_xz")
        write_if_diff(os.path.join(native_gen_path, f"{arch}_binaries.h"), text)

def dump_flag_header(config, args):
    native_gen_path = "native_gen"
    flag_txt = textwrap.dedent(
        """\
        #pragma once
        #define quote(s)            #s
        #define str(s)              quote(s)
        #define MAGISK_FULL_VER     MAGISK_VERSION "(" str(MAGISK_VER_CODE) ")"
        #define NAME_WITH_VER(name) str(name) " " MAGISK_FULL_VER
        """
    )
    flag_txt += f'#define MAGISK_VERSION      "{config["version"]}"\n'
    flag_txt += f'#define MAGISK_VER_CODE     {config["versionCode"]}\n'
    flag_txt += f"#define MAGISK_DEBUG        {0 if args.release else 1}\n"

    os.makedirs(native_gen_path, exist_ok=True)
    write_if_diff(os.path.join(native_gen_path, "flags.h"), flag_txt)

def build_binary(args):
    # Verify NDK install
    try:
        with open(os.path.join(ndk_path, "ONDK_VERSION"), "r") as ondk_ver:
            assert ondk_ver.read().strip(" \t\r\n") == config["ondkVersion"]
    except:
        error('Unmatched NDK. Please install/upgrade NDK with "build.py ndk"')

    if "target" not in vars(args):
        vars(args)["target"] = []

    if args.target:
        args.target = set(args.target) & set(support_targets)
        if not args.target:
            return
    else:
        args.target = default_targets

    header("* Building binaries: " + " ".join(args.target))

    os.chdir(os.path.join("native", "src"))
    run_cargo_build(args)
    os.chdir(os.path.join("..", ".."))

    dump_flag_header(config, args)

    flag = ""
    clean = False

    if "magisk" in args.target:
        flag += " B_MAGISK=1"
        clean = True

    if "magiskpolicy" in args.target:
        flag += " B_POLICY=1"
        clean = True

    if "test" in args.target:
        flag += " B_TEST=1"

    if "magiskinit" in args.target:
        flag += " B_PRELOAD=1"

    if "resetprop" in args.target:
        flag += " B_PROP=1"

    if "magiskboot" in args.target:
        flag += " B_BOOT=1"

    if flag:
        run_ndk_build(flag)

    # magiskinit embeds preload.so

    flag = ""

    if "magiskinit" in args.target:
        flag += " B_INIT=1"

    if flag:
        dump_bin_header(args)
        run_ndk_build(flag)

    if clean:
        clean_elf()

    # BusyBox is built with different libc

    if "busybox" in args.target:
        run_ndk_build("B_BB=1")


def find_jdk():
    env = os.environ.copy()
    if "ANDROID_STUDIO" in env:
        studio = env["ANDROID_STUDIO"]
        jbr = os.path.join(studio, "jbr", "bin")
        if not os.path.exists(jbr):
            jbr = os.path.join(studio, "Contents", "jbr", "Contents", "Home", "bin")
        if os.path.exists(jbr):
            env["PATH"] = f'{jbr}{os.pathsep}{env["PATH"]}'

    no_jdk = False
    try:
        proc = subprocess.run(
            "javac -version",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            shell=True,
        )
        no_jdk = proc.returncode != 0
    except FileNotFoundError:
        no_jdk = True

    if no_jdk:
        error(
            "Please set Android Studio's path to environment variable ANDROID_STUDIO,\n"
            + "or install JDK 17 and make sure 'javac' is available in PATH"
        )

    return env
import subprocess
import os
import shutil
import urllib.request
import tarfile
from zipfile import ZipFile
import glob

def build_apk(args, module):
    env = find_jdk()

    build_type = "Release" if args.release else "Debug"
    proc = subprocess.run(
        [
            "gradlew",
            f"{module}:assemble{build_type}",
            "-PconfigPath=" + os.path.abspath(args.config),
        ],
        env=env,
        capture_output=True,
    )
    if proc.returncode != 0:
        error(f"Build {module} failed!")

    build_type = build_type.lower()

    apk = f"{module}-{build_type}.apk"
    source = os.path.join(module, "build", "outputs", "apk", build_type, apk)
    target = os.path.join(config["outdir"], apk)
    shutil.move(source, target)
    header("Output: " + target)


def build_app(args):
    header("* Building the Magisk app")
    build_apk(args, "app")

    # Stub building is directly integrated into the main app
    # build process. Copy the stub APK into output directory.
    build_type = "release" if args.release else "debug"
    apk = f"stub-{build_type}.apk"
    source = os.path.join("app", "src", build_type, "assets", "stub.apk")
    target = os.path.join(config["outdir"], apk)
    shutil.copy(source, target)


def build_stub(args):
    header("* Building the stub app")
    build_apk(args, "stub")


def cleanup(args):
    support_targets = {"native", "cpp", "rust", "java"}
    if args.target:
        args.target = set(args.target) & support_targets
        if "native" in args.target:
            args.target.add("cpp")
            args.target.add("rust")
    else:
        args.target = support_targets

    if "cpp" in args.target:
        header("* Cleaning C++")
        shutil.rmtree(os.path.join("native", "libs"))
        shutil.rmtree(os.path.join("native", "obj"))
        shutil.rmtree(os.path.join("native", "out"))

    if "rust" in args.target:
        header("* Cleaning Rust")
        shutil.rmtree(os.path.join("native", "src", "target"))
        os.remove(os.path.join("native", "src", "boot", "proto", "mod.rs"))
        os.remove(os.path.join("native", "src", "boot", "proto", "update_metadata.rs"))
        for rs_gen in glob.glob("native/**/*-rs.*pp", recursive=True):
            os.remove(rs_gen)

    if "java" in args.target:
        header("* Cleaning java")
        subprocess.run([gradlew, "app:clean", "app:shared:clean", "stub:clean"], env=find_jdk())
        shutil.rmtree(os.path.join("app", "src", "debug"))
        shutil.rmtree(os.path.join("app", "src", "release"))


def setup_ndk(args):
    ndk_ver = config["ondkVersion"]
    url = f"https://github.com/topjohnwu/ondk/releases/download/{ndk_ver}/ondk-{ndk_ver}-{os_name}.tar.xz"
    ndk_archive = url.split("/")[-1]
    ondk_path = os.path.join(ndk_root, f"ondk-{ndk_ver}")

    header(f"* Downloading and extracting {ndk_archive}")
    shutil.rmtree(ondk_path)
    with urllib.request.urlopen(url) as response:
        with tarfile.open(mode="r|xz", fileobj=response) as tar:
            tar.extractall(ndk_root)

    shutil.rmtree(ndk_path)
    shutil.move(ondk_path, ndk_path)

    header("* Patching static libs")
    for target in ["arm-linux-androideabi", "i686-linux-android"]:
        arch = target.split("-")[0]
        lib_dir = os.path.join(
            ndk_path,
            "toolchains",
            "llvm",
            "prebuilt",
            f"{os_name}-x86_64",
            "sysroot",
            "usr",
            "lib",
            f"{target}",
            "23",
        )
        if not os.path.exists(lib_dir):
            continue
        src_dir = os.path.join("tools", "ndk-bins", arch)
        os.remove(os.path.join(src_dir, ".DS_Store"))
        shutil.copytree(src_dir, lib_dir, copy_function=shutil.copy, dirs_exist_ok=True)


def push_files(args, script):
    abi = subprocess.check_output([adb_path, "shell", "getprop", "ro.product.cpu.abi"]).decode().strip()
    apk = config["outdir"] + ("/app-release.apk" if args.release else "/app-debug.apk")

    # Extract busybox from APK
    busybox = f'{config["outdir"]}/busybox'
    with ZipFile(apk) as zf:
        with zf.open(f"lib/{abi}/libbusybox.so") as libbb:
            with open(busybox, "wb") as bb:
                bb.write(libbb.read())

    try:
        subprocess.run([adb_path, "push", busybox, script, "/data/local/tmp"], check=True)
    finally:
        os.remove(busybox)

    subprocess.run([adb_path, "push", apk, "/data/local/tmp/magisk.apk"], check=True)
import subprocess
import os.path as op
import shutil

def setup_avd(args):
    if not args.skip:
        build_all(args)

    header("* Setting up emulator")

    push_files(args, "scripts/avd_magisk.sh")

    proc = subprocess.run([adb_path, "shell", "sh", "/data/local/tmp/avd_magisk.sh"])
    if proc.returncode != 0:
        error("avd_magisk.sh failed!")


def patch_avd_ramdisk(args):
    if not args.skip:
        args.release = False
        build_all(args)

    header("* Patching emulator ramdisk.img")

    # Create a backup to prevent accidental overwrites
    backup = args.ramdisk + ".bak"
    if not op.exists(backup):
        shutil.copy(args.ramdisk, backup)

    ini = op.join(op.dirname(args.ramdisk), "advancedFeatures.ini")
    with open(ini, "r") as f:
        adv_ft = f.read()

    # Need to turn off system as root
    if "SystemAsRoot = on" in adv_ft:
        # Create a backup
        shutil.copy2(ini, ini + ".bak")
        adv_ft = adv_ft.replace("SystemAsRoot = on", "SystemAsRoot = off")
        with open(ini, "w") as f:
            f.write(adv_ft)

    push_files(args, "scripts/avd_patch.sh")

    proc = subprocess.run([adb_path, "push", backup, "/data/local/tmp/ramdisk.cpio.tmp"])
    if proc.returncode != 0:
        error("adb push failed!")

    proc = subprocess.run([adb_path, "shell", "sh", "/data/local/tmp/avd_patch.sh"])
    if proc.returncode != 0:
        error("avd_patch.sh failed!")

    proc = subprocess.run([adb_path, "pull", "/data/local/tmp/ramdisk.cpio.gz", args.ramdisk])
    if proc.returncode != 0:
        error("adb pull failed!")
import argparse
import sys

def build_all(args):
    build_binary(args)
    build_app(args)

def build_binary(args):
    # code to build binaries

def build_app(args):
    # code to build the Magisk app

def run_cargo_cmd(args):
    # code to run cargo with proper environment

def build_stub(args):
    # code to build the stub app

def setup_avd(args):
    # code to setup AVD for development

def patch_avd_ramdisk(args):
    # code to patch AVD ramdisk.img

def cleanup(args):
    # code to cleanup

def setup_ndk(args):
    # code to setup Magisk NDK

def load_config(args):
    # code to load config

# Create the parser
parser = argparse.ArgumentParser(description="Magisk build script")

# Set default function
parser.set_defaults(func=lambda x: None)

# Add arguments
parser.add_argument("-r", "--release", action="store_true", help="compile in release mode")
parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
parser.add_argument("-c", "--config", default="config.prop", help="custom config file (default: config.prop)")

# Create subparsers
subparsers = parser.add_subparsers(title="actions")

# Create parser for "all" action
all_parser = subparsers.add_parser("all", help="build everything")
all_parser.set_defaults(func=build_all)

# Create parser for "binary" action
binary_parser = subparsers.add_parser("binary", help="build binaries")
binary_parser.add_argument("target", nargs="*", help="targets")
binary_parser.set_defaults(func=build_binary)

# Create parser for "cargo" action
cargo_parser = subparsers.add_parser("cargo", help="run cargo with proper environment")
cargo_parser.add_argument("commands", nargs=argparse.REMAINDER)
cargo_parser.set_defaults(func=run_cargo_cmd)

# Create parser for "app" action
app_parser = subparsers.add_parser("app", help="build the Magisk app")
app_parser.set_defaults(func=build_app)

# Create parser for "stub" action
stub_parser = subparsers.add_parser("stub", help="build the stub app")
stub_parser.set_defaults(func=build_stub)

# Create parser for "emulator" action
avd_parser = subparsers.add_parser("emulator", help="setup AVD for development")
avd_parser.add_argument("-s", "--skip", action="store_true", help="skip building binaries and the app")
avd_parser.set_defaults(func=setup_avd)

# Create parser for "avd_patch" action
avd_patch_parser = subparsers.add_parser("avd_patch", help="patch AVD ramdisk.img")
avd_patch_parser.add_argument("ramdisk", help="path to ramdisk.img")
avd_patch_parser.add_argument("-s", "--skip", action="store_true", help="skip building binaries and the app")
avd_patch_parser.set_defaults(func=patch_avd_ramdisk)

# Create parser for "clean" action
clean_parser = subparsers.add_parser("clean", help="cleanup")
clean_parser.add_argument("target", nargs="*", help="targets")
clean_parser.set_defaults(func=cleanup)

# Create parser for "ndk" action
ndk_parser = subparsers.add_parser("ndk", help="setup Magisk NDK")
ndk_parser.set_defaults(func=setup_ndk)

# Parse the arguments
args = parser.parse_args()

# Load the config
load_config(args)

# Call the corresponding function
args.func(args)
