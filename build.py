import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
import urllib.request
from zipfile import ZipFile
import glob
import lzma

def binary_dump(src, var_name, compressor=lzma):
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


parser = argparse.ArgumentParser(description="Magisk build script")
parser.set_defaults(func=lambda x: None)
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
all_parser.set_defaults(func=build_all)

binary_parser = subparsers.add_parser("binary", help="build binaries")
binary_parser.add_argument(
    "target",
    nargs="*",
    help=f"{', '.join(support_targets)}, \
    or empty for defaults ({', '.join(default_targets)})",
)
binary_parser.set_defaults(func=build_binary)

cargo_parser = subparsers.add_parser("cargo", help="run cargo with proper environment")
cargo_parser.add_argument("commands", nargs=argparse.REMAINDER)
cargo_parser.set_defaults(func=run_cargo_cmd)

app_parser = subparsers.add_parser("app", help="build the Magisk app")
app_parser.set_defaults(func=build_app)

stub_parser = subparsers.add_parser("stub", help="build the stub app")
stub_parser.set_defaults(func=build_stub)

avd_parser = subparsers.add_parser("emulator", help="setup AVD for development")
avd_parser.add_argument(
    "-s", "--skip", action="store_true", help="skip building binaries and the app"
)
avd_parser.set_defaults(func=setup_avd)

avd_patch_parser = subparsers.add_parser("avd_patch", help="patch AVD ramdisk.img")
avd_patch_parser.add_argument("ramdisk", help="path to ramdisk.img")
avd_patch_parser.add_argument(
    "-s", "--skip", action="store_true", help="skip building binaries and the app"
)
avd_patch_parser.set_defaults(func=patch_avd_ramdisk)

clean_parser = subparsers.add_parser("clean", help="cleanup")
clean_parser.add_argument(
    "target", nargs="*", help="native, cpp, rust, java, or empty to clean all"
)
clean_parser.set_defaults(func=cleanup)

ndk_parser = subparsers.add_parser("ndk", help="setup Magisk NDK")
ndk_parser.set_defaults(func=setup_ndk)

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
load_config(args)

# Call corresponding functions
args.func(args)
