import os
import stat
import shutil
import subprocess
import lzma
import lzma
import os.path as op
import zipfile

def move(source, target):
    try:
        shutil.move(source, target)
        verbose_print(f"move {source} -> {target}")
    except:
        pass


def copy(source, target):
    try:
        shutil.copyfile(source, target)
        verbose_print(f"copy {source} -> {target}")
    except:
        pass


def remove(file):
    try:
        os.remove(file)
        verbose_print(f"remove {file}")
    except FileNotFoundError as e:
        pass


def remove_on_error(func, path, _):
    try:
        os.chmod(path, stat.S_IWRITE)
        os.unlink(path)
    except FileNotFoundError as e:
        pass


def remove_recursive(path):
    verbose_print(f"remove -r {path}")
    shutil.rmtree(path, ignore_errors=False, onerror=remove_on_error)


def make_directory(path, mode=0o755):
    try:
        os.mkdir(path, mode)
    except:
        pass


def make_directory_recursive(path, mode=0o755):
    os.makedirs(path, mode, exist_ok=True)


def execute_command(cmd, env=None):
    return subprocess.run(cmd, stdout=STDOUT, env=env)


def run_system_command(cmd):
    return subprocess.run(cmd, shell=True, stdout=STDOUT)


def command_output(cmd, env=None):
    return (
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        .stdout.strip()
        .decode("utf-8")
    )


def compress_xz(data):
    return lzma.compress(data, preset=9, check=lzma.CHECK_NONE)


def parse_properties(file):
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


def load_configuration(args):
    commit_hash = command_output(["git", "rev-parse", "--short=8", "HEAD"])

    # Default values
    config["version"] = commit_hash
    config["versionCode"] = 1000000
    config["outdir"] = "out"

    # Load property files
    if op.exists(args.config):
        config.update(parse_properties(args.config))

    if op.exists("gradle.properties"):
        for key, value in parse_properties("gradle.properties").items():
            if key.startswith("magisk."):
                config[key[7:]] = value

    try:
        config["versionCode"] = int(config["versionCode"])
    except ValueError:
        error('Configuration error: "versionCode" is required to be an integer')

    make_directory_recursive(config["outdir"])
    global STDOUT
    STDOUT = None if args.verbose else subprocess.DEVNULL


def clean_elf():
    if is_windows:
        elf_cleaner = op.join("tools", "elf-cleaner.exe")
    else:
        elf_cleaner = op.join("native", "out", "elf-cleaner")
        if not op.exists(elf_cleaner):
            execute_command(
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
    args = [elf_cleaner, "--api-level", "23"]
    args.extend(
        op.join("native", "out", arch, bin)
        for arch in archs
        for bin in ["magisk", "magiskpolicy"]
    )
    execute_command(args)

def execute_ndk_build(flags):
    os.chdir("native")
    flags = "NDK_PROJECT_PATH=. NDK_APPLICATION_MK=src/Application.mk " + flags
    proc = system(f"{ndk_build} {flags} -j{cpu_count}")
    if proc.returncode != 0:
        error("Build binary failed!")
    os.chdir("..")
    for arch in archs:
        for tgt in support_targets + ["libinit-ld.so"]:
            source = op.join("native", "libs", arch, tgt)
            target = op.join("native", "out", arch, tgt)
            mv(source, target)


def execute_cargo(cmds, triple="aarch64-linux-android"):
    env = os.environ.copy()
    env["PATH"] = f'{rust_bin}{os.pathsep}{env["PATH"]}'
    env["CARGO_BUILD_RUSTC"] = op.join(rust_bin, "rustc" + EXE_EXT)
    env["RUSTFLAGS"] = f"-Clinker-plugin-lto -Zthreads={min(8, cpu_count)}"
    env["TARGET_CC"] = op.join(llvm_bin, "clang" + EXE_EXT)
    env["TARGET_CFLAGS"] = f"--target={triple}23"
    return execv([cargo, *cmds], env)


def execute_cargo_build(args):
    native_out = op.join("..", "out")
    mkdir(native_out)

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
            proc = execute_cargo(cmds, triple)
            if proc.returncode != 0:
                error("Build binary failed!")

        arch_out = op.join(native_out, arch)
        mkdir(arch_out)
        for tgt in targets:
            source = op.join("target", rust_triple, rust_out, f"lib{tgt}.a")
            target = op.join(arch_out, f"lib{tgt}-rs.a")
            mv(source, target)


def execute_cargo_command(args):
    global STDOUT
    STDOUT = None
    if len(args.commands) >= 1 and args.commands[0] == "--":
        args.commands = args.commands[1:]
    os.chdir(op.join("native", "src"))
    execute_cargo(args.commands)
    os.chdir(op.join("..", ".."))


def write_if_different(file_name, text):
    do_write = True
    if op.exists(file_name):
        with open(file_name, "r") as f:
            orig = f.read()
        do_write = orig != text
    if do_write:
        with open(file_name, "w") as f:
            f.write(text)


def generate_binary_dump(src, var_name, compressor=zip):
    out_str = f"constexpr unsigned char {var_name}[] = {{"
    for i, c in enumerate(compressor(src.read())):
        if i % 16 == 0:
            out_str += "\n"
        out_str += f"0x{c:02X},"
    out_str += "\n};\n"
    return out_str


def dump_binary_header(args):
    mkdir_p(native_gen_path)
    for arch in archs:
        preload = op.join("native", "out", arch, "libinit-ld.so")
        with open(preload, "rb") as src:
            text = generate_binary_dump(src, "init_ld_xz")
        write_if_different(op.join(native_gen_path, f"{arch}_binaries.h"), text)


def dump_flag_header():
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

    mkdir_p(native_gen_path)
    write_if_different(op.join(native_gen_path, "flags.h"), flag_txt)


def build_binary(args):
    # Verify NDK install
    try:
        with open(op.join(ndk_path, "ONDK_VERSION"), "r") as ondk_ver:
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

    os.chdir(op.join("native", "src"))
    execute_cargo_build(args)
    os.chdir(op.join("..", ".."))

    dump_flag_header()

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
        execute_ndk_build(flag)

    # magiskinit embeds preload.so

    flag = ""

    if "magiskinit" in args.target:
        flag += " B_INIT=1"

    if flag:
        dump_binary_header(args)
        execute_ndk_build(flag)

    if clean:
        clean_elf()

    # BusyBox is built with different libc

    if "busybox" in args.target:
        execute_ndk_build("B_BB=1")
def find_jdk():
    env_var = os.environ.copy()
    if "ANDROID_STUDIO" in env_var:
        studio_path = env_var["ANDROID_STUDIO"]
        jbr_path = op.join(studio_path, "jbr", "bin")
        if not op.exists(jbr_path):
            jbr_path = op.join(studio_path, "Contents", "jbr", "Contents", "Home", "bin")
        if op.exists(jbr_path):
            env_var["PATH"] = f'{jbr_path}{os.pathsep}{env_var["PATH"]}'

    no_jdk = False
    try:
        proc = subprocess.run(
            "javac -version",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env_var,
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

    return env_var


def build_apk(args, module):
    env_var = find_jdk()

    build_type = "Release" if args.release else "Debug"
    proc = execv(
        [
            gradlew,
            f"{module}:assemble{build_type}",
            "-PconfigPath=" + op.abspath(args.config),
        ],
        env=env_var,
    )
    if proc.returncode != 0:
        error(f"Build {module} failed!")

    build_type = build_type.lower()

    apk = f"{module}-{build_type}.apk"
    source = op.join(module, "build", "outputs", "apk", build_type, apk)
    target = op.join(config["outdir"], apk)
    mv(source, target)
    header("Output: " + target)


def build_app(args):
    header("* Building the Magisk app")
    build_apk(args, "app")

    # Stub building is directly integrated into the main app
    # build process. Copy the stub APK into output directory.
    build_type = "release" if args.release else "debug"
    apk = f"stub-{build_type}.apk"
    source = op.join("app", "src", build_type, "assets", "stub.apk")
    target = op.join(config["outdir"], apk)
    cp(source, target)


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
        rm_rf(op.join("native", "libs"))
        rm_rf(op.join("native", "obj"))
        rm_rf(op.join("native", "out"))

    if "rust" in args.target:
        header("* Cleaning Rust")
        rm_rf(op.join("native", "src", "target"))
        rm(op.join("native", "src", "boot", "proto", "mod.rs"))
        rm(op.join("native", "src", "boot", "proto", "update_metadata.rs"))
        for rs_gen in glob.glob("native/**/*-rs.*pp", recursive=True):
            rm(rs_gen)

    if "java" in args.target:
        header("* Cleaning java")
        execv([gradlew, "app:clean", "app:shared:clean", "stub:clean"], env=find_jdk())
        rm_rf(op.join("app", "src", "debug"))
        rm_rf(op.join("app", "src", "release"))


def setup_ndk(args):
    ndk_version = config["ondkVersion"]
    url = f"https://github.com/topjohnwu/ondk/releases/download/{ndk_version}/ondk-{ndk_version}-{os_name}.tar.xz"
    ndk_archive = url.split("/")[-1]
    ondk_path = op.join(ndk_root, f"ondk-{ndk_version}")

    header(f"* Downloading and extracting {ndk_archive}")
    rm_rf(ondk_path)
    with urllib.request.urlopen(url) as response:
        with tarfile.open(mode="r|xz", fileobj=response) as tar:
            tar.extractall(ndk_root)

    rm_rf(ndk_path)
    mv(ondk_path, ndk_path)

    header("* Patching static libs")
    for target in ["arm-linux-androideabi", "i686-linux-android"]:
        arch = target.split("-")[0]
        lib_dir = op.join(
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
        if not op.exists(lib_dir):
            continue
        src_dir = op.join("tools", "ndk-bins", arch)
        rm(op.join(src_dir, ".DS_Store"))
        shutil.copytree(src_dir, lib_dir, copy_function=cp, dirs_exist_ok=True)


def push_files(args, script):
    abi = cmd_out([adb_path, "shell", "getprop", "ro.product.cpu.abi"])
    apk = config["outdir"] + ("/app-release.apk" if args.release else "/app-debug.apk")

    # Extract busybox from APK
    busybox = f'{config["outdir"]}/busybox'
    with ZipFile(apk) as zf:
        with zf.open(f"lib/{abi}/libbusybox.so") as libbb:
            with open(busybox, "wb") as bb:
                bb.write(libbb.read())

    try:
        proc = execv([adb_path, "push", busybox, script, "/data/local/tmp"])
        if proc.returncode != 0:
            error("adb push failed!")
    finally:
        rm_rf(busybox)

    proc = execv([adb_path, "push", apk, "/data/local/tmp/magisk.apk"])
    if proc.returncode != 0:
        error("adb push failed!")
def initialize_avd(arguments):
    if not arguments.skip:
        build_all(arguments)

    header("* Setting up emulator")

    push_files(arguments, "scripts/avd_magisk.sh")

    process = execv([adb_path, "shell", "sh", "/data/local/tmp/avd_magisk.sh"])
    if process.returncode != 0:
        error("avd_magisk.sh failed!")


def modify_avd_ramdisk(arguments):
    if not arguments.skip:
        arguments.release = False
        build_all(arguments)

    header("* Patching emulator ramdisk.img")

    # Create a backup to prevent accidental overwrites
    backup = arguments.ramdisk + ".bak"
    if not op.exists(backup):
        cp(arguments.ramdisk, backup)

    ini = op.join(op.dirname(arguments.ramdisk), "advancedFeatures.ini")
    with open(ini, "r") as file:
        adv_ft = file.read()

    # Need to turn off system as root
    if "SystemAsRoot = on" in adv_ft:
        # Create a backup
        cp(ini, ini + ".bak")
        adv_ft = adv_ft.replace("SystemAsRoot = on", "SystemAsRoot = off")
        with open(ini, "w") as file:
            file.write(adv_ft)

    push_files(arguments, "scripts/avd_patch.sh")

    process = execv([adb_path, "push", backup, "/data/local/tmp/ramdisk.cpio.tmp"])
    if process.returncode != 0:
        error("adb push failed!")

    process = execv([adb_path, "shell", "sh", "/data/local/tmp/avd_patch.sh"])
    if process.returncode != 0:
        error("avd_patch.sh failed!")

    process = execv([adb_path, "pull", "/data/local/tmp/ramdisk.cpio.gz", arguments.ramdisk])
    if process.returncode != 0:
        error("adb pull failed!")
def build_all(arguments):
    build_binary(arguments)
    build_application(arguments)


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
    help=f"{', '.join(support_targets)}, \
    or empty for defaults ({', '.join(default_targets)})",
)
binary_parser.set_defaults(function=build_binary)

cargo_parser = subparsers.add_parser("cargo", help="run cargo with proper environment")
cargo_parser.add_argument("commands", nargs=argparse.REMAINDER)
cargo_parser.set_defaults(function=run_cargo_command)

app_parser = subparsers.add_parser("app", help="build the Magisk app")
app_parser.set_defaults(function=build_application)

stub_parser = subparsers.add_parser("stub", help="build the stub app")
stub_parser.set_defaults(function=build_stub)

avd_parser = subparsers.add_parser("emulator", help="setup AVD for development")
avd_parser.add_argument(
    "-s", "--skip", action="store_true", help="skip building binaries and the app"
)
avd_parser.set_defaults(function=setup_avd)

avd_patch_parser = subparsers.add_parser("avd_patch", help="patch AVD ramdisk.img")
avd_patch_parser.add_argument("ramdisk", help="path to ramdisk.img")
avd_patch_parser.add_argument(
    "-s", "--skip", action="store_true", help="skip building binaries and the app"
)
avd_patch_parser.set_defaults(function=patch_avd_ramdisk)

clean_parser = subparsers.add_parser("clean", help="cleanup")
clean_parser.add_argument(
    "target", nargs="*", help="native, cpp, rust, java, or empty to clean all"
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
