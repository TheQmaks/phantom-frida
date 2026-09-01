#!/usr/bin/env python3
"""
Custom Frida Builder — build anti-detection Frida server from source.

Extended beyond ajeossida with additional stealth techniques.
Compatibility target: Frida 17.16.4.

Usage (run in WSL Ubuntu):
    python3 build.py --version 17.16.4
    python3 build.py --version 17.16.4 --name stealth --port 27142
    python3 build.py --version 17.16.4 --arch android-arm64,android-arm --extended
    python3 build.py --version 17.16.4 --skip-build  # only patch, don't compile

Requirements:
    - Ubuntu 22.04+ (WSL works)
    - Python 3.10+
    - Git
    - ~20GB free disk space
    - Internet connection (clones Frida + downloads NDK)
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from patches import (
    DETECTION_VECTORS,
    MEMFD_PATCHES,
    SELINUX_PATCHES,
    get_binary_patches,
    get_binary_string_patches,
    get_internal_patches,
    get_memory_signature_patches,
    get_port_patches,
    get_required_file_patches,
    get_rollback_patches,
    get_source_patches,
    get_stability_patches_17,
    get_targeted_patches,
    get_temp_path_patches,
)

# --- Constants ---

NDK_VERSION = "r29"
NDK_REVISION = "29.0.14206865"
NDK_URL = f"https://dl.google.com/android/repository/android-ndk-{NDK_VERSION}-linux.zip"
NDK_ARCHIVE_SHA1 = "87e2bb7e9be5d6a1c6cdf5ec40dd4e0c6d07c30b"
ALL_ARCHS = ["android-arm64", "android-arm", "android-x86_64", "android-x86"]
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]{2,19}$")
ANDROID_FALLBACK_ROOTS = (
    Path("/usr/local/lib/android/sdk"),
    Path("/usr/local/lib/android"),
)
FORBIDDEN_BINARY_MARKERS = (
    b"frida\x00",
    b"frida-zymbiote",
    b"re/frida/HelperBackend",
    b"frida-server",
    b"frida-helper",
    b"frida-agent",
    b"frida-gadget",
    b"frida-eternal-agent",
    b"frida-generate-certificate",
    b"frida-main-loop",
    b"frida:rpc",
    b"FridaScriptEngine",
    b"GLib-GIO",
    b"GDBusProxy",
    b"GumScript",
    b"Frida/",
    b"gum-js-loop",
    b"gmain\x00",
    b"gdbus\x00",
    b"pool-frida",
    b"pool-spawner",
    b"jit-cache\x00",
)
ZYMBIOTE_ARCHITECTURES = ("arm", "arm64", "x86", "x86_64")
ZYMBIOTE_SOCKET_FIELD_SIZE = 64
ZYMBIOTE_SOCKET_TOKEN = b"0" * 32


class BuildError(RuntimeError):
    """Expected build failure that should be shown without a traceback."""


def log(msg: str, level: str = "INFO"):
    colors = {
        "INFO": "\033[36m",
        "OK": "\033[32m",
        "WARN": "\033[33m",
        "ERROR": "\033[31m",
        "STEP": "\033[35m",
        "HEADER": "\033[1;37m",
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    print(f"{color}[{level}]{reset} {msg}", flush=True)


def run(
    command: Sequence[str | os.PathLike[str]],
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run an argument vector with inherited environment plus overrides."""
    if isinstance(command, (str, bytes)):
        raise BuildError("Commands must be passed as an argument vector")

    argv = [os.fspath(part) for part in command]
    if not argv:
        raise BuildError("Command argument vector must not be empty")

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    rendered_command = shlex.join(argv)
    log(f"$ {rendered_command}", "INFO")
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=full_env,
            capture_output=capture_output,
            text=True,
        )
    except OSError as error:
        raise BuildError(f"Unable to run command: {rendered_command}: {error}") from error
    if check and result.returncode != 0:
        raise BuildError(f"Command failed with exit code {result.returncode}: {rendered_command}")
    return result


def validate_version(value: str) -> str:
    """Accept only concrete Frida release tags such as 17.16.4."""
    if VERSION_PATTERN.fullmatch(value) is None:
        raise BuildError("Frida version must use the numeric X.Y.Z release format")
    return value


def validate_custom_name(value: str) -> str:
    """Normalize and validate the identifier used in paths, packages, and symbols."""
    normalized = value.lower()
    if NAME_PATTERN.fullmatch(normalized) is None:
        raise BuildError(
            "Custom name must be 3-20 lowercase letters or digits and start with a letter"
        )
    return normalized


def validate_port(value: int | None) -> int | None:
    """Validate an optional TCP port."""
    if value is not None and not 1 <= value <= 65535:
        raise BuildError("Port must be between 1 and 65535")
    return value


def parse_architectures(value: str) -> list[str]:
    """Parse and validate the requested Android architecture list."""
    architectures = [architecture.strip() for architecture in value.split(",")]
    invalid = [architecture for architecture in architectures if architecture not in ALL_ARCHS]
    if invalid:
        shown = invalid[0] or "<empty>"
        raise BuildError(f"Unknown architecture: {shown}. Valid: {', '.join(ALL_ARCHS)}")
    return architectures


def validate_directory_layout(
    repository_dir: Path, work_dir: Path, output_dir: Path
) -> tuple[Path, Path]:
    """Resolve build paths and reject layouts that publication could destroy."""
    repository_dir = repository_dir.resolve()
    work_dir = work_dir.resolve()
    output_dir = output_dir.resolve()

    if output_dir == repository_dir or output_dir in repository_dir.parents:
        raise BuildError("Output directory must not contain the repository")
    if work_dir == output_dir or work_dir in output_dir.parents or output_dir in work_dir.parents:
        raise BuildError("Work and output directories must not overlap")
    return work_dir, output_dir


def require_executable(name: str) -> str:
    """Resolve a mandatory executable or fail with its name."""
    path = shutil.which(name)
    if path is None:
        raise BuildError(f"Required executable is missing: {name}")
    return path


def _android_sdk_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(variable)
        if value:
            roots.append(Path(value))
    roots.extend(ANDROID_FALLBACK_ROOTS)
    return tuple(dict.fromkeys(roots))


def _sdk_version_key(path: Path) -> tuple[int, ...]:
    """Sort SDK package paths by their numeric version components."""
    package_dir = path.parent.parent if path.name == "d8.jar" else path.parent
    return tuple(int(component) for component in re.findall(r"\d+", package_dir.name))


def find_android_jar() -> Path:
    """Find the newest available Android platform API JAR."""
    candidates = {
        candidate
        for root in _android_sdk_roots()
        if root.exists()
        for candidate in root.glob("platforms/*/android.jar")
        if candidate.is_file()
    }
    if not candidates:
        raise BuildError("Required Android SDK platform file is missing: android.jar")
    return max(candidates, key=_sdk_version_key)


def find_d8_command() -> list[str]:
    """Resolve D8 as an executable or its JAR entry point."""
    executable = shutil.which("d8")
    if executable is not None:
        return [executable]

    roots = [root for root in _android_sdk_roots() if root.exists()]
    executables: set[Path] = {
        candidate
        for root in roots
        for candidate in root.glob("build-tools/*/d8")
        if candidate.is_file() and os.access(candidate, os.X_OK)
    }
    if executables:
        d8_executable = max(executables, key=_sdk_version_key)
        return [os.fspath(d8_executable)]

    jars: set[Path] = {
        candidate
        for root in roots
        for candidate in root.glob("build-tools/*/lib/d8.jar")
        if candidate.is_file()
    }
    if jars:
        d8_jar = max(jars, key=_sdk_version_key)
        return [
            require_executable("java"),
            "-cp",
            os.fspath(d8_jar),
            "com.android.tools.r8.D8",
        ]

    raise BuildError("Required Android build tool is missing: d8")


def validate_build_prerequisites(*, skip_build: bool) -> None:
    """Fail before downloads or patching when required build tools are absent."""
    for executable in ("git", "java", "javac", "jar"):
        require_executable(executable)
    if not skip_build:
        for executable in ("make", "node"):
            require_executable(executable)
    find_android_jar()
    find_d8_command()


def detect_frida_major(version: str) -> int:
    return int(version.split(".")[0])


# ============================================================================
# File operations
# ============================================================================


def replace_in_file(filepath: Path, old: str, new: str) -> int:
    """Replace string in a single file. Returns number of replacements."""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, IsADirectoryError, OSError):
        return 0
    if old not in content:
        return 0
    count = content.count(old)
    content = content.replace(old, new)
    filepath.write_text(content, encoding="utf-8")
    return count


def replace_in_tree(root: Path, old: str, new: str, include_build: bool = False) -> int:
    """Recursively replace string in all text files under root."""
    total = 0
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv"}
    if not include_build:
        skip_dirs.add("build")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                continue
            # Skip binary files by extension
            if fpath.suffix in {
                ".o",
                ".a",
                ".so",
                ".gz",
                ".zip",
                ".png",
                ".jpg",
                ".pyc",
                ".dex",
                ".jar",
                ".class",
                ".elf",
                ".wasm",
                ".dylib",
                ".dll",
            }:
                continue
            total += replace_in_file(fpath, old, new)

    return total


# ============================================================================
# NDK
# ============================================================================


def validate_ndk(ndk_dir: Path) -> Path:
    """Require the exact NDK revision used by the supported build."""
    properties = ndk_dir / "source.properties"
    if not properties.is_file():
        raise BuildError(f"NDK source.properties is missing: {properties}")
    expected = f"Pkg.Revision = {NDK_REVISION}"
    lines = properties.read_text(encoding="utf-8").splitlines()
    if expected not in lines:
        actual = next(
            (line for line in lines if line.startswith("Pkg.Revision")),
            "revision not declared",
        )
        raise BuildError(f"NDK revision mismatch: expected {NDK_REVISION}, found {actual}")
    return ndk_dir


def find_llvm_strip(ndk_dir: Path) -> Path:
    """Locate the host llvm-strip shipped with the validated Android NDK."""
    candidates = sorted(
        candidate
        for prebuilt in (ndk_dir / "toolchains" / "llvm" / "prebuilt").glob("*")
        for candidate in (
            prebuilt / "bin" / "llvm-strip",
            prebuilt / "bin" / "llvm-strip.exe",
        )
        if candidate.is_file()
    )
    if not candidates:
        raise BuildError(f"NDK llvm-strip is missing under {ndk_dir}")
    return candidates[0]


def verify_file_checksum(path: Path, expected: str, algorithm: str) -> None:
    """Verify a file digest without loading a large archive into memory."""
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        raise BuildError(f"{path.name} checksum mismatch: expected {expected}, found {actual}")


def ensure_ndk(work_dir: Path) -> Path:
    """Download and extract Android NDK if needed."""
    ndk_dir = work_dir / f"android-ndk-{NDK_VERSION}"
    if ndk_dir.exists():
        validate_ndk(ndk_dir)
        log(f"NDK already at {ndk_dir}", "OK")
        return ndk_dir

    ndk_zip = work_dir / f"android-ndk-{NDK_VERSION}-linux.zip"
    if not ndk_zip.exists():
        log(f"Downloading NDK {NDK_VERSION} (~1.5 GB)...", "STEP")
        partial = ndk_zip.with_suffix(f"{ndk_zip.suffix}.part")
        run(
            [
                "curl",
                "--fail",
                "--location",
                "--retry",
                "3",
                "--retry-all-errors",
                "--output",
                partial,
                NDK_URL,
            ],
            cwd=work_dir,
        )
        verify_file_checksum(partial, NDK_ARCHIVE_SHA1, "sha1")
        os.replace(partial, ndk_zip)
    else:
        verify_file_checksum(ndk_zip, NDK_ARCHIVE_SHA1, "sha1")

    log("Extracting NDK...", "STEP")
    run(["unzip", "-q", ndk_zip], cwd=work_dir)

    if ndk_dir.exists():
        validate_ndk(ndk_dir)
        log(f"NDK ready at {ndk_dir}", "OK")
        ndk_zip.unlink(missing_ok=True)
        return ndk_dir
    raise BuildError(f"NDK extraction did not create expected directory: {ndk_dir}")


# ============================================================================
# Clone
# ============================================================================


def clone_frida(version: str, work_dir: Path) -> Path:
    """Clone Frida source at the specified version tag."""
    frida_dir = work_dir / "frida"
    if frida_dir.exists():
        log(f"Frida source already at {frida_dir}", "OK")
        return frida_dir

    log(f"Cloning Frida {version} (with submodules)...", "STEP")
    run(
        [
            "git",
            "clone",
            "--recurse-submodules",
            "--branch",
            version,
            "--depth",
            "1",
            "https://github.com/frida/frida.git",
            frida_dir,
        ],
        cwd=work_dir,
    )
    log(f"Frida {version} cloned", "OK")
    return frida_dir


def apply_page_patch(frida_dir: Path) -> None:
    """Apply my_page.patch to the freshly cloned source tree.

    my_page.patch carries the XOM-safe zygote-RX injection fix (Android 10,
    kernel 4.9, SELinux enforcing: transiently soften execute-only text pages
    so zymbiote injection does not SIGSEGV) plus the frida-gum page-handling
    changes that go with it. It must run before the Phase 1 identifier renames
    so its hunk context still matches pristine upstream source.
    """
    patch_file = Path(__file__).parent / "my_page.patch"
    if not patch_file.exists():
        log("my_page.patch not found, skipping page patch", "WARN")
        return
    log("Applying my_page.patch...", "STEP")
    result = run(
        ["git", "apply", "--whitespace=nowarn", str(patch_file)],
        cwd=frida_dir,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail_lines = (result.stderr or "").strip().splitlines()
        detail = " | ".join(detail_lines[:6]) or f"exit code {result.returncode}"
        raise BuildError(
            f"my_page.patch failed to apply: {detail}. Rework its hunks for "
            "this Frida version, or remove the file to build without the "
            "XOM injection fix."
        )
    log("my_page.patch applied", "OK")


# ============================================================================
# PHASE 1: Source-level patches (before build)
# ============================================================================


def rename_frida_files(frida_dir: Path, custom_name: str):
    """
    Rename files on disk whose names contain 'frida-helper' or 'frida-agent' etc.
    After global source patches rename references in meson.build/Vala/C files,
    the actual files on disk must also be renamed to match.

    IMPORTANT: Skip build system files (.symbols, .version, .def, .plist, .xcent)
    because rollback patches revert their references to original names.
    Also skip releng/frida_version.py (not renamed by our patches).
    """
    rename_patterns = [
        ("frida-helper", f"{custom_name}-helper"),
        ("frida-agent", f"{custom_name}-agent"),
        ("frida-gadget", f"{custom_name}-gadget"),
        ("frida-server", f"{custom_name}-server"),
    ]

    # Build system file extensions that rollback patches keep with original names
    skip_extensions = {".symbols", ".version", ".def", ".plist", ".xcent"}
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "build"}
    # Specific files to never rename
    skip_names = {"frida_version.py", "frida-version.py"}
    renamed_count = 0

    for dirpath, dirnames, filenames in os.walk(frida_dir, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname in skip_names:
                continue
            # Skip build system files (rollback patches keep their original names)
            if Path(fname).suffix in skip_extensions:
                continue
            new_fname = fname
            for old_pat, new_pat in rename_patterns:
                if old_pat in new_fname:
                    new_fname = new_fname.replace(old_pat, new_pat)
            if new_fname != fname:
                old_path = Path(dirpath) / fname
                new_path = Path(dirpath) / new_fname
                if old_path.exists() and not new_path.exists():
                    old_path.rename(new_path)
                    renamed_count += 1

    if renamed_count:
        log(f"  Renamed {renamed_count} files on disk", "OK")


def _require_success(tool: str, result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode == 0:
        return
    details = (result.stderr or result.stdout or "").strip()
    suffix = f": {details}" if details else ""
    raise BuildError(f"{tool} failed with exit code {result.returncode}{suffix}")


def rebuild_helper_dex(frida_dir: Path, custom_name: str) -> Path:
    """Rebuild the Android helper DEX with renamed Java package.

    The pre-compiled helper.dex in the repo contains 're.frida.Helper'.
    We need to recompile it with the new package name so that:
    1. The DEX string table doesn't contain 'frida' (binary sweep safe)
    2. The class name matches what the renamed Vala code expects
    """
    helper_dir = frida_dir / "subprojects" / "frida-core" / "src" / "android-helper"
    old_pkg_dir = helper_dir / "re" / "frida"
    new_pkg_dir = helper_dir / "re" / custom_name
    java_file = old_pkg_dir / "Helper.java"

    if not java_file.exists():
        # Package might already be renamed (e.g., from cache)
        java_file = new_pkg_dir / "Helper.java"
        if not java_file.exists():
            raise BuildError(f"Required Android helper source is missing: {java_file}")

    # Rename directory: re/frida/ -> re/{name}/
    if old_pkg_dir.exists() and new_pkg_dir.exists():
        raise BuildError(f"Both helper package directories exist: {old_pkg_dir}, {new_pkg_dir}")
    if old_pkg_dir.exists():
        old_pkg_dir.rename(new_pkg_dir)
        log(f"  Renamed {old_pkg_dir.name}/ -> {new_pkg_dir.name}/", "OK")

    java_file = new_pkg_dir / "Helper.java"
    if not java_file.exists():
        raise BuildError(f"Required Android helper source is missing after rename: {java_file}")

    # The Java source was already patched by replace_in_tree:
    #   "package re.frida;" -> "package re.{name};"
    #   "re.frida.Helper" -> "re.{name}.Helper"
    # Verify:
    content = java_file.read_text(encoding="utf-8")
    if f"package re.{custom_name};" not in content:
        content = content.replace("package re.frida;", f"package re.{custom_name};")
        if f"package re.{custom_name};" not in content:
            raise BuildError(f"Could not patch Android helper package in {java_file}")
        java_file.write_text(content, encoding="utf-8")

    dex_file = helper_dir / "helper.dex"
    if not dex_file.is_file():
        raise BuildError(f"Required precompiled Android helper DEX is missing: {dex_file}")

    javac_path = require_executable("javac")
    jar_path = require_executable("jar")
    android_jar = find_android_jar()
    d8_command = find_d8_command()

    log(f"  Recompiling helper DEX (android.jar: {android_jar.name})...", "STEP")
    with TemporaryDirectory(dir=helper_dir, prefix=".dex-build-") as temporary:
        build_dir = Path(temporary)
        java_build = build_dir / "java"
        dex_build = build_dir / "dex"
        java_build.mkdir()
        dex_build.mkdir()

        javac_result = run(
            [
                javac_path,
                "-cp",
                f".{os.pathsep}{android_jar}",
                "-bootclasspath",
                android_jar,
                "-source",
                "1.8",
                "-target",
                "1.8",
                "-Xlint:-options",
                java_file,
                "-d",
                java_build,
            ],
            cwd=helper_dir,
            check=False,
            capture_output=True,
        )
        _require_success("javac", javac_result)

        class_files = list((java_build / "re" / custom_name).glob("*.class"))
        if not class_files:
            raise BuildError(f"javac generated no helper classes under re/{custom_name}")
        log(f"  Compiled {len(class_files)} helper class files", "OK")

        jar_file = build_dir / f"{custom_name}-helper.jar"
        jar_result = run(
            [jar_path, "cfe", jar_file, f"re.{custom_name}.Helper", "-C", java_build, "."],
            cwd=helper_dir,
            check=False,
            capture_output=True,
        )
        _require_success("jar", jar_result)

        d8_result = run(
            [*d8_command, "--lib", android_jar, "--output", dex_build, jar_file],
            cwd=helper_dir,
            check=False,
            capture_output=True,
        )
        _require_success("d8", d8_result)

        new_dex = dex_build / "classes.dex"
        if not new_dex.is_file():
            raise BuildError(f"d8 did not generate expected output: {new_dex}")
        shutil.copy2(new_dex, dex_file)

    log(
        f"  Helper DEX rebuilt: {dex_file.stat().st_size} bytes (package: re.{custom_name})",
        "OK",
    )
    return dex_file


def apply_required_file_patches(frida_dir: Path, custom_name: str) -> None:
    """Apply source contracts that must match the supported Frida source shape."""
    for patch in get_required_file_patches(custom_name):
        target = frida_dir / patch.relative_path
        if not target.is_file():
            raise BuildError(f"Required patch file is missing: {patch.relative_path}")

        count = replace_in_file(target, patch.old, patch.new)
        if count < patch.minimum:
            raise BuildError(
                f"Required pattern {patch.old!r} occurred {count} times in "
                f"{patch.relative_path}; expected at least {patch.minimum}"
            )
        log(f"  [required] {patch.relative_path}: {count} replacement(s)", "OK")


def patch_zymbiote_artifacts(frida_dir: Path, custom_name: str) -> None:
    """Patch the fixed-size socket field in Frida's tracked helper ELFs."""
    old_socket = b"/frida-zymbiote-" + ZYMBIOTE_SOCKET_TOKEN
    new_socket = f"/{custom_name}-zymbiote-".encode() + ZYMBIOTE_SOCKET_TOKEN
    if len(new_socket) >= ZYMBIOTE_SOCKET_FIELD_SIZE:
        raise BuildError("Custom name does not fit the zymbiote socket field")

    old_field = old_socket.ljust(ZYMBIOTE_SOCKET_FIELD_SIZE, b"\0")
    new_field = new_socket.ljust(ZYMBIOTE_SOCKET_FIELD_SIZE, b"\0")
    artifacts = frida_dir / "subprojects/frida-core/src/linux/helpers/artifacts/native"

    for architecture in ZYMBIOTE_ARCHITECTURES:
        target = artifacts / architecture / "zymbiote.elf"
        relative_path = target.relative_to(frida_dir).as_posix()
        if not target.is_file():
            raise BuildError(f"Required zymbiote artifact is missing: {relative_path}")

        data = target.read_bytes()
        count = data.count(old_field)
        if count != 1:
            raise BuildError(
                f"Required socket field occurred {count} times in {relative_path}; expected 1"
            )

        patched = data.replace(old_field, new_field)
        with TemporaryDirectory(dir=target.parent, prefix=".zymbiote-patch-") as temporary:
            staged = Path(temporary) / target.name
            staged.write_bytes(patched)
            shutil.copymode(target, staged)
            os.replace(staged, target)
        log(f"  [required] {relative_path}: socket field patched", "OK")


def apply_source_patches(frida_dir: Path, custom_name: str):
    """Apply global recursive string replacements across the source tree."""
    log("=" * 60, "HEADER")
    log("PHASE 1: Global source patches", "STEP")
    log("=" * 60, "HEADER")

    apply_required_file_patches(frida_dir, custom_name)
    patch_zymbiote_artifacts(frida_dir, custom_name)

    cap_name = custom_name[0].upper() + custom_name[1:]

    patches = get_source_patches(custom_name, cap_name)
    for old, new in patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  {old} -> {new} ({count})", "OK")
        else:
            log(f"  {old} -> (not found)", "WARN")

    # Rollback accidental renames of build system files
    log("Rolling back build file renames...", "STEP")
    rollbacks = get_rollback_patches(custom_name)
    for old, new in rollbacks:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  [rollback] {old} ({count})", "INFO")

    # Rename actual files on disk to match source references
    rename_frida_files(frida_dir, custom_name)

    # Rebuild helper DEX with renamed Java package
    rebuild_helper_dex(frida_dir, custom_name)

    log("Global source patches complete", "OK")


def apply_targeted_patches(frida_dir: Path, custom_name: str, frida_major: int):
    """Apply patches to specific files (memfd, libc hooks, SELinux, build system)."""
    log("=" * 60, "HEADER")
    log("PHASE 2: Targeted file patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]
    core_dir = frida_dir / "subprojects" / "frida-core"

    # --- memfd_create: hide agent name in /proc/pid/fd ---
    memfd_cfg = MEMFD_PATCHES.get(frida_major, MEMFD_PATCHES[17])
    memfd_file = core_dir / memfd_cfg["file"]
    if memfd_file.exists():
        count = replace_in_file(memfd_file, memfd_cfg["old"], memfd_cfg["new"])
        if count:
            log(f"  memfd_create -> 'jit-code-cache' in {memfd_cfg['file']}", "OK")
        else:
            log(f"  memfd_create: pattern not found in {memfd_cfg['file']}", "WARN")
    else:
        log(f"  memfd file missing: {memfd_cfg['file']}", "WARN")

    # --- SELinux labels (in linjector.vala for 17.x) ---
    for old, new in SELINUX_PATCHES(custom_name):
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  SELinux: {old} -> {new} ({count})", "OK")

    # --- Build system files ---
    targets = {
        "server_meson": core_dir / "server" / "meson.build",
        "compat_build": core_dir / "compat" / "build.py",
        "core_meson": core_dir / "meson.build",
        "gadget_meson": core_dir / "lib" / "gadget" / "meson.build",
        "agent_meson": core_dir / "lib" / "agent" / "meson.build",
    }

    for target_name, target_file in targets.items():
        if target_file.exists():
            patches = get_targeted_patches(custom_name, cap_name, target_name)
            applied = 0
            for old, new in patches:
                applied += replace_in_file(target_file, old, new)
            if applied:
                log(f"  {target_name}: {applied} patches", "OK")
        else:
            log(f"  {target_name}: file not found", "WARN")

    log("Targeted patches complete", "OK")


def apply_ndk29_fstream_patch(frida_dir: Path) -> None:
    """Make frida's libc++ <fstream> overlay patch tolerate NDK r29+.

    Frida's releng patches the NDK <fstream> header so 32-bit Android
    API<24 uses fseek/ftell instead of the broken fseeko/ftello. The
    expected inline ``return fseek(__file, ...)`` pattern was removed in
    newer libc++ (NDK r29+), which restructured fstream to gate the two
    via the _LIBCPP_HAS_NO_OFF_T_FUNCTIONS macro (defined for NEWLIB/
    MSVCRT). Without this, older Frida releng (17.9.x) dies at the compat
    subproject with "Failed to patch libc++ fstream header; expected
    patterns not found".

    We extend the macro's condition with the same 32-bit-Android fallback
    so the seek behaviour is preserved, while keeping the legacy branch
    pattern for older NDKs. Idempotent: a newer Frida releng whose
    _patch_fstream_header no longer matches this shape is left untouched.
    """
    env_android = frida_dir / "releng" / "env_android.py"
    if not env_android.exists():
        log("  env_android.py not found, skipping NDK r29 fstream patch", "WARN")
        return

    old = (
        "    result = header.replace(old_fseek, new_fseek)\n"
        "    result = result.replace(old_ftell, new_ftell)\n"
        "\n"
        "    if result == header:\n"
        "        raise ValueError(\"Failed to patch libc++ fstream header; expected patterns not found\")\n"
        "\n"
        "    return result"
    )

    new = (
        "    result = header.replace(old_fseek, new_fseek)\n"
        "    result = result.replace(old_ftell, new_ftell)\n"
        "\n"
        "    if result != header:\n"
        "        return result\n"
        "\n"
        "    # Newer libc++ (NDK r29+) restructured fstream to gate fseek/fseeko\n"
        "    # via the _LIBCPP_HAS_NO_OFF_T_FUNCTIONS macro (defined for NEWLIB/\n"
        "    # MSVCRT). Extend that macro's condition so 32-bit Android API<24\n"
        "    # also uses fseek/ftell, preserving the legacy branch semantics.\n"
        "    old_macro = \"\"\"#if defined(_LIBCPP_MSVCRT) || defined(_NEWLIB_VERSION)\n"
        "#  define _LIBCPP_HAS_NO_OFF_T_FUNCTIONS\n"
        "#endif\"\"\"\n"
        "\n"
        "    new_macro = \"\"\"#if defined(_LIBCPP_MSVCRT) || defined(_NEWLIB_VERSION) || (defined(__ANDROID__) && __SIZEOF_POINTER__ == 4 && __ANDROID_API__ < 24)\n"
        "#  define _LIBCPP_HAS_NO_OFF_T_FUNCTIONS\n"
        "#endif\"\"\"\n"
        "\n"
        "    result = header.replace(old_macro, new_macro)\n"
        "    if result == header:\n"
        "        raise ValueError(\"Failed to patch libc++ fstream header; expected patterns not found\")\n"
        "\n"
        "    return result"
    )

    count = replace_in_file(env_android, old, new)
    if count:
        log("  env_android.py: NDK r29 fstream compat patch applied", "OK")
    else:
        log("  env_android.py: fstream patch pattern not found (not needed or already applied)", "OK")


def apply_strict_wx_patch(frida_dir: Path, custom_name: str) -> None:
    """Disable persistent anonymous RWX mappings owned by Frida on Android."""
    helper_backend = Path(f"subprojects/frida-core/src/linux/{custom_name}-helper-backend.vala")
    allocator_boxed_types = (
        "G_DEFINE_BOXED_TYPE (GumCodeSlice, gum_code_slice, gum_code_slice_ref,\n"
        "                     gum_code_slice_unref)\n"
        "G_DEFINE_BOXED_TYPE (GumCodeDeflector, gum_code_deflector,\n"
        "                     gum_code_deflector_ref, gum_code_deflector_unref)\n\n"
    )
    patches = (
        (
            Path("subprojects/frida-gum/gum/gumcodeallocator.c"),
            "gum_query_is_rwx_supported ()",
            "gum_code_allocator_is_rwx_supported ()",
            3,
            "code pools use RW then RX",
        ),
        (
            Path("subprojects/frida-gum/gum/gumcodeallocator.c"),
            allocator_boxed_types + "void\ngum_code_allocator_init",
            allocator_boxed_types + "static gboolean\n"
            "gum_code_allocator_is_rwx_supported (void)\n"
            "{\n"
            "#if defined (HAVE_ANDROID)\n"
            "  return FALSE;\n"
            "#else\n"
            "  return gum_query_is_rwx_supported ();\n"
            "#endif\n"
            "}\n\n"
            "void\n"
            "gum_code_allocator_init",
            1,
            "Android allocator policy scoped",
        ),
        (
            Path("subprojects/frida-gum/gum/gummemory.c"),
            "      restored = ((original_protections[i] & GUM_PAGE_WRITE) != 0)\n"
            "          ? GUM_PAGE_RWX\n"
            "          : GUM_PAGE_RX;",
            "#if defined (HAVE_ANDROID)\n"
            "      restored = ((original_protections[i] & GUM_PAGE_WRITE) != 0 &&\n"
            "          (original_protections[i] & GUM_PAGE_EXECUTE) != 0)\n"
            "          ? GUM_PAGE_RWX\n"
            "          : GUM_PAGE_RX;\n"
            "#else\n"
            "      restored = ((original_protections[i] & GUM_PAGE_WRITE) != 0)\n"
            "          ? GUM_PAGE_RWX\n"
            "          : GUM_PAGE_RX;\n"
            "#endif",
            1,
            "new Android code pages finish RX",
        ),
        (
            Path("subprojects/frida-gum/gum/gum-init.h"),
            "GUM_API void _gum_register_early_destructor (GumDestructorFunc destructor);\n"
            "GUM_API void _gum_register_destructor (GumDestructorFunc destructor);\n\n"
            "G_END_DECLS",
            "GUM_API void _gum_register_early_destructor (GumDestructorFunc destructor);\n"
            "GUM_API void _gum_register_destructor (GumDestructorFunc destructor);\n\n"
            "#if defined (HAVE_ANDROID)\n"
            "G_GNUC_INTERNAL gpointer _gum_android_ffi_closure_make_executable (\n"
            "    gpointer closure, gpointer code, gsize closure_size,\n"
            "    gpointer * code_page);\n"
            "G_GNUC_INTERNAL void _gum_android_ffi_closure_free_executable (\n"
            "    gpointer code_page);\n"
            "#endif\n\n"
            "G_END_DECLS",
            1,
            "declare Android NativeCallback W^X helpers",
        ),
        (
            Path("subprojects/frida-gum/gum/gum.c"),
            "static void\n"
            "gum_on_ffi_deallocate (void * base_address,\n"
            "                       size_t size)\n"
            "{\n"
            "  GumMemoryRange range;\n"
            "  range.base_address = GUM_ADDRESS (base_address);\n"
            "  range.size = size;\n"
            "  gum_cloak_remove_range (&range);\n"
            "}\n\n"
            "#endif",
            "static void\n"
            "gum_on_ffi_deallocate (void * base_address,\n"
            "                       size_t size)\n"
            "{\n"
            "  GumMemoryRange range;\n"
            "  range.base_address = GUM_ADDRESS (base_address);\n"
            "  range.size = size;\n"
            "  gum_cloak_remove_range (&range);\n"
            "}\n\n"
            "#endif\n\n"
            "#ifdef HAVE_ANDROID\n\n"
            "gpointer\n"
            "_gum_android_ffi_closure_make_executable (gpointer closure,\n"
            "                                          gpointer code,\n"
            "                                          gsize closure_size,\n"
            "                                          gpointer * code_page)\n"
            "{\n"
            "  gsize page_size, closure_region_size;\n"
            "  guintptr closure_address, closure_page_address, code_address;\n"
            "  guintptr normalized_code_address, code_state, code_offset;\n"
            "  gpointer executable_page;\n"
            "  GumMemoryRange range;\n"
            "  GumPageProtection closure_protection, code_protection;\n\n"
            "  *code_page = NULL;\n"
            "  page_size = gum_query_page_size ();\n"
            "  if (closure_size > page_size)\n"
            "    return NULL;\n\n"
            "  closure_address = GPOINTER_TO_SIZE (closure);\n"
            "  closure_page_address = closure_address & ~((guintptr) page_size - 1);\n"
            "  closure_region_size =\n"
            "      ((closure_address - closure_page_address + closure_size + page_size - 1) /\n"
            "      page_size) * page_size;\n"
            "  code_address = GPOINTER_TO_SIZE (code);\n"
            "  code_state = code_address & 1;\n"
            "  normalized_code_address = code_address - code_state;\n"
            "  if (normalized_code_address < closure_address ||\n"
            "      normalized_code_address - closure_address >= closure_size)\n"
            "  {\n"
            "    if (!gum_memory_query_protection (closure, &closure_protection) ||\n"
            "        !gum_memory_query_protection (\n"
            "            GSIZE_TO_POINTER (normalized_code_address), &code_protection) ||\n"
            "        (closure_protection & GUM_PAGE_WRITE) == 0 ||\n"
            "        (closure_protection & GUM_PAGE_EXECUTE) != 0 ||\n"
            "        (code_protection & GUM_PAGE_WRITE) != 0 ||\n"
            "        (code_protection & GUM_PAGE_EXECUTE) == 0)\n"
            "      return NULL;\n"
            "    return code;\n"
            "  }\n"
            "  code_offset = normalized_code_address - closure_address;\n\n"
            "  executable_page = gum_memory_allocate (NULL, page_size, page_size,\n"
            "      GUM_PAGE_RW);\n"
            "  if (executable_page == NULL)\n"
            "    return NULL;\n"
            "  memcpy (executable_page, closure, closure_size);\n\n"
            "  if (!gum_try_mprotect (GSIZE_TO_POINTER (closure_page_address),\n"
            "      closure_region_size, GUM_PAGE_RW) ||\n"
            "      !gum_try_mprotect (executable_page, page_size, GUM_PAGE_RX))\n"
            "  {\n"
            "    gum_memory_free (executable_page, page_size);\n"
            "    return NULL;\n"
            "  }\n"
            "  gum_clear_cache (executable_page, closure_size);\n\n"
            "  range.base_address = GUM_ADDRESS (executable_page);\n"
            "  range.size = page_size;\n"
            "  gum_cloak_add_range (&range);\n\n"
            "  *code_page = executable_page;\n"
            "  return GSIZE_TO_POINTER (GPOINTER_TO_SIZE (executable_page) +\n"
            "      code_offset + code_state);\n"
            "}\n\n"
            "void\n"
            "_gum_android_ffi_closure_free_executable (gpointer code_page)\n"
            "{\n"
            "  gsize page_size = gum_query_page_size ();\n"
            "  GumMemoryRange range;\n\n"
            "  range.base_address = GUM_ADDRESS (code_page);\n"
            "  range.size = page_size;\n"
            "  gum_cloak_remove_range (&range);\n"
            "  gum_memory_free (code_page, page_size);\n"
            "}\n\n"
            "#endif",
            1,
            "NativeCallback closures use separate RW and RX pages",
        ),
        (
            Path("subprojects/frida-gum/bindings/gumjs/gumquickcore.h"),
            "  JSValue wrapper;\n  JSValue func;\n  ffi_closure * closure;\n  ffi_cif cif;",
            "  JSValue wrapper;\n"
            "  JSValue func;\n"
            "  ffi_closure * closure;\n"
            "#if defined (HAVE_ANDROID)\n"
            "  gpointer code_page;\n"
            "#endif\n"
            "  ffi_cif cif;",
            1,
            "track QuickJS NativeCallback RX page",
        ),
        (
            Path("subprojects/frida-gum/bindings/gumjs/gumquickcore.c"),
            "#include <string.h>\n#include <glib/gprintf.h>",
            "#include <string.h>\n"
            "#include <glib/gprintf.h>\n"
            "#if defined (HAVE_ANDROID)\n"
            "# include <gum/gum-init.h>\n"
            "#endif",
            1,
            "import QuickJS NativeCallback W^X helpers",
        ),
        (
            Path("subprojects/frida-gum/bindings/gumjs/gumquickcore.c"),
            "  if (ffi_prep_closure_loc (cb->closure, &cb->cif,\n"
            "      gum_quick_native_callback_invoke, cb, ptr->value) != FFI_OK)\n"
            "    goto prepare_failed;",
            "  if (ffi_prep_closure_loc (cb->closure, &cb->cif,\n"
            "      gum_quick_native_callback_invoke, cb, ptr->value) != FFI_OK)\n"
            "    goto prepare_failed;\n"
            "#if defined (HAVE_ANDROID)\n"
            "  ptr->value = _gum_android_ffi_closure_make_executable (cb->closure,\n"
            "      ptr->value, sizeof (ffi_closure), &cb->code_page);\n"
            "  if (ptr->value == NULL)\n"
            "    goto prepare_failed;\n"
            "#endif",
            1,
            "QuickJS NativeCallback code finishes RX",
        ),
        (
            Path("subprojects/frida-gum/bindings/gumjs/gumquickcore.c"),
            "gum_quick_native_callback_finalize (GumQuickNativeCallback * callback)\n"
            "{\n"
            "  g_clear_pointer (&callback->closure, ffi_closure_free);",
            "gum_quick_native_callback_finalize (GumQuickNativeCallback * callback)\n"
            "{\n"
            "#if defined (HAVE_ANDROID)\n"
            "  g_clear_pointer (&callback->code_page,\n"
            "      _gum_android_ffi_closure_free_executable);\n"
            "#endif\n"
            "  g_clear_pointer (&callback->closure, ffi_closure_free);",
            1,
            "free QuickJS NativeCallback RX page",
        ),
        (
            Path("subprojects/frida-gum/bindings/gumjs/gumv8core.cpp"),
            "  v8::Global<v8::Function> * func;\n  ffi_closure * closure;\n  ffi_cif cif;",
            "  v8::Global<v8::Function> * func;\n"
            "  ffi_closure * closure;\n"
            "#if defined (HAVE_ANDROID)\n"
            "  gpointer code_page;\n"
            "#endif\n"
            "  ffi_cif cif;",
            1,
            "track V8 NativeCallback RX page",
        ),
        (
            Path("subprojects/frida-gum/bindings/gumjs/gumv8core.cpp"),
            "  if (ffi_prep_closure_loc (callback->closure, &callback->cif,\n"
            "      gum_v8_native_callback_invoke, callback, func) != FFI_OK)\n"
            "  {\n"
            '    _gum_v8_throw_ascii_literal (isolate, "failed to prepare closure");\n'
            "    goto error;\n"
            "  }",
            "  if (ffi_prep_closure_loc (callback->closure, &callback->cif,\n"
            "      gum_v8_native_callback_invoke, callback, func) != FFI_OK)\n"
            "  {\n"
            '    _gum_v8_throw_ascii_literal (isolate, "failed to prepare closure");\n'
            "    goto error;\n"
            "  }\n"
            "#if defined (HAVE_ANDROID)\n"
            "  func = _gum_android_ffi_closure_make_executable (callback->closure,\n"
            "      func, sizeof (ffi_closure), &callback->code_page);\n"
            "  if (func == NULL)\n"
            "  {\n"
            '    _gum_v8_throw_ascii_literal (isolate, "failed to protect closure");\n'
            "    goto error;\n"
            "  }\n"
            "#endif",
            1,
            "V8 NativeCallback code finishes RX",
        ),
        (
            Path("subprojects/frida-gum/bindings/gumjs/gumv8core.cpp"),
            "  gum_v8_native_callback_clear (callback);\n\n"
            "  g_clear_pointer (&callback->closure, ffi_closure_free);",
            "  gum_v8_native_callback_clear (callback);\n\n"
            "#if defined (HAVE_ANDROID)\n"
            "  g_clear_pointer (&callback->code_page,\n"
            "      _gum_android_ffi_closure_free_executable);\n"
            "#endif\n"
            "  g_clear_pointer (&callback->closure, ffi_closure_free);",
            1,
            "free V8 NativeCallback RX page",
        ),
        *(
            (
                Path(relative_path),
                "  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;",
                "#if defined (HAVE_ANDROID)\n"
                "  self->is_rwx_supported = FALSE;\n"
                "#else\n"
                "  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;\n"
                "#endif",
                1,
                "Stalker pools use RW then RX",
            )
            for relative_path in (
                "subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c",
                "subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c",
                "subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c",
            )
        ),
        (
            helper_backend,
            "\t\tprivate static uint64 mmap_offset;\n\t\tprivate static uint64 munmap_offset;",
            "\t\tprivate static uint64 mmap_offset;\n"
            "\t\tprivate static uint64 mprotect_offset;\n"
            "\t\tprivate static uint64 munmap_offset;",
            1,
            "track remote mprotect",
        ),
        (
            helper_backend,
            '\t\t\tmmap_offset = (uint64) (uintptr) libc.find_export_by_name ("mmap")'
            " - local_libc.start;\n"
            '\t\t\tmunmap_offset = (uint64) (uintptr) libc.find_export_by_name ("munmap")'
            " - local_libc.start;",
            '\t\t\tmmap_offset = (uint64) (uintptr) libc.find_export_by_name ("mmap")'
            " - local_libc.start;\n"
            "\t\t\tmprotect_offset = (uint64) (uintptr) libc.find_export_by_name "
            '("mprotect") - local_libc.start;\n'
            '\t\t\tmunmap_offset = (uint64) (uintptr) libc.find_export_by_name ("munmap")'
            " - local_libc.start;",
            1,
            "resolve remote mprotect",
        ),
        (
            helper_backend,
            "\t\t\tBootstrapResult bootstrap_result = yield bootstrap "
            "(loader_layout.size, cancellable);\n"
            "\t\t\tuint64 loader_base = (uintptr) bootstrap_result.context.allocation_base;"
            "\n\n"
            "\t\t\ttry {\n"
            "\t\t\t\tunowned uint8[] loader_code = "
            "Frida.Data.HelperBackend.get_loader_bin_blob ().data;",
            "\t\t\tBootstrapResult bootstrap_result = yield bootstrap "
            "(loader_layout.size, cancellable);\n"
            "\t\t\tuint64 loader_base = (uintptr) bootstrap_result.context.allocation_base;"
            "\n\n"
            "\t\t\ttry {\n"
            "#if ANDROID\n"
            "\t\t\t\tyield protect_memory (bootstrap_result.mprotect,\n"
            "\t\t\t\t\tloader_base, loader_layout.size,\n"
            "\t\t\t\t\tPosix.PROT_READ | Posix.PROT_WRITE, cancellable);\n"
            "#endif\n"
            "\t\t\t\tunowned uint8[] loader_code = "
            "Frida.Data.HelperBackend.get_loader_bin_blob ().data;",
            1,
            "loader staging is writable and non-executable",
        ),
        (
            helper_backend,
            "\t\t\tuint64 loader_base = (uintptr) bres.context.allocation_base;\n"
            "\t\t\tGPRegs regs = saved_regs;",
            "\t\t\tuint64 loader_base = (uintptr) bres.context.allocation_base;\n"
            "#if ANDROID\n"
            "\t\t\tyield protect_memory (bres.mprotect,\n"
            "\t\t\t\tloader_base, loader_layout.ctx_offset,\n"
            "\t\t\t\tPosix.PROT_READ | Posix.PROT_EXEC, cancellable);\n"
            "#endif\n"
            "\t\t\tGPRegs regs = saved_regs;",
            1,
            "loader code is executable and non-writable",
        ),
        (
            helper_backend,
            "\t\t\tuint64 remote_mmap = 0;\n\t\t\tuint64 remote_munmap = 0;",
            "\t\t\tuint64 remote_mmap = 0;\n"
            "\t\t\tuint64 remote_mprotect = 0;\n"
            "\t\t\tuint64 remote_munmap = 0;",
            1,
            "track target mprotect",
        ),
        (
            helper_backend,
            "\t\t\t\tremote_mmap = remote_libc.start + mmap_offset;\n"
            "\t\t\t\tremote_munmap = remote_libc.start + munmap_offset;\n"
            "\t\t\t}",
            "\t\t\t\tremote_mmap = remote_libc.start + mmap_offset;\n"
            "\t\t\t\tremote_mprotect = remote_libc.start + mprotect_offset;\n"
            "\t\t\t\tremote_munmap = remote_libc.start + munmap_offset;\n"
            "\t\t\t}\n"
            "#if ANDROID\n"
            "\t\t\tif (remote_mmap == 0 || remote_mprotect == 0)\n"
            '\t\t\t\tthrow new Error.NOT_SUPPORTED ("Unable to enforce strict W^X '
            'without a matching remote libc");\n'
            "#endif\n"
            "\t\t\tresult.mprotect = remote_mprotect;",
            1,
            "locate target mprotect and fail closed",
        ),
        (
            helper_backend,
            "\t\t\tif (remote_mmap != 0) {\n"
            "\t\t\t\tallocation_base = yield allocate_memory (remote_mmap, allocation_size,\n"
            "\t\t\t\t\tPosix.PROT_READ | Posix.PROT_WRITE | Posix.PROT_EXEC, cancellable);\n"
            "\t\t\t} else {",
            "\t\t\tif (remote_mmap != 0) {\n"
            "#if ANDROID\n"
            "\t\t\t\tallocation_base = yield allocate_memory (remote_mmap, allocation_size,\n"
            "\t\t\t\t\tPosix.PROT_READ | Posix.PROT_WRITE, cancellable);\n"
            "#else\n"
            "\t\t\t\tallocation_base = yield allocate_memory (remote_mmap, allocation_size,\n"
            "\t\t\t\t\tPosix.PROT_READ | Posix.PROT_WRITE | Posix.PROT_EXEC, cancellable);\n"
            "#endif\n"
            "\t\t\t} else {",
            1,
            "bootstrap allocation starts writable and non-executable",
        ),
        (
            helper_backend,
            "\t\t\t\twrite_memory (allocation_base, bootstrapper_code);\n"
            "\t\t\t\tmaybe_fixup_helper_code (allocation_base, bootstrapper_code);\n"
            "\t\t\t\tuint64 code_start = allocation_base;",
            "\t\t\t\twrite_memory (allocation_base, bootstrapper_code);\n"
            "\t\t\t\tmaybe_fixup_helper_code (allocation_base, bootstrapper_code);\n"
            "#if ANDROID\n"
            "\t\t\t\tyield protect_memory (remote_mprotect,\n"
            "\t\t\t\t\tallocation_base, allocation_size - stack_size,\n"
            "\t\t\t\t\tPosix.PROT_READ | Posix.PROT_EXEC, cancellable);\n"
            "#endif\n"
            "\t\t\t\tuint64 code_start = allocation_base;",
            1,
            "bootstrap code is executable and non-writable",
        ),
        (
            helper_backend,
            "\t\tpublic HelperBootstrapContext context;\n"
            "\t\tpublic HelperLibcApi libc;\n"
            "\t\tpublic AllocatedStack allocated_stack;\n\n"
            "\t\tpublic BootstrapResult clone () {\n"
            "\t\t\tvar res = new BootstrapResult ();\n"
            "\t\t\tres.context = context;\n"
            "\t\t\tres.libc = libc;\n"
            "\t\t\tres.allocated_stack = allocated_stack;",
            "\t\tpublic HelperBootstrapContext context;\n"
            "\t\tpublic HelperLibcApi libc;\n"
            "\t\tpublic AllocatedStack allocated_stack;\n"
            "\t\tpublic uint64 mprotect;\n\n"
            "\t\tpublic BootstrapResult clone () {\n"
            "\t\t\tvar res = new BootstrapResult ();\n"
            "\t\t\tres.context = context;\n"
            "\t\t\tres.libc = libc;\n"
            "\t\t\tres.allocated_stack = allocated_stack;\n"
            "\t\t\tres.mprotect = mprotect;",
            1,
            "retain host-side mprotect across rejuvenation",
        ),
        (
            helper_backend,
            "\t\tpublic async void deallocate_memory (uint64 munmap_impl, uint64 address, "
            "size_t size, Cancellable? cancellable)",
            "\t\tpublic async void protect_memory (uint64 mprotect_impl, uint64 address, "
            "size_t size, int prot,\n"
            "\t\t\t\tCancellable? cancellable) throws Error, IOError {\n"
            "\t\t\tvar builder = new RemoteCallBuilder (mprotect_impl, saved_regs);\n"
            "\t\t\tbuilder\n"
            "\t\t\t\t.add_argument (address)\n"
            "\t\t\t\t.add_argument (size)\n"
            "\t\t\t\t.add_argument (prot);\n"
            "\t\t\tRemoteCallResult res = yield builder.build (this).execute (cancellable);\n"
            "\t\t\tif (res.status != COMPLETED)\n"
            '\t\t\t\tthrow new Error.NOT_SUPPORTED ("Unexpected crash while trying to '
            'protect memory");\n'
            "\t\t\tif (res.return_value != 0)\n"
            '\t\t\t\tthrow new Error.NOT_SUPPORTED ("Unexpected failure while trying to '
            'protect memory");\n'
            "\t\t}\n\n"
            "\t\tpublic async void deallocate_memory (uint64 munmap_impl, uint64 address, "
            "size_t size, Cancellable? cancellable)",
            1,
            "add remote mprotect call",
        ),
    )
    for relative_path, old, new, expected_count, description in patches:
        count = replace_in_file(frida_dir / relative_path, old, new)
        if count != expected_count:
            raise BuildError(
                f"Strict W^X pattern occurred {count} times in "
                f"{relative_path.as_posix()}; expected {expected_count}"
            )
        log(f"  [required] {relative_path.as_posix()}: {description}", "OK")


def apply_port_patches(frida_dir: Path, port: int | None) -> None:
    """Apply only the configured listening-port replacement."""
    if port is not None and port != 27042:
        port_patches = get_port_patches(port)
        for patch in port_patches:
            for fpath in patch["files"]:
                full_path = frida_dir / fpath
                if full_path.exists():
                    count = replace_in_file(full_path, patch["pattern"], patch["replacement"])
                    if count:
                        log(f"  Port: {patch['description']} in {Path(fpath).name} ({count})", "OK")
        # Also do a global sweep for the port number in less obvious places
        count = replace_in_tree(frida_dir / "subprojects" / "frida-core", "27042", str(port))
        if count:
            log(f"  Port: global sweep found {count} more occurrences", "OK")


def apply_extended_patches(frida_dir: Path, custom_name: str, port: int | None):
    """Apply extended anti-detection patches beyond ajeossida."""
    log("=" * 60, "HEADER")
    log("PHASE 2.5: Extended anti-detection patches", "STEP")
    log("=" * 60, "HEADER")

    cap_name = custom_name[0].upper() + custom_name[1:]

    apply_port_patches(frida_dir, port)

    # --- D-Bus interface names ---
    # NOTE: Transport/D-Bus interface renames (re.frida.HostSession etc.) are DISABLED.
    # These interface names are part of the Frida client-server protocol.
    # Renaming them on the server breaks communication with the standard frida client.
    # They are NOT visible to other apps (only over USB/TCP channel), so not a detection vector.
    # The D-Bus service name (re.frida.server) IS renamed by global source patches — that's safe.

    # --- Selected GType identifiers ---
    internal_patches = get_internal_patches(custom_name, cap_name)
    for old, new in internal_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Internal: {old} -> {new} ({count})", "OK")

    # --- Temp file paths ---
    temp_patches = get_temp_path_patches(custom_name)
    for old, new in temp_patches:
        count = replace_in_tree(frida_dir, old, new)
        if count:
            log(f"  Temp paths: {old} -> {new} ({count})", "OK")

    log("Extended patches complete", "OK")


def apply_stability_fixes(frida_dir: Path, frida_major: int):
    """Apply optional stability/crash fixes."""
    log("Applying stability fixes...", "STEP")

    core_dir = frida_dir / "subprojects" / "frida-core"

    if frida_major >= 17:
        patches = get_stability_patches_17(frida_dir)
        for patch in patches:
            fpath = frida_dir / patch["file"]
            if fpath.exists():
                count = replace_in_file(fpath, patch["old"], patch["new"])
                if count:
                    log(f"  {patch['description']}", "OK")
                else:
                    log(f"  Pattern not found: {patch['description']}", "WARN")

    # DirListCloaker interceptor detach — safe to disable to prevent crash
    cloak = core_dir / "lib" / "payload" / "cloak.vala"
    if cloak.exists():
        # 17.x: DirListCloaker uses Gum.Interceptor.detach in destructor
        old = "Gum.Interceptor.obtain ().detach (listener);"
        new = "// Gum.Interceptor.obtain ().detach (listener);"
        count = replace_in_file(cloak, old, new)
        if count:
            log(f"  cloak.vala: disabled interceptor detach ({count})", "OK")

    log("Stability fixes complete", "OK")


# ============================================================================
# PHASE 3: Post-build patches (after first compilation)
# ============================================================================


def apply_post_build_patches(frida_dir: Path, custom_name: str):
    """Patch frida_agent_main symbol (generated during first build).

    Must include build/ directory because:
    - agent-glue.c (source) CALLS frida_agent_main
    - meson-generated_agent.c (build output) DEFINES frida_agent_main
    Both must be renamed together, otherwise linker error.
    """
    log("PHASE 3: Post-build patches (frida_agent_main)...", "STEP")
    count = replace_in_tree(
        frida_dir, "frida_agent_main", f"{custom_name}_agent_main", include_build=True
    )
    log(f"  frida_agent_main -> {custom_name}_agent_main ({count})", "OK")


# ============================================================================
# PHASE 4: Binary-level patches (after second compilation)
# ============================================================================


def find_dex_regions(data: bytes) -> list[tuple[int, int]]:
    """Find embedded DEX sections in binary data by scanning for DEX magic.
    Returns list of (start, end) byte ranges to protect from modification."""
    regions = []
    dex_magics = [b"dex\n035\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00"]
    for magic in dex_magics:
        idx = 0
        while True:
            pos = data.find(magic, idx)
            if pos == -1:
                break
            # Read header_size and file_size from DEX header
            if pos + 0x28 < len(data):
                file_size = struct.unpack_from("<I", data, pos + 0x20)[0]
                header_size = struct.unpack_from("<I", data, pos + 0x24)[0]
                # Valid DEX: header_size=112 (0x70), file_size > header_size
                if header_size == 112 and file_size > 112 and file_size < 10_000_000:
                    regions.append((pos, pos + file_size))
                    log(
                        f"    [dex] Protected DEX region: "
                        f"0x{pos:08x}-0x{pos + file_size:08x} ({file_size} bytes)",
                        "INFO",
                    )
            idx = pos + 8
    return regions


def find_elf_alloc_regions(data: bytes) -> list[tuple[int, int]]:
    """Return file ranges for ELF SHF_ALLOC sections, or the full range for non-ELF data."""
    if not data.startswith(b"\x7fELF"):
        return [(0, len(data))]
    if len(data) < 64:
        raise BuildError("ELF header is truncated")
    if data[5] != 1:
        raise BuildError("Only little-endian ELF artifacts are supported")

    elf_class = data[4]
    if elf_class == 2:
        section_table_offset = struct.unpack_from("<Q", data, 0x28)[0]
        section_header_size = struct.unpack_from("<H", data, 0x3A)[0]
        section_count = struct.unpack_from("<H", data, 0x3C)[0]
        minimum_section_header_size = 64
        flags_offset, flags_format = 8, "<Q"
        file_offset_offset, size_offset, value_format = 24, 32, "<Q"
    elif elf_class == 1:
        section_table_offset = struct.unpack_from("<I", data, 0x20)[0]
        section_header_size = struct.unpack_from("<H", data, 0x2E)[0]
        section_count = struct.unpack_from("<H", data, 0x30)[0]
        minimum_section_header_size = 40
        flags_offset, flags_format = 8, "<I"
        file_offset_offset, size_offset, value_format = 16, 20, "<I"
    else:
        raise BuildError(f"Unsupported ELF class: {elf_class}")

    if section_table_offset == 0 or section_header_size < minimum_section_header_size:
        raise BuildError("ELF section table is missing or invalid")
    if section_table_offset + section_header_size > len(data):
        raise BuildError("ELF section table starts outside the artifact")
    if section_count == 0:
        section_count = int(
            struct.unpack_from(value_format, data, section_table_offset + size_offset)[0]
        )
    if section_count == 0:
        raise BuildError("ELF contains no section headers")
    if section_table_offset + (section_count * section_header_size) > len(data):
        raise BuildError("ELF section table extends outside the artifact")

    regions = []
    for index in range(section_count):
        header = section_table_offset + (index * section_header_size)
        section_type = struct.unpack_from("<I", data, header + 4)[0]
        flags = struct.unpack_from(flags_format, data, header + flags_offset)[0]
        file_offset = int(struct.unpack_from(value_format, data, header + file_offset_offset)[0])
        size = int(struct.unpack_from(value_format, data, header + size_offset)[0])
        if flags & 0x2 == 0 or section_type == 8 or size == 0:
            continue
        if file_offset + size > len(data):
            raise BuildError(f"ELF allocated section {index} extends outside the artifact")
        regions.append((file_offset, file_offset + size))
    if not regions:
        raise BuildError("ELF contains no file-backed SHF_ALLOC sections")
    return regions


def replace_bytes_in_regions(
    data: bytes,
    old: bytes,
    new: bytes,
    include_regions: list[tuple[int, int]],
    skip_regions: list[tuple[int, int]],
) -> tuple[bytes, int]:
    """Replace a same-length pattern only inside included, non-protected file ranges."""
    assert len(old) == len(new), "Replacement must be same length"
    result = bytearray(data)
    count = 0
    offset = 0
    while True:
        position = data.find(old, offset)
        if position == -1:
            break
        end = position + len(old)
        included = any(start <= position and end <= stop for start, stop in include_regions)
        protected = any(position < stop and end > start for start, stop in skip_regions)
        if included and not protected:
            result[position:end] = new
            count += 1
        offset = position + 1
    return bytes(result), count


def apply_binary_patches(binary_path: Path, custom_name: str, extended: bool = False):
    """Apply hex-level patches to compiled binaries.
    DEX-aware: protects embedded DEX sections from string sweep corruption."""
    data = binary_path.read_bytes()
    original_size = len(data)
    patched = False

    alloc_regions = find_elf_alloc_regions(data)
    dex_regions = find_dex_regions(data)

    runtime_patches = [*get_memory_signature_patches(custom_name), *get_binary_patches()]
    for old_hex, new_hex, description in runtime_patches:
        old_bytes = bytes.fromhex(old_hex)
        new_bytes = bytes.fromhex(new_hex)
        if old_bytes in data:
            data, count = replace_bytes_in_regions(
                data, old_bytes, new_bytes, alloc_regions, dex_regions
            )
            if count:
                log(f"    {description} ({count}x in SHF_ALLOC)", "OK")
                patched = True

    # Extended: sweep for residual "frida" strings in binary
    # MUST skip DEX regions to avoid corrupting embedded helper DEX
    if extended:
        for old_hex, new_hex, description in get_binary_string_patches(custom_name):
            old_bytes = bytes.fromhex(old_hex)
            new_bytes = bytes.fromhex(new_hex)
            if old_bytes in data:
                data, count = replace_bytes_in_regions(
                    data, old_bytes, new_bytes, alloc_regions, dex_regions
                )
                if count:
                    log(f"    [ext] {description} ({count}x, skipped DEX regions)", "OK")
                    patched = True

    if patched:
        assert len(data) == original_size, "Binary size changed — patches are not same-length!"
        binary_path.write_bytes(data)


# ============================================================================
# Build
# ============================================================================


def configure_arch(frida_dir: Path, arch: str, ndk_path: Path):
    log(f"Configuring for {arch}...", "STEP")
    run(
        ["./configure", f"--host={arch}"],
        cwd=frida_dir,
        env={"ANDROID_NDK_ROOT": str(ndk_path)},
    )


def build_frida(frida_dir: Path, ndk_path: Path):
    cpus = os.cpu_count() or 4
    log(f"Building ({cpus} threads)...", "STEP")
    run(
        ["make", f"-j{cpus}"],
        cwd=frida_dir,
        env={"ANDROID_NDK_ROOT": str(ndk_path)},
    )


def strip_binary(binary_path: Path, strip_tool: Path) -> None:
    """Remove symbols and non-runtime sections from a staged shared library."""
    before = binary_path.stat().st_size
    run([strip_tool, "--strip-unneeded", binary_path])
    after = binary_path.stat().st_size
    log(f"    stripped {binary_path.name}: {before:,} -> {after:,} bytes", "OK")


# ============================================================================
# Collect artifacts
# ============================================================================


@contextmanager
def output_transaction(output_dir: Path) -> Iterator[Path]:
    """Replace the complete output set only after every build step succeeds."""
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if output_dir.exists() and not output_dir.is_dir():
        raise BuildError(f"Output path is not a directory: {output_dir}")

    prefix = f".{output_dir.name}-transaction-"
    with TemporaryDirectory(dir=output_dir.parent, prefix=prefix) as temporary:
        transaction_dir = Path(temporary)
        staged_output = transaction_dir / "next"
        staged_output.mkdir()
        yield staged_output

        previous_output = transaction_dir / "previous"
        had_previous_output = output_dir.exists()
        if had_previous_output:
            os.replace(output_dir, previous_output)
        try:
            os.replace(staged_output, output_dir)
        except OSError as error:
            if had_previous_output:
                os.replace(previous_output, output_dir)
            raise BuildError(f"Could not promote verified output directory: {error}") from error


def collect_artifacts(
    frida_dir: Path,
    arch: str,
    custom_name: str,
    version: str,
    output_dir: Path,
    extended: bool,
    *,
    strip_tool: Path | None = None,
) -> list[Path]:
    """Stage, verify, and promote mandatory build artifacts."""
    log(f"Collecting artifacts for {arch}...", "STEP")

    arch_short = arch.replace("android-", "")

    def find_artifact(subdir: str, patterns: list[str]) -> Path | None:
        base = frida_dir / "build" / "subprojects" / "frida-core" / subdir
        for pattern in patterns:
            candidate = base / pattern
            if candidate.is_file():
                return candidate
        # List directory for debugging
        if base.exists():
            log(f"    Looking in {base}:", "INFO")
            for f in sorted(base.iterdir()):
                if f.is_file() and f.stat().st_size > 1000:
                    log(f"      {f.name} ({f.stat().st_size:,} bytes)", "INFO")
        return None

    def save_artifact(
        src: Path,
        out_name: str,
        stage_dir: Path,
        *,
        strip: bool = False,
    ) -> list[Path]:
        out_bin = stage_dir / out_name
        shutil.copy2(src, out_bin)
        os.chmod(out_bin, 0o755)
        if strip and strip_tool is not None:
            strip_binary(out_bin, strip_tool)

        out_gz = stage_dir / f"{out_name}.gz"
        with out_bin.open("rb") as source, out_gz.open("wb") as raw_output:
            with gzip.GzipFile(
                filename=out_bin.name,
                mode="wb",
                fileobj=raw_output,
                mtime=0,
            ) as compressed:
                shutil.copyfileobj(source, compressed)
        log(
            f"    -> {out_gz.name} ({out_gz.stat().st_size / 1024 / 1024:.1f} MB)",
            "OK",
        )
        return [out_bin, out_gz]

    server = find_artifact(
        "server",
        [
            f"{custom_name}-server",
            f"{custom_name}-server-raw",
            "frida-server",
            "frida-server-raw",
        ],
    )
    if server is None:
        raise BuildError(f"Server artifact not found for {arch}")

    gadget = find_artifact(
        "lib/gadget",
        [
            f"lib{custom_name}-gadget.so",
            f"lib{custom_name}-gadget-modulated.so",
            "libfrida-gadget.so",
            "libfrida-gadget-modulated.so",
        ],
    )
    if gadget is None:
        raise BuildError(f"Gadget artifact not found for {arch}")

    agent = find_artifact(
        "lib/agent",
        [
            f"lib{custom_name}-agent.so",
            f"lib{custom_name}-agent-modulated.so",
            f"lib{custom_name}-agent-raw.so",
            "libfrida-agent.so",
            "libfrida-agent-modulated.so",
        ],
    )

    log(f"  Server: {server.name}", "OK")
    log(f"  Gadget: {gadget.name}", "OK")
    apply_binary_patches(server, custom_name, extended)
    apply_binary_patches(gadget, custom_name, extended)
    if agent is not None:
        log(f"  Agent: {agent.name}", "OK")
        apply_binary_patches(agent, custom_name, extended)

    output_dir.mkdir(parents=True, exist_ok=True)
    promoted: list[Path] = []
    with TemporaryDirectory(dir=output_dir, prefix=".staging-") as temporary:
        stage_dir = Path(temporary)
        staged = [
            *save_artifact(
                server,
                f"{custom_name}-server-{version}-android-{arch_short}",
                stage_dir,
            ),
            *save_artifact(
                gadget,
                f"{custom_name}-gadget-{version}-android-{arch_short}.so",
                stage_dir,
                strip=True,
            ),
        ]

        for artifact in staged:
            if artifact.suffix != ".gz":
                verify_binary(artifact)

        for artifact in sorted(staged, key=lambda path: path.name):
            destination = output_dir / artifact.name
            os.replace(artifact, destination)
            promoted.append(destination)

    return promoted


# ============================================================================
# Verification
# ============================================================================


def scan_forbidden_markers(binary_path: Path) -> dict[str, int]:
    """Count runtime markers that indicate an invalid output artifact."""
    if not binary_path.is_file():
        raise BuildError(f"Binary artifact is missing: {binary_path}")
    data = binary_path.read_bytes()
    return {
        marker.decode("ascii", errors="backslashreplace"): data.count(marker)
        for marker in FORBIDDEN_BINARY_MARKERS
        if marker in data
    }


def verify_binary(binary_path: Path) -> None:
    """Reject compiled artifacts containing known forbidden runtime markers."""
    findings = scan_forbidden_markers(binary_path)
    if findings:
        details = ", ".join(f"{marker} x{count}" for marker, count in findings.items())
        raise BuildError(f"Forbidden runtime markers in {binary_path.name}: {details}")
    log(f"  {binary_path.name}: forbidden-marker scan passed", "OK")


def git_revision(path: Path) -> str:
    """Return the exact Git revision for a repository or submodule."""
    result = run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True)
    revision = (result.stdout or "").strip()
    if not revision:
        raise BuildError(f"Could not resolve git revision for {path}")
    return revision


def create_build_info(
    *,
    builder_dir: Path,
    frida_dir: Path,
    name: str,
    port: int | None,
    version: str,
    architectures: list[str],
    strict_wx: bool = False,
) -> dict[str, object]:
    """Create release provenance for the builder and upstream source revisions."""
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    workflow_url = (
        f"https://github.com/{repository}/actions/runs/{run_id}" if repository and run_id else None
    )
    return {
        "architectures": architectures,
        "builder_commit": git_revision(builder_dir),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "frida_commit": git_revision(frida_dir),
        "frida_core_commit": git_revision(frida_dir / "subprojects/frida-core"),
        "frida_version": version,
        "name": name,
        "ndk_version": NDK_VERSION,
        "port": port or 27042,
        "strict_wx": strict_wx,
        "workflow_url": workflow_url,
    }


def write_release_assets(
    output_dir: Path,
    *,
    builder_dir: Path,
    frida_dir: Path,
    name: str,
    port: int | None,
    version: str,
    architectures: list[str],
    strict_wx: bool = False,
) -> tuple[Path, Path]:
    """Write deterministic metadata JSON and checksums for release artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    info_path = output_dir / "build-info.json"
    sums_path = output_dir / "SHA256SUMS"
    info = create_build_info(
        builder_dir=builder_dir,
        frida_dir=frida_dir,
        name=name,
        port=port,
        version=version,
        architectures=architectures,
        strict_wx=strict_wx,
    )
    info_path.write_text(
        json.dumps(info, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    artifacts = sorted(
        path
        for path in output_dir.iterdir()
        if path.is_file() and path.name not in {info_path.name, sums_path.name}
    )
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in artifacts]
    sums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return info_path, sums_path


# ============================================================================
# Main
# ============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Build custom anti-detection Frida server from source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build.py --version 17.16.4
  python3 build.py --version 17.16.4 --name stealth --port 27142
  python3 build.py --version 17.16.4 --arch android-arm64,android-arm --extended
  python3 build.py --version 17.16.4 --skip-build  # patch only, no compilation
  python3 build.py --version 17.16.4 --temp-fixes  # add stability patches

Transformations and verification boundaries:
"""
        + DETECTION_VECTORS,
    )

    parser.add_argument(
        "--version", "-v", required=True, help="Frida version to build (e.g. 17.16.4)"
    )
    parser.add_argument(
        "--arch",
        "-a",
        default="android-arm64",
        help=f"Comma-separated architectures. Options: {', '.join(ALL_ARCHS)}",
    )
    parser.add_argument(
        "--name", "-n", default="ajeossida", help="Replacement for supported internal identifiers"
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        help="Custom listening port (default: 27042 unchanged)",
    )
    parser.add_argument(
        "--extended",
        "-e",
        action="store_true",
        help="Apply optional port, GType, path, and byte transformations",
    )
    parser.add_argument(
        "--temp-fixes",
        action="store_true",
        help="Apply stability fixes (perfetto skip, cloak detach)",
    )
    parser.add_argument(
        "--strict-wx",
        action="store_true",
        help="Harden Frida-owned persistent anonymous RWX mappings on Android",
    )
    parser.add_argument(
        "--work-dir", "-w", default=None, help="Working directory (default: ./build)"
    )
    parser.add_argument(
        "--output-dir", "-o", default=None, help="Output directory (default: ./output)"
    )
    parser.add_argument(
        "--ndk-path", default=None, help="Path to existing Android NDK r29 (skip download)"
    )
    parser.add_argument("--skip-clone", action="store_true", help="Use existing source in work-dir")
    parser.add_argument(
        "--skip-build", action="store_true", help="Only apply patches, don't compile"
    )
    parser.add_argument(
        "--verify", action="store_true", help="Reject known forbidden markers in final artifacts"
    )

    args = parser.parse_args()

    # Validate
    version = validate_version(args.version)
    frida_major = detect_frida_major(version)
    custom_name = validate_custom_name(args.name)
    archs = parse_architectures(args.arch)
    port = validate_port(args.port)
    validate_build_prerequisites(skip_build=args.skip_build)

    # Directories
    script_dir = Path(__file__).parent.resolve()
    work_dir, output_dir = validate_directory_layout(
        script_dir,
        Path(args.work_dir) if args.work_dir else script_dir / "build",
        Path(args.output_dir) if args.output_dir else script_dir / "output",
    )
    work_dir.mkdir(parents=True, exist_ok=True)

    # Banner
    log("=" * 60, "HEADER")
    log("Custom Frida Builder", "HEADER")
    log("=" * 60, "HEADER")
    log(f"  Version:  Frida {version} (major: {frida_major})", "INFO")
    log(f"  Name:     '{custom_name}'", "INFO")
    log(f"  Archs:    {', '.join(archs)}", "INFO")
    log(f"  Port:     {port or '27042 (default)'}", "INFO")
    log(f"  Extended: {args.extended}", "INFO")
    log(f"  Strict W^X: {args.strict_wx}", "INFO")
    log(f"  Work dir: {work_dir}", "INFO")
    log(f"  Output:   {output_dir}", "INFO")

    # Step 1: NDK
    if args.ndk_path:
        ndk_path = validate_ndk(Path(args.ndk_path).resolve())
    else:
        ndk_path = ensure_ndk(work_dir)
    log(f"  NDK:      {ndk_path}", "INFO")

    # Step 2: Clone
    frida_dir = work_dir / "frida"
    if not args.skip_clone:
        if frida_dir.exists():
            log("Removing existing frida dir...", "WARN")
            shutil.rmtree(frida_dir)
        frida_dir = clone_frida(version, work_dir)
    else:
        if not frida_dir.exists():
            raise BuildError("--skip-clone requires existing source in work-dir")
        log(f"Using existing source at {frida_dir}", "OK")

    # Step 2.5: Apply page patch (XOM-safe zygote injection) before the renames
    apply_page_patch(frida_dir)

    # Step 3: Source patches
    apply_source_patches(frida_dir, custom_name)
    apply_targeted_patches(frida_dir, custom_name, frida_major)

    # Step 3.1: NDK r29 libc++ <fstream> compat (frida releng vs newer NDK)
    apply_ndk29_fstream_patch(frida_dir)

    if args.strict_wx:
        apply_strict_wx_patch(frida_dir, custom_name)

    # Step 3.5: Extended patches
    if args.extended:
        apply_extended_patches(frida_dir, custom_name, port)
    elif port:
        apply_port_patches(frida_dir, port)

    # Step 4: Stability fixes
    if args.temp_fixes:
        apply_stability_fixes(frida_dir, frida_major)

    if args.skip_build:
        log("=" * 60, "HEADER")
        log("Patches applied. Build skipped (--skip-build).", "OK")
        log(f"Source ready at: {frida_dir}", "INFO")
        log("To build manually:", "INFO")
        log(f"  cd {frida_dir}", "INFO")
        log(f"  ANDROID_NDK_ROOT={ndk_path} ./configure --host=android-arm64", "INFO")
        log(f"  ANDROID_NDK_ROOT={ndk_path} make -j$(nproc)", "INFO")
        return

    with output_transaction(output_dir) as staged_output:
        strip_tool = find_llvm_strip(ndk_path)
        # Step 5: Build loop
        for arch in archs:
            log("=" * 60, "HEADER")
            log(f"Building for {arch}", "STEP")
            log("=" * 60, "HEADER")

            # Multi-arch support: undo the frida_agent_main rename that the
            # previous architecture's post-build phase persisted in the source
            # tree (include_build=True). Each architecture's fresh build tree
            # regenerates the Vala declaration as frida_agent_main, so the
            # source tree must call the original symbol again before
            # configuring; otherwise the first build of this architecture
            # mismatches declaration and call site.
            reset_count = replace_in_tree(
                frida_dir, f"{custom_name}_agent_main", "frida_agent_main"
            )
            if reset_count:
                log(
                    f"  Reset {custom_name}_agent_main -> frida_agent_main "
                    f"in source ({reset_count})",
                    "OK",
                )

            # Configure
            configure_arch(frida_dir, arch, ndk_path)

            # First build
            log("First build...", "STEP")
            build_frida(frida_dir, ndk_path)

            # Post-build patches (frida_agent_main appears only after first build)
            apply_post_build_patches(frida_dir, custom_name)

            # Second build (incremental — only recompiles files with patched symbol)
            log("Second build (incremental)...", "STEP")
            build_frida(frida_dir, ndk_path)

            # Collect and binary-patch artifacts
            collect_artifacts(
                frida_dir,
                arch,
                custom_name,
                version,
                staged_output,
                args.extended,
                strip_tool=strip_tool,
            )

        # Step 6: Verification
        if args.verify:
            log("=" * 60, "HEADER")
            log("Verification: scanning for residual 'frida' strings...", "STEP")
            for f in sorted(staged_output.iterdir()):
                if f.is_file() and not f.name.endswith(".gz"):
                    verify_binary(f)

        write_release_assets(
            staged_output,
            builder_dir=script_dir,
            frida_dir=frida_dir,
            name=custom_name,
            port=port,
            version=version,
            architectures=archs,
            strict_wx=args.strict_wx,
        )

    # Done
    log("=" * 60, "HEADER")
    log("BUILD COMPLETE", "OK")
    log(f"Artifacts in: {output_dir}", "OK")
    for f in sorted(output_dir.iterdir()):
        size_mb = f.stat().st_size / (1024 * 1024)
        log(f"  {f.name} ({size_mb:.1f} MB)", "OK")

    # Usage hint
    log("", "INFO")
    log("To deploy:", "STEP")
    arch_short = archs[0].replace("android-", "")
    server_name = f"{custom_name}-server-{version}-android-{arch_short}"
    log(f"  adb push output/{server_name} /data/local/tmp/{custom_name}-server", "INFO")
    log(f"  adb shell chmod 755 /data/local/tmp/{custom_name}-server", "INFO")
    log(f"  adb shell /data/local/tmp/{custom_name}-server &", "INFO")
    if port:
        log(f"  frida -H 127.0.0.1:{port} -f <package>", "INFO")
    else:
        log("  frida -U -f <package>", "INFO")


if __name__ == "__main__":
    try:
        main()
    except BuildError as error:
        log(str(error), "ERROR")
        raise SystemExit(1) from error
