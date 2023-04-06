# Several tools expect that they can interact with a venv through pip.
# This module is installed by default into all virtpys and will translate and
# forward commands to virtpy.
#
# This allows transparent usage of virtpy by tools that are not aware of it
# (which is just, like, every single one of them)
#
# EXTREMELY incomplete
from __future__ import annotations

import argparse
import sys
import pathlib
import os.path
import itertools
import time
import subprocess
from typing import List, Optional, Union


def virtpy_path() -> Optional[pathlib.Path]:
    path = pathlib.Path(__file__)
    # linux:   venv/lib/python3.X/site-packages/pip
    # windows: venv/lib/site-packages/pip              (I think)
    # So the venv dir is either the 3rd or 4th parent.
    parents = itertools.islice(iter(path.parents), 3, 5)

    path = next(
        (p for p in parents if p.joinpath("virtpy_link_metadata").exists()),
        None,
    )
    return path


def record_time(operation) -> None:
    virtpy = virtpy_path()
    if virtpy is None:
        print("pip_shim: failed to detect virtpy path")
        return

    log_file = virtpy.joinpath("virtpy_link_metadata", "pip_shim.log")

    def _record_time(time_taken: float, success: bool, message: Optional[str] = None):
        args = " ".join(sys.argv[1:])
        status = "✅" if success else "❌"
        with open(log_file, "a", encoding="utf8") as f:
            message = f": {message}" if message is not None else ""
            print(f"{status} {time_taken:4.3}: {args}{message}", file=f)

    start = time.time()
    try:
        operation()
        time_taken = time.time() - start
        _record_time(time_taken, True)
    except Exception as e:
        time_taken = time.time() - start
        _record_time(time_taken, False, str(e))
        raise


# Taken from argparse docs.
# The standard argparse exits the program on any argument error.
# We want to log ALL invocations of this shim however, so we need to catch
# those cases.
class ErrorCatchingArgumentParser(argparse.ArgumentParser):
    def exit(self, status=0, message=None):
        if status:
            raise Exception(f"Exiting because of an error: {message}")
        exit(status)


def main() -> None:
    parser = ErrorCatchingArgumentParser()

    # Only used when no subcommand overwrites func
    def require_version_or_subcommand(args: argparse.Namespace) -> None:
        if args.version:
            # poetry runs a pip version check before running the install command
            # `install --no-deps -U path/to/package/git/repo`
            # I have no idea what it is looking for in the version, but it
            # continues even if we print nothing.
            pass
        else:
            parser.print_help()

    parser.set_defaults(func=require_version_or_subcommand)
    parser.add_argument("--version", action="store_true")
    subcommands = parser.add_subparsers(title="Commands")
    add_install_subcommand(subcommands)
    add_uninstall_subcommand(subcommands)

    def parse_and_run() -> None:
        args = parser.parse_args()
        args.func(args)

    try:
        record_time(parse_and_run)
    except Exception as e:
        print(f"{e}", file=sys.stderr)
        sys.exit(1)


def add_install_subcommand(
    argparser: argparse._SubParsersAction,
) -> None:
    cmd = argparser.add_parser("install")
    cmd.add_argument(
        "--no-deps", required=True, action="store_true"
    )  # required, we never add deps
    cmd.add_argument(
        "-U", "--upgrade", action="store_true"
    )  # TODO: add logic using this
    cmd.add_argument("path")
    # ignored
    cmd.add_argument("--disable-pip-version-check", action="store_true")
    # ignored
    cmd.add_argument("--prefix")
    # forwarded to pip wheel conversion
    cmd.add_argument("--use-pep517", action="store_true")

    def install(args: argparse.Namespace) -> None:
        # CAREFUL! Impossible to typecheck args.
        package_path = args.path
        prefix = "file:///" if os.name == "nt" else "file://"
        if package_path.startswith(prefix):
            package_path = package_path[len(prefix) :]
        if os.path.isfile(package_path):
            install_package_from_file(package_path, args.use_pep517)
        elif os.path.isdir(args.path):
            install_package_from_folder(package_path, args.use_pep517)
        else:
            raise Exception("Not a path to a file or folder")

    cmd.set_defaults(func=install)


def add_uninstall_subcommand(
    argparser: argparse._SubParsersAction,
) -> None:
    cmd = argparser.add_parser("uninstall")
    cmd.add_argument(
        "-y", "--yes", required=True, action="store_true"
    )  # required, we never prompt
    cmd.add_argument("package")  # TODO: allow multiple

    def uninstall(args: argparse.Namespace) -> None:
        # CAREFUL! Impossible to typecheck args.
        uninstall_package(args.package)

    cmd.set_defaults(func=uninstall)


def install_package_from_folder(package_path: str, use_pep517: bool) -> None:
    import tempfile
    import glob

    package_name = os.path.basename(package_path) or os.path.basename(
        os.path.dirname(package_path)
    )
    virtpy = virtpy_path()
    assert virtpy is not None

    global_python = subprocess.run(
        [*virtpy_cmd(virtpy), "internal-use-only", "global-python", virtpy],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.rstrip("\n")

    with tempfile.TemporaryDirectory() as directory:
        subprocess.run(
            [
                global_python,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-cache-dir",
                "--wheel-dir",
                directory,
                package_path,
                *(["--use-pep517"] if use_pep517 else []),
            ],
            check=True,
        )
        pattern = os.path.join(directory, f"{package_name}-*.whl")
        print(pattern)
        print(type(directory))
        print(os.listdir(directory))
        output_files = glob.glob(pattern)
        assert len(output_files) == 1, f"{output_files=}"
        # forwarding use_pep517 here would have no effect, because it's already a wheel
        install_package_from_file(output_files[0], False)


def install_package_from_file(package_path: str, use_pep517: bool) -> None:
    if not os.path.abspath(package_path):
        return

    virtpy = virtpy_path()
    assert virtpy is not None

    strategy = check_strategy(virtpy)
    strategy_args = ["--check-strategy", strategy] if strategy is not None else []

    subprocess.run(
        [
            *virtpy_cmd(virtpy),
            "internal-use-only",
            "add-from-file",
            virtpy,
            package_path,
            *strategy_args,
            *(["--use-pep517"] if use_pep517 else []),
        ],
        check=True,
    )


def uninstall_package(package_name: str) -> None:
    assert not package_name.startswith("-")

    virtpy = virtpy_path()
    assert virtpy is not None

    subprocess.run(
        [*virtpy_cmd(virtpy), "remove", "--virtpy-path", virtpy, package_name],
        check=True,
    )


def virtpy_cmd(venv_path: Union[str, pathlib.Path]) -> List[str]:
    metadata = os.path.join(venv_path, "virtpy_link_metadata")
    virtpy_exe = open(os.path.join(metadata, "virtpy_exe")).read()
    proj_dir = open(os.path.join(metadata, "proj_dir")).read()
    return [virtpy_exe, "--project-dir", proj_dir]


def check_strategy(venv_path: Union[str, pathlib.Path]) -> Optional[str]:
    try:
        metadata = os.path.join(venv_path, "virtpy_link_metadata")
        return open(os.path.join(metadata, "wheel_check_strategy")).read().strip()
    except FileNotFoundError:
        return None
