# Several tools expect that they can interact with a venv through pip.
# This module can be installed into a virtpy via `virtpy new --with-pip-shim`
# instead of pip and will translate and forward commands to virtpy.
#
# This allows transparent usage of virtpy by tools that are not aware of it
# (which is just like every single one of them)
#
# EXTREMELY incomplete and brittle.

import sys
import pathlib
import os.path
import itertools
import time
import subprocess
from typing import List, Optional


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

    def _record_time(time_taken: float, success: bool):
        args = " ".join(sys.argv[1:])
        status = "✅" if success else "❌"
        with open(log_file, "a") as f:
            print(f"{status} {time_taken:4.3}: {args}", file=f)

    start = time.time()
    try:
        operation()
        time_taken = time.time() - start
        _record_time(time_taken, True)
    except:
        time_taken = time.time() - start
        _record_time(time_taken, False)
        raise


# TODO: add real argument parser.
# TODO: make it work with `python3 -m pip`.
#       Calling the shim like that changes the number of arguments in sys.argv and
#       breaks the logic below.
#       It can currently only be called via `pip $ARGS...`
def main() -> None:
    if sys.argv[1:3] == ["install", "--no-deps"] and len(sys.argv) == 4:
        record_time(lambda: install_package_from_file(sys.argv[-1]))
    elif sys.argv[1] == "uninstall" and sys.argv[3] == "-y" and len(sys.argv) == 4:
        record_time(uninstall_package)
    elif (
        sys.argv[1:4] == ["install", "--no-deps", "-U"]
        and len(sys.argv) == 5
        and os.path.isdir(sys.argv[4])
    ):
        record_time(lambda: install_package_from_folder(sys.argv[-1]))
    elif sys.argv[1:] == ["--version"]:
        # poetry runs this version check before running the install command above.
        # I have no idea what it is looking for, but it continues even if we
        # print nothing.
        pass
    else:
        # noop = lambda: None

        def fail() -> None:
            raise Exception("unknown command")

        # Log the command, but don't do anything
        record_time(fail)
        # record_time(noop)


def install_package_from_file(package_path: str) -> None:
    prefix = "file:///" if os.name == "nt" else "file://"
    if package_path.startswith(prefix):
        package_path = package_path[len(prefix) :]

    _install_package(package_path)


def install_package_from_folder(package_path: str) -> None:
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
        # TODO: make sure this is the global python
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
                ".venv/src/pendulum/",
            ],
            check=True,
        )
        pattern = os.path.join(directory, f"{package_name}-*.whl")
        print(pattern)
        print(type(directory))
        print(os.listdir(directory))
        output_files = glob.glob(pattern)
        assert len(output_files) == 1, f"{output_files=}"
        _install_package(output_files[0])


def _install_package(package_path: str) -> None:
    if not os.path.abspath(package_path):
        return

    virtpy = virtpy_path()
    assert virtpy is not None

    subprocess.run(
        [
            *virtpy_cmd(virtpy),
            "internal-use-only",
            "add-from-file",
            virtpy,
            package_path,
        ],
        check=True,
    )


def uninstall_package() -> None:
    package_name = sys.argv[2]
    assert not package_name.startswith("-")

    virtpy = virtpy_path()
    assert virtpy is not None

    subprocess.run(
        [*virtpy_cmd(virtpy), "remove", "--virtpy-path", virtpy, package_name],
        check=True,
    )


def virtpy_cmd(venv_path: str) -> List[str]:
    metadata = os.path.join(venv_path, "virtpy_link_metadata")
    virtpy_exe = open(os.path.join(metadata, "virtpy_exe")).read()
    proj_dir = open(os.path.join(metadata, "proj_dir")).read()
    return [virtpy_exe, "--project-dir", proj_dir]
