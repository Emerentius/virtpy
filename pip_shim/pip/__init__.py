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
import subprocess
from typing import Optional


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


def record_args() -> None:
    virtpy = virtpy_path()
    if virtpy is None:
        print("pip_shim: failed to detect virtpy path")
        return

    log_file = virtpy.joinpath("virtpy_link_metadata", "pip_shim.log")
    with open(log_file, "a") as f:
        print(" ".join(sys.argv[1:]), file=f)


# TODO: add real argument parser.
# TODO: make it work with `python3 -m pip`.
#       Calling the shim like that changes the number of arguments in sys.argv and
#       breaks the logic below.
#       It can currently only be called via `pip $ARGS...`
def main() -> None:
    record_args()

    if sys.argv[1:3] == ["install", "--no-deps"] and len(sys.argv) == 4:
        install_package()

    if sys.argv[1] == "uninstall" and sys.argv[3] == "-y" and len(sys.argv) == 4:
        uninstall_package()


def install_package():
    package_path = sys.argv[3]
    prefix = "file://"
    if package_path.startswith(prefix):
        package_path = package_path[len(prefix) :]

    if not os.path.abspath(package_path):
        return

    virtpy = virtpy_path()
    assert virtpy is not None

    subprocess.run(
        ["virtpy", "internal-use-only", "add-from-file", virtpy, package_path],
        check=True,
    )


def uninstall_package():
    package_name = sys.argv[2]
    assert not package_name.startswith("-")

    virtpy = virtpy_path()
    assert virtpy is not None

    subprocess.run(
        ["virtpy", "remove", "--virtpy-path", virtpy, package_name], check=True
    )
