import sys
import pathlib
import itertools
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


main = record_args
