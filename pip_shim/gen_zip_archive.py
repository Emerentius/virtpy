import shutil
from pathlib import Path

script_dir = Path(__file__).parent

shutil.make_archive(
    script_dir.joinpath("pip_shim"),  # type: ignore
    "zip",
    script_dir.joinpath("pip"),
    ".",
)
