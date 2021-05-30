from pathlib import Path
import shutil

script_dir = Path(__file__).parent

shutil.make_archive(
    script_dir.joinpath("pip_shim"),
    "zip",
    script_dir.joinpath("pip"),
    ".",
)
