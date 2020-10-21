# virtpy

virtpy creates Python [venv](https://docs.python.org/3/library/venv.html)s where all the dependencies are symlinked in from a central store. This makes each individual virtpy environment very lightweight.

The name stands for <b>virt</b>ual <b>py</b>thon and is subject to change. The entire project is an early prototype. Expect bugs and crashes.

# Requirements
* Python3  
  with a modern-ish pip installed. It should also have the `wheel` module available for greater compatibility.  
  This program requires all the modules it manages to be available as wheels or convertible into wheels.
  Behind the scenes, it installs packages using pip into a temporary directory and then moves them
  from there to the internal store (at least for now).  
  When `wheel` is installed, pip will automatically convert many non-wheel packages to wheels.
* (Optional) Poetry
  The demo commands `poetry-install` and `install` both require [poetry](https://github.com/python-poetry/poetry).

# Create and Add Dependencies

`virtpy new` creates a new barebones venv named '.virtpy' in the current directory.  
`virtpy add PATH_TO_REQUIREMENTS.TXT` adds the packages from the file to the `.virtpy` environment in the current directory.

These two commands form the core functionality of this tool.

# Install python executables in isolated environments
`virtpy install PACKAGE` installs `PACKAGE` into a virtpy in this tool's data directory (see [directories::ProjectDirs::data_dir()](https://docs.rs/directories/3.0.1/directories/struct.ProjectDirs.html#method.data_dir)) and places executables in a central location that you can add to your path `${virtpy_data_dir}/bin`.

This is similar to [pipx](https://pypi.org/project/pipx/), but it uses virtpy for isolation insted of venv.

# Create venv from poetry
`virtpy poetry-install` does the job that `poetry install` does, but uses `virtpy` instead of `venv`.
