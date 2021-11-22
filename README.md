# virtpy

virtpy creates Python [venv](https://docs.python.org/3/library/venv.html)s where all the dependencies are symlinked in from a central store. Dependencies that are used in multiple venvs are only stored once on disk. This makes each individual virtpy environment very lightweight.

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

`virtpy new [VENV_PATH]` creates a new barebones venv at `VENV_PATH` or at '.venv' in the current directory, if no path is given.  

There are currently two ways to install dependencies into the virtpy:
1. `virtpy add PATH_TO_REQUIREMENTS.TXT` adds the packages from the file to the `.virtpy` environment in the current directory.
   This uses pip behind the scenes to select the right package to download and install.
2. Use `poetry`. `poetry add`, `poetry install` and `poetry remove` all work thanks to a shim. Poetry itself uses pip to install or remove packages and `virtpy` adds a pseudo `pip` package that redirects the commands to `virtpy`.

This forms the core functionality of this tool.

# Install python executables in isolated environments
`virtpy install PACKAGE` installs `PACKAGE` into a virtpy in this tool's data directory (see [directories::ProjectDirs::data_dir()](https://docs.rs/directories/3.0.1/directories/struct.ProjectDirs.html#method.data_dir)) and places executables in a central location that you can add to your path.
Run `virtpy path bin` to get the directory to add to your `PATH`.

This is similar to [pipx](https://pypi.org/project/pipx/), but it uses virtpy for isolation insted of venv.
