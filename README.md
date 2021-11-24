# virtpy

virtpy creates Python [venv](https://docs.python.org/3/library/venv.html)s where all the dependencies are symlinked in from a central store. Dependencies that are used in multiple venvs are only stored once on disk. This makes each individual virtpy environment very lightweight.

The name stands for <b>virt</b>ual <b>py</b>thon and is subject to change. The entire project is an early prototype. Expect bugs and crashes.

# Requirements
* Python3  
  with
  * a modern-ish pip version
  * the `wheel` module available globally for python.
    It should be installed for every python version you intend to use with virtpy. It is not strictly required, but needed
    for installing non-wheel packages by converting them into wheels first.
* [Poetry](https://github.com/python-poetry/poetry)
  Virtpy does not manage dependencies or download packages. It can currently only be used in conjunction with poetry.

# Create and Add Dependencies

`virtpy new [VENV_PATH]` creates a new barebones venv at `VENV_PATH` or at '.venv' in the current directory, if no path is given.  

This venv can be used with `poetry`. `poetry add`, `poetry install` and `poetry remove` all work thanks to a shim. Poetry itself uses pip to install or remove packages and `virtpy` adds a pseudo `pip` package that redirects the commands to `virtpy`.

This forms the core functionality of this tool.

# Install python executables in isolated environments
`virtpy install PACKAGE` installs `PACKAGE` into a virtpy in a central location and places executables inside `virtpy path bin` which you can add to your `PATH`.

This is similar to [pipx](https://pypi.org/project/pipx/), but it uses `virtpy`s for isolation insted of regular venvs.
It's currently integrated into `virtpy` but is planned to be separated into its own tool or at least subcommand.
