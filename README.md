# virtpy

virtpy creates Python [venv](https://docs.python.org/3/library/venv.html)s where all the dependencies are symlinked in from a central store. 
Dependencies that are used in multiple venvs are only stored once on disk. 
This makes each individual virtpy environment very lightweight.

As a side effect, creation of virtpys and installation of packages is significantly faster.
This is especially true for repeat installs, but it remains the case for the first install.

The name stands for <b>virt</b>ual <b>py</b>thon and is subject to change. The entire project is an early prototype. Expect bugs and crashes.

# Requirements
* Python3.8+  
  with
  * a modern-ish pip version
  * the `wheel` module available globally for python.  
    It should be installed for every python version you intend to use with virtpy. It is not strictly required, but needed
    for installing non-wheel packages by converting them into wheels first.
* [Poetry](https://github.com/python-poetry/poetry)  
  Virtpy does not manage dependencies or download packages. It can currently only be used in conjunction with poetry.

# How to use
The tool's core subcommands are:
```
virtpy new [TARGET_PATH]
virtpy add WHEEL_PACKAGE_PATH
virtpy remove PACKAGE
```

It's easiest to use virtpys together with [poetry](https://python-poetry.org/) in which case you don't use `add` or `remove` directly.

## Create virtual environment
`virtpy new [TARGET_PATH]`  
This creates a new virtpy.
It works like `python3 -m venv [TARGET_PATH]`.
You can then use `poetry` with the generated environment and it will work as if it were a regular venv.
You have to create the environment yourself.
If you let poetry do it, it will generate a regular venv.

## Add / Remove dependencies
It's easiest to use poetry. `poetry add`, `poetry remove` and `poetry install` all work transparently.

Packages can also be added or removed manually via
* `virtpy add WHEEL_PACKAGE_PATH`  
  Installs the package from the given wheel file.
  Dependencies are not installed.
  Nothing is downloaded and no dependency resolution is done.
  It works like `python3 -m pip install --no-deps WHEEL_PACKAGE_PATH`.
* `virtpy remove PACKAGE`
  Removes the PACKAGE from the virtpy.  
  No dependency resolution is done and dependent packages will remain.


# Install python executables in isolated environments
Two subcommands build on top of the core `virtpy` functionality to install packages with executables
into isolated environments, making their executables available globally.
```
virtpy install PACKAGE
virtpy uninstall PACKAGE
```
The executables are placed in the directory returned by `virtpy path bin`.
You must add this directory to your PATH yourself.

This is similar to [pipx](https://pypi.org/project/pipx/), but it uses `virtpy`s for isolation insted of regular venvs.
It's currently integrated into `virtpy` but is planned to be separated into its own tool or at least subcommand.
