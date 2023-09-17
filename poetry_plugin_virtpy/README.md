# poetry_plugin_virtpy

A poetry plugin that makes poetry capable of detecting existing virtpys and installing packages into them the right way.

# Installation
The usual way of installing plugins is `poetry self add <plugin>`, but that command currently does not work with paths or git links, it can only install from PyPi and I haven't yet uploaded the package.

Therefore, you have to build and install the package locally from the cloned repo and then install the wheel into your poetry's environment using the pip present in that venv.

```
poetry build
# On linux, the pip path would be this by default
~/.local/share/pypoetry/venv/bin/pip install dist/poetry_plugin_virtpy-0.1.0-py3-none-any.whl
```

# Uninstallation
Like with installation, the usual way of uninstalling the plugin doesn't work. You have to use the pip from poetry's environment.

```
~/.local/share/pypoetry/venv/bin/pip uninstall poetry_plugin_virtpy
```

# Usage
```
# create a venv like usual
virtpy new

# then use poetry as usual
poetry install
# The virtpy venv will be detected and utilized.
```
