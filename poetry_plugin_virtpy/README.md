# poetry_plugin_virtpy

A poetry plugin that makes poetry capable of detecting existing virtpys and installing packages into them the right way.

# Installation
The installation depends on how poetry is installed ([official docs](https://python-poetry.org/docs/plugins/#using-plugins)).
Installing via `poetry self add <plugin>` doesn't work, as the package is not on PyPi.

Therefore, you have to build and install the package locally from the cloned repo and then install the wheel into your poetry's environment.

In any case, build the package file before performing the next step.
```
poetry build
```

## pipx
```
pipx inject poetry ./dist/poetry_plugin_virtpy-0.1.0-py3-none-any.wh
```

## poetry installer
When poetry was installed via its installed, find the venv in which it is located and run the pip executable
from that venv to install the plugin.
```
# On linux, the pip path would be this by default.
# POETRY_HOME=~/.local/share/pypoetry/venv

$POETRY_HOME/bin/pip install dist/poetry_plugin_virtpy-0.1.0-py3-none-any.whl
```

# Uninstallation

## pipx
```
pipx uninject poetry poetry_plugin_virtpy
```

## poetry installer
Like during the installation, use pip from poetry's venv to uninstall the plugin.
```
$POETRY_HOME/bin/pip uninstall poetry_plugin_virtpy
```

# Usage
```
# create a venv like usual
virtpy new

# then use poetry as usual
poetry install
# The virtpy venv will be detected and utilized.
```
