from __future__ import annotations
import os

from poetry.config.config import boolean_normalizer
from poetry.config.config import boolean_validator
import subprocess
import typing
from pathlib import Path

from poetry.installation.wheel_installer import WheelInstaller
from poetry.plugins.application_plugin import ApplicationPlugin
from poetry.console.commands.config import ConfigCommand
from typing import Any

from poetry.utils.env import EnvManager
from poetry.config.config import Config

if typing.TYPE_CHECKING:
    from poetry.console.application import Application

DEBUG_LOG = False

# poetry config we're injecting to activate / deactivate automatic virtpy creation
USE_VIRTPY_SETTING = "virtpy.use_virtpy"

def debug_log(message: str) -> None:
    # stdout logging gets swallowed by poetry
    # logging module has too many configs that could interfere with the output here
    # so it's plain string formatting.
    Path("/tmp/poetry_plugin_virtpy_log").open("a").write(message.rstrip("\n") + "\n")

class VirtpyPlugin(ApplicationPlugin):
    def __init__(self) -> None:
        debug_log("VirtpyPlugin.__init__()")
        self.application: Application | None = None

    def activate(self, application: Application):
        debug_log("VirtpyPlugin.activate()")
        self.application = application
        self.application.configure_installer_for_command
        EnvManager.build_venv = build_venv  # type: ignore
        WheelInstaller.install = install  # type: ignore



def should_create_virtpy() -> bool:
    return Config.create().get("virtpy.use_virtpy", True)


original_build_venv = EnvManager.build_venv


# # This function replaces the original EnvManager.build_venv and creates
# # virtpys, if the config is set accordingly. Otherwise, it falls back to the
# # original function.
# #
# # All arguments are the same for the *args and **kwargs (which are all ignored)
# # and the return value is also different, as we can't return some type from virtualenv.
# # However, at time of implementation, the return value isn't used anywhere
@classmethod
def build_venv(
    cls: EnvManager,
    path: Path,
    *args, # currently empty
    executable: Path | None = None,
    # flags: dict[str, bool] | None = None,
    # with_pip: bool | None = None,
    # with_wheel: bool | None = None,
    # with_setuptools: bool | None = None,
    # prompt: str | None = None,
    **kwargs,
) -> None:  # virtualenv.run.session.Session:
    should_create_virtpy_ = should_create_virtpy()
    debug_log(f"virtpy build_venv called. {should_create_virtpy_=}")

    if should_create_virtpy_:
        executable_args = (
            ["--python", executable.resolve().as_posix()] if executable is not None else []
        )
        subprocess.run([*virtpy_cmd_from_env(), "new", path, *executable_args])
    else:
        return original_build_venv(path, *args, executable=executable, **kwargs)




old_install = WheelInstaller.install


# Monkeypatch function for poetry's wheel installer
def install(self: WheelInstaller, wheel: Path, *args, **kwargs) -> None:
    debug_log("WheelInstaller.install() (monkey_patch)")
    debug_log(str(wheel))
    debug_log(f"path={self._env.path}")

    def virtpy_add(virtpy_path: Path) -> None:
        # Don't overwrite our pip shim.
        # Poetry wants to install it, when virtualenvs.options.no-pip is set to false
        if virtpy_path.name.startswith("pip-"):
            return

        subprocess.run(
            [*virtpy_cmd(virtpy_path), "add", wheel, "--virtpy-path", virtpy_path],
            check=True,
        )

    central_metadata = self._env.path.joinpath("virtpy_central_metadata")
    if central_metadata.exists():
        debug_log(f"central metadata found at {central_metadata}")
        link_location = (
            central_metadata.joinpath("link_location").read_text().removesuffix("\n")
        )
        debug_log(f"link_location={link_location}")
        virtpy_add(Path(link_location))
    if self._env.path.joinpath("virtpy_link_metadata").exists():
        debug_log("virtpy link metadata found")
        virtpy_add(self._env.path)
    else:
        old_install(self, wheel, *args, **kwargs)


# duplicated in pip shim
def virtpy_cmd(venv_path: Path) -> list[str]:
    """Use the virtpy executable associated with virtpy"""
    metadata = venv_path / "virtpy_link_metadata"
    virtpy_exe = (metadata / "virtpy_exe").read_text()
    proj_dir = (metadata / "proj_dir").read_text()
    return [virtpy_exe, "--project-dir", proj_dir]

# necessary during venv creation
def virtpy_cmd_from_env() -> list[str]:
    """Use virtpy executable set in ENV variable or default to global executable."""
    # `virtpy install` forwards the virtpy setup using env variables.
    # venv creation initiated by poetry will not => use global setup.
    project_dir_ = os.environ.get("VIRTPY_PROJECT_DIR")
    virtpy_exe_ = os.environ.get("VIRTPY_EXECUTABLE")

    virtpy_exe = virtpy_exe_ if virtpy_exe_ is not None else "virtpy"
    project_dir = ["--project-dir", project_dir_] if project_dir_ is not None else []

    return [virtpy_exe] + project_dir


original_unique_config_values = ConfigCommand.unique_config_values

@property
def unique_config_values(self) -> dict[str, tuple[Any, Any]]:
    
    # We're expanding a property from ConfigCommand, so extract the getter function and call that,
    # then extend return val
    return original_unique_config_values.fget(self) | { USE_VIRTPY_SETTING: (boolean_validator, boolean_normalizer) }

ConfigCommand.unique_config_values = unique_config_values