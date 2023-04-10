from __future__ import annotations

import subprocess
import typing
from pathlib import Path

from poetry.installation.wheel_installer import WheelInstaller
from poetry.plugins.application_plugin import ApplicationPlugin

# from poetry.utils.env import EnvManager

if typing.TYPE_CHECKING:
    from poetry.console.application import Application

# TODO: Allow making virtpy creation the default for poetry.
#       Requires custom config logic in virtpy.
#       Right now, only package installation is overridden, if a virtpy is detected.
# original_build_venv = EnvManager.build_venv


# # This function replaces the original EnvManager.build_venv and creates
# # virtpys, if the config is set accordingly. Otherwise, it falls back to the
# # original function.
# #
# # All arguments are the same for the *args and **kwargs (which are all ignored)
# # and the return value is also different, as we can't return some type from virtualenv.
# # However, at time of implementation, the return value isn't used anywhere
# def build_venv(
#     cls: EnvManager,
#     path: Path,
#     executable: Path | None = None,
#     flags: dict[str, bool] | None = None,
#     with_pip: bool | None = None,
#     with_wheel: bool | None = None,
#     with_setuptools: bool | None = None,
#     prompt: str | None = None,
#     *args,
#     **kwargs,
# ) -> None:  # virtualenv.run.session.Session:
#     # TODO: allow overriding prompt
#     # cls._poetry.config.

#     executable_args = (
#         ["--python", executable.resolve().as_posix()] if executable is not None else []
#     )
#     subprocess.run(["virtpy", "new", path, *executable_args])


class VirtpyPlugin(ApplicationPlugin):
    def __init__(self) -> None:
        self.application: Application | None = None

    # def activate(self, poetry: Poetry, io: IO):
    def activate(self, application: Application):
        self.application = application
        # EnvManager.build_venv = build_venv  # type: ignore
        WheelInstaller.install = install  # type: ignore


old_install = WheelInstaller.install


# Monkeypatch function for poetry's wheel installer
def install(self: WheelInstaller, wheel: Path, *args, **kwargs) -> None:
    if self._env.path.joinpath("virtpy_link_metadata").exists():
        subprocess.run(
            ["virtpy", "add", wheel, "--virtpy-path", self._env.path], check=True
        )
    else:
        old_install(self, wheel, *args, **kwargs)
