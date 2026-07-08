"""MkDocs build hooks: expose the latest released version to templates.

Sets ``config.extra.version`` to the newest git tag (what is actually published
on PyPI), falling back to the ``X.Y.Z`` base of the installed distribution when
tags are unavailable. Templates reference it as ``{{ config.extra.version }}``
so the announcement bar never hardcodes a version number.
"""

from __future__ import annotations

import re
import subprocess
from importlib.metadata import PackageNotFoundError, version
from typing import Any

_RELEASE = re.compile(r"\d+\.\d+\.\d+")


def _latest_tag() -> str | None:
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip().lstrip("v") or None


def _installed_release() -> str | None:
    try:
        match = _RELEASE.match(version("deadbolt"))
    except PackageNotFoundError:
        return None
    return match.group(0) if match else None


def on_config(config: Any, **_: Any) -> Any:
    config.extra["version"] = _latest_tag() or _installed_release() or "dev"
    return config
