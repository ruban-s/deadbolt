"""Session lifecycle: create, validate, rotate, revoke; cookie encode/decode."""

from __future__ import annotations

from .manager import SessionManager

__all__ = ["SessionManager"]
