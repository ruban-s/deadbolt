"""Email/password endpoints and the endpoint registry."""

from __future__ import annotations

from .context import EndpointRequest, EndpointResult
from .registry import ENDPOINTS, Endpoint, Registry

__all__ = ["ENDPOINTS", "Endpoint", "EndpointRequest", "EndpointResult", "Registry"]
