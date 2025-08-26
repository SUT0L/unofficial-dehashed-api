"""
Unofficial DeHashed API Client

A Python library for interacting with the DeHashed Web-API.
"""

from .types import (
    DehashedResult,
    SearchResponse,
    SearchParams,
    RequestConfig,
    SearchType,
)
from ._core import DehashedAPIError
from .sync_client import Client
from .async_client import AsyncClient

__version__ = "0.2.1"
__all__ = [
    "Client",
    "AsyncClient",
    "DehashedAPIError",
    "DehashedResult",
    "SearchResponse",
    "SearchParams",
    "RequestConfig",
    "SearchType",
]

import logging as _logging

_logging.getLogger(__name__).addHandler(_logging.NullHandler())