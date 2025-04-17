"""
Unofficial DeHashed API Client

A Python library for interacting with the DeHashed Web-API.
"""

from .client import (
    DehashedClient,
    DehashedAPIError,
    DehashedResult,
    SearchResponse,
    SearchParams,
    RequestConfig
)

__version__ = "0.1.0"
__all__ = [
    "DehashedClient",
    "DehashedAPIError", 
    "DehashedResult",
    "SearchResponse",
    "SearchParams",
    "RequestConfig"
]