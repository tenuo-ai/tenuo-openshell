"""Authorize NeMo Agent Toolkit function calls with a task-scoped Tenuo warrant."""

from nat.plugins.tenuo.context import authority
from nat.plugins.tenuo.middleware import ApprovalRequired
from nat.plugins.tenuo.middleware import AuthorizationDenied
from nat.plugins.tenuo.middleware import TenuoFunctionMiddleware
from nat.plugins.tenuo.middleware import TenuoMiddlewareConfig

__all__ = [
    "ApprovalRequired",
    "AuthorizationDenied",
    "TenuoFunctionMiddleware",
    "TenuoMiddlewareConfig",
    "authority",
]
