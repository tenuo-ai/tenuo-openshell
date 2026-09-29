"""Function middleware that authorizes a call before ``call_next``."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from collections.abc import Sequence
from typing import Any

from pydantic import Field
from pydantic import field_validator

from nat.plugin_api import FunctionMiddleware
from nat.plugin_api import FunctionMiddlewareBaseConfig
from nat.plugin_api import FunctionMiddlewareContext

from nat.plugins.tenuo.context import current_bound

_CATEGORIES = {
    "tool_not_allowed": "tool_denied",
    "constraint_violation": "constraint_violation",
    "expired": "expired",
    "invalid_pop": "invalid_pop",
    "untrusted_issuer": "untrusted_issuer",
    "insufficient_approvals": "approval_required",
}


class AuthorizationDenied(Exception):
    """A function call was not authorized.

    The message is a category and a correlation id. It does not include
    arguments, roots, or warrant contents.
    """

    def __init__(self, category: str, ref: str) -> None:
        self.category = category
        self.ref = ref
        super().__init__(f"Authorization denied ({category}, ref={ref})")


class ApprovalRequired(AuthorizationDenied):
    """The call needs a signed approval before it can be retried."""

    def __init__(self, ref: str) -> None:
        super().__init__("approval_required", ref)


def _ref() -> str:
    return secrets.token_hex(8)


def parse_trusted_roots(values: Sequence[str]) -> list[Any]:
    """Decode hex-encoded 32-byte issuer public keys."""
    from tenuo import PublicKey

    if not values:
        raise ValueError("trusted_roots must not be empty")
    roots: list[Any] = []
    for item in values:
        if not isinstance(item, str):
            raise ValueError("trusted_roots entries must be hex-encoded public keys")
        try:
            raw = bytes.fromhex(item)
        except ValueError as exc:
            raise ValueError("trusted_roots entries must be hex-encoded public keys") from exc
        if len(raw) != 32:
            raise ValueError("trusted_roots entries must be 32-byte public keys")
        roots.append(PublicKey.from_bytes(raw))
    return roots


def argument_view(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Build the argument object the warrant is checked against."""
    if args and kwargs:
        raise AuthorizationDenied("invalid_request", _ref())
    if len(args) > 1:
        raise AuthorizationDenied("invalid_request", _ref())
    if kwargs:
        return dict(kwargs)
    if not args or args[0] is None:
        return {}
    value = args[0]
    if isinstance(value, dict):
        return dict(value)
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        dumped = dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    raise AuthorizationDenied("invalid_request", _ref())


class TenuoMiddlewareConfig(FunctionMiddlewareBaseConfig, name="tenuo"):
    """Trusted issuer keys for the function middleware.

    The task warrant is not part of this configuration. Application code binds
    it with ``authority()`` for the current task.
    """

    trusted_roots: list[str] = Field(
        min_length=1,
        description="Hex-encoded 32-byte issuer public keys.",
    )

    @field_validator("trusted_roots")
    @classmethod
    def _valid_roots(cls, value: list[str]) -> list[str]:
        parse_trusted_roots(value)
        return value


class TenuoFunctionMiddleware(FunctionMiddleware):
    """Check the task warrant, then call the next stage once on allow."""

    def __init__(self, *, trusted_roots: Sequence[Any]) -> None:
        super().__init__()
        if not trusted_roots:
            raise ValueError("trusted_roots must not be empty")
        self._trusted_roots = list(trusted_roots)

    def _authorize(self, args: tuple[Any, ...], kwargs: dict[str, Any], context: FunctionMiddlewareContext) -> None:
        name = context.name
        if not isinstance(name, str) or not name:
            raise AuthorizationDenied("invalid_request", _ref())
        arguments = argument_view(args, kwargs)
        bound = current_bound()
        if bound is None:
            raise AuthorizationDenied("missing_warrant", _ref())

        from tenuo._enforcement import enforce_tool_call
        from tenuo.approval import ApprovalRequired as TenuoApprovalRequired

        try:
            result = enforce_tool_call(
                name,
                arguments,
                bound,
                trusted_roots=self._trusted_roots,
            )
        except TenuoApprovalRequired:
            raise ApprovalRequired(_ref()) from None
        except Exception:
            raise AuthorizationDenied("verifier_failed", _ref()) from None

        if result.allowed:
            return
        category = _CATEGORIES.get(result.error_type or "", "verifier_failed")
        ref = _ref()
        if category == "approval_required":
            raise ApprovalRequired(ref)
        raise AuthorizationDenied(category, ref)

    async def function_middleware_invoke(
        self,
        *args: Any,
        call_next: Any,
        context: FunctionMiddlewareContext,
        **kwargs: Any,
    ) -> Any:
        self._authorize(args, kwargs, context)
        return await call_next(*args, **kwargs)

    async def function_middleware_stream(
        self,
        *args: Any,
        call_next: Any,
        context: FunctionMiddlewareContext,
        **kwargs: Any,
    ) -> AsyncIterator[Any]:
        self._authorize(args, kwargs, context)
        async for chunk in call_next(*args, **kwargs):
            yield chunk
