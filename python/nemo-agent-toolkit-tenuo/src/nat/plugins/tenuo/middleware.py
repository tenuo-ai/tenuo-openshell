"""Function middleware that authorizes a call before ``call_next``."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from typing import Literal

from pydantic import Field
from pydantic import field_validator
from pydantic import model_validator

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


def load_bound_warrant(warrant_file: str, holder_key_file: str) -> Any:
    """Read a warrant or warrant stack and its holder key from files.

    The warrant file holds base64 or PEM text, as ``tenuo-openshell-agent
    install-warrant`` writes it. The key file holds the 32-byte holder key, raw
    or as 64 hex characters, as ``tenuo-openshell-agent keygen`` writes it.
    Returns the leaf warrant bound to the key, and the chain when it has more
    than one warrant.
    """
    from tenuo import SigningKey
    from tenuo import decode_warrant_stack_base64

    chain = decode_warrant_stack_base64(Path(warrant_file).read_text().strip())
    if not chain:
        raise ValueError("the warrant file holds no warrant")
    secret = Path(holder_key_file).read_bytes()
    if len(secret) != 32:
        secret = bytes.fromhex(secret.decode().strip())
    bound = chain[-1].bind(SigningKey.from_bytes(secret))
    return bound, (list(chain) if len(chain) > 1 else None)


class TenuoMiddlewareConfig(FunctionMiddlewareBaseConfig, name="tenuo"):
    """Trusted issuer keys for the function middleware.

    Application code binds the task warrant with ``authority()`` for the
    current task. Where no application code runs around the workflow, as with
    ``nat run``, ``warrant_file`` and ``holder_key_file`` name the warrant to
    use when none is bound.
    """

    trusted_roots: list[str] = Field(
        min_length=1,
        description="Hex-encoded 32-byte issuer public keys.",
    )
    warrant_file: str | None = Field(
        default=None,
        description=(
            "Warrant or warrant stack file, read on every call when no task authority is bound, "
            "for example the warrant tenuo-openshell-agent installs in an OpenShell sandbox. "
            "Needs holder_key_file."
        ),
    )
    holder_key_file: str | None = Field(
        default=None,
        description="Holder key of the warrant in warrant_file: 32 bytes, raw or hex.",
    )
    strip_function_group: bool = Field(
        default=False,
        description=(
            "Check a function group's function by its name in the group (read_logs) instead of "
            "its qualified name (ops__read_logs), so a warrant that names MCP tools applies to an "
            "mcp_client function group. Use it only on MCP function groups: it drops the first "
            "group__ prefix, so other__read_logs on another function would be checked as read_logs."
        ),
    )
    approval_required: Literal["raise", "defer"] = Field(
        default="raise",
        description=(
            "raise stops a call that needs an approval with ApprovalRequired. defer passes it to "
            "the next stage, for MCP tools behind tenuo-openshell-agent proxy, which records the "
            "request for an approver and attaches the approval; the OpenShell middleware enforces "
            "it. Calls the warrant does not allow stop here either way. A deferred call that "
            "reaches a server which does not check warrants runs without an approval."
        ),
    )

    @field_validator("trusted_roots")
    @classmethod
    def _valid_roots(cls, value: list[str]) -> list[str]:
        parse_trusted_roots(value)
        return value

    @model_validator(mode="after")
    def _files_together(self) -> "TenuoMiddlewareConfig":
        if (self.warrant_file is None) != (self.holder_key_file is None):
            raise ValueError("warrant_file and holder_key_file go together")
        return self


class TenuoFunctionMiddleware(FunctionMiddleware):
    """Check the task warrant, then call the next stage once on allow."""

    def __init__(
        self,
        *,
        trusted_roots: Sequence[Any],
        warrant_file: str | None = None,
        holder_key_file: str | None = None,
        strip_function_group: bool = False,
        approval_required: Literal["raise", "defer"] = "raise",
    ) -> None:
        super().__init__()
        if not trusted_roots:
            raise ValueError("trusted_roots must not be empty")
        if (warrant_file is None) != (holder_key_file is None):
            raise ValueError("warrant_file and holder_key_file go together")
        if approval_required not in ("raise", "defer"):
            raise ValueError("approval_required is raise or defer")
        self._trusted_roots = list(trusted_roots)
        self._files = (warrant_file, holder_key_file) if warrant_file and holder_key_file else None
        self._strip_function_group = strip_function_group
        self._defer_approvals = approval_required == "defer"

    def _authority(self) -> tuple[Any, list[Any] | None]:
        bound = current_bound()
        if bound is not None:
            return bound, None
        if self._files is None:
            raise AuthorizationDenied("missing_warrant", _ref())
        try:
            return load_bound_warrant(*self._files)
        except Exception:
            raise AuthorizationDenied("missing_warrant", _ref()) from None

    def _authorize(self, args: tuple[Any, ...], kwargs: dict[str, Any], context: FunctionMiddlewareContext) -> None:
        name = context.name
        if not isinstance(name, str) or not name:
            raise AuthorizationDenied("invalid_request", _ref())
        if self._strip_function_group:
            from nat.builder.function import FunctionGroup

            name = name.split(FunctionGroup.SEPARATOR, 1)[-1]
            if not name:
                raise AuthorizationDenied("invalid_request", _ref())
        arguments = argument_view(args, kwargs)
        bound, chain = self._authority()

        from tenuo import ApprovalRequired as TenuoApprovalRequired
        from tenuo import enforce_tool_call

        try:
            result = enforce_tool_call(
                name,
                arguments,
                bound,
                trusted_roots=self._trusted_roots,
                warrant_chain=chain,
            )
        except TenuoApprovalRequired:
            category = "approval_required"
        except Exception:
            raise AuthorizationDenied("verifier_failed", _ref()) from None
        else:
            if result.allowed:
                return
            category = _CATEGORIES.get(result.error_type or "", "verifier_failed")

        if category != "approval_required":
            raise AuthorizationDenied(category, _ref())
        # The next stage records the request for an approver and enforces the
        # approval; this one cannot see approvals.
        if not self._defer_approvals:
            raise ApprovalRequired(_ref())

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
