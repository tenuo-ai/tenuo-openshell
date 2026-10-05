"""The middleware calls the next stage only when the task warrant allows it."""

from __future__ import annotations

import asyncio
from types import NoneType

import pytest
from nat.middleware.function_middleware import FunctionMiddleware
from nat.middleware.function_middleware import FunctionMiddlewareChain
from nat.middleware.middleware import FunctionMiddlewareContext
from pydantic import BaseModel

from nat.plugins.tenuo import ApprovalRequired
from nat.plugins.tenuo import AuthorizationDenied
from nat.plugins.tenuo import TenuoFunctionMiddleware
from nat.plugins.tenuo import TenuoMiddlewareConfig
from nat.plugins.tenuo import authority
from tenuo import Pattern
from tenuo import SigningKey
from tenuo import Warrant


class ReadLogs(BaseModel):
    service: str


def _context(name: str) -> FunctionMiddlewareContext:
    return FunctionMiddlewareContext(
        name=name,
        config=None,
        description=None,
        input_schema=ReadLogs,
        single_output_schema=NoneType,
        stream_output_schema=NoneType,
    )


def _bound(tool: str, *, constraint: Pattern | None = None):
    key = SigningKey.generate()
    builder = Warrant.mint_builder().tool(tool).ttl(3600)
    if constraint is not None:
        builder = builder.constraint("service", constraint)
    warrant = builder.mint(key)
    return key, warrant.bind(key)


async def _invoke(middleware, bound, name, value, call_next):
    with authority(bound):
        return await middleware.function_middleware_invoke(
            value,
            call_next=call_next,
            context=_context(name),
        )


@pytest.fixture
def read_logs():
    return _bound("read_logs")


def test_constructor_rejects_empty_roots():
    with pytest.raises(ValueError, match="trusted_roots"):
        TenuoFunctionMiddleware(trusted_roots=[])


def test_config_rejects_a_short_key():
    with pytest.raises(ValueError, match="32-byte"):
        TenuoMiddlewareConfig(trusted_roots=["aa" * 16])


def test_is_not_final(read_logs):
    key, _bound_warrant = read_logs
    middleware = TenuoFunctionMiddleware(trusted_roots=[key.public_key])
    assert middleware.is_final is False


async def test_missing_warrant_does_not_call_next(read_logs):
    key, _bound_warrant = read_logs
    middleware = TenuoFunctionMiddleware(trusted_roots=[key.public_key])
    called = False

    async def call_next(*_args, **_kwargs):
        nonlocal called
        called = True
        return "ran"

    with pytest.raises(AuthorizationDenied, match=r"missing_warrant, ref=") as caught:
        await middleware.function_middleware_invoke(
            {"service": "api"},
            call_next=call_next,
            context=_context("read_logs"),
        )

    assert called is False
    assert "api" not in str(caught.value)


async def test_other_tool_does_not_call_next(read_logs):
    key, bound = read_logs
    middleware = TenuoFunctionMiddleware(trusted_roots=[key.public_key])
    called = False

    async def call_next(*_args, **_kwargs):
        nonlocal called
        called = True
        return "ran"

    with authority(bound):
        with pytest.raises(AuthorizationDenied, match=r"tool_denied, ref=") as caught:
            await middleware.function_middleware_invoke(
                {"service": "secret-db"},
                call_next=call_next,
                context=_context("restart_service"),
            )

    assert called is False
    assert not isinstance(caught.value, ApprovalRequired)
    assert "secret-db" not in str(caught.value)
    assert "restart_service" not in str(caught.value)


async def test_constraint_mismatch_hides_the_argument():
    key, bound = _bound("read_logs", constraint=Pattern("api-*"))
    middleware = TenuoFunctionMiddleware(trusted_roots=[key.public_key])

    async def call_next(*_args, **_kwargs):
        raise AssertionError("denied call reached the function")

    with authority(bound):
        with pytest.raises(AuthorizationDenied, match=r"constraint_violation, ref=") as caught:
            await middleware.function_middleware_invoke(
                ReadLogs(service="secret-db"),
                call_next=call_next,
                context=_context("read_logs"),
            )

    assert "secret-db" not in str(caught.value)
    assert "api-*" not in str(caught.value)


async def test_allowed_call_runs_once(read_logs):
    key, bound = read_logs
    middleware = TenuoFunctionMiddleware(trusted_roots=[key.public_key])
    seen = []

    async def call_next(*args, **kwargs):
        seen.append((args, kwargs))
        return "ok"

    result = await _invoke(middleware, bound, "read_logs", ReadLogs(service="api"), call_next)

    assert result == "ok"
    assert seen == [((ReadLogs(service="api"),), {})]


async def test_arguments_do_not_select_the_warrant(read_logs):
    key, bound = read_logs
    other_key, other = _bound("restart_service")
    middleware = TenuoFunctionMiddleware(trusted_roots=[key.public_key, other_key.public_key])

    async def call_next(*_args, **_kwargs):
        raise AssertionError("a warrant inside the arguments authorized the call")

    with authority(bound):
        with pytest.raises(AuthorizationDenied, match=r"tool_denied, ref="):
            await middleware.function_middleware_invoke(
                {"service": "api", "warrant": "restart_service"},
                call_next=call_next,
                context=_context("restart_service"),
            )


async def test_untrusted_issuer_is_denied(read_logs):
    _key, bound = read_logs
    stranger = SigningKey.generate()
    middleware = TenuoFunctionMiddleware(trusted_roots=[stranger.public_key])

    async def call_next(*_args, **_kwargs):
        raise AssertionError("untrusted issuer reached the function")

    with authority(bound):
        with pytest.raises(AuthorizationDenied, match=r"untrusted_issuer, ref="):
            await middleware.function_middleware_invoke(
                {"service": "api"},
                call_next=call_next,
                context=_context("read_logs"),
            )


async def test_approval_required_is_distinct():
    issuer = SigningKey.generate()
    approver = SigningKey.generate()
    warrant = (
        Warrant.mint_builder()
        .tool("restart_service")
        .approval_gates({"restart_service": None})
        .required_approvers([approver.public_key])
        .min_approvals(1)
        .ttl(3600)
        .mint(issuer)
    )
    middleware = TenuoFunctionMiddleware(trusted_roots=[issuer.public_key])

    async def call_next(*_args, **_kwargs):
        raise AssertionError("approval-gated call reached the function")

    with authority(warrant.bind(issuer)):
        with pytest.raises(ApprovalRequired, match=r"approval_required, ref=") as caught:
            await middleware.function_middleware_invoke(
                {"service": "api"},
                call_next=call_next,
                context=_context("restart_service"),
            )

    assert isinstance(caught.value, AuthorizationDenied)
    assert "restart_service" not in str(caught.value)


async def test_denied_stream_does_not_start(read_logs):
    key, _bound_warrant = read_logs
    middleware = TenuoFunctionMiddleware(trusted_roots=[key.public_key])
    started = False

    async def call_next(*_args, **_kwargs):
        nonlocal started
        started = True
        yield "chunk"

    with pytest.raises(AuthorizationDenied, match=r"missing_warrant, ref="):
        async for _chunk in middleware.function_middleware_stream(
            {"service": "api"},
            call_next=call_next,
            context=_context("read_logs"),
        ):
            pass

    assert started is False


async def test_later_middleware_runs_only_after_allow(read_logs):
    key, bound = read_logs
    tenuo = TenuoFunctionMiddleware(trusted_roots=[key.public_key])

    class Counting(FunctionMiddleware):
        def __init__(self) -> None:
            super().__init__()
            self.seen = 0

        async def function_middleware_invoke(self, *args, call_next, context, **kwargs):
            self.seen += 1
            return await call_next(*args, **kwargs)

    later = Counting()
    ran = 0

    async def final(*_args, **_kwargs):
        nonlocal ran
        ran += 1
        return "ok"

    chain = FunctionMiddlewareChain(
        middleware=[tenuo, later],
        context=_context("restart_service"),
    ).build_single(final)

    with authority(bound):
        with pytest.raises(AuthorizationDenied, match=r"tool_denied, ref="):
            await chain({"service": "api"})
    assert later.seen == 0
    assert ran == 0

    chain = FunctionMiddlewareChain(
        middleware=[tenuo, later],
        context=_context("read_logs"),
    ).build_single(final)
    with authority(bound):
        assert await chain(ReadLogs(service="api")) == "ok"
    assert later.seen == 1
    assert ran == 1


async def test_concurrent_tasks_keep_their_own_warrants():
    read_key, read_bound = _bound("read_logs")
    restart_key, restart_bound = _bound("restart_service")
    middleware = TenuoFunctionMiddleware(
        trusted_roots=[read_key.public_key, restart_key.public_key],
    )

    async def attempt(bound, name):
        await asyncio.sleep(0)
        called = False

        async def call_next(*_args, **_kwargs):
            nonlocal called
            called = True
            return name

        try:
            with authority(bound):
                await asyncio.sleep(0)
                result = await middleware.function_middleware_invoke(
                    {"service": "api"},
                    call_next=call_next,
                    context=_context(name),
                )
        except AuthorizationDenied as exc:
            return ("denied", exc.category, called)
        return ("allowed", result, called)

    outcomes = await asyncio.gather(
        attempt(read_bound, "read_logs"),
        attempt(restart_bound, "read_logs"),
        attempt(restart_bound, "restart_service"),
        attempt(read_bound, "restart_service"),
    )
    assert outcomes[0] == ("allowed", "read_logs", True)
    assert outcomes[1][0] == "denied" and outcomes[1][1] == "tool_denied" and outcomes[1][2] is False
    assert outcomes[2] == ("allowed", "restart_service", True)
    assert outcomes[3][0] == "denied" and outcomes[3][1] == "tool_denied" and outcomes[3][2] is False


def test_authority_rejects_a_raw_warrant(read_logs):
    _key, bound = read_logs
    with pytest.raises(TypeError, match="BoundWarrant"):
        with authority(bound.warrant):
            pass


async def test_registered_builder_uses_the_configured_root(read_logs):
    from importlib.metadata import entry_points

    import nat.plugins.tenuo.register as register
    from nat.cli.type_registry import GlobalTypeRegistry

    discovered = [item for item in entry_points(group="nat.plugins") if item.name == "nat_tenuo"]
    assert [item.value for item in discovered] == ["nat.plugins.tenuo.register"]
    assert discovered[0].load() is register

    key, bound = read_logs
    infos = GlobalTypeRegistry.get().get_registered_middleware()
    assert any(info.config_type is TenuoMiddlewareConfig for info in infos)

    config = TenuoMiddlewareConfig(trusted_roots=[key.public_key.to_bytes().hex()])
    async with register.tenuo_middleware(config, builder=None) as middleware:
        assert isinstance(middleware, TenuoFunctionMiddleware)
        assert middleware.is_final is False

        async def call_next(*_args, **_kwargs):
            return "ok"

        with authority(bound):
            assert (
                await middleware.function_middleware_invoke(
                    {"service": "api"},
                    call_next=call_next,
                    context=_context("read_logs"),
                )
                == "ok"
            )


def _restart_warrant(issuer: SigningKey, holder: SigningKey) -> Warrant:
    approver = SigningKey.generate()
    return (
        Warrant.mint_builder()
        .tool("read_logs")
        .tool("restart_service")
        .holder(holder.public_key)
        .approval_gates({"restart_service": None})
        .required_approvers([approver.public_key])
        .min_approvals(1)
        .ttl(3600)
        .mint(issuer)
    )


def _write_authority(tmp_path, warrant: Warrant, holder: SigningKey):
    """The files tenuo-openshell-agent keeps: a base64 stack and a raw 32-byte key."""
    from tenuo import encode_warrant_stack

    warrant_file = tmp_path / "warrant"
    key_file = tmp_path / "holder.key"
    warrant_file.write_text(encode_warrant_stack([warrant]))
    key_file.write_bytes(holder.secret_key_bytes())
    return str(warrant_file), str(key_file)


def test_config_needs_both_files():
    root = SigningKey.generate().public_key.to_bytes().hex()
    with pytest.raises(ValueError, match="go together"):
        TenuoMiddlewareConfig(trusted_roots=[root], warrant_file="/sandbox/.tenuo/warrant")
    with pytest.raises(ValueError, match="raise"):
        TenuoMiddlewareConfig(trusted_roots=[root], approval_required="allow")


async def test_warrant_file_is_used_when_nothing_is_bound(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    files = _write_authority(tmp_path, _restart_warrant(issuer, holder), holder)
    middleware = TenuoFunctionMiddleware(
        trusted_roots=[issuer.public_key], warrant_file=files[0], holder_key_file=files[1]
    )

    async def call_next(value):
        return f"read {value['service']}"

    result = await middleware.function_middleware_invoke(
        {"service": "payments"}, call_next=call_next, context=_context("read_logs")
    )
    assert result == "read payments"

    # A bound warrant still takes precedence over the files.
    _key, other = _bound("read_logs")
    with authority(other):
        with pytest.raises(AuthorizationDenied, match=r"untrusted_issuer"):
            await middleware.function_middleware_invoke(
                {"service": "payments"}, call_next=call_next, context=_context("read_logs")
            )


async def test_unreadable_warrant_file_is_a_missing_warrant(tmp_path):
    issuer = SigningKey.generate()
    middleware = TenuoFunctionMiddleware(
        trusted_roots=[issuer.public_key],
        warrant_file=str(tmp_path / "absent"),
        holder_key_file=str(tmp_path / "absent.key"),
    )

    async def call_next(*_args, **_kwargs):
        raise AssertionError("ran without a warrant")

    with pytest.raises(AuthorizationDenied, match=r"missing_warrant, ref="):
        await middleware.function_middleware_invoke(
            {"service": "payments"}, call_next=call_next, context=_context("read_logs")
        )


async def test_function_group_names_need_stripping(read_logs):
    key, bound = read_logs

    async def call_next(*_args, **_kwargs):
        return "ran"

    qualified = TenuoFunctionMiddleware(trusted_roots=[key.public_key])
    with pytest.raises(AuthorizationDenied, match=r"tool_denied"):
        await _invoke(qualified, bound, "ops__read_logs", {"service": "api"}, call_next)

    stripped = TenuoFunctionMiddleware(trusted_roots=[key.public_key], strip_function_group=True)
    assert await _invoke(stripped, bound, "ops__read_logs", {"service": "api"}, call_next) == "ran"
    with pytest.raises(AuthorizationDenied, match=r"tool_denied"):
        await _invoke(stripped, bound, "ops__restart_service", {"service": "api"}, call_next)


async def test_deferred_approval_reaches_the_next_stage_and_denials_do_not(tmp_path):
    issuer, holder = SigningKey.generate(), SigningKey.generate()
    bound = _restart_warrant(issuer, holder).bind(holder)
    calls = []

    async def call_next(value):
        calls.append(value)
        return "handed on"

    deferring = TenuoFunctionMiddleware(trusted_roots=[issuer.public_key], approval_required="defer")
    assert await _invoke(deferring, bound, "restart_service", {"service": "payments"}, call_next) == "handed on"
    assert calls == [{"service": "payments"}]

    # A tool the warrant does not name still stops here.
    with pytest.raises(AuthorizationDenied, match=r"tool_denied"):
        await _invoke(deferring, bound, "delete_service", {"service": "payments"}, call_next)
    assert len(calls) == 1

    raising = TenuoFunctionMiddleware(trusted_roots=[issuer.public_key])
    with pytest.raises(ApprovalRequired):
        await _invoke(raising, bound, "restart_service", {"service": "payments"}, call_next)
    assert len(calls) == 1
