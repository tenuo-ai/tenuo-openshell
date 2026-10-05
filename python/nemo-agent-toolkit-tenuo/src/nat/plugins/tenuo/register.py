"""Register the middleware with NeMo Agent Toolkit."""

from nat.plugin_api import Builder
from nat.plugin_api import register_middleware

from nat.plugins.tenuo.middleware import TenuoFunctionMiddleware
from nat.plugins.tenuo.middleware import TenuoMiddlewareConfig
from nat.plugins.tenuo.middleware import parse_trusted_roots


@register_middleware(config_type=TenuoMiddlewareConfig)
async def tenuo_middleware(config: TenuoMiddlewareConfig, builder: Builder):
    """Build middleware that reads the task warrant from ``authority()``."""
    del builder
    yield TenuoFunctionMiddleware(
        trusted_roots=parse_trusted_roots(config.trusted_roots),
        warrant_file=config.warrant_file,
        holder_key_file=config.holder_key_file,
        strip_function_group=config.strip_function_group,
        approval_required=config.approval_required,
    )
