"""Task-local warrant binding.

The active warrant is a ``ContextVar``. Function arguments, model output, and
other tasks cannot select it.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

from tenuo import BoundWarrant

_bound: ContextVar[BoundWarrant | None] = ContextVar("tenuo_nat_bound_warrant", default=None)


def current_bound() -> BoundWarrant | None:
    """Return the warrant bound to the current task, if any."""
    return _bound.get()


@contextmanager
def authority(bound: BoundWarrant) -> Iterator[BoundWarrant]:
    """Bind ``bound`` for the current task and restore the previous value on exit."""
    if not isinstance(bound, BoundWarrant):
        raise TypeError("authority() requires a BoundWarrant")
    token = _bound.set(bound)
    try:
        yield bound
    finally:
        _bound.reset(token)
