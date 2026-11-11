"""Tool registry: name -> callable.

Each tool is registered with a `ToolSpec` that includes its default
risk level and whether it requires a target. The callable receives a
plain dict of parameters and returns a dict. Heavy I/O is fine; the
gateway schedules async execution separately.
"""

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, ParamSpec, TypeVar

from ..models.common import RiskLevel

P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class ToolSpec:
    name: str
    description: str
    risk_level: RiskLevel = RiskLevel.LOW
    requires_target: bool = False
    parameters_schema: dict = field(default_factory=dict)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, tuple[ToolSpec, Callable[..., Any]]] = {}

    def register(self, spec: ToolSpec, fn: Callable[..., Any]) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} already registered")
        # Sanity: function exists
        if not callable(fn):
            raise TypeError(f"tool {spec.name!r} function is not callable")
        self._tools[spec.name] = (spec, fn)

    def get(self, name: str) -> tuple[ToolSpec, Callable[..., Any]]:
        if name not in self._tools:
            raise KeyError(f"tool {name!r} not registered")
        return self._tools[name]

    def list(self) -> list[ToolSpec]:
        return [spec for spec, _ in self._tools.values()]


# --- Decorator helper ---

def tool(
    name: str,
    *,
    description: str = "",
    risk_level: RiskLevel = RiskLevel.LOW,
    requires_target: bool = False,
    parameters_schema: dict | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator: register a tool when the module is imported."""

    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        from .gateway import _default_registry  # local to avoid cycle
        _default_registry.register(
            ToolSpec(
                name=name,
                description=description or (inspect.getdoc(fn) or ""),
                risk_level=risk_level,
                requires_target=requires_target,
                parameters_schema=parameters_schema or {},
            ),
            fn,
        )
        return fn

    return decorator
