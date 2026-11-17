"""Registry-driven LLM / ADK toolset builder for SecOpsEngine.

Generates typed, signature-preserving tool functions directly from
``SecOpsEngine.registry`` so autonomous agents and SOAR ADK integrations never
hand-wrap ad-hoc closures that bypass ``WorkflowRegistry`` policies:

- Read-only by default (``include_mutations=False`` excludes ``kind == 'primitive'``
  and any composed workflow with ``side_effects`` or transitive mutation edges).
- Enforces Invariant #9 (``require_filter_for_unbounded_query``) via
  ``registry.validate_agent_call`` before calling the handler.
- Preserves ``inspect.Signature`` and docstrings for Gemini / ADK function schema
  introspection and propagates API errors visibly without fabricating data.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
import inspect
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Set

from engine.registry import WorkflowCapability, WorkflowRegistry
from engine.taxonomy import is_tenant_read_only_capability

if TYPE_CHECKING:
    from engine.facade import SecOpsEngine


def serialize_tool_output(obj: Any, *, max_list_items: int = 200) -> Any:
    """Converts engine domain dataclasses, enums, and nested collections into JSON-safe structures."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return serialize_tool_output(obj.to_dict(), max_list_items=max_list_items)
    if is_dataclass(obj) and not isinstance(obj, type):
        return serialize_tool_output(asdict(obj), max_list_items=max_list_items)
    if isinstance(obj, dict):
        return {str(k): serialize_tool_output(v, max_list_items=max_list_items) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        seq = list(obj)
        if len(seq) > max_list_items:
            return {
                "items": [serialize_tool_output(x, max_list_items=max_list_items) for x in seq[:max_list_items]],
                "truncated": True,
                "total_items": len(seq),
            }
        return [serialize_tool_output(x, max_list_items=max_list_items) for x in seq]
    return str(obj)


def is_read_only_capability(
    cap: WorkflowCapability,
    registry: WorkflowRegistry,
    _visited: Optional[Set[str]] = None,
) -> bool:
    """Returns True iff ``cap`` performs no live tenant mutations directly or transitively."""
    return is_tenant_read_only_capability(cap, registry, _visited)


def build_capability_tool(
    engine: "SecOpsEngine",
    cap: WorkflowCapability,
    *,
    enforce_agent_policy: bool = True,
    serialize_result: bool = True,
) -> Callable[..., Any]:
    """Wraps a single registered ``WorkflowCapability`` as a signature-preserving callable."""
    tool_name = cap.mcp_tool_name or cap.capability_id.replace(".", "_")
    handler = cap.handler
    orig_sig = inspect.signature(handler)
    clean_params = [
        p
        for p in orig_sig.parameters.values()
        if "Callable" not in str(p.annotation)
        and "callback" not in p.name.lower()
        and p.name != "on_batch"
    ]
    sig = orig_sig.replace(parameters=clean_params, return_annotation=Dict[str, Any])

    def _tool_wrapper(*args: Any, **kwargs: Any) -> Any:
        if enforce_agent_policy:
            engine.registry.validate_agent_call(cap, *args, **kwargs)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        result = handler(**bound.arguments)
        if serialize_result:
            return serialize_tool_output(result)
        return result

    _tool_wrapper.__name__ = tool_name
    _tool_wrapper.__qualname__ = tool_name
    _tool_wrapper.__doc__ = cap.description or getattr(handler, "__doc__", "") or f"Executes {cap.capability_id}."
    _tool_wrapper.__signature__ = sig  # type: ignore[attr-defined]
    _tool_wrapper._capability_id = cap.capability_id  # type: ignore[attr-defined]
    _tool_wrapper._capability_kind = cap.kind  # type: ignore[attr-defined]
    return _tool_wrapper


def build_registry_toolset(
    engine: "SecOpsEngine",
    *,
    capability_ids: Optional[Sequence[str]] = None,
    tool_filter: Optional[Sequence[str]] = None,
    include_mutations: bool = False,
    enforce_agent_policy: bool = True,
    serialize_result: bool = True,
) -> List[Callable[..., Any]]:
    """Builds a filtered list of signature-preserving tool callables from ``engine.registry``.

    Args:
        engine: Configured ``SecOpsEngine`` instance.
        capability_ids: Optional allowlist of capability IDs or MCP tool names. When omitted,
            selects all registered capabilities permitted by ``include_mutations``.
        tool_filter: Optional additional allowlist of tool names or capability IDs (enforced strictly).
        include_mutations: If False (default), excludes all ``primitive`` capabilities and any
            composed ``workflow`` with ``side_effects`` or mutating ``uses`` dependencies.
        enforce_agent_policy: If True (default), enforces Invariant #9 filter requirements.
        serialize_result: If True (default), converts domain dataclasses into JSON-safe dicts.
    """
    reg = engine.registry
    if capability_ids is not None:
        candidates: List[WorkflowCapability] = []
        seen_ids: Set[str] = set()
        for raw_id in capability_ids:
            cap = reg.get(raw_id)
            if cap is None:
                raise KeyError(f"Capability '{raw_id}' is not registered on SecOpsEngine.")
            if cap.capability_id not in seen_ids:
                seen_ids.add(cap.capability_id)
                candidates.append(cap)
    else:
        candidates = reg.list_capabilities()

    allowed_filter: Optional[Set[str]] = None
    if tool_filter is not None:
        allowed_filter = {str(x).strip() for x in tool_filter if str(x).strip()}

    tools: List[Callable[..., Any]] = []
    for cap in candidates:
        tool_name = cap.mcp_tool_name or cap.capability_id.replace(".", "_")
        if allowed_filter is not None and cap.capability_id not in allowed_filter and tool_name not in allowed_filter:
            continue
        if not include_mutations and not is_read_only_capability(cap, reg):
            if capability_ids is not None:
                raise PermissionError(
                    f"Capability '{cap.capability_id}' (kind={cap.kind!r}) is a mutating capability "
                    f"and cannot be bound when include_mutations=False."
                )
            continue
        tools.append(
            build_capability_tool(
                engine,
                cap,
                enforce_agent_policy=enforce_agent_policy,
                serialize_result=serialize_result,
            )
        )
    return tools
