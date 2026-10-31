"""Workflow Capability Registry for SecOps Workflow Engine.

Provides a unified namespace of capabilities that map directly to engine workflows,
CLI commands, UI actions, and MCP tool definitions.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from engine.taxonomy import (
    REQUIRE_FILTER_POLICY_KEY,
    VALID_CARDINALITIES,
    VALID_KINDS,
    derive_cardinality,
    derive_domain,
    derive_kind,
)


@dataclass
class WorkflowCapability:
    """Represents a discrete or composed capability registered in the engine."""

    capability_id: str
    name: str
    description: str
    category: str  # e.g., 'search', 'investigation', 'entity', 'rule'
    handler: Callable[..., Any]
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None
    mcp_tool_name: Optional[str] = None
    composed: bool = False
    evidence_path: Optional[str] = None
    # --- Step 2 taxonomy fields (auto-derived when left unset) ---------------
    kind: Optional[str] = None
    domain: Optional[str] = None
    side_effects: List[str] = field(default_factory=list)
    # --- Step 3 composition graph: capability_ids this workflow composes -
    uses: Tuple[str, ...] = field(default_factory=tuple)
    # --- Step 4 result-set cardinality + agent safety policy -----------
    # `cardinality` is auto-derived for queries when left unset (explicit
    # values win, e.g. tagging a verified finite enum as 'bounded').
    # `agent` holds per-capability policy hints consumed by CLI/MCP; the
    # require-filter policy is auto-attached to every unbounded query.
    cardinality: Optional[str] = None
    agent: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Derive taxonomy fields from existing data; explicit values win."""
        if self.domain is None:
            self.domain = derive_domain(self.capability_id, self.category)
        if self.kind is None:
            self.kind = derive_kind(self.capability_id, self.composed)
        if self.kind not in VALID_KINDS:
            raise ValueError(
                f"Capability '{self.capability_id}' has invalid kind "
                f"'{self.kind}'; must be one of {sorted(VALID_KINDS)}."
            )
        # Invariant: a query is read-only. Catch mislabeling at construction.
        if self.kind == "query" and self.side_effects:
            raise ValueError(
                f"Capability '{self.capability_id}' is kind=query but declares "
                f"side_effects={self.side_effects}; queries must be side-effect free."
            )
        # Invariant: only composed workflows may declare `uses` edges, and a
        # capability may never list itself (trivial cycle). The full DAG /
        # dangling-edge check lives in the capability contract suite, which
        # can see the whole registry at once.
        self.uses = tuple(self.uses) if self.uses else ()
        if self.uses:
            if self.kind != "workflow":
                raise ValueError(
                    f"Capability '{self.capability_id}' declares uses="
                    f"{self.uses!r} but kind={self.kind!r}; only workflows "
                    f"may compose other capabilities."
                )
            if self.capability_id in self.uses:
                raise ValueError(
                    f"Capability '{self.capability_id}' lists itself in "
                    f"uses; a capability cannot compose itself."
                )
        # Derive result-set cardinality for queries (explicit wins).
        if self.cardinality is None:
            self.cardinality = derive_cardinality(self.capability_id, self.kind)
        if (
            self.cardinality is not None
            and self.cardinality not in VALID_CARDINALITIES
        ):
            raise ValueError(
                f"Capability '{self.capability_id}' has invalid cardinality "
                f"'{self.cardinality}'; must be one of "
                f"{sorted(VALID_CARDINALITIES)}."
            )
        # Only queries carry a cardinality; a mutating primitive or a
        # composed workflow must not claim one.
        if self.cardinality is not None and self.kind != "query":
            raise ValueError(
                f"Capability '{self.capability_id}' is kind={self.kind!r} but "
                f"declares cardinality={self.cardinality!r}; only queries have "
                f"a result-set cardinality."
            )
        # Auto-attach the require-filter policy to every unbounded query so
        # an autonomous agent cannot page an entire tenant unfiltered. An
        # explicit False is respected only if a human has justified it.
        if self.cardinality == "unbounded":
            self.agent.setdefault(REQUIRE_FILTER_POLICY_KEY, True)


_NON_FILTER_PARAM_NAMES = frozenset({
    "limit",
    "max_results",
    "page_size",
    "page_number",
    "page_token",
    "order_by",
    "max_events",
    "receive_limit",
    "batch_size",
    "max_values_per_field",
    "max_aggregations",
    "case_insensitive",
    "case_sensitive",
    "generate_ai_overview",
    "include_field_schemas",
    "view",
    "on_batch",
    "on_state_change",
    "cancel_token",
    "poll_interval",
    "max_poll_seconds",
})

_UNFILTERED_SENTINELS = frozenset({"", "-", "ALL", "all"})


def _has_effective_filter(value: Any) -> bool:
    """Returns True if a parameter value represents a non-empty filter constraint."""
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return value.strip() not in _UNFILTERED_SENTINELS
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    if hasattr(value, "__dataclass_fields__"):
        for fname in value.__dataclass_fields__:
            if fname in _NON_FILTER_PARAM_NAMES:
                continue
            if _has_effective_filter(getattr(value, fname, None)):
                return True
        return False
    return True


class WorkflowRegistry:
    """Central registry tracking all operational workflow capabilities."""

    def __init__(self):
        self._capabilities: Dict[str, WorkflowCapability] = {}
        self._by_mcp_tool: Dict[str, WorkflowCapability] = {}

    def register(self, capability: WorkflowCapability) -> None:
        """Registers a workflow capability and indexes its MCP tool name."""
        if capability.mcp_tool_name:
            existing_mcp = self._by_mcp_tool.get(capability.mcp_tool_name)
            if (
                existing_mcp is not None
                and existing_mcp.capability_id != capability.capability_id
            ):
                raise ValueError(
                    f"Duplicate mcp_tool_name '{capability.mcp_tool_name}' on "
                    f"'{capability.capability_id}' (already registered by "
                    f"'{existing_mcp.capability_id}')."
                )
        prev = self._capabilities.get(capability.capability_id)
        if prev is not None and prev.mcp_tool_name and prev.mcp_tool_name != capability.mcp_tool_name:
            self._by_mcp_tool.pop(prev.mcp_tool_name, None)

        self._capabilities[capability.capability_id] = capability
        if capability.mcp_tool_name:
            self._by_mcp_tool[capability.mcp_tool_name] = capability

    def get(self, capability_id: str) -> Optional[WorkflowCapability]:
        """Retrieves a capability by capability ID or MCP tool name."""
        cap = self._capabilities.get(capability_id)
        if cap is not None:
            return cap
        return self._by_mcp_tool.get(capability_id)

    def list_capabilities(
        self,
        category: Optional[str] = None,
        domain: Optional[str] = None,
        kind: Optional[str] = None,
    ) -> List[WorkflowCapability]:
        """Lists registered capabilities, optionally filtered by category, domain, or kind."""
        caps = list(self._capabilities.values())
        if category is not None:
            caps = [c for c in caps if c.category == category]
        if domain is not None:
            caps = [c for c in caps if c.domain == domain]
        if kind is not None:
            caps = [c for c in caps if c.kind == kind]
        return caps

    def validate_agent_call(
        self, capability: WorkflowCapability, *args: Any, **kwargs: Any
    ) -> None:
        """Enforces Invariant #9 (`require_filter_for_unbounded_query`) for autonomous callers."""
        if not capability.agent.get(REQUIRE_FILTER_POLICY_KEY):
            return

        import inspect

        try:
            sig = inspect.signature(capability.handler)
            bound = sig.bind_partial(*args, **kwargs)
            supplied = dict(bound.arguments)
        except TypeError:
            supplied = dict(kwargs)
            for idx, val in enumerate(args):
                supplied[f"_arg_{idx}"] = val

        nested_kwargs = supplied.pop("kwargs", None)
        if isinstance(nested_kwargs, dict):
            supplied.update(nested_kwargs)

        for param_name, val in supplied.items():
            if param_name in _NON_FILTER_PARAM_NAMES:
                continue
            if _has_effective_filter(val):
                return

        raise ValueError(
            f"Capability '{capability.capability_id}' has cardinality='unbounded' "
            f"and requires at least one filter argument under agent policy "
            f"'{REQUIRE_FILTER_POLICY_KEY}'."
        )

    def execute(
        self,
        capability_id: str,
        *args: Any,
        enforce_agent_policy: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Executes a capability by capability ID or MCP tool name."""
        cap = self.get(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found in registry.")
        if enforce_agent_policy:
            self.validate_agent_call(cap, *args, **kwargs)
        return cap.handler(*args, **kwargs)


# Global default registry instance
registry = WorkflowRegistry()
