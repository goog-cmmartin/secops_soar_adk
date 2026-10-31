"""Capability taxonomy: the `kind` and `domain` classification model (Step 2).

This module centralizes the rules that assign every registered capability a
`kind` and a `domain`. Both are derivable from data the registry already
carries (`capability_id`, `category`, `composed`), so the 104 existing
registrations need ZERO per-call edits: derivation happens in
`WorkflowCapability.__post_init__`. Explicit values always win over derivation,
which is how Step 3+ will hand-tune the handful of ambiguous cases.

Taxonomy axes
-------------
kind:
  * ``query``     -- read-only. MUST be side-effect free. (`.get/.search/.list`)
  * ``primitive`` -- a single atomic operation that may mutate state.
  * ``workflow``  -- a composed, multi-step capability (``composed=True``).

domain:
  * The coarse functional area (search, case, case_config, soar_settings, ...).
    Today this equals ``category``; making it a first-class field lets the
    contract suite and CLI/MCP layers filter on it without reaching into the
    legacy ``category`` name.
"""

from __future__ import annotations

from typing import Optional

# The only legal kinds. Kept in sync with the contract suite's KINDS set.
VALID_KINDS = frozenset({"primitive", "query", "workflow"})

# The only legal cardinalities for a query capability's result set. Kept in
# sync with the contract suite's expectations (Step 4).
#   * ``single``    -- returns exactly one addressed resource (e.g. ``.get``).
#   * ``bounded``   -- result size is intrinsically constrained by a required
#                      caller-supplied argument (e.g. a query the caller writes,
#                      or a verified small/static enumeration).
#   * ``unbounded`` -- an open-ended collection over a paginated/streaming
#                      endpoint that could enumerate an entire tenant. These
#                      MUST carry a require-filter policy so an autonomous agent
#                      cannot accidentally page the whole dataset.
VALID_CARDINALITIES = frozenset({"single", "bounded", "unbounded"})

# The agent-policy key the contract suite looks for on unbounded capabilities.
REQUIRE_FILTER_POLICY_KEY = "require_filter_for_unbounded_query"

# Terminal verbs that return a single addressed resource.
SINGLE_RESULT_VERBS = frozenset({
    "get",
    "get_rule",
    "get_ruleset",
    "diff",
    "metrics",
    "summarize",
    "get_latest",
    "latest",
})

# Terminal verbs whose result set is bounded by a required caller argument
# (the caller writes the query, so they own the bound).
BOUNDED_RESULT_VERBS = frozenset({
    "execute_query",
    "validate_query",
    "verify",
})

# Terminal verbs that return an open-ended collection. This is the union of the
# explicit search/list verbs and their list-like aliases already recognized as
# read verbs. Anything here is treated as ``unbounded`` unless a registration
# explicitly overrides it (e.g. a verified finite enum -> ``bounded``).
COLLECTION_RESULT_VERBS = frozenset({
    "search",
    "stats",
    "list",
    "list_rows",
    "rows",
    "search_rulesets",
    "search_enterprise",
    "instances",
    "logs",
    "categories",
    "remote_agents",
    "affected_items",
    "list_sources",
    "list_log_types",
    "revisions",
    "errors",
    "list_comments",
    "get_wall",
})

# Verb suffixes (the final dotted segment of a capability_id) that denote a
# read-only operation. Anything ending in one of these is a `query` unless it
# is composed (then it is a `workflow`) or explicitly overridden.
READ_VERB_SUFFIXES = frozenset({
    "get",
    "search",
    "stats",
    "search_enterprise",
    "summarize",
    "list",
    "list_rows",
    "rows",
    "list_log_types",
    "list_sources",
    "instances",
    "logs",
    "metrics",
    "diff",
    "affected_items",
    "categories",
    "remote_agents",
    "get_rule",
    "get_ruleset",
    "search_rulesets",
    "execute_query",
    "validate_query",
    "verify",
    "revisions",
    "errors",
    "list_comments",
    "get_wall",
    "get_latest",
    "latest",
})


def _terminal_segment(capability_id: str) -> str:
    """Return the final dotted segment of a capability id (its 'verb')."""
    return capability_id.rsplit(".", 1)[-1] if capability_id else ""


def derive_kind(capability_id: str, composed: bool) -> str:
    """Classify a capability into exactly one VALID_KINDS member.

    Rules, in priority order:
      1. composed capabilities are ``workflow``;
      2. capabilities whose terminal verb is a known read verb are ``query``;
      3. everything else is a ``primitive`` (a single mutating operation).
    """
    if composed:
        return "workflow"
    if _terminal_segment(capability_id) in READ_VERB_SUFFIXES:
        return "query"
    return "primitive"


def derive_domain(capability_id: str, category: Optional[str]) -> str:
    """Determine a capability's domain.

    Prefers the explicit legacy ``category``; otherwise falls back to the
    leading dotted segment of the id (e.g. ``case_config.view.get`` -> the
    ``case_config`` domain).
    """
    if category:
        return category
    if capability_id and "." in capability_id:
        return capability_id.split(".", 1)[0]
    return capability_id or ""


def derive_cardinality(capability_id: str, kind: str) -> Optional[str]:
    """Classify a query's result-set cardinality, or ``None`` for non-queries.

    Cardinality only constrains read-only capabilities: a ``workflow`` bounds
    its own output through its parameters, and a ``primitive`` mutates rather
    than enumerates. For queries we map the terminal verb:

      * single-result verbs      -> ``single``
      * caller-bounded verbs     -> ``bounded``
      * collection verbs         -> ``unbounded`` (the safe default)

    Any query verb we do not recognize also defaults to ``unbounded``: it is
    always safe to over-require a filter, never safe to under-require one.
    """
    if kind != "query":
        return None
    verb = _terminal_segment(capability_id)
    if verb in SINGLE_RESULT_VERBS:
        return "single"
    if verb in BOUNDED_RESULT_VERBS:
        return "bounded"
    if verb in COLLECTION_RESULT_VERBS:
        return "unbounded"
    # Unknown query verb: fail safe.
    return "unbounded"
