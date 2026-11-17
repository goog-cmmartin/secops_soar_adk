"""Clean dependency-inversion ports for optional persistence andSOC ledger backends.

``engine/`` and ``adapters/`` are standalone packages that may be vendored into
environments (such as Google SecOps SOAR integrations) where ``agents/``,
``runbooks/``, and ``clients/`` are not installed. No module inside ``engine/``
or ``adapters/`` may directly import those upper layers.
"""

from __future__ import annotations

import importlib
import importlib.util
from typing import Any, Callable, Dict, List, Optional, Protocol


class EvidenceStorePort(Protocol):
    """Structural protocol for optional rule/audit/posture persistence backends."""

    def get_rule_state(self, rule_id: str) -> Optional[Dict[str, Any]]: ...
    def list_rule_states(self, limit: int = 10000) -> List[Dict[str, Any]]: ...
    def generate_rule_embeddings(self, texts: List[str]) -> List[List[float]]: ...


class KnowledgeStorePort(Protocol):
    """Structural protocol for SOC observation and knowledge-gap storage."""

    def get_composite_entity(self, subject_type: str, subject_id: str) -> Dict[str, Any]: ...


class WorkQueuePort(Protocol):
    """Structural protocol for SOC issue queue storage."""

    def list_issues(self, **kwargs: Any) -> List[Any]: ...


class MaterializerPort(Protocol):
    """Structural protocol for git-backed SOC issue event materialization."""

    def list_issue_events(self, issue_id: str) -> List[Any]: ...


_registered_factories: Dict[str, Callable[[], Any]] = {}


def register_store_factory(kind: str, factory: Callable[[], Any]) -> None:
    """Registers an explicit factory for 'evidence', 'knowledge', 'work_queue', or 'materializer'."""
    _registered_factories[kind] = factory


def _load_optional_factory(module_name: str, attr_name: str, *, required: bool, label: str) -> Any:
    if label in _registered_factories:
        return _registered_factories[label]()
    try:
        spec = importlib.util.find_spec(module_name)
    except (ModuleNotFoundError, ValueError):
        spec = None
    if spec is None:
        if not required:
            return None
        raise RuntimeError(
            f"No {label} backend provided and optional module '{module_name}' is not installed. "
            f"Pass an explicit backend instance or set persist=False."
        )
    mod = importlib.import_module(module_name)
    factory = getattr(mod, attr_name)
    return factory()


def resolve_evidence_store(explicit_store: Any = None, *, required: bool = True) -> Any:
    """Resolves an explicit evidence store or lazily loads the default provider."""
    if explicit_store is not None:
        return explicit_store
    return _load_optional_factory(
        "agents.core.evidence_store",
        "get_evidence_store",
        required=required,
        label="evidence_store",
    )


def resolve_knowledge_store(explicit_store: Any = None, *, required: bool = True) -> Any:
    """Resolves an explicit knowledge store or lazily loads the default provider."""
    if explicit_store is not None:
        return explicit_store
    return _load_optional_factory(
        "agents.core.knowledge_store",
        "get_knowledge_store",
        required=required,
        label="knowledge_store",
    )


def resolve_work_queue(explicit_queue: Any = None, *, required: bool = True) -> Any:
    """Resolves an explicit work queue or lazily loads the default provider."""
    if explicit_queue is not None:
        return explicit_queue
    return _load_optional_factory(
        "agents.core.work_queue",
        "get_work_queue",
        required=required,
        label="work_queue",
    )


def resolve_materializer(explicit_materializer: Any = None, *, required: bool = True) -> Any:
    """Resolves an explicit issue materializer or lazily loads the default provider."""
    if explicit_materializer is not None:
        return explicit_materializer
    return _load_optional_factory(
        "agents.core.materializer",
        "IssueMaterializer",
        required=required,
        label="materializer",
    )
