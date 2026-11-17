"""
Log Source Drift Detection & Profiling Engine.

Provides deterministic syntactic and semantic drift analysis for Google SecOps log sources.
Supports dimensional partitioning by (log_type, event_type) and format-agnostic raw key extraction.
"""

import json
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

# Regex pattern for Key-Value / CEF / Syslog key extraction fallback
KV_REGEX = re.compile(r"(\b[a-zA-Z0-9_\-\.]+)\s*=")


def extract_raw_keys(raw_text: str) -> Set[str]:
    """
    Extracts structural keys from a raw log payload.
    Attempts JSON parsing first; falls back to Key-Value / CEF regex extraction.
    """
    keys = set()
    raw_str = (raw_text or "").strip()
    if not raw_str:
        return keys

    if (raw_str.startswith("{") and raw_str.endswith("}")) or (raw_str.startswith("[") and raw_str.endswith("]")):
        try:
            parsed = json.loads(raw_str)
            return extract_json_keys(parsed)
        except Exception:
            pass

    # Fallback to key-value extraction (e.g. CEF, PAN-OS KV, Syslog)
    for match in KV_REGEX.finditer(raw_str):
        keys.add(match.group(1))
    return keys


def extract_json_keys(obj: Any, prefix: str = "") -> Set[str]:
    """Recursively flattens JSON keys into dot-notated paths."""
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            keys.add(full_key)
            if isinstance(v, (dict, list)):
                keys.update(extract_json_keys(v, full_key))
    elif isinstance(obj, list):
        list_prefix = f"{prefix}[]"
        for item in obj:
            if isinstance(item, (dict, list)):
                keys.update(extract_json_keys(item, list_prefix))
    return keys


def extract_udm_paths(obj: Any, prefix: str = "") -> Set[str]:
    """
    Recursively extracts populated UDM field paths from a UDM event dictionary.
    Excludes volatile per-event IDs and timestamps to ensure baseline stability.
    """
    paths = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("id", "eventTimestamp", "collectedTimestamp", "ingestedTimestamp"):
                continue
            full_path = f"{prefix}.{k}" if prefix else str(k)
            if v not in (None, "", [], {}):
                paths.add(full_path)
            if isinstance(v, (dict, list)):
                paths.update(extract_udm_paths(v, full_path))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                paths.update(extract_udm_paths(item, prefix))
    return paths


def build_profile_from_events(
    log_type: str,
    event_type: Optional[str],
    events: List[Any],
    raw_log_payloads: List[str],
    min_key_prevalence: float = 0.20,
    critical_udm_threshold: float = 0.50,
) -> Dict[str, Any]:
    """
    Deterministically computes a baseline profile from sampled UDM events and raw logs.
    """
    udm_counter = Counter()
    for ev in events:
        d = ev.to_dict().get("event", {}) if hasattr(ev, "to_dict") else ev.get("event", ev)
        udm_counter.update(extract_udm_paths(d))

    raw_key_counter = Counter()
    for raw_text in raw_log_payloads:
        raw_key_counter.update(extract_raw_keys(raw_text))

    raw_sample_count = max(len(raw_log_payloads), 1)
    event_sample_count = max(len(events), 1)

    # Qualified keys: must meet minimum prevalence floor
    qualified_raw_keys = {
        k: cnt / raw_sample_count
        for k, cnt in raw_key_counter.items()
        if (cnt / raw_sample_count) >= min_key_prevalence
    }

    # Critical UDM fields: fields that appear reliably in >= threshold of events
    critical_udm_fields = {
        k: cnt / event_sample_count
        for k, cnt in udm_counter.items()
        if (cnt / event_sample_count) >= critical_udm_threshold
    }

    partition_key = f"{log_type}:{event_type}" if event_type else log_type

    return {
        "partition_key": partition_key,
        "log_type": log_type,
        "event_type": event_type or "",
        "raw_samples_count": len(raw_log_payloads),
        "udm_events_count": len(events),
        "total_raw_keys_discovered": len(raw_key_counter),
        "qualified_raw_keys": qualified_raw_keys,
        "critical_udm_fields": critical_udm_fields,
        "all_udm_rates": {k: cnt / event_sample_count for k, cnt in udm_counter.items()},
    }


def evaluate_stream_drift(
    baseline: Dict[str, Any],
    events: List[Any],
    raw_log_payloads: List[str],
    min_events_required: int = 10,
    drift_tolerance: float = 0.15,
    udm_collapse_floor: float = 0.05,
) -> Dict[str, Any]:
    """
    Evaluates a live sample stream against a learned baseline profile.
    Returns structured drift metrics, vanished/emergent keys, and alert conditions.
    """
    total_events = len(events)
    if total_events < min_events_required:
        return {
            "partition_key": baseline.get("partition_key", "UNKNOWN"),
            "status": "INSUFFICIENT_VOLUME",
            "message": f"Sample volume ({total_events}) is below minimum requirement ({min_events_required}). Skipping evaluation.",
            "syntactic_drift": 0.0,
            "key_overlap": 1.0,
            "vanished_keys": [],
            "emergent_keys": [],
            "collapsed_critical_fields": [],
            "alerts": [],
        }

    # 1. Syntactic Raw Log Drift Analysis
    current_raw_keys = set()
    for raw_text in raw_log_payloads:
        current_raw_keys.update(extract_raw_keys(raw_text))

    base_qualified = set(baseline.get("qualified_raw_keys", {}).keys())
    common_keys = base_qualified.intersection(current_raw_keys)
    vanished_keys = base_qualified - current_raw_keys
    emergent_keys = current_raw_keys - base_qualified

    key_overlap = len(common_keys) / len(base_qualified) if base_qualified else 1.0
    syntactic_drift = 1.0 - key_overlap

    # 2. Semantic UDM Field Completeness Analysis
    udm_counter = Counter()
    for ev in events:
        d = ev.to_dict().get("event", {}) if hasattr(ev, "to_dict") else ev.get("event", ev)
        udm_counter.update(extract_udm_paths(d))

    current_udm_rates = {k: cnt / total_events for k, cnt in udm_counter.items()}

    collapsed_critical_fields = []
    for field_path, base_rate in baseline.get("critical_udm_fields", {}).items():
        curr_rate = current_udm_rates.get(field_path, 0.0)
        # Alert if a field that was reliably populated dropped to near zero
        if base_rate >= 0.50 and curr_rate < udm_collapse_floor:
            collapsed_critical_fields.append(
                {
                    "field": field_path,
                    "baseline_rate": base_rate,
                    "current_rate": curr_rate,
                    "drop_delta": base_rate - curr_rate,
                }
            )

    # 3. Alert Formulation
    alerts = []
    if syntactic_drift >= drift_tolerance:
        alerts.append(
            f"SYNTACTIC_DRIFT: {len(vanished_keys)} qualified baseline raw keys vanished (Drift: {syntactic_drift * 100:.1f}% >= {drift_tolerance * 100:.0f}%)"
        )

    if collapsed_critical_fields:
        collapsed_names = [c["field"] for c in collapsed_critical_fields]
        alerts.append(
            f"SEMANTIC_UDM_COLLAPSE: {len(collapsed_critical_fields)} critical UDM fields collapsed to ~0%: {collapsed_names[:5]}"
        )

    status = "ALERT" if alerts else "STABLE"

    return {
        "partition_key": baseline.get("partition_key", "UNKNOWN"),
        "status": status,
        "alerts": alerts,
        "syntactic_drift": syntactic_drift,
        "key_overlap": key_overlap,
        "total_baseline_keys": len(base_qualified),
        "preserved_keys": len(common_keys),
        "vanished_keys": sorted(list(vanished_keys)),
        "emergent_keys": sorted(list(emergent_keys)),
        "collapsed_critical_fields": collapsed_critical_fields,
    }
