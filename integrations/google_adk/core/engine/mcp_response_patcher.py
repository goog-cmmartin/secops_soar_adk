"""SecOps Hosted MCP Server Response Evaluator & Patcher.

Solves the Google SecOps Remote MCP bug where tool responses contain massively
nested schemas, unpruned arrays, deep protobuf hierarchies, or empty configs
that cause Gemini / Vertex AI timeouts and 500 INTERNAL:
'Limits exceeded while trying to flatten schema. Schema is too complex to process.'
"""

from typing import Any, Dict, List, Optional, Set


def prune_deep_object(
    obj: Any,
    max_depth: int = 4,
    current_depth: int = 0,
    max_list_items: int = 25,
    max_str_len: int = 4000,
) -> Any:
    """Recursively bounds object depth and list length to prevent schema recursion blowups."""
    if obj is None:
        return None
    if isinstance(obj, (int, float, bool)):
        return obj
    if isinstance(obj, str):
        if len(obj) > max_str_len:
            return obj[:max_str_len] + "... [truncated]"
        return obj

    if current_depth >= max_depth:
        if isinstance(obj, list):
            return f"[Array of {len(obj)} items]"
        if isinstance(obj, dict):
            keys = list(obj.keys())
            return f"[Object with {len(keys)} keys: {', '.join(keys[:5])}]"
        return str(obj)

    if isinstance(obj, list):
        pruned_list = [
            prune_deep_object(
                item,
                max_depth=max_depth,
                current_depth=current_depth + 1,
                max_list_items=max_list_items,
                max_str_len=max_str_len,
            )
            for item in obj[:max_list_items]
        ]
        return pruned_list

    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            # Skip empty nested dictionaries or lists that bloat schema
            if v is None:
                continue
            if isinstance(v, dict) and len(v) == 0:
                continue
            if isinstance(v, list) and len(v) == 0:
                continue
            result[k] = prune_deep_object(
                v,
                max_depth=max_depth,
                current_depth=current_depth + 1,
                max_list_items=max_list_items,
                max_str_len=max_str_len,
            )
        return result

    return str(obj)


def patch_list_feeds(data: Any) -> Dict[str, Any]:
    """Patches list_feeds response by stripping unused empty connector configs."""
    raw_feeds = []
    if isinstance(data, dict):
        raw_feeds = data.get("feeds", [])
    elif isinstance(data, list):
        raw_feeds = data

    feeds = []
    for f in raw_feeds[:30]:
        if not isinstance(f, dict):
            continue
        details = f.get("details", {})
        active_settings = None
        for k, v in details.items():
            if k.endswith("Settings") and isinstance(v, dict) and len(v) > 0:
                active_settings = {k: v}
                break

        feed_id = f.get("uid") or f.get("referenceId") or f.get("name", "").split("/")[-1]
        log_type = details.get("logType", "")
        if "/" in log_type:
            log_type = log_type.split("/")[-1]

        item = {
            "feedId": feed_id,
            "displayName": f.get("displayName"),
            "feedSourceType": details.get("feedSourceType"),
            "logType": log_type,
            "state": f.get("state"),
            "lastFeedInitiationTime": f.get("lastFeedInitiationTime"),
        }
        if active_settings:
            item["settings"] = active_settings
        feeds.append(item)

    return {
        "totalFeeds": len(raw_feeds),
        "returnedFeedsCount": len(feeds),
        "feeds": feeds,
    }


def patch_feed_operation(tool_name: str, data: Any) -> Dict[str, Any]:
    """Patches get_feed, create_feed, update_feed, enable_feed, disable_feed."""
    feed = data
    if isinstance(data, dict) and "feed" in data:
        feed = data["feed"]
    if not isinstance(feed, dict):
        return {"status": "SUCCESS", "operation": tool_name, "raw": str(data)}

    details = feed.get("details", {})
    active_settings = None
    for k, v in details.items():
        if k.endswith("Settings") and isinstance(v, dict) and len(v) > 0:
            active_settings = {k: v}
            break

    feed_id = feed.get("uid") or feed.get("referenceId") or feed.get("name", "").split("/")[-1]
    log_type = details.get("logType", "")
    if "/" in log_type:
        log_type = log_type.split("/")[-1]

    return {
        "operation": tool_name,
        "status": feed.get("state") or "SUCCESS",
        "feedId": feed_id,
        "displayName": feed.get("displayName"),
        "feedSourceType": details.get("feedSourceType"),
        "logType": log_type,
        "state": feed.get("state"),
        "lastFeedInitiationTime": feed.get("lastFeedInitiationTime"),
        "activeSettings": active_settings,
    }


def patch_udm_search(data: Any) -> Dict[str, Any]:
    """Patches udm_search by extracting high-value telemetry and bounding event lists."""
    raw_events = []
    if isinstance(data, dict):
        raw_events = data.get("events", [])
    elif isinstance(data, list):
        raw_events = data

    events = []
    for e in raw_events[:15]:
        if not isinstance(e, dict):
            continue
        meta = e.get("metadata", {})
        principal = e.get("principal", {})
        target = e.get("target", {})
        network = e.get("network", {})
        security_results = e.get("securityResult", [])

        sec_res = []
        for sr in security_results:
            if isinstance(sr, dict):
                sec_res.append({
                    "action": sr.get("action"),
                    "severity": sr.get("severity"),
                    "ruleName": sr.get("ruleName") or sr.get("ruleId"),
                })

        item = {
            "timestamp": meta.get("eventTimestamp") or meta.get("collectedTimestamp"),
            "eventType": meta.get("eventType"),
            "productName": meta.get("productName"),
        }
        if principal:
            item["principal"] = {
                "ip": principal.get("ip"),
                "hostname": principal.get("hostname"),
                "user": principal.get("user", {}).get("userid") if isinstance(principal.get("user"), dict) else None,
            }
        if target:
            target_user = target.get("user", {}).get("userid") if isinstance(target.get("user"), dict) else None
            target_file = target.get("file", {}).get("fullPath") if isinstance(target.get("file"), dict) else None
            item["target"] = {
                "ip": target.get("ip"),
                "hostname": target.get("hostname"),
                "user": target_user,
                "file": target_file,
            }
        if network:
            item["network"] = {
                "direction": network.get("direction"),
                "ipProtocol": network.get("ipProtocol"),
                "sessionDuration": network.get("sessionDuration"),
            }
        if sec_res:
            item["securityResult"] = sec_res
        events.append(item)

    return {
        "totalEventsMatched": len(raw_events),
        "returnedCount": len(events),
        "truncated": len(raw_events) > 15,
        "events": events,
    }


def patch_search_raw_logs(data: Any) -> Dict[str, Any]:
    """Patches search_raw_logs by bounding log array and truncating giant raw blobs."""
    raw_logs = []
    if isinstance(data, dict):
        raw_logs = data.get("rawLogs") or data.get("logs") or []
    elif isinstance(data, list):
        raw_logs = data

    logs = []
    for l in raw_logs[:15]:
        if isinstance(l, dict):
            snippet = l.get("rawText") or l.get("logText") or str(l)
            if len(snippet) > 300:
                snippet = snippet[:300] + "... [truncated]"
            log_type = l.get("logType")
            if isinstance(log_type, dict):
                log_type = log_type.get("displayName") or log_type.get("name", "").split("/")[-1]
            logs.append({
                "timestamp": l.get("timestamp") or l.get("collectionTime"),
                "logType": log_type,
                "snippet": snippet,
            })
        else:
            snippet = str(l)[:300]
            logs.append({"snippet": snippet})

    return {
        "totalLogsMatched": len(raw_logs),
        "returnedCount": len(logs),
        "truncated": len(raw_logs) > 15,
        "logs": logs,
    }


def patch_security_alerts(tool_name: str, data: Any) -> Dict[str, Any]:
    """Patches list_security_alerts, get_security_alert, update_security_alert."""
    alerts_list = []
    if isinstance(data, dict):
        if "alerts" in data and isinstance(data["alerts"], dict) and "alerts" in data["alerts"]:
            alerts_list = data["alerts"]["alerts"]
        elif "alerts" in data and isinstance(data["alerts"], list):
            alerts_list = data["alerts"]
        elif "alert" in data:
            alerts_list = [data["alert"]]
        else:
            alerts_list = [data]
    elif isinstance(data, list):
        alerts_list = data

    alerts = []
    for a in alerts_list[:15]:
        if not isinstance(a, dict):
            continue
        detections = a.get("detection") or []
        first_det = detections[0] if detections and isinstance(detections[0], dict) else {}
        fb = a.get("feedbackSummary", {})

        alert_id = a.get("id") or a.get("name", "").split("/")[-1]
        rule_name = first_det.get("ruleName") or a.get("ruleName") or a.get("displayName")
        rule_id = first_det.get("ruleId") or a.get("ruleId")

        event_count = len(a.get("events") or [])
        if event_count == 0 and "events" in first_det:
            event_count = len(first_det.get("events") or [])

        alerts.append({
            "alertId": alert_id,
            "ruleName": rule_name,
            "ruleId": rule_id,
            "createdTime": a.get("createdTime") or first_det.get("detectionTime"),
            "status": fb.get("status") or a.get("status"),
            "severity": fb.get("severityDisplay") or a.get("severity"),
            "caseName": a.get("caseName") or a.get("caseId"),
            "matchedEventsCount": event_count,
            "summary": a.get("summary") or a.get("detectionSummary"),
        })

    if tool_name in ("get_security_alert", "update_security_alert") and len(alerts) > 0:
        return alerts[0]

    return {
        "totalAlerts": len(alerts_list),
        "returnedCount": len(alerts),
        "alerts": alerts,
    }


def patch_list_rule_detections(data: Any) -> Dict[str, Any]:
    """Patches list_rule_detections by extracting detection highlights."""
    raw_detections = []
    if isinstance(data, dict):
        raw_detections = data.get("detections", [])
    elif isinstance(data, list):
        raw_detections = data

    detections = []
    for d in raw_detections[:15]:
        if not isinstance(d, dict):
            continue
        rule_obj = d.get("rule", {})
        rule_id = d.get("ruleId") or (rule_obj.get("id") if isinstance(rule_obj, dict) else None)
        rule_name = d.get("ruleName") or (rule_obj.get("name") if isinstance(rule_obj, dict) else None)

        detections.append({
            "detectionTime": d.get("detectionTime"),
            "ruleId": rule_id,
            "ruleName": rule_name,
            "alertState": d.get("alertState"),
            "url": d.get("url"),
            "summary": d.get("summary"),
        })

    return {
        "totalDetections": len(raw_detections),
        "returnedCount": len(detections),
        "detections": detections,
    }


def patch_investigation(tool_name: str, data: Any) -> Dict[str, Any]:
    """Patches get_investigation_by_id, get_alert_latest_investigation, trigger_investigation."""
    inv = data
    if isinstance(data, dict) and "investigation" in data:
        inv = data["investigation"]
    if not isinstance(inv, dict):
        return {"status": "SUCCESS", "operation": tool_name, "raw": str(data)}

    raw_findings = inv.get("findings") or []
    findings = []
    for f in raw_findings[:10]:
        if isinstance(f, dict):
            desc = f.get("description", "")
            if isinstance(desc, str) and len(desc) > 300:
                desc = desc[:300] + "... [truncated]"
            findings.append({
                "title": f.get("title"),
                "severity": f.get("severity"),
                "description": desc,
            })

    summary = inv.get("summary") or inv.get("analysis", "")
    if isinstance(summary, str) and len(summary) > 500:
        summary = summary[:500] + "... [truncated]"

    return {
        "investigationId": inv.get("id") or inv.get("investigationId"),
        "status": inv.get("status") or inv.get("state"),
        "verdict": inv.get("verdict") or inv.get("assessment"),
        "summary": summary,
        "createdTime": inv.get("createdTime") or inv.get("createTime"),
        "findingsCount": len(raw_findings),
        "findings": findings,
        "recommendedActions": (inv.get("recommendations") or inv.get("recommendedActions") or [])[:5],
    }


def patch_run_parser(data: Any) -> Dict[str, Any]:
    """Patches run_parser by bounding parsed events and isolating errors."""
    if not isinstance(data, dict):
        return {"status": "SUCCESS", "raw": str(data)}

    parsed = data.get("parsedEvents") or data.get("events") or []
    sample_event = prune_deep_object(parsed[0], 3) if parsed else None

    return {
        "status": data.get("status") or ("SUCCESS" if len(parsed) > 0 else "NO_EVENTS_PARSED"),
        "parsedEventsCount": len(parsed),
        "sampleParsedEvent": sample_event,
        "errors": data.get("errors") or data.get("errorMessages"),
    }


def patch_entity(tool_name: str, data: Any) -> Any:
    """Patches summarize_entity and search_entity."""
    raw_entities = []
    if isinstance(data, dict):
        if "entities" in data and isinstance(data["entities"], list):
            raw_entities = data["entities"]
        else:
            raw_entities = [data]
    elif isinstance(data, list):
        raw_entities = data

    entities = []
    for e in raw_entities[:10]:
        if not isinstance(e, dict):
            continue
        alerts = e.get("alerts") or []
        entities.append({
            "entityId": e.get("entityId") or e.get("id") or e.get("name"),
            "entityType": e.get("entityType") or e.get("type"),
            "primaryName": e.get("displayName") or e.get("primaryName") or e.get("name"),
            "riskScore": e.get("riskScore") or e.get("score"),
            "firstSeen": e.get("firstSeenTime") or e.get("firstSeen"),
            "lastSeen": e.get("lastSeenTime") or e.get("lastSeen"),
            "summary": e.get("summary") or e.get("description"),
            "associatedIps": (e.get("associatedIps") or [])[:5],
            "associatedUsers": (e.get("associatedUsers") or [])[:5],
            "recentAlertCount": e.get("recentAlertCount") or len(alerts),
        })

    if tool_name == "summarize_entity" and len(entities) == 1:
        return entities[0]

    return {
        "totalEntities": len(raw_entities),
        "entities": entities,
    }


def patch_generate_synthetic_events(data: Any) -> Dict[str, Any]:
    """Patches generate_synthetic_events by providing an event summary and 1-2 event samples."""
    events = []
    if isinstance(data, dict):
        events = data.get("events") or data.get("syntheticEvents") or []
    elif isinstance(data, list):
        events = data

    event_types = list({
        e.get("metadata", {}).get("eventType")
        for e in events
        if isinstance(e, dict) and "metadata" in e
    })

    return {
        "status": "SUCCESS",
        "totalGenerated": len(events),
        "eventTypes": event_types,
        "sampleEvents": [prune_deep_object(e, 3) for e in events[:2]],
    }


def patch_secops_tool_response(tool_name: str, response_data: Any) -> Any:
    """Master evaluator and response patcher for SecOps MCP tools.

    Prunes massively nested schemas and bounds array sizes to protect Gemini
    and Vertex AI function calling from recursion/schema limits and timeouts.
    """
    if response_data is None or not isinstance(response_data, (dict, list)):
        return response_data

    # Preserve explicit errors unmodified for failure visibility
    if isinstance(response_data, dict) and "error" in response_data:
        return response_data

    try:
        if tool_name == "list_feeds":
            return patch_list_feeds(response_data)
        elif tool_name in ("get_feed", "create_feed", "update_feed", "enable_feed", "disable_feed"):
            return patch_feed_operation(tool_name, response_data)
        elif tool_name == "udm_search":
            return patch_udm_search(response_data)
        elif tool_name == "search_raw_logs":
            return patch_search_raw_logs(response_data)
        elif tool_name in ("list_security_alerts", "get_security_alert", "update_security_alert"):
            return patch_security_alerts(tool_name, response_data)
        elif tool_name == "list_rule_detections":
            return patch_list_rule_detections(response_data)
        elif tool_name in ("get_investigation_by_id", "get_alert_latest_investigation", "trigger_investigation"):
            return patch_investigation(tool_name, response_data)
        elif tool_name == "run_parser":
            return patch_run_parser(response_data)
        elif tool_name in ("summarize_entity", "search_entity"):
            return patch_entity(tool_name, response_data)
        elif tool_name == "generate_synthetic_events":
            return patch_generate_synthetic_events(response_data)
        else:
            # Generic safety net for any other deeply nested tool response
            return prune_deep_object(response_data, max_depth=4)
    except Exception:
        # Fallback to universal deep pruner if specialized extraction encounters unusual schema
        return prune_deep_object(response_data, max_depth=4)
