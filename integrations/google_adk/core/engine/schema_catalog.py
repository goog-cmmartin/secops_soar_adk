"""Protobuf Schema Catalog and GoogleSQL Grounding for Google SecOps.

Provides parsed schema definitions, type hierarchies, enum constants,
and dialect invariants derived from Google SecOps Protobuf definitions
(udm.proto, collections.proto, case.proto, case_history.proto, rule.proto).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional


class SecOpsSchemaCatalog:
    """Catalog of Google SecOps tables and Protobuf schema structures."""

    DEFAULT_PROTOS_DIR = Path(__file__).resolve().parent.parent / "schemas" / "protos"

    # Curated column and nested struct specifications for GoogleSQL compilation
    TABLES: Dict[str, Dict[str, Any]] = {
        "events": {
            "proto_file": "udm.proto",
            "description": "Unified Data Model (UDM) raw security telemetry events.",
            "fields": {
                "metadata": {
                    "type": "STRUCT",
                    "description": "Event metadata, timestamps, and product info.",
                    "subfields": {
                        "event_timestamp": {"type": "STRUCT {seconds INT64, nanos INT32}", "sql_access": "TIMESTAMP_SECONDS(metadata.event_timestamp.seconds)"},
                        "ingested_timestamp": {"type": "STRUCT {seconds INT64, nanos INT32}", "sql_access": "TIMESTAMP_SECONDS(metadata.ingested_timestamp.seconds)"},
                        "event_type": {"type": "STRING", "description": "Enum event type (e.g. USER_LOGIN, PROCESS_LAUNCH, NETWORK_CONNECTION, STATUS_UPDATE)."},
                        "product_event_type": {"type": "STRING", "description": "Raw vendor event type string."},
                        "product_name": {"type": "STRING", "description": "Product name (e.g. Microsoft Windows, CrowdStrike Falcon, Okta)."},
                        "id": {"type": "STRING", "description": "Unique event UUID."},
                    },
                },
                "principal": {
                    "type": "STRUCT",
                    "description": "The actor or initiating entity of the event.",
                    "subfields": {
                        "hostname": {"type": "STRING"},
                        "ip": {"type": "ARRAY<STRING>", "description": "Repeated IP addresses."},
                        "port": {"type": "INT32"},
                        "user": {"type": "STRUCT {userid STRING, email_addresses ARRAY<STRING>}"},
                        "process": {"type": "STRUCT {command_line STRING, file STRUCT {sha256 STRING, full_path STRING}}"},
                    },
                },
                "target": {
                    "type": "STRUCT",
                    "description": "The recipient, object, or destination entity of the event.",
                    "subfields": {
                        "hostname": {"type": "STRING"},
                        "ip": {"type": "ARRAY<STRING>", "description": "Repeated IP addresses."},
                        "port": {"type": "INT32"},
                        "user": {"type": "STRUCT {userid STRING, email_addresses ARRAY<STRING>}"},
                        "process": {"type": "STRUCT {command_line STRING, file STRUCT {sha256 STRING, full_path STRING}}"},
                        "file": {"type": "STRUCT {sha256 STRING, md5 STRING, full_path STRING, size INT64}"},
                        "resource": {"type": "STRUCT {name STRING, resource_type STRING}"},
                    },
                },
                "network": {
                    "type": "STRUCT",
                    "description": "Network protocol, byte counts, and direction.",
                    "subfields": {
                        "ip_protocol": {"type": "STRING", "description": "Protocol name (e.g. TCP, UDP, ICMP)."},
                        "sent_bytes": {"type": "INT64"},
                        "received_bytes": {"type": "INT64"},
                        "direction": {"type": "STRING", "description": "INBOUND, OUTBOUND, LATERAL."},
                    },
                },
                "security_result": {
                    "type": "ARRAY<STRUCT>",
                    "description": "Security verdicts, detections, and policy enforcement actions.",
                    "subfields": {
                        "action": {"type": "ARRAY<STRING>", "description": "Repeated action strings: 'BLOCK', 'ALLOW', 'QUARANTINE', 'UNKNOWN_ACTION'."},
                        "category": {"type": "STRING", "description": "SECURITY_RESULT_CATEGORY."},
                        "summary": {"type": "STRING"},
                        "severity": {"type": "STRING", "description": "INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL."},
                    },
                },
            },
        },
        "detections": {
            "proto_file": "collections.proto",
            "description": "Chronicle detection alerts produced by custom YARA-L rules and curated rule engines.",
            "fields": {
                "id": {"type": "STRING", "description": "Unique detection alert ID."},
                "detection": {
                    "type": "ARRAY<STRUCT>",
                    "description": "List of detection metadata and rule information.",
                    "subfields": {
                        "rule_id": {"type": "STRING", "description": "Detection rule identifier (e.g. ru_6cb096c8-...)."},
                        "rule_name": {"type": "STRING", "description": "Display name of the detection rule."},
                        "rule_version": {"type": "STRING"},
                        "rule_type": {"type": "STRING", "description": "USER_RULE, CURATED_RULE."},
                        "alert_state": {"type": "STRING", "description": "ALERTING or NOT_ALERTING."},
                    },
                },
                "soar_alert": {"type": "BOOL", "description": "Whether this detection was forwarded to SOAR."},
                "collection_elements": {
                    "type": "ARRAY<STRUCT>",
                    "description": "Collection references linking detections to underlying UDM telemetry events.",
                    "subfields": {
                        "references": {
                            "type": "ARRAY<STRUCT>",
                            "subfields": {
                                "event": {"type": "STRUCT {metadata STRUCT {id STRING}}"},
                            },
                        },
                    },
                },
            },
        },
        "cases": {
            "proto_file": "case.proto",
            "description": "SOAR incidents and case management tracking. NOTE: SELECT * is rejected by Chronicle compiler.",
            "fields": {
                "name": {"type": "STRING", "description": "Resource identifier of the case."},
                "display_name": {"type": "STRING", "description": "Title or display name of the case."},
                "status": {"type": "STRING", "description": "Case status: 'OPENED' or 'CLOSED'."},
                "priority": {"type": "STRING", "description": "Priority: 'PRIORITY_LOW', 'PRIORITY_MEDIUM', 'PRIORITY_HIGH', 'PRIORITY_CRITICAL'."},
                "stage": {"type": "STRING", "description": "Workflow stage."},
                "create_time": {"type": "STRUCT {seconds INT64, nanos INT32}", "sql_access": "TIMESTAMP_SECONDS(create_time.seconds)"},
                "update_time": {"type": "STRUCT {seconds INT64, nanos INT32}", "sql_access": "TIMESTAMP_SECONDS(update_time.seconds)"},
                "response_platform_info": {
                    "type": "STRUCT",
                    "subfields": {
                        "response_platform_id": {"type": "STRING", "description": "Primary case ID."},
                        "response_platform_type": {"type": "STRING"},
                    },
                },
                "alerts": {
                    "type": "ARRAY<STRUCT>",
                    "subfields": {
                        "metadata": {"type": "STRUCT {id STRING}"},
                    },
                },
            },
        },
        "case_history": {
            "proto_file": "case_history.proto",
            "description": "Audit trail of case activity, reassignments, stage changes, and playbook execution.",
            "fields": {
                "case_response_platform_info": {
                    "type": "STRUCT",
                    "subfields": {
                        "case_id": {"type": "STRING", "description": "Case reference ID linking to cases table."},
                    },
                },
                "case_activity": {
                    "type": "STRING",
                    "description": "Activity enum: 'STAGE_CHANGE', 'ASSIGNEE_CHANGE', 'PRIORITY_CHANGE', 'MARK_INCIDENT', 'TAG_ADDED'.",
                },
                "event_time": {"type": "STRUCT {seconds INT64, nanos INT32}", "sql_access": "TIMESTAMP_SECONDS(event_time.seconds)"},
            },
        },
        "rules": {
            "proto_file": "rule.proto",
            "description": "Chronicle YARA-L detection rule catalog.",
            "fields": {
                "rule_id": {"type": "STRING"},
                "version_id": {"type": "STRING"},
                "rule_name": {"type": "STRING"},
                "text": {"type": "STRING", "description": "Raw YARA-L rule code."},
                "enabled": {"type": "BOOL"},
                "alerting": {"type": "BOOL"},
                "create_time": {"type": "STRUCT {seconds INT64}", "sql_access": "TIMESTAMP_SECONDS(create_time.seconds)"},
            },
        },
    }

    DIALECT_INVARIANTS = [
        "1. Protobuf Timestamps: Fields like metadata.event_timestamp, create_time, and update_time are {seconds, nanos} structs. Always extract seconds using TIMESTAMP_SECONDS(field.seconds).",
        "2. Repeated Fields are ARRAY<T>: Fields like target.ip, principal.ip, and security_result are arrays. Use 'BLOCK' IN UNNEST(security_result[SAFE_OFFSET(0)].action), or UNNEST(field) AS alias. Never compare ARRAY = STRING directly.",
        "3. Table Column Projections: SELECT * FROM cases or case_history is rejected by Chronicle. Column selections on cases and case_history must be explicit.",
        "4. Enum Literals: Must match Protobuf enum values exactly (e.g. Case status is 'OPENED' or 'CLOSED', not 'OPEN'; alert_state is 'ALERTING').",
        "5. Join Keys Across Tables:\n   • detections ⟕ events: ON ref.event.metadata.id = e.metadata.id (via UNNEST(collection_elements) and UNNEST(references))\n   • cases ⟕ case_history: ON c.response_platform_info.response_platform_id = ch.case_response_platform_info.case_id\n   • cases ⟕ detections: ON a.metadata.id = det.id (via UNNEST(c.alerts) AS a)",
    ]

    FEW_SHOT_EXAMPLES: List[Dict[str, str]] = [
        {
            "question": "Show top 10 users with failed login attempts and calculate failure rate",
            "sql": """SELECT
  principal.user.userid AS user_id,
  count(*) AS total_attempts,
  COUNTIF('BLOCK' IN UNNEST(security_result[SAFE_OFFSET(0)].action)) AS blocked_attempts,
  COUNTIF('ALLOW' IN UNNEST(security_result[SAFE_OFFSET(0)].action)) AS allowed_attempts,
  ROUND(SAFE_DIVIDE(COUNTIF('BLOCK' IN UNNEST(security_result[SAFE_OFFSET(0)].action)), count(*)) * 100, 2) AS failure_pct
FROM events
WHERE metadata.event_type = 'USER_LOGIN' AND principal.user.userid IS NOT NULL
GROUP BY user_id
ORDER BY total_attempts DESC
LIMIT 10;""",
        },
        {
            "question": "Compare detection rule counts vs alerting counts over recent days",
            "sql": """SELECT
  d.rule_name,
  d.rule_id,
  count(*) AS total_detections,
  COUNTIF(d.alert_state = 'ALERTING') AS alerting_count,
  ROUND(SAFE_DIVIDE(COUNTIF(d.alert_state = 'ALERTING'), count(*)) * 100, 2) AS alert_conversion_pct
FROM detections, UNNEST(detection) AS d
GROUP BY d.rule_name, d.rule_id
ORDER BY total_detections DESC
LIMIT 20;""",
        },
        {
            "question": "Find SOAR cases with the highest workflow stage and assignee changes",
            "sql": """SELECT
  c.response_platform_info.response_platform_id AS case_id,
  c.display_name AS case_name,
  c.priority,
  COUNTIF(ch.case_activity = 'STAGE_CHANGE') AS stage_changes,
  COUNTIF(ch.case_activity = 'ASSIGNEE_CHANGE') AS assignee_changes,
  count(*) AS total_activities
FROM cases c
JOIN case_history ch
  ON c.response_platform_info.response_platform_id = ch.case_response_platform_info.case_id
GROUP BY case_id, case_name, c.priority
ORDER BY total_activities DESC
LIMIT 15;""",
        },
        {
            "question": "Count network connections by protocol and inbound vs outbound direction",
            "sql": """SELECT
  network.ip_protocol AS protocol,
  network.direction AS direction,
  count(*) AS connection_count,
  SUM(network.sent_bytes) AS total_sent_bytes,
  SUM(network.received_bytes) AS total_received_bytes
FROM events
WHERE metadata.event_type = 'NETWORK_CONNECTION'
GROUP BY protocol, direction
ORDER BY connection_count DESC
LIMIT 10;""",
        },
    ]

    def __init__(self, protos_dir: Optional[Path] = None):
        self.protos_dir = protos_dir or self.DEFAULT_PROTOS_DIR

    def list_tables(self) -> List[str]:
        """Returns the list of available table names in Google SecOps GoogleSQL."""
        return list(self.TABLES.keys())

    def get_table_schema(self, table_name: str) -> Optional[Dict[str, Any]]:
        """Returns schema details for the specified table."""
        return self.TABLES.get(table_name.lower())

    def get_grounding_prompt(self) -> str:
        """Constructs an LLM grounding prompt chunk describing all available tables and fields."""
        lines = ["# GOOGLE SECOPS CHRONICLE GOOGLESQL PROTOBUF SCHEMA CATALOG\n"]
        for table_name, table_info in self.TABLES.items():
            lines.append(f"## Table: `{table_name}` ({table_info['description']})")
            for field_name, f_info in table_info["fields"].items():
                f_type = f_info.get("type", "UNKNOWN")
                desc = f_info.get("description", "")
                sql_acc = f_info.get("sql_access")
                desc_str = f" - {desc}" if desc else ""
                acc_str = f" [Access: `{sql_acc}`]" if sql_acc else ""
                lines.append(f"  • `{field_name}`: {f_type}{desc_str}{acc_str}")
                if "subfields" in f_info:
                    for sub_name, s_info in f_info["subfields"].items():
                        s_type = s_info.get("type", "UNKNOWN")
                        s_desc = s_info.get("description", "")
                        s_desc_str = f" - {s_desc}" if s_desc else ""
                        lines.append(f"      - `{sub_name}`: {s_type}{s_desc_str}")
            lines.append("")

        lines.append("# STRICT CHRONICLE GOOGLESQL COMPILER INVARIANTS")
        for inv in self.DIALECT_INVARIANTS:
            lines.append(inv)
        lines.append("")

        return "\n".join(lines)

    def get_nl_to_sql_system_prompt(self) -> str:
        """Constructs complete system prompt for NL-to-GoogleSQL agent with schema grounding."""
        grounding = self.get_grounding_prompt()
        return (
            "You are the Google SecOps SQL Analyst Agent (@sql-analyst).\n"
            "Your mission is to answer security and operational telemetry questions by generating and executing Chronicle GoogleSQL queries.\n\n"
            f"{grounding}\n\n"
            "OPERATING GUIDELINES & MANDATORY EXECUTION DIRECTIVE:\n"
            "1. When an operator asks a question (e.g. 'What are the latest 10 cases in SOAR?', 'Show me the top 5 event types', 'How many failed logins?'), your job is to RETRIEVE AND PRESENT THE LIVE DATA for them.\n"
            "2. Generate GoogleSQL strictly respecting protobuf field structures, ARRAY unnesting, explicit column selection (never SELECT * on cases/case_history), and timestamp seconds extraction.\n"
            "3. MANDATORY EXECUTION: You must ALWAYS execute the query using `execute_sql(sql)` so that live results are returned and rendered in a data table widget for the operator. Do NOT stop after just generating or validating the SQL query unless the user specifically asked 'Write the SQL query' or 'Show me the SQL syntax only'.\n"
            "4. If query validation fails, inspect the compiler diagnostic error message, fix the query, and re-execute.\n"
            "5. Provide a concise summary of the query logic and findings alongside the executed results table."
        )
