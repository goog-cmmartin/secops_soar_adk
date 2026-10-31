"""
Query capability definitions for UDM Search vs Dashboard Query.

Defines which proto schemas are available for each query type and provides
validation helpers for query construction.
"""

from typing import Set, Literal

QueryType = Literal["udm_search", "dashboard_query"]

# Proto schemas available for each query type
UDM_SEARCH_TABLES: Set[str] = {
    "udm",        # Default - Unified Data Model events
    "case",       # SOAR case management
    "detection",  # Alert collections (maps to collections.proto)
    "graph",      # Entity relationships (uses udm.proto structure)
}

DASHBOARD_QUERY_PROTOS: Set[str] = {
    # All protos supported in Dashboard Query
    "udm",                   # Unified Data Model events
    "case",                  # SOAR case management
    "collections",           # Detection/alert collections
    "rule",                  # Detection rules metadata
    "ruleset",               # Managed rule sets
    "ioc",                   # Indicators of compromise
    "gemini_investigation",  # AI investigation results
    "playbook",              # SOAR playbook executions
    "ingestion",             # Log ingestion statistics
    "case_history",          # Case audit trail
}

# Mapping of UDM Search table names to proto files
UDM_TO_PROTO_MAP = {
    "udm": "udm.proto",
    "case": "case.proto",
    "detection": "collections.proto",  # Note: table name differs from proto name
    "graph": "udm.proto",              # Uses UDM structure
}

# Dashboard Query proto to file mapping
DASHBOARD_TO_PROTO_MAP = {
    "udm": "udm.proto",
    "case": "case.proto",
    "collections": "collections.proto",
    "rule": "rule.proto",
    "ruleset": "ruleset.proto",
    "ioc": "ioc.proto",
    "gemini_investigation": "gemini_investigation.proto",
    "playbook": "playbook.proto",
    "ingestion": "ingestion.proto",
    "case_history": "case_history.proto",
}


def is_valid_udm_search_table(table: str) -> bool:
    """Check if table name is valid for UDM Search."""
    return table.lower() in UDM_SEARCH_TABLES


def is_valid_dashboard_proto(proto: str) -> bool:
    """Check if proto schema is valid for Dashboard Query."""
    return proto.lower() in DASHBOARD_QUERY_PROTOS


def get_query_capabilities(query_type: QueryType) -> Set[str]:
    """
    Get available tables/protos for a query type.
    
    Args:
        query_type: Either "udm_search" or "dashboard_query"
        
    Returns:
        Set of available table/proto names
    """
    if query_type == "udm_search":
        return UDM_SEARCH_TABLES.copy()
    elif query_type == "dashboard_query":
        return DASHBOARD_QUERY_PROTOS.copy()
    else:
        raise ValueError(f"Unknown query type: {query_type}")


def get_proto_file(table_or_proto: str, query_type: QueryType) -> str:
    """
    Get the proto file for a table/proto name.
    
    Args:
        table_or_proto: Table name (for UDM) or proto name (for Dashboard)
        query_type: Either "udm_search" or "dashboard_query"
        
    Returns:
        Proto filename (e.g., "udm.proto")
        
    Raises:
        ValueError: If table/proto is not valid for query type
    """
    table_or_proto = table_or_proto.lower()
    
    if query_type == "udm_search":
        if table_or_proto not in UDM_SEARCH_TABLES:
            raise ValueError(
                f"Invalid UDM Search table: {table_or_proto}. "
                f"Valid tables: {', '.join(sorted(UDM_SEARCH_TABLES))}"
            )
        return UDM_TO_PROTO_MAP[table_or_proto]
    
    elif query_type == "dashboard_query":
        if table_or_proto not in DASHBOARD_QUERY_PROTOS:
            raise ValueError(
                f"Invalid Dashboard Query proto: {table_or_proto}. "
                f"Valid protos: {', '.join(sorted(DASHBOARD_QUERY_PROTOS))}"
            )
        return DASHBOARD_TO_PROTO_MAP[table_or_proto]
    
    else:
        raise ValueError(f"Unknown query type: {query_type}")


def format_capability_help(query_type: QueryType) -> str:
    """
    Format human-readable help text for query capabilities.
    
    Args:
        query_type: Either "udm_search" or "dashboard_query"
        
    Returns:
        Formatted help text
    """
    capabilities = get_query_capabilities(query_type)
    
    if query_type == "udm_search":
        return f"""UDM Search Supported Tables:
  • udm (default) - Unified Data Model security events
  • case - SOAR case management
  • detection - Alert collections (maps to collections.proto)
  • graph - Entity relationships (uses UDM structure)

Example: metadata.event_type = 'USER_LOGIN'
         case.status = 'OPEN'
         detection.rule_name = 'Suspicious Login'"""
    
    else:  # dashboard_query
        return f"""Dashboard Query Supported Protos:
  All Chronicle data model protos:
  • udm, case, collections - Core event/case/alert data
  • rule, ruleset - Detection rule metadata
  • ioc - Indicators of compromise
  • gemini_investigation - AI investigation results
  • playbook - SOAR playbook executions
  • ingestion - Log ingestion statistics
  • case_history - Case audit trail

Example: SELECT rule.rule_name, COUNT(*) FROM rule
         WHERE @event.ingest_time >= timestamp("2024-01-01T00:00:00Z")"""
