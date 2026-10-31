import json
import sys
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import construct_csv, output_handler

try:
    from LogJammerManager import LogJammerManager
except ImportError:
    try:
        from core.LogJammerManager import LogJammerManager
    except ImportError:
        from ..core.LogJammerManager import LogJammerManager

INTEGRATION_NAME = "LogJammer"
SCRIPT_NAME = "Search Curated Rules"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = False

    try:
        query = siemplify.extract_action_param("Search Query", default_value="")
        technique = siemplify.extract_action_param("MITRE Technique", default_value="")
        tactic = siemplify.extract_action_param("MITRE Tactic", default_value="")
        category = siemplify.extract_action_param("Category", default_value="")
        raw_limit = siemplify.extract_action_param("Limit", default_value="20")
        try:
            limit = max(1, min(100, int(raw_limit)))
        except (ValueError, TypeError):
            limit = 20

        # Instantiate Manager (no API key needed for local search)
        manager = LogJammerManager(logger=siemplify.LOGGER)

        matched_rules = manager.search_curated_rules(
            query=str(query).strip() if query else None,
            technique=str(technique).strip().upper() if technique else None,
            tactic=str(tactic).strip().upper() if tactic else None,
            category=str(category).strip() if category else None,
            limit=limit,
        )

        siemplify.result.add_result_json(matched_rules)
        result_value = len(matched_rules) > 0

        if matched_rules:
            # Build tabular display
            table_data = [
                {
                    "Rule ID": r.get("rule_id"),
                    "Rule Name": r.get("display_name"),
                    "Severity": r.get("severity"),
                    "Category": r.get("category"),
                    "MITRE Techniques": ", ".join(r.get("techniques", [])),
                }
                for r in matched_rules
            ]
            siemplify.result.add_data_table("Curated Detection Rules", construct_csv(table_data))
            output_message = f"Found {len(matched_rules)} matching Google SecOps curated detection rules."
        else:
            output_message = "No matching curated detection rules found for the specified criteria."

    except Exception as err:
        siemplify.LOGGER.error(f"Failed to search curated rules: {err}")
        output_message = f"Error searching curated rules: {str(err)}"
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
