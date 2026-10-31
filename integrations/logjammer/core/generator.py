"""AI-powered scenario log generation service."""

from datetime import datetime, timezone
import json
import re
from typing import Dict, List, Optional, Union
try:
  from google.genai import types
except ImportError:
  types = None

from .config import LogJammerConfig, get_genai_client
from .gti import GTIClient
from .models import GeneratedScenario, LogEntry, LogFormat, RuleAnalysis, SecOpsRule
from .playbook import PlaybookService
from .rule_analyzer import RuleAnalyzer
from .rules import RuleService
from .templates import (
    TimeTemplateService,
    extract_timestamp_from_text,
    parse_base_timestamp,
    replace_time_templates,
)


SCENARIO_SYSTEM_PROMPT = """You are an elite Red Team Operator and Security Telemetry Architect.
Your task is to generate highly authentic, realistic, multi-source synthetic logs depicting a security scenario.

You will be given:
1. A natural language scenario narrative or SOAR Case/Alert Triage Summary.
2. The requested log types (e.g. OKTA, CS_EDR, BIND_DNS, PAN_FIREWALL, AWS_CLOUDTRAIL, AWS_VPC_FLOW).
3. Detailed Schema Guides for each log type detailing required fields, delimiters, headers, and timestamp formats.

CRITICAL RULES:
1. **Schema Fidelity**: Strictly follow the provided Schema Guides for each log type. Every log line must conform to real-world format expectations.
2. **Cohesive Narrative & Entity Consistency**: Ensure all events across different log sources correlate coherently:
   - Strictly reuse all exact usernames, internal IP addresses, external malicious IPs, AWS EC2 instance IDs (e.g. i-...), hostnames, and account IDs mentioned in the scenario description across all generated log types.
   - The timeline must progress logically (initial recon/authentication -> delivery/connection -> execution -> persistence/post-exploitation).
3. **Relative Time Templating (Backdating to Anchor Time)**:
   - Never hardcode static timestamps!
   - All relative template tags are automatically resolved relative to the Alert's Anchor Base Timestamp (`0d0h0m0s`):
     * ISO 8601: `##$TimeStamp-0d0h15m0s$##` (e.g. 15 minutes before the alert anchor timestamp)
     * Unix Epoch (seconds): `##$Epoch-0d0h10m0s$##`
     * Unix Epoch (milliseconds): `##$EpochMillis-0d0h10m0s$##`
     * Syslog: `##$SyslogTime-0d0h5m0s$##`
   - Space events realistically leading up to and immediately surrounding `-0d0h0m0s` (for example from `-0d0h20m0s` to `+0d0h5m0s`).
4. **Case Triage Summary Reconstruction**:
   - If the input is a SIEM/SOAR Triage Summary that states "no corroborating evidence was found", "transient/blocked", or "no further action is required", IGNORE that benign conclusion!
   - Your mission is to synthesize the MISSING corroborating attack telemetry (successful authentication, process creation, command execution, cloud API calls, and bidirectional network flows) that surrounds and substantiates the alert.
5. **Output Format**:
   Return a single valid JSON object with the following structure:
   ```json
   {
     "title": "Short descriptive title of the attack scenario",
     "summary": "2-3 sentence overview of the simulated attack chain",
     "logs": {
       "<LOG_TYPE_1>": [
         "log line 1 or JSON string",
         "log line 2 or JSON string"
       ],
       "<LOG_TYPE_2>": [
         "log line 1",
         "log line 2"
       ]
     }
   }
   ```
   Do not include any conversational preamble outside the JSON markdown block.
"""

RULE_SYSTEM_PROMPT = """You are an elite Detection Engineer and Security Telemetry Specialist.
Your task is to reverse-engineer and generate synthetic raw logs that will be parsed by Google SecOps (Chronicle SIEM) and trigger a specific YARA-L 2.0 detection rule, while also synthesizing realistic surrounding multi-source attack telemetry when additional alert context is provided.

You will be given:
1. The target YARA-L detection rule (logic, metadata, MITRE techniques).
2. The deconstructed UDM constraints (required event types, positive regex/string criteria, negative exclusions to avoid, thresholds, and time windows).
3. The target log source type(s) and their detailed Schema Guides.
4. The generation objective: 'fire' (trigger detection), 'evade' (negative test), or 'full-chain' (end-to-end simulation with pre-incident, trigger, and post-incident surrounding logs).
5. Optional ADDITIONAL USER CONTEXT (such as a SOAR Case/Alert Triage Summary and Involved Entities).

CRITICAL RULES:
1. **Rule Satisfaction**:
   - For 'fire' and 'full-chain': Ensure the generated trigger log(s) contain the exact strings, regexes, parameters, and UDM fields specified in the positive constraints.
   - Strictly avoid matching any negative exclusion patterns (clauses with '!=') so the rule does not discard the event.
   - If the rule requires a threshold (e.g. count > 5), generate at least that many distinct trigger events within the specified match window.
   - If the rule is a multi-event join, bind matching entity fields (e.g. same user, IP, asset_id, or hostname) across the joined events in proper sequence.
2. **Entity Binding & Case Triage Reconstruction**:
   - When ADDITIONAL USER CONTEXT is provided, you MUST reuse all exact external malicious IP addresses (e.g. `221.194.148.34`), internal IP addresses, AWS EC2 instance IDs (e.g. `i-0942348f80748b397`), hostnames (`ComputerName`), and usernames directly inside BOTH the YARA-L trigger event(s) AND the surrounding logs!
   - For example, if the rule matches an SSH command line connecting to an external IP (`/ssh.*\s\w+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/`) and excludes `127.0.0.1` / RFC1918 private IPs, use `localhost` for the local port forwarding bind and the exact malicious external IP from the alert context as the SSH destination (e.g. `/usr/bin/ssh -N -R 8080:localhost:22 root@221.194.148.34`).
   - If the input context is a SIEM/SOAR Triage Summary stating "no corroborating evidence was found" or "no further action is required", IGNORE that benign conclusion and synthesize the complete corroborating attack chain!
3. **Schema Fidelity**:
   - Format each log line strictly according to the Schema Guide for the target log source (e.g. CrowdStrike Falcon EDR `CS_EDR` JSON with all string values and 32-char hex `aid`, Windows Sysmon, AWS VPC Flow, AWS CloudTrail, Linux Syslog).
   - Ensure the fields that Google SecOps parsers use to populate the target UDM attributes (e.g. `CommandLine`, `ImageFileName`, `aid`, `ComputerName`, `UserName`) are realistically placed in the raw log.
4. **Relative Time Templating (Backdating to Anchor Time)**:
   - Never hardcode static timestamps! Use relative template tags resolved against the Alert Anchor Timestamp (`0d0h0m0s`):
     * ISO 8601: `##$TimeStamp-0d0h5m0s$##`
     * Unix Epoch (seconds): `##$Epoch-0d0h5m0s$##`
     * Unix Epoch (milliseconds): `##$EpochMillis-0d0h5m0s$##`
     * Syslog: `##$SyslogTime-0d0h5m0s$##`
5. **Output Format**:
   Return a single valid JSON object:
   ```json
   {
     "title": "Trigger simulation for <RULE_NAME>",
     "summary": "Explanation of how the generated logs satisfy the YARA-L detection logic and surrounding scenario",
     "logs": {
       "<LOG_TYPE_1>": [
         "log line 1",
         "log line 2"
       ],
       "<LOG_TYPE_2>": [
         "log line 1"
       ]
     }
   }
   ```
   Do not include any conversational preamble outside the JSON markdown block.
"""


class ScenarioGenerator:
  """Generates multi-source synthetic logs for arbitrary security scenarios."""

  def __init__(
      self,
      config: Optional[LogJammerConfig] = None,
      playbook_service: Optional[PlaybookService] = None,
      gti_client: Optional[GTIClient] = None,
      rule_service: Optional[RuleService] = None,
      rule_analyzer: Optional[RuleAnalyzer] = None,
  ):
    self.config = config or LogJammerConfig()
    self.playbook_service = playbook_service or PlaybookService(self.config)
    self.gti_client = gti_client or GTIClient(api_key=self.config.gti_api_key)
    self.rule_service = rule_service or RuleService(self.config)
    available_types = self.playbook_service.list_available_log_types()
    self.rule_analyzer = rule_analyzer or RuleAnalyzer(available_types)
    self._client = None

  @property
  def client(self):
    if self._client is None:
      self._client = get_genai_client(self.config)
    return self._client

  def _build_prompt(
      self,
      scenario: str,
      log_types: List[str],
      custom_system_prompt: Optional[str] = None,
      count: Optional[int] = None,
  ) -> str:
    """Construct the full generation prompt including schema guides."""
    guides_section = []
    for lt in log_types:
      guide = self.playbook_service.get_guide(lt)
      if guide:
        guides_section.append(f"### Schema Guide for {lt}:\n{guide}\n")
      else:
        guides_section.append(
            f"### Schema Guide for {lt}:\n(No saved guide found. Use standard industry format for {lt}.)\n"
        )

    guides_text = "\n".join(guides_section)
    count_directive = f"\n## Target Event Count:\nGenerate approximately {count or 5} total log event(s) across the requested log sources.\n"

    return f"""## Scenario Description:
{scenario}
{count_directive}
## Requested Log Types:
{', '.join(log_types)}

## Log Type Schema Guides:
{guides_text}

Generate the complete attack scenario logs as specified."""

  def generate(
      self,
      scenario: str,
      log_types: Optional[List[str]] = None,
      base_time: Optional[datetime] = None,
      custom_system_prompt: Optional[str] = None,
      enrich_gti: bool = False,
      count: Optional[int] = 5,
  ) -> GeneratedScenario:
    """Generate synthetic logs for the specified scenario."""
    if not log_types:
      log_types = self.infer_log_types(scenario)
    if not log_types:
      log_types = ["WINDOWS_SYSMON"]

    if not scenario or len(scenario.strip()) < 5:
      raise ValueError("Scenario description must be provided.")

    enriched_text = None
    actual_scenario = scenario
    if enrich_gti:
      enriched_text = self.gti_client.enrich_scenario(scenario)
      actual_scenario = f"""### User High-Level Intent:
{scenario}

### Google Threat Intelligence (GTI) Real-World Scenario & Indicators:
{enriched_text}
"""

    prompt = self._build_prompt(actual_scenario, log_types, custom_system_prompt, count=count)
    system_instruction = custom_system_prompt or SCENARIO_SYSTEM_PROMPT

    try:
      from google.genai import types as genai_types
      gen_config = genai_types.GenerateContentConfig(
          system_instruction=system_instruction,
          temperature=self.config.temperature,
          top_p=self.config.top_p,
          response_mime_type="application/json",
          thinking_config=genai_types.ThinkingConfig(
              thinking_budget=self.config.thinking_budget,
          ),
      )
    except (ImportError, AttributeError):
      gen_config = None

    response = self.client.models.generate_content(
        model=self.config.model,
        contents=prompt,
        config=gen_config,
    )

    raw_text = response.text or "{}"
    return self._parse_response(
        raw_text, scenario, base_time, enriched_narrative=enriched_text
    )

  def _parse_response(
      self,
      raw_text: str,
      scenario_description: str,
      base_time: Optional[datetime] = None,
      enriched_narrative: Optional[str] = None,
  ) -> GeneratedScenario:
    """Parse Gemini's JSON response and resolve time templates."""
    # Strip optional markdown code fence
    cleaned = raw_text.strip()
    if cleaned.startswith("```json"):
      cleaned = cleaned[7:]
    if cleaned.startswith("```"):
      cleaned = cleaned[3:]
    if cleaned.endswith("```"):
      cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    try:
      data = json.loads(cleaned)
    except json.JSONDecodeError:
      # Fallback: extract json using regex
      match = re.search(r"\{.*\}", cleaned, re.DOTALL)
      if match:
        data = json.loads(match.group(0))
      else:
        data = {"title": "Generated Scenario", "logs": {}}

    title = data.get("title", "Synthetic Attack Scenario")
    raw_logs = data.get("logs", {})

    effective_base_time = (
        parse_base_timestamp(base_time)
        or extract_timestamp_from_text(scenario_description)
        or datetime.now(timezone.utc)
    )
    time_service = TimeTemplateService(effective_base_time)

    parsed_logs: Dict[str, List[LogEntry]] = {}

    for log_type, entries in raw_logs.items():
      parsed_logs[log_type] = []
      for entry in entries:
        # Convert dict to JSON string if needed
        if isinstance(entry, (dict, list)):
          entry_str = json.dumps(entry)
          fmt = LogFormat.JSON
        else:
          entry_str = str(entry)
          fmt = LogFormat.JSON if entry_str.strip().startswith(("{", "[")) else LogFormat.RAW

        # Resolve relative timestamps into real dates and capture per-event offset timestamp
        resolved_content, entry_dt = time_service.replace_templates_with_timestamp(entry_str)

        parsed_logs[log_type].append(
            LogEntry(
                log_type=log_type,
                content=resolved_content,
                format=fmt,
                timestamp=entry_dt,
            )
        )

    return GeneratedScenario(
        title=title,
        description=scenario_description,
        logs=parsed_logs,
        raw_response=raw_text,
        enriched_narrative=enriched_narrative,
    )

  def infer_log_types(self, case_text: str) -> List[str]:
    """Analyze a case report and infer the appropriate SIEM log types from available playbooks."""
    available_types = self.playbook_service.list_available_log_types()
    available_str = (
        ", ".join(available_types)
        if available_types
        else "AWS_CLOUDTRAIL, AWS_VPC_FLOW, GUARDDUTY, OKTA, WINDOWS_SYSMON, GCP_CLOUDAUDIT"
    )

    prompt = f"""Given the following Security Case Report / Incident Alert Summary, identify the most relevant SIEM log types required to generate full surrounding telemetry (Pre-incident setup, Core alert events, and Post-incident outcome).

Available Log Jammer Playbook Schemas:
{available_str}

Case Report:
{case_text}

Return a valid JSON array of 1 to 5 matching log type strings (e.g. ["AWS_CLOUDTRAIL", "AWS_VPC_FLOW"]).
Return ONLY the JSON array."""

    try:
      from google.genai import types as genai_types
      gen_config = genai_types.GenerateContentConfig(
          response_mime_type="application/json",
          temperature=0.2,
      )
      response = self.client.models.generate_content(
          model=self.config.model,
          contents=prompt,
          config=gen_config,
      )
      data = json.loads(response.text)
      if isinstance(data, list) and data:
        return [str(x) for x in data]
    except Exception:
      pass

    # Heuristic fallback matching keywords
    text_lower = case_text.lower()
    inferred = []
    if any(k in text_lower for k in ("aws", "cloudtrail", "glue", "iam", "sts", "s3")):
      inferred.append("AWS_CLOUDTRAIL")
      if any(k in text_lower for k in ("ip", "network", "connection", "vpc", "flow")):
        inferred.append("AWS_VPC_FLOW")
    elif any(k in text_lower for k in ("gcp", "google", "bigquery")):
      inferred.append("GCP_CLOUDAUDIT")
    elif any(k in text_lower for k in ("azure", "entra")):
      inferred.append("AZURE_ACTIVITY")
    elif "slack" in text_lower:
      inferred.append("SLACK_AUDIT")
    elif "github" in text_lower:
      inferred.append("GITHUB")

    return inferred or ["AWS_CLOUDTRAIL"]

  def generate_from_case(
      self,
      case_text: str,
      log_types: Optional[List[str]] = None,
      surround_before: str = "30m",
      surround_after: str = "30m",
      outcome: str = "benign",
      base_time: Optional[datetime] = None,
      custom_system_prompt: Optional[str] = None,
      enrich_gti: bool = False,
  ) -> GeneratedScenario:
    """Generate a multi-stage surrounding log scenario from an input case report."""
    if not log_types:
      log_types = self.infer_log_types(case_text)

    case_scenario_prompt = f"""### INPUT CASE REPORT / INCIDENT ALERT:
{case_text}

### SCENARIO GENERATION REQUIREMENTS:
1. **Pre-Incident Phase (-{surround_before} before anchor timeline)**:
   Generate initial authentication, network handshakes, STS session creation, API key lookups, or user activity leading up to the case events.
2. **Core Incident Anchor Phase**:
   Re-create the exact sequence of events detailed in the case report timeline.
3. **Post-Incident Phase (+{surround_after} after anchor timeline)**:
   Generate the outcome activity based on the specified verdict/outcome: '{outcome}'.
   If benign: routine data verification, cleanup, session logout, or normal scheduled task completion.
   If malicious: credential dumping, data exfiltration, lateral movement, or backdoor creation.
4. **Entity Consistency**:
   Re-use all exact IPs, usernames, role ARNs, session IDs, hostnames, and account IDs from the case report across all generated log types.
"""
    return self.generate(
        scenario=case_scenario_prompt,
        log_types=log_types,
        base_time=base_time,
        custom_system_prompt=custom_system_prompt,
        enrich_gti=enrich_gti,
    )

  def generate_from_rule(
      self,
      rule: Union[SecOpsRule, str],
      log_types: Optional[List[str]] = None,
      outcome: str = "fire",
      base_time: Optional[datetime] = None,
      custom_system_prompt: Optional[str] = None,
      count: Optional[int] = None,
      additional_context: Optional[str] = None,
  ) -> GeneratedScenario:
    """Generate synthetic logs engineered to trigger or test a specific YARA-L rule."""
    if isinstance(rule, str):
      rule_obj = self.rule_service.get_rule(rule)
      if not rule_obj:
        # Check if rule string is raw YARA-L rule code
        if "rule " in rule and ("meta:" in rule or "events:" in rule or "condition:" in rule):
          from .rules import extract_mitre_ids
          techs, tacs = extract_mitre_ids({}, rule)
          rule_name_match = re.search(r"rule\s+([A-Za-z0-9_]+)", rule)
          rule_obj = SecOpsRule(
              rule_id=rule_name_match.group(1) if rule_name_match else "custom_rule",
              display_name=rule_name_match.group(1) if rule_name_match else "Custom Rule",
              text=rule,
              techniques=techs,
              tactics=tacs,
          )
        else:
          raise ValueError(
              f"Could not find SecOps rule '{rule}' in local cache, files, or tenant API."
          )
    else:
      rule_obj = rule

    analysis = self.rule_analyzer.analyze(rule_obj)

    # Inferred log types if not provided
    primary_trigger_type = (
        analysis.suggested_log_types[0] if analysis.suggested_log_types else "WINDOWS_SYSMON"
    )
    if not log_types:
      if additional_context and additional_context.strip() and outcome in ("full-chain", "fire"):
        surrounding_types = self.infer_log_types(additional_context)
        merged_types = [primary_trigger_type]
        for st in surrounding_types:
          if st.upper() not in merged_types and len(merged_types) < 4:
            merged_types.append(st.upper())
        log_types = merged_types
      else:
        log_types = analysis.suggested_log_types[:2] if analysis.suggested_log_types else ["WINDOWS_SYSMON"]
    else:
      # Ensure the rule's primary trigger log type is always included first
      if primary_trigger_type not in [lt.upper() for lt in log_types]:
        log_types = [primary_trigger_type] + list(log_types)

    # Target event count
    target_count = max(count or 1, analysis.threshold_count, 1)

    rule_scenario_prompt = f"""### TARGET YARA-L DETECTION RULE:
Name: {rule_obj.display_name}
Rule ID: {rule_obj.rule_id}
Precision: {rule_obj.raw_data.get('precision', 'PRECISE')}
MITRE Techniques: {', '.join(analysis.techniques) if analysis.techniques else 'N/A'}
MITRE Tactics: {', '.join(analysis.tactics) if analysis.tactics else 'N/A'}

### YARA-L 2.0 RULE TEXT:
```yara
{rule_obj.text}
```

### TRIGGER ANALYSIS & UDM REQUIREMENTS:
{analysis.summary}
- Primary Trigger Log Type (MUST generate the rule-triggering event(s) in this log source): `{primary_trigger_type}`

### SCENARIO GENERATION OBJECTIVE:
Objective: '{outcome.upper()}'
- If 'fire': You MUST generate logs in `{primary_trigger_type}` that trigger this detection. Every positive constraint in the rule must be matched. Exclusions MUST be strictly avoided. Ensure at least {analysis.threshold_count} matching trigger event(s) are generated, plus supporting telemetry across `{', '.join(log_types)}` up to ~{target_count} total events.
- If 'evade' or 'negative': Deliberately generate activity that resembles the threat but hits at least one exclusion clause (to verify false positive defense).
- If 'full-chain': Generate a cohesive multi-source attack timeline (~{target_count} total events across `{', '.join(log_types)}`):
  1. Pre-incident recon / initial access / authentication events in surrounding log sources,
  2. The exact {analysis.threshold_count}+ rule-triggering event(s) in `{primary_trigger_type}` that 100% satisfy every YARA-L positive constraint and avoid every negative exclusion,
  3. Post-incident network/cloud/system corroborating events.

Generate raw logs in the specified log format(s) ({', '.join(log_types)}) that Google SecOps parsers will convert into UDM events satisfying the rule.
"""
    if additional_context and additional_context.strip():
      rule_scenario_prompt += f"\n### ADDITIONAL USER CONTEXT:\n{additional_context.strip()}\n"

    system_instruction = custom_system_prompt or RULE_SYSTEM_PROMPT
    return self.generate(
        scenario=rule_scenario_prompt,
        log_types=log_types,
        base_time=base_time,
        custom_system_prompt=system_instruction,
        count=target_count,
    )

