# Google Decisions (`gemini-decision-1`) SOAR Integration

Zero-decoded-token, sub-second probabilistic classification, routing, and rubric scoring for **Google SecOps (Chronicle) SOAR** powered by Google's **`gemini-decision-1`** model (`POST /v1beta/decisions`).

---

## Overview

Traditional LLM triage steps decode hundreds or thousands of output tokens to explain a routing decision—adding 5–15 seconds of latency, output-token costs, and brittle JSON/regex parsing.

The **`GoogleDecisions`** custom SOAR integration wraps the native **Gemini Decisions API** (`https://generativelanguage.googleapis.com/v1beta/decisions`), which computes exact single-forward-pass log-likelihood probabilities across structured question criteria (`noul` boolean, `multiple_choice`, and `ranking` rubrics) with **`0` output tokens** in **~350–650 ms**.

### Key Capabilities
- **Sub-Second Playbook Branching (`0` Output Tokens)**: Evaluates multiple independent boolean, routing, and severity rubric questions in a single API call and returns calibrated probabilities (`0.0` to `1.0`) for every choice.
- **Confidence Gating (`auto_action_ready`)**: Automatically computes `min_confidence`, `avg_confidence`, `low_confidence_questions`, and an `auto_action_ready` boolean gate against a configurable threshold (e.g., `0.80`) so SOAR playbooks can deterministically decide whether to auto-execute or escalate to a human analyst.
- **5 Built-In SOC Decision Presets**: Ready-to-run question batteries for common SecOps workflows, plus dynamic custom question injection.
- **Native SOAR Case Overview HTML Widgets**: Includes two theme-synchronized (`--soar-*` Dark/Light mode) HTML widgets for the Case Overview and Playbook Step Result views.
- **Enterprise Triple-Mode Authentication**: Supports Gemini API Key (`x-goog-api-key`), Service Account JSON, and keyless Workload Identity Federation (WIF) / Application Default Credentials.

---

## Authentication & Configuration

Configure the integration under **Response > Integrations Setup > GoogleDecisions**:

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `API Endpoint` | String | Yes | `https://generativelanguage.googleapis.com/v1beta/decisions` | Gemini Decisions API endpoint URL. |
| `Model ID` | String | Yes | `gemini-decision-1` | Target Decisions model identifier. |
| `Gemini API Key` | Password | No | — | Google AI Studio / Gemini API Key (`x-goog-api-key`). |
| `GCP Project ID` | String | No | — | Google Cloud Project ID used for Vertex/IAM quota attribution (`x-goog-user-project`). |
| `Workload Identity Email` | String | No | — | Optional Service Account email to impersonate via keyless Workload Identity / ADC. |
| `Service Account JSON` | Password | No | — | Optional GCP Service Account JSON key when not using API Key or WIF. |
| `Verify SSL` | Boolean | Yes | `true` | Validate SSL certificates on outbound HTTPS calls. |

---

## Actions Reference

### 1. `Ping`
Validates connectivity and authentication against `POST /v1beta/decisions` using `gemini-decision-1`.
- **Inputs**: None (uses Integration Instance settings).
- **Outputs**: `is_success: true/false` and authenticated endpoint details.

---

### 2. `Run SOC Decision Preset`
Executes one of 5 pre-built SOC decision batteries against the current SOAR Case and Alert telemetry (automatically collecting Case metadata, Alert rule descriptions, UDM fields, and involved entities), with optional custom question overrides.

#### Built-In Decision Presets (`Decision Preset` DDL):
1. **`Tier-1 Alert Triage & Routing`**:
   - `is_likely_true_positive` (`noul`: `true` / `false`)
   - `has_sufficient_context_for_auto_triage` (`noul`: `true` / `false`)
   - `recommended_routing_queue` (`multiple_choice`: `auto_close_benign` | `tier1_standard_queue` | `tier2_threat_hunt` | `incident_commander_critical`)
   - `severity_assessment` (`ranking`: `critical` | `high` | `medium` | `low` | `informational`)
2. **`Autonomous Detection Tuning Safety Gate`**:
   - `is_safe_for_automated_exclusion` (`noul`: `true` / `false`)
   - `contains_active_attacker_tradecraft` (`noul`: `true` / `false`)
   - `recommended_tuning_scope` (`multiple_choice`: `do_not_tune_investigate` | `host_or_account_scoped_exclusion` | `command_line_or_hash_scoped_exclusion` | `rule_logic_refinement_required`)
   - `blast_radius_risk` (`ranking`: `critical_blindspot_risk` | `moderate_coverage_risk` | `low_scoped_risk` | `minimal_safe_to_apply`)
3. **`Containment & Remediation Safety Gate`**:
   - `is_malicious_activity_confirmed` (`noul`)
   - `is_safe_for_automated_containment` (`noul`)
   - `recommended_containment_action` (`multiple_choice`)
   - `business_disruption_risk` (`ranking`)
4. **`Phishing & BEC Triage`**:
   - `is_malicious_phishing_or_bec` (`noul`)
   - `is_credential_or_session_compromised` (`noul`)
   - `email_threat_classification` (`multiple_choice`)
   - `remediation_urgency` (`ranking`)
5. **`DLP & Data Exfiltration Assessment`**:
   - `is_unauthorized_external_exfiltration` (`noul`)
   - `contains_regulated_or_sensitive_ip` (`noul`)
   - `data_movement_classification` (`multiple_choice`)
   - `escalation_path` (`ranking`)

#### Action Parameters:
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Decision Preset` | Dropdown | `Tier-1 Alert Triage & Routing` | Pre-configured SOC decision battery to evaluate. |
| `Include Case & Alert Context` | Boolean | `true` | Automatically inspect active SOAR Case, Alerts, and Entities to build the input context. |
| `Additional Context or Telemetry` | String | — | Optional enrichment results, silent detection summaries, or command lines to append to the context. |
| `Custom Questions Override (JSON)` | String | — | Optional JSON object of additional/override questions merged into the preset. |
| `Confidence Threshold` | String | `0.80` | Minimum top-choice probability (`0.0`–`1.0`) required to mark `auto_action_ready = true`. |
| `Max Input Characters` | String | `60000` | Maximum character budget for the shared input context before smart JSON compaction and 70/30 head+tail truncation are applied to stay safely below the 262,144 token limit. |
| `Post Case Wall Summary` | Boolean | `true` | Post a formatted Markdown decision scorecard table to the SOAR Case Wall. |

---

### 3. `Evaluate Decisions`
Evaluates an arbitrary user-defined JSON schema of `noul` (boolean), `multiple_choice`, and `ranking` questions against any provided context text.

#### Example `Questions Schema (JSON)`:
```json
{
  "requires_deep_adk_investigation": {
    "type": "noul",
    "instructions": "Does this case exhibit multi-stage attack progression, silent YARA-L detections, suspicious command lines, or ambiguity that warrants a deep multi-turn AI investigation?",
    "criteria": {
      "true_description": "Multi-stage attack indicators, silent YARA-L detections, lateral movement, or investigative ambiguity requiring deep multi-turn analysis.",
      "false_description": "Single isolated false-positive or routine benign activity with zero correlated silent detections."
    }
  }
}
```

---

## Playbook Patterns & JSON Result Placeholders

Every execution returns a structured `JsonResult` engineered for deterministic SOAR `IfFlowCondition` playbook branches (using Chronicle SOAR's pipe JSON-path syntax):

- `[GoogleDecisions_Run SOC Decision Preset_1.JsonResult| "all_confident"]` (`true` / `false`)
- `[GoogleDecisions_Run SOC Decision Preset_1.JsonResult| "escalation_required"]` (`true` / `false`)
- `[GoogleDecisions_Run SOC Decision Preset_1.JsonResult| "summary.<question_key>"]` (e.g., `true`, `false`, or selected choice key)
- `[GoogleDecisions_Run SOC Decision Preset_1.JsonResult| "summary.<question_key>_confidence"]` (e.g., `0.942`)

### Example Playbook Use Cases
1. **Smart Compute & Latency Gate Ahead of Multi-Turn AI Agents (`GoogleADK`)**:
   Evaluate correlated entities and silent detections in `~400–600 ms` with `0` output tokens before invoking a 30–60s multi-turn Vertex AI / ADK investigation agent—skipping heavy LLM compute on clear benign false positives and routing directly to autonomous tuning.
2. **Autonomous Detection Tuning Safety Gate**:
   Gate YARA-L exclusion proposals generated by `SecOpsSDKEngine_Autonomous Detection Tuning` to verify `is_safe_for_automated_exclusion == true` and `contains_active_attacker_tradecraft == false` before applying rule exclusions.

---

## Repository Structure

```text
.
├── definition.yaml                         # Content Hub integration manifest (v1.2)
├── pyproject.toml                          # Python 3.11 package & dependency metadata
├── release_notes.yaml                      # Versioned release notes
├── uv.lock                                 # Deterministic lockfile
├── core/
│   ├── __init__.py
│   └── GoogleDecisionsManager.py           # Decisions API client, SOC presets & probability parser
├── actions/
│   ├── ping.py / ping.yaml
│   ├── evaluate_decisions.py / .yaml
│   └── run_soc_decision_preset.py / .yaml
├── widgets/
│   ├── evaluate_decisions_view.html / .yaml
│   └── soc_decision_preset_view.html / .yaml
├── resources/
│   ├── logo.svg
│   └── image.png
├── tests/
│   └── test_decisions.py                   # Offline & live API unit test suite
└── dist/
    └── GoogleDecisions.zip                 # Ready-to-import Chronicle SOAR package
```

---

## Deployment & Installation

### Option A: Single-Click Chronicle SOAR Web UI Import
1. Download [`dist/GoogleDecisions.zip`](dist/GoogleDecisions.zip).
2. In Google SecOps SOAR, navigate to **Response > IDE / Response Integrations** -> **Import Custom Integration**.
3. Upload `GoogleDecisions.zip` and configure an instance in **Response > Integrations Setup**.

### Option B: Chronicle Content Hub CLI (`mp`)
```bash
# Build and validate
mp build --custom-integration -i google_decisions

# Push directly to your Chronicle SOAR tenant
mp push integration google_decisions --custom --keep-zip
```
