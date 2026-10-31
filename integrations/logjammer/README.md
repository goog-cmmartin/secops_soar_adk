# LogJammer Google SecOps SOAR Integration

LogJammer integrates Google Gemini, curated YARA-L detection rule deconstruction, schema guide lookup, Google Threat Intelligence (GTI) enrichment, and direct Chronicle v1alpha log ingestion into Google SecOps SOAR.

## Features
- **Attack Scenario Log Generation**: Generates multi-source synthetic logs conforming to exact schema guides (Sysmon, Okta, CloudTrail, PAN Firewall, Zeek, etc.).
- **Curated Rule Telemetry Synthesis**: Reverse-engineers any of the 5,719 bundled Google Curated Detection rules to generate telemetry guaranteed to trigger or evade detections.
- **37 Bundled Playbooks**: Includes detailed guides covering log formats, headers, field distributions, and relative timestamping (`##$TimeStamp-0d1h0s$##`).
- **GTI Threat Grounding**: Enriches prompts with live threat actor indicators, hashes, and infrastructure from Google Threat Intelligence / VirusTotal.
- **Direct SecOps Ingestion**: Ingests generated logs directly into Chronicle SIEM via `POST /v1alpha/.../logs:import`.
- **SOAR Interactive Widget**: Rich HTML visualization showing multi-log source tabs, event counts, MITRE ATT&CK badges, and ingestion status.
- **Scheduled Scenario Job**: Periodically injects synthetic scenarios for automated detection regression testing.

## Configuration Parameters
- **Gemini API Key**: (Optional) API key for direct Google Gemini API access.
- **Google Threat Intelligence API Key**: (Optional) API key for VirusTotal / GTI Agentic enrichment.
- **Service Account JSON / Workload Identity Email**: (Optional) For GCP Vertex AI and SecOps API authentication.
- **GCP Project ID**: SecOps project ID / number (e.g. `37679061640`).
- **SecOps Customer ID**: Chronicle customer ID GUID (e.g. `a556547c-1cff-43ef-a2e4-cf5b12a865df`).
- **SecOps Region**: SecOps instance region (e.g. `us`).
- **Model Name**: Gemini model (default `gemini-3.7-flash`).
