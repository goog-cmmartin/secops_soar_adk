# SecOps SDK Engine SOAR Integration

High-performance, deterministic Google SecOps SOAR Integration powered by the custom **SecOps Engine SDK**.

---

## Overview

The `SecOpsSDKEngine` integration provides direct, high-throughput Chronicle SIEM and SOAR automation capabilities without external agent overhead. It wraps core SecOps Engine SDK workflows into native Siemplify SOAR actions adhering strictly to the Google Chronicle Content Hub standard.

### Key Capabilities
- **Deterministic Silent Detection Correlation**: Scans case entities across configurable time windows, discovers non-alerting rule detections and underlying UDM events, and automatically binds them to the Case.
- **Automated Case Evidence Attachment**: Uses the Chronicle SOAR native `batchCreateCaseEvidence` API to attach detections and events directly to the Case Evidence collection.
- **Automated Case Entity Discovery & Attachment**: Automatically discovers delta observables (IPs, user accounts/ARNs, URLs, hostnames) in detection events and attaches them directly to the Case Alert via `POST /v1alpha/.../cases/{caseId}/caseAlerts/{alertId}/involvedEntities`.
- **Rich Case Wall Reporting**: Formats executive Markdown tables summarizing lookback windows, scanned entities, detections found, evidence attached, and newly discovered entities.
- **Results View Widget**: An integrated HTML/CSS widget visualizing correlation metrics, detection timelines, and attached evidence records.

---

## Authentication & Configuration

The integration supports dual enterprise authentication methods:

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `SecOps Customer ID` | String | Yes | Chronicle SecOps Customer GUID (e.g. `a556547c-1cff-43ef-a2e4-cf5b12a865df`). |
| `GCP Project ID` | String | Yes | Google Cloud Project hosting SecOps (e.g. `sdl-preview-americas`). |
| `SecOps Region` | String | Yes | SecOps region (default: `us`). |
| `Workload Identity Email` | String | No | Target Service Account email for keyless WIF / SA impersonation (e.g. `sa-chronicle-api@sdl-preview-americas.iam.gserviceaccount.com`). |
| `Service Account JSON` | Password | No | Google Cloud Service Account JSON credentials (for off-GCP / standalone execution). |
| `Verify SSL` | Boolean | Yes | Validate SSL certificates (default: `true`). |

---

## Actions Reference

### 1. `Ping`
Validates connectivity and authentication credentials against Google SecOps.
- **Inputs**: None (uses Integration Instance settings).
- **Outputs**:
  - `is_success`: `true` / `false`
  - JSON payload with authenticated customer ID and region.

### 2. `Correlate Silent Detections`
Correlates case entities with silent (non-alerting) detections and UDM events, with optional native case evidence and entity attachment.

#### Action Parameters:
- `Case ID` (String, Optional): Numeric or terminal Case ID (defaults to active case context).
- `Lookback Hours` (Integer, Default: `24`): Time window to query prior to the case creation time.
- `Attach to Case` (Boolean, Default: `false`): Attaches discovered detections and events to Case Evidence.
- `Attach Entities` (Boolean, Default: `true`): Discovers delta entities in detection events and attaches them to the Case.
- `Post Wall Comment` (Boolean, Default: `true`): Publishes the Markdown correlation report to the Case Wall.
- `Entity Filter` (String, Optional): Comma-separated list of entities to scan (defaults to all case entities).
- `Max Events` (Integer, Default: `1000`): Maximum UDM events to process.

### 3. `Related Cases by Entity`
Searches active (open) and historical (closed) SOAR cases for shared entities involved in the current case, returning related cases ranked by entity overlap, status, priority, and recency, along with an interactive HTML Widget featuring clickable Case links.

#### Action Parameters:
- `Case ID` (String, Optional): Numeric or terminal Case ID (defaults to active case context).
- `Lookback Days` (Integer, Default: `90`): Number of days in the past to search for active and historical SOAR cases.
- `Case Status Scope` (DDL, Default: `ALL`): Filter related cases by status (`ALL`, `ACTIVE_ONLY`, or `CLOSED_ONLY`).
- `Min Shared Entities` (Integer, Default: `1`): Minimum number of shared entities required to include a related case.
- `Max Related Cases` (Integer, Default: `50`): Maximum number of related cases to return.
- `Entity Filter` (String, Optional): Optional comma-separated list of entity identifiers to filter or explicitly search for.
- `Include Threat Actor Entities` (Boolean, Default: `false`): If true, includes high-level Threat Actor and Malware entities (e.g., UNC groups) in addition to concrete observables.
- `Post Wall Comment` (Boolean, Default: `false`): If true, posts a Markdown summary table of related cases to the Case Wall.
- `SecOps UI Base URL` (String, Optional): Optional SecOps UI base URL for Case links (auto-detected from the active SecOps browser window if left blank).

---

## Deployment & Installation

### Option A: Web UI 1-Click Import
1. Download `dist/SecOpsSDKEngine.zip` (9.7 MB).
2. In Google SecOps SOAR, navigate to **Response Integrations** -> **+ Add Integration** -> **Import Integration**.
3. Upload `SecOpsSDKEngine.zip` and configure the instance.

### Option B: Content Hub CLI (`mp`)
```bash
mp push integration secops_sdk_engine --custom --keep-zip
```
