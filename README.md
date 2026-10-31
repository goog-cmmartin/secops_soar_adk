# Google SecOps SOAR - Google ADK Integration

An enterprise-ready custom integration package for orchestrating **Google Agent Development Kit (ADK)** agents directly within **Google Security Operations (SecOps) SOAR** playbooks and cases.

Equips SOC teams, security engineers, and incident responders with autonomous, tool-augmented Gemini agents that run natively or in isolated cloud sandboxes to investigate alerts, execute complex triage workflows, search the open web (OSINT), interact with Model Context Protocol (MCP) servers, query knowledge bases, and maintain multi-turn investigation memories.

---

## 🚀 How to Import into Google SecOps SOAR

There are two primary ways to deploy and import this integration:

### Method 1: Direct Web UI Import (Quickest & Recommended)

Users do not need Python, Docker, or development tooling installed locally:

1. **Download the Compiled Package**:
   - Download [`GoogleADK.zip`](dist/GoogleADK.zip) (approx. 10.6 MB) directly from the `dist/` directory or the GitHub Releases section of this repository.
   - *This standalone archive is pre-compiled with all action handlers, Google ADK manager layer, official SVG/PNG branding assets, pre-built HTML Results Widget, and vendored wheels compatible with the Chronicle Python 3.11 runner.*
2. **Import into SecOps SOAR**:
   - Log into your Google SecOps instance.
   - Navigate to **Response** > **Integrations** (or **Settings** > **Integrations**).
   - Click **+ Add Integration** or **Import Custom Integration**.
   - Drag and drop or browse to upload `GoogleADK.zip`.
3. **Configure & Enable**:
   - Click on the newly imported **GoogleADK** integration in your integration catalog.
   - Configure an instance following the [Authentication Setup](#-authentication-setup) instructions below.

---

### Method 2: Chronicle Content Hub CLI (`mp`) Deployment

For DevOps, SecOps engineers, and CI/CD pipelines deploying integrations as code:

```bash
# 1. Clone this repository
git clone https://github.com/goog-cmmartin/secops_soar_adk.git
cd secops_soar_adk

# 2. Build the integration bundle (validates definition, deps, and packages out zip)
mp build integration google_adk --custom

# 3. Push directly to your Chronicle SOAR tenant
mp push integration google_adk --custom
```

---

## 🔐 Authentication Setup

GoogleADK supports three flexible authentication methods:

### Option A: Workload Identity Federation (Recommended & Keyless)

Eliminates static service account keys by using ambient GKE cluster credentials and Google Cloud IAM impersonation.

1. **Configure Integration Instance**:
   - **Workload Identity Email**: Set to your target GCP service account (e.g. `sa-chronicle-api@<PROJECT_ID>.iam.gserviceaccount.com`).
   - **GCP Project ID**: Set to your Google Cloud project ID (e.g. `sdl-preview-americas`).
2. **Grant IAM Token Creator Role**:
   Grant the Chronicle SOAR host runner service account permission to generate tokens on behalf of your target service account:
   ```bash
   gcloud iam service-accounts add-iam-policy-binding \
     sa-chronicle-api@<PROJECT_ID>.iam.gserviceaccount.com \
     --member="serviceAccount:<CHRONICLE_RUNNER_SA>" \
     --role="roles/iam.serviceAccountTokenCreator" \
     --project=<PROJECT_ID>
   ```
   > [!TIP]
   > If you encounter an `iam.serviceAccounts.getAccessToken` permission denial during initial testing, click the **IAM Policy Troubleshooter URL** output directly in your SOAR action execution log to identify the exact caller identity and grant access with a single click.

---

### Option B: Service Account JSON Key

For environments utilizing standard service account key credentials:
1. Paste the full JSON contents of your GCP service account key into the **Service Account JSON** configuration parameter.
2. Ensure the service account has Vertex AI User (`roles/aiplatform.user`) permissions on your GCP project.

---

### Option C: Gemini API Key

For testing or environments leveraging Google AI Studio:
1. Paste your Gemini API key into the **Gemini API Key** configuration parameter.
2. The integration will automatically route requests through Google GenAI API services.

---

## 🧠 Frontier Models & Global Routing

The integration natively supports modern Gemini models:
- **`gemini-3.8-flash`** *(Default)*: Optimized for real-time threat analysis, sub-second responses, and live Google Search grounding.
- **`gemini-4-argon`**: Deep reasoning and complex autonomous incident triage.
- **`gemini-3.7-flash`**: High-performance reasoning with configurable thinking budgets.
- **`gemini-2.5-pro`** & **`gemini-2.5-flash`**: Enterprise Vertex AI models.

> [!NOTE]
> Frontier models (`gemini-3.8-flash`, `gemini-4-argon`, etc.) are automatically routed to the Vertex AI `global` location endpoint (`location="global"`), while regional models route to the specified `SecOps Region` parameter.

---

## ⚡ Integration Actions Catalog

| Action | Description | Key Parameters |
| :--- | :--- | :--- |
| **`Ping`** | Validates API connectivity, credentials, and model availability. | `Model Name` |
| **`Run ADK Agent`** | Executes a general-purpose ADK reasoning and analysis agent with optional embedded `SecOpsEngine` (`32` native tools), Hosted MCP, Google Search, and Code Execution. | `User Prompt`, `Thinking Budget`, `Agent Name`, `Enable SecOps Engine Toolset`, `Enable Google Search`, `Enable Memory` |
| **`Run Google Search Agent`** | Performs live web searches and OSINT threat intelligence research using native Google Search grounding. | `User Prompt`, `Thinking Budget`, `Enable Memory` |
| **`Run Code Execution Agent`** | Executes dynamic Python code inside the Gemini model interpreter for rapid calculations and data analysis. | `User Prompt`, `Thinking Budget`, `Enable Memory` |
| **`Run Code Execution Agent Sandbox`** | Executes Python code in a dedicated, isolated Vertex AI Agent Engine container sandbox. | `User Prompt`, `Thinking Budget`, `Agent Engine Resource Name` |
| **`Run Hosted MCP ADK Agent`** | Connects to Google-hosted or custom Model Context Protocol (MCP) servers with dynamic OAuth token rotation. | `User Prompt`, `Thinking Budget`, `Tool Filter` |
| **`Run ADK Memory Bank Agent`** | Multi-turn stateful agent leveraging short-term and long-term session memory banks across playbook steps. | `User Prompt`, `Session ID`, `Enable Memory` |
| **`Run ADK GCS Agent`** | Autonomous agent equipped with Google Cloud Storage tools for reading and writing bucket artifacts. | `User Prompt`, `Thinking Budget`, `Bucket Name` |
| **`Run ADK Skill Registry Agent`** | Dynamically discovers, loads, and executes remote security runbooks and skills from the GCP Skill Registry. | `User Prompt`, `Thinking Budget`, `Skill ID` |
| **`Run ADK Agent Registry Agent`** | Discovers and invokes multi-agent configurations from the central GCP Agent Registry. | `User Prompt`, `Thinking Budget` |

---

## ⏱️ SOAR Scheduled & On-Demand Jobs

| Job | Description | Key Parameters |
| :--- | :--- | :--- |
| **`Run ADK Autonomous Agent Job`** | Executes an autonomous Google ADK Agent on a recurring schedule or on-demand in SOAR Jobs Scheduler. Supports both **Autonomous Mission Mode** (auditing Data Tables, Native Dashboards, Playbooks, Rules, and UDM) and **Open Case Sweep Mode** (sweeping recent open SOAR cases, correlating silent detections, and posting Markdown reports to Case Walls). | `Prompt`, `Agent Name`, `Thinking Budget`, `Enable SecOps Engine Toolset`, `Enable Hosted MCP Toolset`, `Enable Google Search`, `Enable Code Execution`, `Sweep Recent Open Cases`, `Target Case IDs`, `Post Report to Case Wall` |

---

## 🛠️ Embedded `SecOpsEngine` Toolset (`32` Native Tools)

When `Enable SecOps Engine Toolset` is enabled on **`Run ADK Agent`** or **`Run ADK Autonomous Agent Job`**, the agent is equipped with `32` native Python functions powered by the embedded `secops_engine_sdk`:

- **UDM, Silent Detections & Entities (`4`)**: `correlate_silent_detections`, `search_udm_events`, `aggregate_udm_events`, `investigate_entity`
- **YARA-L 2.0 Rules & Tuning (`3`)**: `get_detection_rule`, `list_detection_rules`, `find_top_noisy_rules`
- **SOAR Cases & Case Wall (`5`)**: `list_soar_cases`, `investigate_soar_case`, `add_soar_case_comment`, `list_soar_case_comments`, `update_soar_case`
- **Chronicle Data Tables (`7`)**: `list_data_tables`, `get_data_table`, `create_data_table`, `list_data_table_rows`, `add_data_table_rows`, `delete_data_table_row`, `audit_data_table_health`
- **Chronicle Native Dashboards (`9`)**: `search_dashboards`, `get_dashboard`, `execute_dashboard_query`, `create_dashboard`, `update_dashboard`, `add_dashboard_chart`, `update_dashboard_chart`, `remove_dashboard_chart`, `audit_dashboard_health`
- **SOAR Playbooks & Health Audits (`4`)**: `search_playbooks`, `get_playbook`, `audit_playbook_health`, `audit_playbook_decay`

---

## 🎨 Built-in HTML Results Widget

Every agent action automatically packages rich structured output and is paired with the custom **ADK Result View** widget (`widgets/adk_result_view`):
- Displays the Agent Name, Model Version, and Session ID badge.
- Shows agent reasoning steps and internal thoughts in an expandable carousel.
- Displays executed Google Search queries and clickable web citations.
- Renders Markdown responses with highlighted technical indicators, code snippets, and IOC tables directly in the Case Overview / Case Wall.

---

## ⚙️ Configuration Parameters

Configure instance settings under **Response** > **Integrations** > **GoogleADK**:

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `Gemini API Key` | Password | Optional | `None` | Google Gemini API Key. Optional if using Service Account authentication. |
| `GCP Project ID` | String | Optional | `None` | Google Cloud Project ID hosting Vertex AI, Agent Engine, or GCS resources. |
| `Service Account JSON` | Password | Optional | `None` | JSON Service Account key for Vertex AI and Cloud Storage authentication. |
| `Workload Identity Email` | String | Optional | `None` | Target service account email assumed via Chronicle SOAR Workload Identity. |
| `Model Name` | String | Optional | `gemini-3.8-flash` | Default Gemini model version used across ADK agent actions. |
| `SecOps Region` | String | Optional | `us-central1` | Regional location for Vertex AI and MCP endpoints. |
| `MCP Server URL` | String | Optional | `https://chronicle.us.rep.googleapis.com/mcp` | Endpoint URL for Google-hosted or custom MCP servers. |
| `Agent Engine Resource Name`| String | Optional | `None` | Vertex AI Agent Engine resource path for containerized Python execution. |

---

## 🛠️ Repository Layout

```text
secops_soar_adk/
├── README.md                      # Master integration documentation
├── dist/
│   └── GoogleADK.zip              # Pre-compiled package ready for direct SOAR UI import
├── docs/
│   └── resources/
│       └── google_secops_mcp_tools.md # SecOps MCP tools catalog & filtering guide
└── integrations/
    └── google_adk/                # Content Hub (mp) source integration
        ├── definition.yaml        # Integration & parameter metadata
        ├── pyproject.toml         # Python package & dependency specifications
        ├── release_notes.yaml     # Version history & release changelogs
        ├── uv.lock                # Deterministic dependency lockfile
        ├── .python-version        # Target Python runtime (3.11)
        ├── actions/               # 10 Action Python entrypoints
        ├── core/                  # GoogleADKManager & SafeLogger layer
        ├── resources/             # Official SVG & PNG branding icons
        ├── widgets/               # HTML/JS ADK Result View widget
        └── tests/                 # 19 Pytest unit tests
```

---

## 🧪 Local Testing

To run the complete unit test suite locally:

```bash
# Run pytest with mock SDK environment
pytest integrations/google_adk/tests/ -v
```

All 19 tests validate action interfaces, parameter extraction, manager fallback handling, memory bank resolution, toolset attachments, and token caching.

---

## 📄 License & Attribution

Authored by **Christopher Martin** (`cmmartin@google.com`).  
Built for Google Security Operations (SecOps) SOAR. Distributed under the Apache 2.0 License.
