# Google SecOps SOAR - Google ADK Integration

This repository contains the official custom integration package for orchestrating **Google Agent Development Kit (ADK)** agents directly within **Google Security Operations (SecOps) SOAR** playbooks.

It equips SOC teams and security engineers with autonomous, tool-augmented Gemini agents that run natively or in isolated cloud sandboxes to investigate alerts, execute complex triage workflows, search the open web (OSINT), interact with Model Context Protocol (MCP) servers, query knowledge bases via Vertex AI RAG, and store multi-turn investigation memories.

---

## Features & Capabilities

- **Native Google ADK Integration:** Built on `google-adk` to manage agent lifecycles, structured reasoning steps, and tool execution.
- **Model Support:** Defaults to `gemini-3.7-flash` for high-speed reasoning with configurable token thinking budgets; supports `gemini-2.5-pro` and other Gemini models.
- **Dual Authentication Modes:** Authenticate using standard Gemini API keys or enterprise Google Cloud Service Account JSON credentials with dynamic OAuth/OIDC token generation.
- **Dual Project Support:** Seamlessly decouple the Google Cloud Project hosting Vertex AI/Agent Engine from the Google SecOps tenant project.
- **MCP Integration:** Connect agents to Google-hosted Model Context Protocol (MCP) server endpoints with dynamic credential rotation and configurable tool filtering to prevent token bloat.
- **Vertex AI RAG:** Search and ingest unstructured case data into Vertex AI RAG Corpora directly from playbooks.
- **Session Memory Persistence:** Support for stateful multi-step agent investigations using ADK Memory Bank and GCS-backed session storage.

---

## Integration Actions

The integration provides 13 specialized SOAR actions:

| Action | Description | Key Parameters |
| :--- | :--- | :--- |
| **`Ping`** | Validates API connectivity, credentials, and model availability. | `Model Name` |
| **`Run ADK Agent`** | Executes a general-purpose ADK logic and analysis agent. | `User Prompt`, `Thinking Budget`, `Agent Name` |
| **`Run ADK Triage Agent`** | Autonomous tier-1 alert investigation agent that triages cases, inspects entities, and writes structured verdicts to the Case Wall. | `Dry Run`, `Triage Identity` |
| **`Run Code Execution Agent`** | Executes dynamic Python scripts natively inside the Google backend API lifecycle for fast calculations and data manipulation. | `User Prompt`, `Thinking Budget` |
| **`Run Code Execution Agent Sandbox`** | Executes Python code within a dedicated, isolated Vertex AI Agent Engine container sandbox. | `User Prompt`, `Thinking Budget`, `Agent Engine Resource Name` |
| **`Run Google Search Agent`** | Performs live web searches and OSINT threat intelligence research using Google Search grounding. | `User Prompt`, `Thinking Budget` |
| **`Run Hosted MCP ADK Agent`** | Connects to Google-hosted MCP servers with self-refreshing OAuth headers to invoke enterprise security toolsets. | `User Prompt`, `Thinking Budget`, `Tool Filter` |
| **`Run ADK Memory Bank Agent`** | Multi-turn stateful agent leveraging short-term or long-term session memory banks across playbook steps. | `User Prompt`, `Session ID`, `Memory Mode`, `Preload Memory` |
| **`Run ADK GCS Agent`** | Autonomous agent equipped with Google Cloud Storage tools for reading, writing, and inspecting bucket artifacts. | `User Prompt`, `Thinking Budget`, `Allow GCS Write`, `Allow GCS Admin` |
| **`Run ADK Skill Registry Agent`** | Connects to the GCP Skill Registry to dynamically discover, search, load, and execute remote security skills and runbooks. | `User Prompt`, `Thinking Budget` |
| **`Run ADK Agent Registry Agent`** | Discovers and invokes multi-agent configurations from the central GCP Agent Registry. | `User Prompt`, `Thinking Budget` |
| **`Query Vertex AI RAG`** | Queries a Vertex AI RAG Corpus for relevant context and semantic matches. | `Query Text`, `Top K` |
| **`Ingest to RAG`** | Uploads and ingests structured text or alert context into a Vertex AI RAG Corpus GCS ingest bucket. | `Content`, `Filename`, `Metadata JSON`, `Append to Existing` |

---

## Integration Configuration

Configure the instance settings under **Integrations > Google ADK > Configure Instance**:

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `Gemini API Key` | Password | Optional | `None` | Google Gemini API Key. Optional if using Service Account JSON authentication. |
| `GCP Project ID` | String | Optional | `None` | Google Cloud Project ID hosting Vertex AI, RAG Corpora, and Agent Engine resources. |
| `Service Account JSON` | Password | Optional | `None` | JSON Service Account key for Vertex AI, Cloud Storage, and SecOps MCP authentication. |
| `MCP Server URL` | String | Optional | `https://chronicle.us.rep.googleapis.com/mcp` | Endpoint URL for the Google-hosted Model Context Protocol server. |
| `SecOps Customer ID` | String | Optional | `None` | Google SecOps customer ID (UUID) for tenant-scoped operations. |
| `SecOps Region` | String | Optional | `us-central1` | Regional location for Vertex AI and SecOps MCP endpoints. |
| `SecOps Project ID` | String | Optional | `None` | Google Cloud Project ID associated with the Google SecOps tenant (if different from GCP Project ID). |
| `Model Name` | String | Optional | `gemini-3.7-flash` | Default Gemini model version used across ADK agent actions. |
| `RAG Corpus Name` | String | Optional | `None` | Vertex AI RAG Corpus display name or numeric resource ID. |
| `RAG GCS Bucket` | String | Optional | `None` | Cloud Storage bucket name for RAG document ingestion. |
| `Agent Engine Resource Name` | String | Optional | `None` | Vertex AI Agent Engine resource path for isolated Python sandbox code execution. |

---

## Repository Structure

```text
├── Actions/                  # Action Python scripts and JSON definition files
│   ├── Ping.py / Ping.json
│   ├── Run ADK Agent.py / Run ADK Agent.json
│   ├── Run ADK Triage Agent.py / Run ADK Triage Agent.json
│   ├── Run Code Execution Agent.py / Run Code Execution Agent.json
│   ├── Run Code Execution Agent Sandbox.py / ...
│   ├── Run Google Search Agent.py / ...
│   ├── Run Hosted MCP ADK Agent.py / ...
│   ├── Run ADK Memory Bank Agent.py / ...
│   ├── Run ADK GCS Agent.py / ...
│   ├── Run ADK Skill Registry Agent.py / ...
│   ├── Run ADK Agent Registry Agent.py / ...
│   ├── Query Vertex AI RAG.py / ...
│   └── Ingest to RAG.py / ...
├── Managers/                 # Shared manager modules and business logic
│   └── GoogleADKManager.py   # Core ADK manager, token cache, and toolset provider
├── Dependencies/             # Vendored Python wheels for offline SOAR deployment
├── docs/                     # Documentation and reference guides
│   └── resources/            # Supplementary reference artifacts and tool catalogs
│       └── google_secops_mcp_tools.md  # Google SecOps MCP server tool categories and filtering guide
├── Integration-Google ADK.json # Master integration manifest and instance parameter schema
└── metadata.json             # Integration metadata
```

---

## Documentation & Resources

- [Google SecOps MCP Tool Reference Guide](docs/resources/google_secops_mcp_tools.md): Comprehensive catalog of SecOps MCP tools grouped by category (Case Management, Playbooks & Actions, UDM Search, Reference Lists, Detection Rules, Parsers, Feeds, Data Tables, and Investigations) for configuring `Tool Filter` parameters in `Run Hosted MCP ADK Agent`.

---

## Installation & Deployment

1. Export or zip the repository directory containing `Actions/`, `Managers/`, `Dependencies/`, and `Integration-Google ADK.json`.
2. Navigate to **Google SecOps SOAR > Settings > Integrations**.
3. Upload the integration package.
4. Open **Google ADK > Configure Instance**, provide your credentials and project configuration, and test the connection using the **`Ping`** action.
