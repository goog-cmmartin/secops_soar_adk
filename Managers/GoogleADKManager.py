import asyncio
import os
import json
# Import types for structured content
from google.genai import types
from google.adk.agents import LlmAgent
from google.adk.apps import App
# GCS and Auth imports
from google.cloud import storage
from google.oauth2 import service_account
from google.adk.integrations.gcs import GCSToolset, GCSAdminToolset
from google.adk.integrations.gcs.settings import GCSToolSettings, Capabilities
from google.adk.integrations.gcs.gcs_credentials import GCSCredentialsConfig
import urllib.request
import urllib.error
import urllib.parse
# Thinking logic
from google.adk.planners import BuiltInPlanner
# Code Execution imports
from google.adk.code_executors import BuiltInCodeExecutor, AgentEngineSandboxCodeExecutor
# MCP and Auth imports
from google.adk.tools.mcp_tool import McpToolset, StreamableHTTPConnectionParams
# Import RAG and Search tools from the ADK
from google.adk.tools import google_search

class DynamicAuthHeaders(dict):
    """
    Subclass of dict that evaluates the Authorization header dynamically.
    Ensures McpToolset always receives a fresh Bearer token.
    """
    def __init__(self, manager, user_project):
        super().__init__()
        self.manager = manager
        self.user_project = user_project

    def __getitem__(self, key):
        if key == "Authorization":
            token = self.manager.get_valid_token()
            return f"Bearer {token}"
        if key == "x-goog-user-project":
            return self.user_project
        if key == "Content-Type":
            return "application/json"
        raise KeyError(key)

    def __contains__(self, key):
        return key in ["Authorization", "x-goog-user-project", "Content-Type"]

    def __iter__(self):
        return iter(["Authorization", "x-goog-user-project", "Content-Type"])

    def __len__(self):
        return 3

    def keys(self):
        return ["Authorization", "x-goog-user-project", "Content-Type"]

    def items(self):
        token = self.manager.get_valid_token()
        return [
            ("Authorization", f"Bearer {token}"),
            ("x-goog-user-project", self.user_project),
            ("Content-Type", "application/json")
        ]

    def values(self):
        token = self.manager.get_valid_token()
        return [
            f"Bearer {token}",
            self.user_project,
            "application/json"
        ]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


class GoogleADKManager:
    """
    Manager for Google ADK Integration.
    Supports GCS-backed skills, Hosted MCP tools, and multiple Code Execution runtimes.
    Handles tool exclusivity rules for Gemini models.
    """

    def __init__(self, api_key=None, service_account_json=None, logger=None, project_id=None, location=None, model_name="gemini-2.5-flash", agent_engine_resource_name=None, rag_corpus_name=None, rag_gcs_bucket=None):
        self.logger = logger
        self.api_key = api_key
        self.service_account_json = service_account_json
        self.model_name = model_name
        self.app_name = "google_secops_soar"
        self.project_id = project_id
        self.location = location or "us-central1"
        self.agent_engine_resource_name = agent_engine_resource_name
        self.rag_corpus_name = rag_corpus_name
        self.rag_gcs_bucket = rag_gcs_bucket
        
        # Fallback: Extract project_id from Service Account JSON if not explicitly provided
        if not self.project_id and self.service_account_json:
            try:
                import json
                sa_data = json.loads(self.service_account_json)
                if "project_id" in sa_data:
                    self.project_id = sa_data["project_id"]
                    if self.logger:
                        self.logger.info(f"ADK Manager: Resolved fallback Project ID from Service Account JSON: {self.project_id}")
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"ADK Manager: Failed to parse project_id from Service Account JSON: {e}")
        
        self._creds = None
        self._gcs_client = None
        
        if self.api_key:
            os.environ["GOOGLE_API_KEY"] = self.api_key
            self.logger.info("ADK Manager: API Key set in environment.")

        # Set GOOGLE_APPLICATION_CREDENTIALS dynamically if Service Account JSON is provided.
        # This is critical because certain internal ADK clients (like GCPSkillRegistry)
        # do not accept explicit credentials objects and rely on Application Default Credentials (ADC)
        # to authenticate their REST and gRPC API calls.
        if self.service_account_json and self.service_account_json.strip() not in ("", "{}"):
            try:
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
                    f.write(self.service_account_json)
                    temp_creds_path = f.name
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = temp_creds_path
                self.logger.info(f"ADK Manager: Set GOOGLE_APPLICATION_CREDENTIALS to temporary file: {temp_creds_path}")
            except Exception as e:
                self.logger.warning(f"ADK Manager: Failed to write service account to temp file for ADC: {e}")

        # Vertex AI SDK initialization is no longer needed since we use REST-lite for RAG operations
        pass

    # --- START OF TOOLS ---

    def query_rag_engine(self, question: str, top_k: int = 5) -> str:
        """
        Queries the Vertex AI RAG Engine (Knowledge Base) for relevant security context.
        Use this to find historical case details, internal policies, or specific technical guidance.
        """
        self.logger.info(f"Agent tool call: query_rag_engine('{question}')")
        if not self.rag_corpus_name:
            return "Error: RAG Corpus Name not configured."

        try:
            corpus_id = self._get_rag_corpus_id(self.rag_corpus_name)
            if not corpus_id:
                return f"Error: Could not find RAG Corpus with name '{self.rag_corpus_name}'"

            token = self.get_valid_token()
            url = f"https://{self.location}-aiplatform.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}:retrieveContexts"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "SOAR-RAG-Lite/1.0"
            }
            payload = {
                "query": {
                    "text": question,
                    "rag_retrieval_config": {
                        "top_k": top_k
                    }
                },
                "vertex_rag_store": {
                    "rag_resources": [
                        {
                            "rag_corpus": f"projects/{self.project_id}/locations/{self.location}/ragCorpora/{corpus_id}"
                        }
                    ]
                }
            }
            req_body = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
            
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                contexts = data.get("contexts", {}).get("contexts", [])
                if not contexts:
                    return "No relevant context found in the knowledge base."
                    
                formatted_results = ["### RAG KNOWLEDGE BASE RESULTS ###"]
                for ctx in contexts:
                    source = ctx.get("sourceUri", "Unknown Source")
                    text = ctx.get("text", "")
                    formatted_results.append(f"--- Source: {source} ---\n{text}\n")
                    
                return "\n".join(formatted_results)
        except Exception as e:
            return f"Error: RAG Query failed: {str(e)}"

    def upload_rag_content(self, filename: str, content: str, metadata: dict = None, append: bool = False) -> str:
        """
        Uploads structured content to the RAG GCS bucket as JSONL (NDJSON).
        If append=True, it adds the content as a new line to an existing file.
        """
        self.logger.info(f"Agent tool call: upload_rag_content('{filename}', append={append})")
        if not self.rag_gcs_bucket:
            return "Error: RAG GCS Bucket not configured."

        try:
            # 1. Prepare the new line
            payload = {
                "content": content,
                "metadata": metadata or {}
            }
            new_jsonl_line = json.dumps(payload) + "\n"

            # 2. Get Cached GCS Client
            client = self._get_gcs_client()
            bucket = client.bucket(self.rag_gcs_bucket)
            
            if not filename.endswith(".jsonl"):
                filename += ".jsonl"
                
            blob = bucket.blob(f"ingest/{filename}")
            
            # 3. Handle Append vs Overwrite
            final_content = new_jsonl_line
            mode_msg = "created/overwritten"

            if append and blob.exists():
                existing_text = blob.download_as_text()
                # Ensure existing text ends with a newline before appending
                if existing_text and not existing_text.endswith("\n"):
                    existing_text += "\n"
                final_content = existing_text + new_jsonl_line
                mode_msg = "appended"

            # 4. Upload
            blob.upload_from_string(final_content, content_type="application/x-ndjson")
            
            return f"Successfully {mode_msg} {filename} in gs://{self.rag_gcs_bucket}/ingest/. Call refresh_rag_engine() to ingest."

        except Exception as e:
            return f"Error: RAG Content Upload failed: {str(e)}"

    def refresh_rag_engine(self) -> str:
        """
        Notifies the RAG Engine to re-scan the GCS bucket and ingest new or updated content.
        Call this after using upload_rag_content to ensure the knowledge base is up to date.
        """
        self.logger.info("Agent tool call: refresh_rag_engine()")
        if not self.rag_corpus_name or not self.rag_gcs_bucket:
            return "Error: RAG configuration incomplete (missing Corpus Name or GCS Bucket)."

        try:
            corpus_id = self._get_rag_corpus_id(self.rag_corpus_name)
            if not corpus_id:
                return "Error: RAG configuration incomplete (missing or unresolved Corpus)."

            token = self.get_valid_token()
            url = f"https://{self.location}-aiplatform.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}/ragCorpora/{corpus_id}/ragFiles:import"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "SOAR-RAG-Lite/1.0"
            }
            gcs_path = f"gs://{self.rag_gcs_bucket}/ingest/"
            payload = {
                "import_rag_files_config": {
                    "gcs_source": {
                        "uris": [gcs_path]
                    },
                    "rag_file_transformation_config": {
                        "rag_file_chunking_config": {
                            "fixed_length_chunking": {
                                "chunk_size": 1024,
                                "chunk_overlap": 200
                            }
                        }
                    }
                }
            }
            req_body = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))
                if "response" in data:
                    imported_count = data["response"].get("importedRagFilesCount", 0)
                else:
                    imported_count = data.get("importedRagFilesCount", 0)
                return f"RAG Engine refresh triggered. Imported {imported_count} files from {gcs_path}."
        except Exception as e:
            return f"Error: RAG Refresh failed: {str(e)}"

    def query_knowledge_base(self, question: str) -> str:
        """
        Queries the security knowledge base (RAG) for relevant reference documentation, playbooks, or history.
        Use this tool when you need context about a security procedure, tool, internal policy, or past cases.

        Args:
            question: The search query to submit to the knowledge base.

        Returns:
            The raw relevant matching context documents from the knowledge base.
        """
        return self.query_rag_engine(question=question, top_k=5)

    # --- END OF TOOLS ---

    def _get_rag_corpus_id(self, identifier: str) -> str:
        """
        Resolves a RAG Corpus ID from a variety of input formats:
        1. Full Resource Name: projects/.../ragCorpora/123 -> returns 123
        2. Numeric ID: 123 -> returns 123
        3. Display Name: 'My Corpus' -> returns ID via list_corpora()
        """
        if not identifier: return None
        
        # 1. Handle Full Resource Name or Numeric ID directly
        # If it's a full path, the ID is the last part
        if "/" in identifier:
            return identifier.split('/')[-1]
        
        # If it's a pure numeric string, it's likely already the ID
        if identifier.isdigit():
            return identifier

        # 2. Lookup by Display Name via REST
        try:
            self.logger.info(f"Searching for RAG Corpus with display name: {identifier}")
            token = self.get_valid_token()
            url = f"https://{self.location}-aiplatform.googleapis.com/v1/projects/{self.project_id}/locations/{self.location}/ragCorpora"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "SOAR-RAG-Lite/1.0"
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode('utf-8'))
                corpora = data.get("ragCorpora", [])
                for c in corpora:
                    if c.get("displayName") == identifier:
                        full_name = c.get("name", "")
                        resolved_id = full_name.split("/")[-1]
                        self.logger.info(f"Resolved display name '{identifier}' to ID: {resolved_id}")
                        return resolved_id
            self.logger.warning(f"ADK Manager: RAG Corpus with display name '{identifier}' was not found.")
            return None
        except Exception as e:
            self.logger.error(f"Failed to list RAG corpora via REST: {str(e)}")
            return None



    def _get_cached_credentials(self):
        """Retrieves or initializes cached credentials with multi-service scopes."""
        if self._creds is None:
            scopes = [
                'https://www.googleapis.com/auth/chronicle', 
                'https://www.googleapis.com/auth/devstorage.read_only', 
                'https://www.googleapis.com/auth/cloud-platform'
            ]
            if not self.service_account_json or self.service_account_json.strip() in ("", "{}"):
                import google.auth
                creds, _ = google.auth.default(scopes=scopes)
                self._creds = creds
                self.logger.info("ADK Manager: Credentials initialized via Application Default Credentials (ADC).")
            else:
                try:
                    info = json.loads(self.service_account_json)
                    creds = service_account.Credentials.from_service_account_info(info)
                    self._creds = creds.with_scopes(scopes)
                    self.logger.info("ADK Manager: Credentials initialized via explicit Service Account JSON.")
                except Exception as e:
                    self.logger.error(f"Failed to load service account JSON: {str(e)}")
                    raise
        return self._creds

    def _get_gcs_client(self):
        """Retrieves or initializes cached GCS Client."""
        if self._gcs_client is None:
            if self.service_account_json:
                info = json.loads(self.service_account_json)
                self._gcs_client = storage.Client.from_service_account_info(info)
            else:
                self._gcs_client = storage.Client()
        return self._gcs_client

    def get_valid_token(self) -> str:
        """Retrieves an up-to-date, valid authentication token, refreshing if necessary."""
        creds = self._get_cached_credentials()
        if not creds.valid:
            self.logger.info("ADK Manager: Credentials expired or invalid. Refreshing token...")
            from google.auth.transport.requests import Request
            auth_request = Request()
            creds.refresh(auth_request)
        
        if not creds.token:
            raise RuntimeError("Failed to obtain a valid access token from credentials.")
            
        return creds.token

    def init_mcp_toolset(self, mcp_url, user_project, tool_filter=None):
        """Initializes an McpToolset for the Google Hosted MCP server with self-refreshing auth headers."""
        self.logger.info(f"Initializing MCP Toolset for URL: {mcp_url} with tool_filter: {tool_filter}")
        
        # Define a dynamic header provider callback for runtime requests
        def dynamic_header_provider(readonly_context=None):
            token = self.get_valid_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            if user_project:
                headers["x-goog-user-project"] = user_project
            return headers

        return McpToolset(
            connection_params=StreamableHTTPConnectionParams(
                url=mcp_url,
                headers=DynamicAuthHeaders(self, user_project),
                timeout=15.0 # Increase timeout to 15 seconds to prevent transient connection issues
            ),
            header_provider=dynamic_header_provider,
            tool_filter=tool_filter
        )

    def test_connection(self):
        """Validates connectivity by initializing a minimal agent."""
        try:
            self.logger.info(f"Verifying ADK connectivity with model {self.model_name}...")
            LlmAgent(
                name="ping_tester",
                model=self.model_name,
                instruction="Health check agent."
            )
            return True
        except Exception as e:
            self.logger.error(f"ADK Connection test failed: {str(e)}")
            raise Exception(f"Connectivity Error: {str(e)}")

    async def _run_agent_async(self, agent_name, instructions, input_text, tools=None, session_id="default", thinking_budget=0, enable_code_execution=False, use_builtin_code_exec=False, temperature=0.0, max_output_tokens=2048, top_p=0.95, top_k=40, memory_service=None):
        """
        Internal asynchronous runner that initializes the Gemini ADK Agent and processes the event stream.

        Args:
            agent_name (str): Name of the agent.
            instructions (str): System instructions to guide agent behavior.
            input_text (str): The prompt or query from the user/SOAR playbook.
            tools (list, optional): Custom functions or ADK tools to equip the agent with.
            session_id (str, optional): ID to manage context/history. Defaults to "default".
            thinking_budget (int, optional): Thinking budget (token count) for reasoning. Defaults to 0.
            enable_code_execution (bool, optional): Enable managed sandbox code executor. Defaults to False.
            use_builtin_code_exec (bool, optional): Enable Gemini native single-tool code execution. Defaults to False.

        Returns:
            dict: Structured session execution results with the following schema:
                {
                    "thoughts": list[str],        # Sequential list of reasoning steps and thoughts.
                    "final_response": str,       # The final generated text answer (excludes thought parts).
                    "tool_calls": list[dict],    # Details of function/tool executions: [{"tool": name, "args": dict}].
                    "code_logs": list[dict]      # Logs of any executed Python code: [{"type": "generated_code"|"execution_result", ...}]
                }
        """
        planner = None
        if thinking_budget != 0:
            self.logger.info(f"Enabling Agent Thinking with budget: {thinking_budget}")
            planner = BuiltInPlanner(
                thinking_config=types.ThinkingConfig(
                    include_thoughts=True,
                    thinking_budget=thinking_budget
                )
            )

        # Configure Code Execution Runtime
        code_executor = None
        all_tools = []

        # Determine Tool List based on Exclusivity Rules
        is_search_requested = False
        if tools:
            for t in tools:
                if getattr(t, '__name__', '') == 'google_search' or t == google_search:
                    is_search_requested = True
                    break

        if use_builtin_code_exec:
            self.logger.info("Enabling Built-in Gemini Code Execution (Single tool mode).")
            code_executor = BuiltInCodeExecutor()
            all_tools = [] # Cannot be combined with other tools
        
        elif is_search_requested:
            self.logger.info("Enabling Google Search (Single tool mode for compatibility).")
            # For Gemini 1.x, search cannot be mixed. For safety, we make it exclusive.
            all_tools = tools
            
        else:
            # Standard Mode: Managed Sandbox (if requested) + Runbook tool + custom tools
            if enable_code_execution and self.agent_engine_resource_name:
                self.logger.info(f"Enabling Managed Sandbox Code Execution: {self.agent_engine_resource_name}")
                code_executor = AgentEngineSandboxCodeExecutor(
                    agent_engine_resource_name=self.agent_engine_resource_name
                )
            
            # Initialize empty tools list
            all_tools = []
            
            # Conditionally add RAG tools if configured
            if self.rag_corpus_name:
                all_tools.extend([
                    self.query_knowledge_base,
                    self.upload_rag_content,
                    self.refresh_rag_engine
                ])

            if tools:
                all_tools.extend(tools)

        # Resolve all tools asynchronously before building the agent to verify registration
        # Strip response schemas to avoid Gemini 500 flattening schema compile limits on complex schemas (like udm_search)
        def monkeypatch_toolset_to_strip_response_schema(toolset):
            original_get_tools = toolset.get_tools
            async def stripped_get_tools(*args, **kwargs):
                tools = await original_get_tools(*args, **kwargs)
                # Hard filter: exclude 'list_skills' from SkillToolset to force remote registry search
                if type(toolset).__name__ == "SkillToolset":
                    tools = [t for t in tools if getattr(t, "name", "") != "list_skills"]
                for tool in tools:
                    if hasattr(tool, "_get_declaration") and not hasattr(tool, "_response_stripped"):
                        original_get_dec = tool._get_declaration
                        def make_stripped_get_dec(orig_method):
                            def stripped_get_dec(*args, **kwargs):
                                dec = orig_method(*args, **kwargs)
                                if hasattr(dec, "response"):
                                    dec.response = None
                                if hasattr(dec, "response_json_schema"):
                                    dec.response_json_schema = None
                                return dec
                            return stripped_get_dec
                        tool._get_declaration = make_stripped_get_dec(original_get_dec)
                        tool._response_stripped = True
                return tools
            toolset.get_tools = stripped_get_tools

        resolved_tool_names = []
        try:
            for t in all_tools:
                if hasattr(t, "get_tools"):
                    # Apply monkeypatch to the toolset to strip response schemas dynamically
                    monkeypatch_toolset_to_strip_response_schema(t)
                    # For Toolsets (like McpToolset), dynamically query and list their tools
                    try:
                        ts_tools = await t.get_tools()
                        resolved_tool_names.extend([tool.name for tool in ts_tools])
                        self.logger.info(f"Loaded {len(ts_tools)} tools from Toolset {type(t).__name__}")
                    except Exception as ts_err:
                        self.logger.error(f"CRITICAL: Failed to get tools from Toolset {type(t).__name__}: {str(ts_err)}")
                else:
                    if hasattr(t, "_get_declaration") and not hasattr(t, "_response_stripped"):
                        original_get_dec = t._get_declaration
                        def make_stripped_get_dec(orig_method):
                            def stripped_get_dec(*args, **kwargs):
                                dec = orig_method(*args, **kwargs)
                                if hasattr(dec, "response"):
                                    dec.response = None
                                if hasattr(dec, "response_json_schema"):
                                    dec.response_json_schema = None
                                return dec
                            return stripped_get_dec
                        t._get_declaration = make_stripped_get_dec(original_get_dec)
                        t._response_stripped = True

                    if hasattr(t, "__name__"):
                        resolved_tool_names.append(t.__name__)
                    elif hasattr(t, "name"):
                        resolved_tool_names.append(t.name)
                    else:
                        resolved_tool_names.append(str(t))
            self.logger.info(f"Agent [{agent_name}] registering resolved tools: {resolved_tool_names}")
        except Exception as tool_err:
            self.logger.warning(f"Error while inspecting agent tools: {str(tool_err)}")

        # Configure Generation Parameters (to minimize hallucination and enforce low variance)
        config = types.GenerateContentConfig(
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            top_p=top_p,
            top_k=top_k
        )

        # Configure Memory Auto-Save Callback if Memory Service is provided
        after_agent_callback = None
        if memory_service:
            async def auto_save_session_to_memory_callback(callback_context):
                self.logger.info("ADK Manager Hook: Saving completed session to long-term memory...")
                await callback_context.add_session_to_memory()
                return None
            after_agent_callback = auto_save_session_to_memory_callback

        # Initialize the Agent
        agent = LlmAgent(
            name=agent_name,
            model=self.model_name,
            instruction=instructions,
            tools=all_tools,
            planner=planner,
            code_executor=code_executor,
            generate_content_config=config,
            after_agent_callback=after_agent_callback
        )

        # Initialize the App
        app = App(
            name=self.app_name,
            root_agent=agent
        )

        from google.adk.runners import Runner
        from google.adk.sessions.in_memory_session_service import InMemorySessionService
        from google.adk.artifacts.in_memory_artifact_service import InMemoryArtifactService

        session_service = InMemorySessionService()
        artifact_service = InMemoryArtifactService()

        runner = Runner(
            app=app,
            session_service=session_service,
            artifact_service=artifact_service,
            memory_service=memory_service
        )

        user_id = "soar_analyst"
        try:
            await runner.session_service.create_session(
                app_name=self.app_name, user_id=user_id, session_id=str(session_id)
            )
        except Exception as e:
            self.logger.debug(f"ADK Manager: Session creation note/skip (session may already exist): {str(e)}")

        new_message = types.Content(parts=[types.Part.from_text(text=input_text)])
        results = {
            "thoughts": [],
            "final_response": "",
            "tool_calls": [],
            "code_logs": []
        }

        async for event in runner.run_async(user_id=user_id, session_id=str(session_id), new_message=new_message):
            # Rich debug logging to analyze ADK events, parts, and content streams
            try:
                try:
                    event_json = event.model_dump_json()
                except Exception:
                    try:
                        event_json = str(event.model_dump())
                    except Exception:
                        event_json = str(event)
                self.logger.info(f"RAW ADK EVENT JSON: {event_json}")

                self.logger.debug(
                    f"ADK Event: is_final={event.is_final_response()}, "
                    f"partial={getattr(event, 'partial', None)}, "
                    f"has_content={bool(event.content)}, "
                    f"parts_count={len(event.content.parts) if event.content and event.content.parts else 0}"
                )
                if event.content and event.content.parts:
                    for idx, part in enumerate(event.content.parts):
                        part_type = "unknown"
                        if hasattr(part, 'executable_code') and part.executable_code:
                            part_type = "executable_code"
                        elif hasattr(part, 'code_execution_result') and part.code_execution_result:
                            part_type = "code_execution_result"
                        elif getattr(part, 'thought', False):
                            part_type = "thought"
                        elif part.text:
                            part_type = "text"
                        
                        text_preview = (part.text[:80] + "...") if part.text and len(part.text) > 80 else part.text
                        self.logger.debug(
                            f"  -> Part {idx}: type={part_type}, "
                            f"thought_attr={getattr(part, 'thought', None)}, "
                            f"text='{text_preview}'"
                        )
            except Exception as debug_err:
                self.logger.debug(f"ADK Event Logging Error: {str(debug_err)}")

            fc = event.get_function_calls()
            if fc:
                for call in fc:
                    call_dict = {"tool": call.name, "args": call.args}
                    if call_dict not in results["tool_calls"]:
                        results["tool_calls"].append(call_dict)
                        self.logger.info(f"Agent [{agent_name}] calling tool: {call.name}")

            if event.is_final_response():
                if event.content and event.content.parts:
                    # Only take parts that are NOT thoughts for the final response
                    final_text = "".join([part.text for part in event.content.parts if not getattr(part, 'thought', False) and part.text])
                    results["final_response"] = final_text
            
            if event.content and event.content.parts:
                for part in event.content.parts:
                    # Capture Agent-Generated Code
                    if hasattr(part, 'executable_code') and part.executable_code:
                        code_snippet = part.executable_code.code
                        if not any(log.get("type") == "generated_code" and log.get("content") == code_snippet for log in results["code_logs"]):
                            results["code_logs"].append({"type": "generated_code", "content": code_snippet})
                            results["thoughts"].append(f"Generated Python Code:\n```python\n{code_snippet}\n```")

                    # Capture Code Execution Results
                    elif hasattr(part, 'code_execution_result') and part.code_execution_result:
                        outcome_raw = part.code_execution_result.outcome
                        outcome = outcome_raw.value if hasattr(outcome_raw, 'value') else str(outcome_raw)
                        output = part.code_execution_result.output
                        if not any(log.get("type") == "execution_result" and log.get("output") == output for log in results["code_logs"]):
                            results["code_logs"].append({"type": "execution_result", "outcome": outcome, "output": output})
                            results["thoughts"].append(f"Code Execution ({outcome}):\n```\n{output}\n```")

                    # Capture dedicated thought parts
                    elif getattr(part, 'thought', False) and part.text:
                        if part.text not in results["thoughts"]:
                            results["thoughts"].append(part.text)
                            self.logger.info(f"Agent [{agent_name}] is thinking...")
                    
                    # Capture intermediate reasoning text
                    elif part.text and not event.partial and not event.is_final_response():
                        if part.text not in results["thoughts"]:
                            results["thoughts"].append(part.text)

        return results

    def run_agent(self, agent_name, instructions, input_text, tools=None, session_id="default", thinking_budget=0, enable_code_execution=False, use_builtin_code_exec=False, temperature=0.0, max_output_tokens=2048, top_p=0.95, top_k=40, memory_service=None):
        """
        Synchronous bridge to the async ADK runner.
        Safely handles active event loop execution environments to prevent deadlocks.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            raise RuntimeError(
                "GoogleADKManager: run_agent() was called from a thread with an active event loop. "
                "To prevent deadlocking the thread, please call the async '_run_agent_async()' "
                "method directly with 'await'."
            )

        try:
            return asyncio.run(
                self._run_agent_async(
                    agent_name=agent_name, 
                    instructions=instructions, 
                    input_text=input_text, 
                    tools=tools, 
                    session_id=session_id, 
                    thinking_budget=thinking_budget, 
                    enable_code_execution=enable_code_execution, 
                    use_builtin_code_exec=use_builtin_code_exec,
                    temperature=temperature,
                    max_output_tokens=max_output_tokens,
                    top_p=top_p,
                    top_k=top_k,
                    memory_service=memory_service
                )
            )
        except Exception as e:
            self.logger.error(f"Error running agent {agent_name}: {str(e)}")
            raise

    def init_gcs_toolsets(self, enable_admin=False, enable_write=False):
        """
        Initializes the GCS and GCS Admin toolsets using the manager's authenticated credentials.
        """
        self.logger.info(f"Initializing GCS Toolsets (Admin: {enable_admin}, Write: {enable_write})")
        
        # 1. Configure GCS Credentials with the manager's resolved credentials
        credentials_config = GCSCredentialsConfig(credentials=self._get_cached_credentials())
        
        # 2. Configure capabilities (READ_ONLY vs READ_WRITE)
        capabilities = [Capabilities.READ_WRITE] if enable_write else [Capabilities.READ_ONLY]
        tool_settings = GCSToolSettings(capabilities=capabilities)
        
        # 3. Build Toolsets list
        tools = []
        
        # Standard GCS Storage tools (object upload, download, metadata, deletion)
        tools.append(
            GCSToolset(
                credentials_config=credentials_config, 
                gcs_tool_settings=tool_settings
            )
        )
        
        # GCS Admin tools (create/list/update buckets)
        if enable_admin:
            tools.append(
                GCSAdminToolset(credentials_config=credentials_config)
            )
            
        return tools

    def init_skill_registry_toolset(self):
        """
        Initializes the GCPSkillRegistry and binds it to a SkillToolset.
        This dynamically equips the agent with search_skills and load_skill tools.
        """
        self.logger.info(f"Initializing GCP Skill Registry Toolset for Project: {self.project_id}, Location: {self.location}")
        
        # Lazy load imports to avoid import-time crashes if dependencies are missing in sandbox
        from google.adk.integrations.skill_registry import GCPSkillRegistry
        from google.adk.tools.skill_toolset import SkillToolset
        import vertexai

        # 1. Globally initialize vertexai with our resolved credentials, project and location
        creds = self._get_cached_credentials()
        vertexai.init(project=self.project_id, location=self.location, credentials=creds)
        
        # 2. Instantiate the registry
        registry = GCPSkillRegistry(
            project_id=self.project_id,
            location=self.location
        )
        
        # 3. Create and return the SkillToolset
        # We exclude 'list_skills' because it only lists statically registered local skills (which is empty here),
        # forcing the agent to use the live remote 'search_skills' tool to query your GCP registry.
        return SkillToolset(
            skills=[],
            registry=registry,
            tool_filter=["search_skills", "load_skill", "load_skill_resource", "run_skill_script"]
        )

    def register_gcp_skill(self, skill_id: str, display_name: str, description: str, instructions_markdown: str) -> str:
        """
        Registers or uploads a brand-new skill package to the Google Cloud Skill Registry on Vertex AI.
        
        Args:
            skill_id: A unique alphanumeric identifier for the skill (e.g., 'virustotal-helpers', 'threat-intel'). Must use kebab-case.
            display_name: A human-readable display name for the skill (e.g., 'VirusTotal Lookup Helpers').
            description: A concise description of the skill's capabilities (starting with a third-person verb, e.g., 'Allows querying VT APIs').
            instructions_markdown: The complete markdown system instructions for the skill (including any headers and documentation).
            
        Returns:
            str: A success or failure message detailing the registered skill.
        """
        self.logger.info(f"Tool call: register_gcp_skill('{skill_id}', '{display_name}')")
        import tempfile
        import shutil
        import os
        import vertexai
        
        temp_dir = tempfile.mkdtemp()
        try:
            # Write SKILL.md
            skill_md_content = f"""---
name: {skill_id}
description: {description}
---
{instructions_markdown}
"""
            with open(os.path.join(temp_dir, "SKILL.md"), "w", encoding="utf-8") as f:
                f.write(skill_md_content)
                
            # Initialize Client with credentials
            creds = self._get_cached_credentials()
            client = vertexai.Client(
                project=self.project_id,
                location=self.location,
                credentials=creds
            )
            
            # Create Skill
            skill = client.skills.create(
                display_name=display_name,
                description=description,
                config={
                    "skill_id": skill_id,
                    "local_path": temp_dir
                }
            )
            return f"SUCCESS: Skill '{skill_id}' was successfully registered in the GCP Skill Registry. Resource Name: {skill.name}"
        except Exception as e:
            self.logger.error(f"Failed to register skill: {str(e)}")
            return f"Error registering skill: {str(e)}"
        finally:
            shutil.rmtree(temp_dir)

    def init_memory_bank_service(self, agent_engine_id: str = None):
        """
        Initializes and returns a VertexAiMemoryBankService for persistent memory.
        If agent_engine_id is not provided, it falls back to parsing self.agent_engine_resource_name.
        """
        # Lazy load to prevent sandbox import failures
        from google.adk.memory import VertexAiMemoryBankService
        import vertexai

        resolved_id = agent_engine_id
        if not resolved_id and self.agent_engine_resource_name:
            resolved_id = self.agent_engine_resource_name.split("/")[-1]

        if not resolved_id:
            raise ValueError("Memory Bank: No active Agent Engine ID or Resource Name was provided or resolved.")

        self.logger.info(f"Initializing Vertex AI Memory Bank Service for Project: {self.project_id}, Agent Engine ID: {resolved_id}")
        
        creds = self._get_cached_credentials()
        vertexai.init(project=self.project_id, location=self.location, credentials=creds)

        return VertexAiMemoryBankService(
            project=self.project_id,
            location=self.location,
            agent_engine_id=resolved_id
        )

    def init_in_memory_memory_service(self):
        """
        Initializes and returns an InMemoryMemoryService for local prototyping/testing.
        """
        from google.adk.memory import InMemoryMemoryService
        self.logger.info("Initializing local InMemoryMemoryService.")
        return InMemoryMemoryService()

    def get_memory_tools(self, preload: bool = False):
        """
        Returns the appropriate pre-built ADK memory tools.
        If preload is True, returns [preload_memory].
        Otherwise, returns [load_memory].
        """
        if preload:
            from google.adk.tools import preload_memory
            return [preload_memory]
        else:
            from google.adk.tools import load_memory
            return [load_memory]
