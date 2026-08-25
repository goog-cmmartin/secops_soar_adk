import sys
from types import ModuleType

# Pre-inject dummy modules to satisfy internal ADK checks for optional packages
# that are not available in public pip repositories but are imported on init
m1 = ModuleType('google.cloud.agentidentitycredentials_v1')
sys.modules['google.cloud.agentidentitycredentials_v1'] = m1
m1.AuthProviderCredentialsServiceClient = object
m1.RetrieveCredentialsRequest = object
m1.RetrieveCredentialsResponse = object

m2 = ModuleType('google.cloud.iamconnectorcredentials_v1alpha')
sys.modules['google.cloud.iamconnectorcredentials_v1alpha'] = m2
m2.IAMConnectorCredentialsServiceClient = object
m2.RetrieveCredentialsMetadata = object
m2.RetrieveCredentialsRequest = object
m2.RetrieveCredentialsResponse = object

import os
import asyncio
import unicodedata
import json
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from GoogleADKManager import GoogleADKManager

INTEGRATION_NAME = "Google_ADK"
SCRIPT_NAME = "Run Agent Registry Agent"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    
    # Initialize default states
    status = EXECUTION_STATE_COMPLETED 
    output_message = ""
    result_value = False

    try:
        # 1. Configuration (Integration Level)
        api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Gemini API Key")
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        model_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "Model Name", default_value="gemini-3.5-flash")
        
        # Optional Environment Context
        proj_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")

        # 2. Action Parameters (With updated gus-sdl defaults)
        registry_project_id = siemplify.extract_action_param("Agent Registry Project ID", default_value="gus-sdl")
        registry_location = siemplify.extract_action_param("Agent Registry Location", default_value="us-central1")
        agent_name = siemplify.extract_action_param("Agent Name", default_value="projects/gus-sdl/locations/us-central1/agents/agentregistry-00000000-0000-0000-9fad-9fca5ba05f30")
        reasoning_engine_name = siemplify.extract_action_param("Reasoning Engine Name", default_value="projects/288909297183/locations/us-central1/reasoningEngines/5540974004770177024")
        user_query = siemplify.extract_action_param("User Query", default_value="Can you pull the overview details for security case ID 16999?")

        if not user_query or not str(user_query).strip():
            raise ValueError("The 'User Query' parameter is required and cannot be empty.")

        # 3. Initialize Manager to set up ADC environment variables automatically
        manager = GoogleADKManager(
            api_key=api_key, 
            service_account_json=sa_json, 
            model_name=model_name, 
            project_id=proj_id,
            location=region,
            logger=siemplify.LOGGER
        )

        # Set execution environment overrides for Vertex AI models (if routing Gemini inference)
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"
        os.environ["GOOGLE_CLOUD_PROJECT"] = registry_project_id
        os.environ["GOOGLE_CLOUD_LOCATION"] = "us" # Multi-region for inference

        siemplify.LOGGER.info(f"Connecting to Agent Registry. Project: {registry_project_id}, Location: {registry_location}")
        siemplify.LOGGER.info(f"Agent Card Name: {agent_name}")
        siemplify.LOGGER.info(f"Reasoning Engine Name: {reasoning_engine_name}")

        async def execute_a2a_query_async(query: str) -> str:
            import vertexai
            from google.adk.integrations.agent_registry import AgentRegistry
            from google.adk.agents.llm_agent import Agent as ADKAgent
            from vertexai.agent_engines import AdkApp
            from a2a.types import Message as A2AMessage, Part as A2APart
            from google.auth.transport import requests as requests_auth
            from google.oauth2 import service_account
            import google.auth

            # Generate dedicated GCP Credentials with clean cloud-platform scope
            # to guarantee no chronicle scopes interfere with Vertex/Registry API requests
            gcp_scopes = ['https://www.googleapis.com/auth/cloud-platform']
            if sa_json and sa_json.strip() not in ("", "{}"):
                try:
                    info = json.loads(sa_json)
                    cached_creds = service_account.Credentials.from_service_account_info(info).with_scopes(gcp_scopes)
                    siemplify.LOGGER.info("Successfully initialized dedicated GCP credentials with clean cloud-platform scope.")
                except Exception as se:
                    siemplify.LOGGER.warn(f"Failed to load service account JSON for dedicated GCP scope: {se}")
                    cached_creds = manager._get_cached_credentials()
            else:
                try:
                    cached_creds, _ = google.auth.default(scopes=gcp_scopes)
                    siemplify.LOGGER.info("Successfully initialized dedicated GCP credentials via Application Default Credentials (ADC).")
                except Exception as se:
                    siemplify.LOGGER.warn(f"Failed to load ADC with dedicated GCP scope: {se}")
                    cached_creds = manager._get_cached_credentials()

            # Initialize global vertexai context with service account credentials
            vertexai.init(
                project=registry_project_id,
                location=registry_location,
                credentials=cached_creds
            )

            # 1. Connect to Google Cloud Agent Registry
            registry = AgentRegistry(project_id=registry_project_id, location=registry_location)
            
            # Override Agent Registry default credentials and session to use our service account credentials
            registry._credentials = cached_creds
            registry._session = requests_auth.AuthorizedSession(credentials=cached_creds)

            # 2. Retrieve the Remote A2A Agent
            remote_agent = registry.get_remote_a2a_agent(agent_name)
            await remote_agent._ensure_resolved()

            # 3. Intercept & Patch the standard client to route securely via vertexai RPC
            async def intercepted_send_message(request, **kwargs):
                # Extract plain-text query from A2A message request parts with Pydantic RootModel compatibility
                query_text = ""
                if hasattr(request, "parts") and request.parts:
                    for p in request.parts:
                        actual_part = getattr(p, "root", p)
                        if hasattr(actual_part, "text") and actual_part.text:
                            query_text += actual_part.text
                        elif isinstance(actual_part, dict) and "text" in actual_part:
                            query_text += actual_part["text"]
                        elif hasattr(p, "text") and p.text:
                            query_text += p.text
                elif isinstance(request, dict) and "parts" in request:
                    for p in request["parts"]:
                        if isinstance(p, dict):
                            actual_part = p.get("root", p)
                            if isinstance(actual_part, dict) and "text" in actual_part:
                                query_text += actual_part["text"]
                            elif hasattr(actual_part, "text") and actual_part.text:
                                query_text += actual_part.text
                        elif hasattr(p, "text") and p.text:
                            query_text += p.text

                # Log extracted query text for debugging visibility in SOAR logs
                siemplify.LOGGER.info(f"Intercepted send_message. Extracted query: '{query_text}'")
                
                try:
                    # Initialize secure Vertex client with explicit credentials
                    client = vertexai.Client(
                        project=registry_project_id, 
                        location=registry_location,
                        credentials=cached_creds
                    )
                    agent_engine = client.agent_engines.get(name=reasoning_engine_name)

                    # Route and stream from Reasoning Engine API
                    async for chunk in agent_engine.async_stream_query(
                        user_id="soar_integration_user",
                        message=query_text
                    ):
                        text_chunk = ""
                        if isinstance(chunk, dict):
                            content_part = chunk.get("content")
                            if isinstance(content_part, dict) and "parts" in content_part:
                                for part in content_part["parts"]:
                                    if isinstance(part, dict) and "text" in part:
                                        text_chunk += part["text"]
                        elif hasattr(chunk, "text"):
                            text_chunk = chunk.text
                        elif hasattr(chunk, "content"):
                            text_chunk = chunk.content

                        # Stream parsed chunk back to local Orchestrator as a schema-compliant A2AMessage
                        if text_chunk:
                            yield A2AMessage(
                                message_id="adapted-msg-id",
                                role="agent", # ADK Schema requires 'agent' or 'user'
                                parts=[A2APart(text=text_chunk)]
                            )
                except Exception as ex:
                    siemplify.LOGGER.error(f"Error in intercepted send_message RPC: {str(ex)}")
                    raise ex

            # Inject our RPC adapter into the remote A2A client
            remote_agent._a2a_client.send_message = intercepted_send_message

            # 4. Bind the remote peer to a local Orchestrator Agent
            local_orchestrator = ADKAgent(
                name="local_a2a_orchestrator",
                model=model_name,
                instruction="Delegate the user's inquiry verbatim to your sub-agent and stream the exact response back.",
                sub_agents=[remote_agent]
            )

            # 5. Execute and collect the streamed response
            local_app = AdkApp(agent=local_orchestrator)
            response_text = ""

            async for chunk in local_app.async_stream_query(
                user_id="soar_integration_user",
                message=query
            ):
                text_chunk = ""
                if isinstance(chunk, dict):
                    content = chunk.get("content")
                    if isinstance(content, dict) and "parts" in content:
                        for part in content["parts"]:
                            if isinstance(part, dict) and "text" in part:
                                text_chunk += part["text"]
                else:
                    text_chunk = getattr(chunk, "text", getattr(chunk, "content", ""))
                
                if text_chunk:
                    response_text += text_chunk

            return response_text

        # 4. Run the Async execution pipeline synchronously
        siemplify.LOGGER.info("Executing Agent Registry async pipeline...")
        response_text = asyncio.run(execute_a2a_query_async(user_query))

        if not response_text:
            siemplify.LOGGER.warn("A2A Agent returned an empty or missing response.")
            response_text = "The remote agent registry agent did not return any output."

        result_value = response_text
        output_message = f"Agent Registry Agent successfully executed and returned analysis."

        # Assemble JSON results payload
        results_json = {
            "agent_name": agent_name,
            "reasoning_engine": reasoning_engine_name,
            "project_id": registry_project_id,
            "location": registry_location,
            "query": user_query,
            "final_response": response_text
        }

        # Explicitly pre-serialize the dictionary to a valid JSON string to guarantee 
        # full compatibility across all strict Chronicle SOAR execution runtime versions.
        serialized_json = json.dumps(results_json)

        # ADD JSON RESULTS
        siemplify.result.add_result_json(serialized_json)
        siemplify.result.add_json("AgentRegistryResults", serialized_json)

        # Post response to Case Wall
        siemplify.add_comment(f"### Remote Agent [{agent_name}] Analysis ###\n\n{response_text}")

    except Exception as e:
        # Prevent .NET serialization errors by force-converting the error to clean ASCII string
        normalized_str = unicodedata.normalize('NFKD', str(e))
        error_msg = normalized_str.encode('ascii', 'ignore').decode('ascii')
        output_message = f"Action failed with error: {error_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Action Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
