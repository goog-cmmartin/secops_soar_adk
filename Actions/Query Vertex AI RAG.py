from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
import json
import urllib.request
import urllib.error
import unicodedata

INTEGRATION_NAME = "Google_ADK"
SCRIPT_NAME = "Query Vertex RAG REST-Lite"

def get_bearer_token(sa_json, logger):
    """
    Generates a standard GCP OAuth access token using the lightweight google-auth library.
    """
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request
    
    logger.info("Generating GCP OAuth access token from Service Account...")
    scopes = ['https://www.googleapis.com/auth/cloud-platform']
    info = json.loads(sa_json)
    creds = service_account.Credentials.from_service_account_info(info)
    scoped_creds = creds.with_scopes(scopes)
    
    auth_request = Request()
    scoped_creds.refresh(auth_request)
    return scoped_creds.token

def resolve_rag_corpus_id(location, project_id, corpus_display_name, token, logger):
    """
    Queries the RAG Corpora REST endpoint to resolve a user-friendly display name (e.g., 'My Corpus')
    to its unique numeric RAG Corpus ID. Supports full resource paths and numeric IDs directly.
    """
    # 1. Handle Full Resource Name (e.g., 'projects/.../ragCorpora/123')
    if "/" in corpus_display_name:
        corpus_id = corpus_display_name.split("/")[-1].strip()
        logger.info(f"Detected full resource path in parameter. Extracted Corpus ID directly: '{corpus_id}'")
        return corpus_id
        
    # 2. Handle pure numeric string directly
    if corpus_display_name.isdigit():
        logger.info(f"Using provided numeric ID directly: {corpus_display_name}")
        return corpus_display_name

    url = f"https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/ragCorpora"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "SOAR-RAG-Lite/1.0"
    }
    
    req = urllib.request.Request(url, headers=headers, method="GET")
    
    try:
        logger.info(f"Listing RAG corpora in projects/{project_id}/locations/{location} to resolve '{corpus_display_name}'")
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            corpora = data.get("ragCorpora", [])
            for c in corpora:
                if c.get("displayName") == corpus_display_name:
                    full_name = c.get("name", "")
                    corpus_id = full_name.split("/")[-1]
                    logger.info(f"Successfully resolved display name '{corpus_display_name}' to ID '{corpus_id}'")
                    return corpus_id
                
            raise ValueError(f"RAG Corpus with display name '{corpus_display_name}' was not found in location '{location}'.")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f"GCP API Error listing RAG Corpora (HTTP {e.code}): {body}")
    except Exception as e:
        raise RuntimeError(f"Failed to list RAG Corpora: {str(e)}")

def retrieve_rag_contexts(location, project_id, corpus_id, query_text, top_k, token, logger):
    """
    Queries the retrieveContexts REST API endpoint to retrieve document chunks matching the query.
    """
    url = f"https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}:retrieveContexts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "SOAR-RAG-Lite/1.0"
    }
    
    payload = {
        "query": {
            "text": query_text,
            "rag_retrieval_config": {
                "top_k": top_k
            }
        },
        "vertex_rag_store": {
            "rag_resources": [
                {
                    "rag_corpus": f"projects/{project_id}/locations/{location}/ragCorpora/{corpus_id}"
                }
            ]
        }
    }
    
    req_body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
    
    try:
        logger.info(f"Retrieving contexts for query: '{query_text[:60]}...'")
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # Process and format the returned context elements
            contexts = data.get("contexts", {}).get("contexts", [])
            if not contexts:
                return "No relevant context found in the knowledge base."
                
            formatted_results = ["### RAG KNOWLEDGE BASE RESULTS (LITE-REST) ###"]
            for ctx in contexts:
                source = ctx.get("sourceUri", "Unknown Source")
                text = ctx.get("text", "")
                formatted_results.append(f"--- Source: {source} ---\n{text}\n")
                
            return "\n".join(formatted_results)
            
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f"GCP API Error retrieving RAG context (HTTP {e.code}): {body}")
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve RAG contexts: {str(e)}")

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    
    status = EXECUTION_STATE_COMPLETED 
    output_message = ""
    result_value = False

    try:
        # 1. Fetch Global Configuration
        sa_json = siemplify.extract_configuration_param(INTEGRATION_NAME, "Service Account JSON")
        proj_id = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        safe_region = str(region).strip() if region and str(region).strip() else "us-central1"
        rag_corpus_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "RAG Corpus Name")

        # 2. Validation Checks
        if not sa_json or not str(sa_json).strip():
            raise ValueError("The global configuration parameter 'Service Account JSON' is required.")
        try:
            json.loads(sa_json)
        except json.JSONDecodeError:
            raise ValueError("The global configuration parameter 'Service Account JSON' is malformed JSON.")

        if not proj_id or not str(proj_id).strip():
            raise ValueError("The global configuration parameter 'SecOps Project ID' is required.")

        if not rag_corpus_name or not str(rag_corpus_name).strip():
            raise ValueError("The global configuration parameter 'RAG Corpus Name' is required.")

        # 3. Fetch Action-Specific Parameters
        query_text = siemplify.extract_action_param("Query Text")
        if not query_text or not str(query_text).strip():
            raise ValueError("The 'Query Text' parameter is required and cannot be empty.")

        raw_top_k = siemplify.extract_action_param("Top K", default_value="5")
        try:
            top_k = int(raw_top_k) if raw_top_k else 5
            if top_k <= 0:
                raise ValueError()
        except ValueError:
            raise ValueError(f"'Top K' must be a positive integer, got: '{raw_top_k}'")

        # 4. Auth & Request Processing
        token = get_bearer_token(sa_json, siemplify.LOGGER)
        
        # Resolve display name to numeric corpus ID
        corpus_id = resolve_rag_corpus_id(
            location=safe_region,
            project_id=proj_id,
            corpus_display_name=rag_corpus_name,
            token=token,
            logger=siemplify.LOGGER
        )
        
        # Query contexts via REST
        raw_results = retrieve_rag_contexts(
            location=safe_region,
            project_id=proj_id,
            corpus_id=corpus_id,
            query_text=query_text,
            top_k=top_k,
            token=token,
            logger=siemplify.LOGGER
        )

        output_message = "Successfully retrieved knowledge base context from RAG Engine via REST-Lite."
        result_value = True
        
        # Programmatic results for playbooks
        siemplify.result.add_result_json({"raw_output": raw_results, "query": query_text})
        # UI visualization
        siemplify.result.add_json("RAG_Search_Results", {"results": raw_results})

    except Exception as e:
        normalized_str = unicodedata.normalize('NFKD', str(e))
        error_msg = normalized_str.encode('ascii', 'ignore').decode('ascii')
        output_message = f"Python Error: {error_msg}"
        siemplify.LOGGER.error(output_message)
        result_value = False
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(f"Action Finalized. Status: {status}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
