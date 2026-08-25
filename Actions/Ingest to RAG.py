from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
import json
import urllib.request
import urllib.error
import urllib.parse
import hashlib
import unicodedata
import os
import re

INTEGRATION_NAME = "Google ADK"
SCRIPT_NAME = "Ingest to RAG REST-Lite"

def parse_rag_resource_name(identifier, default_project, default_location):
    """
    Parses a RAG identifier which may be:
    1. Full resource name: projects/{project}/locations/{location}/ragCorpora/{corpus_id}
    2. Numeric ID
    3. Display name
    Returns (resolved_project, resolved_location, corpus_name_or_id).
    """
    if not identifier:
        return default_project, default_location, identifier
    
    clean_id = str(identifier).strip()
    match = re.match(r"^projects/([^/]+)/locations/([^/]+)/ragCorpora/([^/]+)$", clean_id)
    if match:
        return match.group(1), match.group(2), match.group(3)
    
    return default_project, default_location, clean_id

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
    Queries the ragCorpora REST API to resolve a display name or numeric ID into a corpus ID.
    If corpus_display_name is already a numeric ID, it is returned directly.
    """
    if not corpus_display_name:
        raise ValueError("RAG Corpus Name cannot be empty.")
        
    # If it's already a numeric ID, return directly
    if str(corpus_display_name).strip().isdigit():
        return str(corpus_display_name).strip()

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

def download_gcs_content(bucket, filename, token, logger):
    """
    Downloads the text content of a file from GCS. Returns None if the file doesn't exist.
    """
    object_name = f"ingest/{filename}"
    encoded_name = urllib.parse.quote(object_name, safe="")
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{encoded_name}?alt=media"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "SOAR-RAG-Lite/1.0"
    }
    
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        logger.info(f"Checking if gs://{bucket}/{object_name} exists for append mode...")
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.info("File not found in GCS. Will create a new file.")
            return None
        body = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f"GCS API Error downloading file (HTTP {e.code}): {body}")
    except Exception as e:
        raise RuntimeError(f"Failed to check/download from GCS: {str(e)}")

def upload_gcs_content(bucket, filename, content, token, logger):
    """
    Uploads text content to GCS at ingest/{filename}.
    """
    object_name = f"ingest/{filename}"
    encoded_name = urllib.parse.quote(object_name, safe="")
    url = f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?uploadType=media&name={encoded_name}"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-ndjson",
        "User-Agent": "SOAR-RAG-Lite/1.0"
    }
    
    req_body = content.encode('utf-8')
    req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
    try:
        logger.info(f"Uploading content to gs://{bucket}/{object_name}...")
        with urllib.request.urlopen(req, timeout=15) as response:
            response_data = json.loads(response.read().decode('utf-8'))
            logger.info(f"Successfully uploaded to GCS. Generation: {response_data.get('generation')}")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f"GCS API Error uploading file (HTTP {e.code}): {body}")
    except Exception as e:
        raise RuntimeError(f"Failed to upload to GCS: {str(e)}")

def import_rag_file(location, project_id, corpus_id, bucket, filename, token, logger):
    """
    Imports the GCS file into the Vertex AI RAG Corpus.
    """
    url = f"https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/ragCorpora/{corpus_id}/ragFiles:import"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "SOAR-RAG-Lite/1.0"
    }
    
    gcs_uri = f"gs://{bucket}/ingest/{filename}"
    
    payload = {
        "import_rag_files_config": {
            "gcs_source": {
                "uris": [gcs_uri]
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
    try:
        logger.info(f"Triggering RAG file import for '{gcs_uri}'...")
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))
            logger.info(f"RAG import response: {json.dumps(data)}")
            
            # The API response is usually an Operation (LRO) or a direct count.
            # Handle both gracefully.
            if "response" in data:
                imported_count = data["response"].get("importedRagFilesCount", 0)
            else:
                imported_count = data.get("importedRagFilesCount", 0)
                
            return imported_count
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f"GCP API Error importing RAG file (HTTP {e.code}): {body}")
    except Exception as e:
        raise RuntimeError(f"Failed to import RAG file: {str(e)}")

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
        proj_id = (
            siemplify.extract_configuration_param(INTEGRATION_NAME, "GCP Project ID")
            or siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Project ID")
        )
        region = siemplify.extract_configuration_param(INTEGRATION_NAME, "SecOps Region")
        safe_region = str(region).strip() if region and str(region).strip() else "us-central1"
        rag_corpus_name = siemplify.extract_configuration_param(INTEGRATION_NAME, "RAG Corpus Name")
        rag_gcs_bucket = siemplify.extract_configuration_param(INTEGRATION_NAME, "RAG GCS Bucket")

        # 2. Parse RAG Resource Name (if full path provided, extract project, location, and corpus identifier)
        target_project, target_location, parsed_corpus_identifier = parse_rag_resource_name(
            rag_corpus_name,
            default_project=proj_id,
            default_location=safe_region
        )

        # 3. Validation Checks
        if not sa_json or not str(sa_json).strip():
            raise ValueError("The global configuration parameter 'Service Account JSON' is required.")
        try:
            json.loads(sa_json)
        except json.JSONDecodeError:
            raise ValueError("The global configuration parameter 'Service Account JSON' is malformed.")

        if not target_project or not str(target_project).strip():
            raise ValueError("A Google Cloud Project ID ('GCP Project ID' or 'SecOps Project ID') is required.")

        if not parsed_corpus_identifier or not str(parsed_corpus_identifier).strip():
            raise ValueError("The global configuration parameter 'RAG Corpus Name' is required.")

        if not rag_gcs_bucket or not str(rag_gcs_bucket).strip():
            raise ValueError("The global configuration parameter 'RAG GCS Bucket' is required.")

        # 4. Fetch Action-Specific Parameters
        content = siemplify.extract_action_param("Content")
        if not content or not str(content).strip():
            raise ValueError("The 'Content' parameter is required.")

        raw_filename = siemplify.extract_action_param("Filename")
        if not raw_filename or not str(raw_filename).strip():
            raise ValueError("The 'Filename' parameter is required.")

        # Sanitize filename
        safe_filename = os.path.basename(str(raw_filename).strip())
        safe_filename = "".join(c for c in safe_filename if c.isalnum() or c in "._-")
        if not safe_filename:
            raise ValueError(f"The 'Filename' parameter is invalid: '{raw_filename}'")
        filename = safe_filename
        if not filename.endswith(".jsonl"):
            filename += ".jsonl"

        metadata_json = siemplify.extract_action_param("Metadata JSON", default_value="{}")
        append = siemplify.extract_action_param("Append to Existing", input_type=bool, default_value=False)
        
        try:
            metadata = json.loads(metadata_json) if metadata_json and str(metadata_json).strip() else {}
            if not isinstance(metadata, dict):
                raise ValueError("Metadata must be a JSON object.")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid 'Metadata JSON' format: {e.msg}")

        # 5. Generate token & resolve corpus ID
        token = get_bearer_token(sa_json, siemplify.LOGGER)
        
        corpus_id = resolve_rag_corpus_id(
            location=target_location,
            project_id=target_project,
            corpus_display_name=parsed_corpus_identifier,
            token=token,
            logger=siemplify.LOGGER
        )

        # 6. Prepare payload structure
        payload_line = {
            "content": content,
            "metadata": metadata
        }
        new_jsonl_line = json.dumps(payload_line) + "\n"

        # 7. GCS Operations (Append vs Overwrite)
        final_gcs_content = new_jsonl_line
        mode_str = "Overwrite"

        if append:
            existing_content = download_gcs_content(
                bucket=rag_gcs_bucket,
                filename=filename,
                token=token,
                logger=siemplify.LOGGER
            )
            if existing_content:
                if not existing_content.endswith("\n"):
                    existing_content += "\n"
                final_gcs_content = existing_content + new_jsonl_line
                mode_str = "Append"

        # 8. Upload to GCS
        upload_gcs_content(
            bucket=rag_gcs_bucket,
            filename=filename,
            content=final_gcs_content,
            token=token,
            logger=siemplify.LOGGER
        )

        # 9. Trigger RAG Import via REST
        import_rag_file(
            location=target_location,
            project_id=target_project,
            corpus_id=corpus_id,
            bucket=rag_gcs_bucket,
            filename=filename,
            token=token,
            logger=siemplify.LOGGER
        )

        # 9. Finalize and report to SOAR Case Wall
        output_message = f"Successfully ingested '{filename}' and refreshed the RAG engine via REST-Lite."
        result_value = True
        
        content_hash = hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest()[:16]

        siemplify.result.add_result_json({
            "status": "ingested", 
            "filename": filename,
            "content_length": len(content),
            "content_hash": content_hash,
            "append_mode": append,
            "metadata_keys": list(metadata.keys()) if metadata else [],
            "corpus": rag_corpus_name,
            "bucket": rag_gcs_bucket
        })

        if metadata:
            meta_str = f"{len(metadata)} keys: {', '.join(metadata.keys())}"
        else:
            meta_str = "None"
            
        report_comment = (
            f"### Vertex AI RAG Ingestion Report (LITE-REST) ###\n\n"
            f"- **Filename:** `{filename}`\n"
            f"- **Content Length:** `{len(content)}` characters\n"
            f"- **Content Hash (SHA-256):** `{content_hash}`\n"
            f"- **Target Corpus:** `{rag_corpus_name}`\n"
            f"- **Storage Bucket:** `gs://{rag_gcs_bucket}`\n"
            f"- **Mode:** `{mode_str}`\n"
            f"- **Metadata:** `{meta_str}`\n\n"
            f"**Status:** Successfully Ingested & RAG Engine Refreshed via direct REST calls."
        )
        siemplify.add_comment(report_comment)

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
