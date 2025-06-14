# -*- coding: utf-8 -*-
import os
import sys
import base64
import pickle
import logging
import json
from datetime import datetime
from email.mime.text import MIMEText
from typing import Optional, List, Dict, Any

# --- New Imports for Supabase/Decryption ---
from dotenv import load_dotenv
from supabase import create_client, Client, ClientOptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Existing Imports ---
from email_validator import validate_email, EmailNotValidError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.tools import (
    FunctionTool,
    agent_tool,
    google_search,
    built_in_code_execution,
)
from google.adk.sessions import InMemorySessionService
from google.genai import types as adk_types

# --- Configuration ---
load_dotenv()
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly'
]
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_PICKLE_FILE = os.path.join(SCRIPT_DIR, 'token.pickle')
NONCE_SIZE = 12
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s')
log = logging.getLogger(__name__)
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging.getLogger('google.auth.transport.requests').setLevel(logging.WARNING)
logging.getLogger('httpx').setLevel(logging.WARNING) # Quieten supabase transport logs

# --- Custom Exception ---
class AuthenticationNeededError(Exception):
    """Custom exception raised when token.pickle is missing."""
    pass

# --- Supabase Credential Fetching & Decryption Tool ---

def decrypt_token(encrypted_hex_str: Optional[str], key_bytes: bytes) -> Optional[str]:
    """Decrypts a hex-encoded, AES-GCM encrypted string."""
    if not encrypted_hex_str:
        return None
    try:
        combined_data = bytes.fromhex(encrypted_hex_str)
        if len(combined_data) < NONCE_SIZE:
            raise ValueError("Encrypted data is too short to contain a nonce.")
        nonce = combined_data[:NONCE_SIZE]
        ciphertext = combined_data[NONCE_SIZE:]
        aesgcm = AESGCM(key_bytes)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        log.error(f"Decryption failed. This could be due to an incorrect key or corrupted data. Error: {e}", exc_info=True)
        return None

def setup_google_authentication(user_id: str) -> str:
    """
    Fetches, decrypts, and caches Google OAuth credentials for a given user_id from the backend database.
    This tool MUST be called before any other Google tools (like Gmail) can be used.

    Args:
        user_id: The Supabase user ID for whom to fetch credentials.

    Returns:
        A success or error message string.
    """
    log.info(f"--- Starting Google Authentication Setup for user_id: {user_id} ---")

    db_host = os.getenv("BLUEPRINT_DB_HOST")
    db_schema = os.getenv("BLUEPRINT_DB_SCHEMA")
    supabase_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    hex_encryption_key = os.getenv("TOKEN_ENCRYPTION_KEY")
    google_client_id = os.getenv("GOOGLE_CLIENT_ID")
    google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    required_vars = {
        "BLUEPRINT_DB_HOST": db_host, "BLUEPRINT_DB_SCHEMA": db_schema,
        "SUPABASE_SERVICE_ROLE_KEY": supabase_key, "TOKEN_ENCRYPTION_KEY": hex_encryption_key,
        "GOOGLE_CLIENT_ID": google_client_id, "GOOGLE_CLIENT_SECRET": google_client_secret,
    }
    for var, value in required_vars.items():
        if not value:
            return f"Error: Server-side environment variable '{var}' is not set. Cannot proceed."

    supabase_url = f"https://{db_host[3:]}" if db_host and db_host.startswith("db.") else None
    if not supabase_url: return "Error: Server-side BLUEPRINT_DB_HOST format is incorrect."

    try:
        encryption_key = bytes.fromhex(hex_encryption_key)
        if len(encryption_key) != 32: return "Error: Server-side TOKEN_ENCRYPTION_KEY must be 32 bytes when hex decoded."
    except (ValueError, TypeError): return "Error: Server-side TOKEN_ENCRYPTION_KEY is not a valid hex string."

    try:
        client_options = ClientOptions(schema=db_schema)
        supabase: Client = create_client(supabase_url, supabase_key, options=client_options)
        table_name = 'user_google_tokens'; column_to_query = 'user_id'
        log.info(f"Querying table '{table_name}' for user_id '{user_id}'")
        response = supabase.table(table_name).select('*').eq(column_to_query, user_id).execute()
        if not response.data: return f"Error: No Google authentication data found for user_id '{user_id}'. The user may need to log in and connect their Google account on the frontend."
        token_data = response.data[0]
    except Exception as e:
        log.error(f"Error fetching data from Supabase: {e}", exc_info=True)
        return f"Error: Could not connect to the backend database or fetch token data. Details: {e}"

    access_token = decrypt_token(token_data.get('encrypted_access_token'), encryption_key)
    refresh_token = decrypt_token(token_data.get('encrypted_refresh_token'), encryption_key)

    if not access_token:
        return "Error: Failed to decrypt the Google access token. The server's encryption key may have changed or the data is corrupt."

    expiry_dt = None
    expiry_str = token_data.get('token_expiry')
    if expiry_str:
        try:
            aware_dt = datetime.fromisoformat(expiry_str)
            expiry_dt = aware_dt.replace(tzinfo=None)
        except (ValueError, TypeError):
            log.warning(f"Could not parse expiry timestamp '{expiry_str}'.")

    creds = Credentials(
        token=access_token, refresh_token=refresh_token,
        token_uri=GOOGLE_TOKEN_URI, client_id=google_client_id,
        client_secret=google_client_secret, scopes=token_data.get('scopes'),
        expiry=expiry_dt
    )

    try:
        # Before saving, remove the old file if it exists to ensure a clean state
        if os.path.exists(TOKEN_PICKLE_FILE):
            os.remove(TOKEN_PICKLE_FILE)
        with open(TOKEN_PICKLE_FILE, 'wb') as token_file:
            pickle.dump(creds, token_file)
        log.info(f"Successfully saved credentials to '{TOKEN_PICKLE_FILE}' for user '{user_id}'.")
        return f"Success! Google authentication is now set up for user {user_id}. You can now proceed with Google-related tasks."
    except Exception as e:
        log.error(f"Error saving credentials to pickle file: {e}", exc_info=True)
        return f"Error: Could not save the fetched credentials locally. Details: {e}"

# --- Refactored Google Authentication Helpers ---

def load_or_refresh_credentials():
    """
    Loads credentials from token.pickle. If expired, attempts to refresh.
    Raises AuthenticationNeededError if the file does not exist.
    """
    if not os.path.exists(TOKEN_PICKLE_FILE):
        raise AuthenticationNeededError(f"'{TOKEN_PICKLE_FILE}' not found. The 'setup_google_authentication' tool must be run first.")
    
    with open(TOKEN_PICKLE_FILE, 'rb') as token:
        creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            log.info("Credentials expired. Attempting to refresh...")
            creds.refresh(Request())
            with open(TOKEN_PICKLE_FILE, 'wb') as token:
                pickle.dump(creds, token)
            log.info("Credentials refreshed and saved.")
        else:
            raise AuthenticationNeededError("Credentials are invalid and cannot be refreshed. Please run 'setup_google_authentication' again.")
    return creds

def get_gmail_service():
    """Creates and returns an authenticated Gmail API service object."""
    log.info("Building new Gmail service object...")
    credentials = load_or_refresh_credentials() # This can now raise AuthenticationNeededError
    service = build('gmail', 'v1', credentials=credentials, cache_discovery=False)
    log.info("New Gmail service object built successfully.")
    return service

# --- Gmail API Functions (Tools) ---

def _parse_email_body(payload: Dict[str, Any]) -> (str, List[Dict[str, Any]]):
    """Helper function to recursively parse email payload for body and attachments."""
    body = ""
    attachments = []
    if "parts" in payload:
        for part in payload["parts"]:
            # Recursively parse nested parts (for multipart/alternative, etc.)
            nested_body, nested_attachments = _parse_email_body(part)
            if nested_body and not body: # Prioritize plain text from nested parts
                body = nested_body
            attachments.extend(nested_attachments)

            # Find plain text body at the current level
            if part.get("mimeType") == "text/plain" and "data" in part.get("body", {}):
                body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
            
            # Find attachments
            if part.get("filename"):
                attachment_info = {
                    "filename": part["filename"],
                    "mime_type": part["mimeType"],
                    "size_bytes": part["body"].get("size")
                }
                attachments.append(attachment_info)

    elif "body" in payload and "data" in payload["body"]:
        if payload.get("mimeType") == "text/plain":
            body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
            
    return body, attachments

def get_email_details(message_id: str) -> dict | str:
    """
    Retrieves the full body and attachment details of a specific email by its ID.
    First, use 'search_emails' to find the ID of the email you want to read.

    Args:
        message_id: The ID of the email message to retrieve.

    Returns:
        A dictionary containing the email's subject, sender, body, and a list of attachments,
        or an error message string on failure.
    """
    if not message_id or not message_id.strip():
        return "Error: A message_id must be provided."
    try:
        service = get_gmail_service()
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        
        payload = msg.get('payload', {})
        headers = {h['name'].lower(): h['value'] for h in payload.get('headers', [])}
        
        body, attachments = _parse_email_body(payload)
        
        return {
            "id": msg.get("id"),
            "subject": headers.get("subject", "N/A"),
            "from": headers.get("from", "N/A"),
            "date": headers.get("date", "N/A"),
            "snippet": msg.get("snippet", "").strip(),
            "body": body.strip() if body else "[No plain text body found]",
            "attachments": attachments
        }
    except AuthenticationNeededError as e:
        return f"Error: Authentication is not set up. Please tell me your user ID so I can run the authentication setup tool first. Details: {e}"
    except HttpError as error:
        log.error(f'An HTTP error occurred getting email details: {error}', exc_info=True)
        return f"Error: A Google API error occurred getting email details. Details: {error}"
    except Exception as e:
        log.error(f'An unexpected error occurred getting email details: {e}', exc_info=True)
        return f"Error: An unexpected error occurred. Details: {e}"

def send_email(to: str, subject: str, body: str) -> str:
    """Sends an email using the authenticated Gmail account."""
    try:
        validate_email(to, check_deliverability=False)
        service = get_gmail_service()
        message = MIMEText(body)
        message['to'] = to
        message['subject'] = subject
        message['from'] = 'me'
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        sent_message = service.users().messages().send(userId='me', body={'raw': raw_message}).execute()
        return f"Success! Email sent to {to}. Message ID: {sent_message['id']}"
    except EmailNotValidError as e:
        return f"Error: Invalid recipient email address format: {e}"
    except AuthenticationNeededError as e:
        return f"Error: Authentication is not set up. Please tell me your user ID so I can run the authentication setup tool first. Details: {e}"
    except HttpError as error:
        log.error(f'An HTTP error occurred while sending email: {error}', exc_info=True)
        return f"Error: A Google API error occurred while sending email. Details: {error}"
    except Exception as e:
        log.error(f'An unexpected error occurred while sending email: {e}', exc_info=True)
        return f"Error: An unexpected error occurred. Details: {e}"

def search_emails(query: str, max_results: int = 10) -> list[dict] | str:
    """Searches for emails in the authenticated user's Gmail account."""
    if not query or not query.strip():
        return "Error: A search query must be provided."
    try:
        service = get_gmail_service()
        result = service.users().messages().list(userId='me', q=query, maxResults=min(max_results, 50)).execute()
        messages = result.get('messages', [])
        if not messages: return f"No emails found matching your query: '{query}'"
        
        email_details = []
        for msg_summary in messages:
            msg_id = msg_summary.get('id')
            if not msg_id: continue
            msg = service.users().messages().get(userId='me', id=msg_id, format='metadata', metadataHeaders=['subject', 'from', 'date']).execute()
            headers = {h['name'].lower(): h['value'] for h in msg.get('payload', {}).get('headers', [])}
            email_details.append({
                "id": msg.get('id'), "snippet": msg.get('snippet', '').strip(),
                "subject": headers.get('subject', 'N/A'), "from": headers.get('from', 'N/A'),
                "date": headers.get('date', 'N/A')
            })
        return email_details
    except AuthenticationNeededError as e:
        return f"Error: Authentication is not set up. Please tell me your user ID so I can run the authentication setup tool first. Details: {e}"
    except HttpError as error:
        log.error(f'An HTTP error occurred during email search: {error}', exc_info=True)
        return f"Error: A Google API error occurred during email search. Details: {error}"
    except Exception as e:
        log.error(f'An unexpected error occurred during email search: {e}', exc_info=True)
        return f"Error: An unexpected error occurred. Details: {e}"

def list_labels() -> list[dict] | str:
    """Lists all labels (folders) in the authenticated user's Gmail account."""
    try:
        service = get_gmail_service()
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        if not labels: return "No labels found."
        return [{"id": lbl['id'], "name": lbl['name'], "type": lbl.get('type', 'user')} for lbl in labels]
    except AuthenticationNeededError as e:
        return f"Error: Authentication is not set up. Please tell me your user ID so I can run the authentication setup tool first. Details: {e}"
    except HttpError as error:
        log.error(f'An HTTP error occurred while listing labels: {error}', exc_info=True)
        return f"Error: A Google API error occurred while listing labels. Details: {error}"
    except Exception as e:
        log.error(f'An unexpected error occurred while listing labels: {e}', exc_info=True)
        return f"Error: An unexpected error occurred. Details: {e}"

# --- Create ADK FunctionTools ---
setup_google_auth_tool = FunctionTool(func=setup_google_authentication)
send_email_tool = FunctionTool(func=send_email)
search_emails_tool = FunctionTool(func=search_emails)
get_email_details_tool = FunctionTool(func=get_email_details)
list_labels_tool = FunctionTool(func=list_labels)

# --- Define ADK Agents ---
search_agent = Agent(
    model='gemini-2.0-flash-lite', name='SearchAgent',
    instruction="You are a specialist in using Google Search to find information on the web.",
    tools=[google_search],
)
coding_agent = Agent(
    model='gemini-2.0-flash-lite', name='CodeAgent',
    instruction="You are a specialist in writing and executing Python code snippets.",
    tools=[built_in_code_execution],
)
gmail_send_agent = Agent(
    model='gemini-2.0-flash-lite', name='GmailSendAgent',
    instruction="You are a specialist agent for sending emails using the 'send_email' tool. You must have all arguments: 'to', 'subject', and 'body'.",
    tools=[send_email_tool],
)
gmail_read_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='GmailReadAgent',
    instruction="""You are a specialist agent for reading and searching emails and listing labels in Gmail.

Your capabilities are:
1.  `search_emails`: To find emails using a query. This returns a list of email summaries including their ID.
2.  `get_email_details`: To read the full content and see attachments of a SINGLE email using its `message_id`.
3.  `list_labels`: To list all available email folders/labels.

**WORKFLOW FOR READING AN EMAIL (VERY IMPORTANT):**
You MUST follow this two-step process to read an email's content:
1.  **SEARCH**: The user will ask to find an email. Use `search_emails` with a precise query to locate it. This gives you the `message_id`.
2.  **GET DETAILS**: Use the `get_email_details` tool with the `message_id` you received from the search results to retrieve the email's full content.

**EXAMPLE WORKFLOW**:
-   User: "Read the latest email from jane@example.com"
-   Your FIRST action: Call `search_emails(query='from:jane@example.com', max_results=1)`
-   Tool returns: `[{'id': '123xyz', 'snippet': 'Hi, please see the report attached...'}]`
-   Your SECOND action: Call `get_email_details(message_id='123xyz')`
-   Tool returns the full email body and attachments. You then present this to the user.

**CRITICAL RULES**:
-   For `search_emails`, you MUST extract the search phrase from the user's request for the 'query' argument.
-   Do NOT call `get_email_details` without first getting a `message_id` from `search_emails`.
-   If the user's request is ambiguous, ask for clarification.
""",
    tools=[search_emails_tool, get_email_details_tool, list_labels_tool],
)

root_agent = Agent(
    name="RootAgent",
    model="gemini-2.0-flash-lite",
    instruction="""You are the main assistant coordinating tasks.
    - For web searches, delegate to SearchAgent.
    - For code execution, delegate to CodeAgent.
    - For sending emails, delegate to GmailSendAgent.
    - For reading/searching emails, listing labels, and getting full email content, delegate to the GmailReadAgent. The GmailReadAgent is responsible for the multi-step process of searching and then reading email content.

    *** VERY IMPORTANT: GOOGLE AUTHENTICATION WORKFLOW ***
    To use any Google tool (like Gmail), you MUST first ensure authentication is set up for the user.
    1. The user's prompt will contain a session context like `(Context: The user_id for this session is 'some-uuid-string')`. You MUST extract this `user_id`.
    2. Before using ANY Gmail tool, you MUST first call the `setup_google_authentication` tool, passing the extracted `user_id` as an argument.
    3. ONLY AFTER `setup_google_authentication` returns a success message can you proceed to call the requested Gmail tool (e.g., by delegating to the GmailReadAgent or GmailSendAgent).
    4. If the user asks "read my last email from 'boss@example.com'" and the context provides user_id 'abc-123', your ABSOLUTE FIRST action must be to call `setup_google_authentication(user_id='abc-123')`. In the next turn, after success, you will delegate to the `GmailReadAgent` to perform the search and read steps.
    5. If a Gmail tool fails with an authentication error, tell the user there was a problem and that you are trying to re-authenticate, then call `setup_google_authentication` again.
    """,
    tools=[
        setup_google_auth_tool,
        agent_tool.AgentTool(agent=search_agent),
        agent_tool.AgentTool(agent=coding_agent),
        agent_tool.AgentTool(agent=gmail_send_agent),
        agent_tool.AgentTool(agent=gmail_read_agent)
    ],
)

# --- Runner Setup ---
APP_NAME = "agents"
session_service = InMemorySessionService()
runner = Runner(agent=root_agent, app_name=APP_NAME, session_service=session_service)

# --- Agent Interaction Loop (Demo) ---
def run_conversation():
    print("\n--- Google Auth Integrated Agent ---")
    
    # In a real server, this would come from the incoming request.
    # For this demo, we'll use a hardcoded Supabase user ID.
    user_id_for_session = os.getenv("DEMO_SUPABASE_USER_ID", "default-demo-user-id-not-set")
    if user_id_for_session == "default-demo-user-id-not-set":
        print("WARNING: DEMO_SUPABASE_USER_ID environment variable not set. Using a placeholder.")
    
    # Create a persistent session for this demo run
    adk_user_id = "demo_user"
    adk_session_id = "demo_session_123"
    session_service.create_session(app_name=APP_NAME, user_id=adk_user_id, session_id=adk_session_id)
    print(f"Running demo session for Supabase User ID: '{user_id_for_session}'")
    print("Agent is ready. Type 'quit' to exit.")
    print("-" * 30)

    while True:
        try:
            query = input("You: ")
            if query.strip().lower() == 'quit':
                print("Exiting agent.")
                break
            if not query.strip():
                continue

            print("Agent thinking...")

            # Augment the user's query with the necessary context for the agent
            augmented_query = f"{query}\n\n(Context: The user_id for this session is '{user_id_for_session}')"
            
            content = adk_types.Content(role='user', parts=[adk_types.Part(text=augmented_query)])
            events = runner.run(user_id=adk_user_id, session_id=adk_session_id, new_message=content)

            final_response_text = ""
            for event in events:
                if event.is_final_response():
                    final_response_text = "".join(part.text for part in event.content.parts if part.text)
                    if not final_response_text:
                         final_response_text = "[Agent finished processing, but no text response was generated]"
                    break

            print("\nAgent Response:")
            print(final_response_text)
            print("-" * 30)

        except KeyboardInterrupt:
             print("\nExiting agent due to keyboard interrupt.")
             break
        except Exception as e:
             log.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
             print(f"\nERROR: An unexpected issue occurred. Please check the logs. Details: {e}")
             print("-" * 30)

if __name__ == "__main__":
    run_conversation()