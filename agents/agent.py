# -*- coding: utf-8 -*-
import os
import sys
import base64
import pickle
import logging
import json
from datetime import datetime, timezone, timedelta
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
    # built_in_code_execution,
)
from google.adk.sessions import InMemorySessionService
from google.genai import types as adk_types

# --- Configuration ---
load_dotenv()
# Added new scopes for Profile, Calendar, and Drive
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/calendar.events',
    'https://www.googleapis.com/auth/drive.metadata.readonly',
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
logging.getLogger('httpx').setLevel(logging.WARNING)

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
        log.error(f"Decryption failed: {e}", exc_info=True)
        return None

def setup_google_authentication(user_id: str) -> str:
    """
    Fetches, decrypts, and caches Google OAuth credentials for a given user_id.
    This tool MUST be called before any other Google tools can be used.
    """
    log.info(f"--- Starting Google Authentication Setup for user_id: {user_id} ---")

    # Environment variable fetching and validation...
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
            return f"Error: Server-side environment variable '{var}' is not set."

    try:
        encryption_key = bytes.fromhex(hex_encryption_key)
    except (ValueError, TypeError):
        return "Error: Server-side TOKEN_ENCRYPTION_KEY is not a valid hex string."

    # Supabase connection and data fetching...
    try:
        # --- FIX: Address SSL Hostname Mismatch ---
        # The SSL certificate is valid for the API host (e.g., project-ref.supabase.co),
        # not the direct DB host (e.g., db.project-ref.supabase.co).
        # We must strip the "db." prefix if it exists to use the correct API endpoint.
        api_host = db_host[3:] if db_host and db_host.startswith("db.") else db_host
        supabase_url = f"https://{api_host}"
        log.info(f"Connecting to Supabase at derived URL: {supabase_url}")
        
        client_options = ClientOptions(schema=db_schema)
        supabase: Client = create_client(supabase_url, supabase_key, options=client_options)
        response = supabase.table('user_google_tokens').select('*').eq('user_id', user_id).execute()
        
        if not response.data:
            return f"Error: No Google authentication data found for user_id '{user_id}'."
        token_data = response.data[0]
    except Exception as e:
        return f"Error connecting to backend database: {e}"

    # Decrypt tokens and create credentials object
    access_token = decrypt_token(token_data.get('encrypted_access_token'), encryption_key)
    refresh_token = decrypt_token(token_data.get('encrypted_refresh_token'), encryption_key)
    if not access_token:
        return "Error: Failed to decrypt the Google access token."

    creds = Credentials(
        token=access_token, refresh_token=refresh_token,
        token_uri=GOOGLE_TOKEN_URI, client_id=google_client_id,
        client_secret=google_client_secret, scopes=token_data.get('scopes')
    )

    # Save credentials to local pickle file
    try:
        if os.path.exists(TOKEN_PICKLE_FILE):
            os.remove(TOKEN_PICKLE_FILE)
        with open(TOKEN_PICKLE_FILE, 'wb') as token_file:
            pickle.dump(creds, token_file)
        return f"Success! Google authentication is now set up for user {user_id}."
    except Exception as e:
        return f"Error saving credentials locally: {e}"

# --- Refactored Google Authentication & Service Helpers ---

def load_or_refresh_credentials() -> Credentials:
    """Loads and refreshes credentials, raising AuthenticationNeededError if unavailable."""
    if not os.path.exists(TOKEN_PICKLE_FILE):
        raise AuthenticationNeededError(f"'{TOKEN_PICKLE_FILE}' not found. Run 'setup_google_authentication' first.")

    with open(TOKEN_PICKLE_FILE, 'rb') as token:
        creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            log.info("Credentials expired. Refreshing...")
            creds.refresh(Request())
            with open(TOKEN_PICKLE_FILE, 'wb') as token:
                pickle.dump(creds, token)
            log.info("Credentials refreshed.")
        else:
            raise AuthenticationNeededError("Credentials invalid and cannot be refreshed. Run setup again.")
    return creds

def get_google_api_service(service_name: str, version: str):
    """Generic factory for creating an authenticated Google API service object."""
    log.info(f"Building new '{service_name}' v'{version}' service object...")
    credentials = load_or_refresh_credentials()
    service = build(service_name, version, credentials=credentials, cache_discovery=False)
    log.info(f"Successfully built '{service_name}' service object.")
    return service

# --- API Tool Functions (Gmail, User Profile, Calendar, Drive) ---

# User Profile Tool
def get_user_profile() -> dict | str:
    """Retrieves the authenticated user's profile information (name, email, picture)."""
    try:
        service = get_google_api_service('oauth2', 'v2')
        user_info = service.userinfo().get().execute()
        return {
            "email": user_info.get("email"), "name": user_info.get("name"),
            "given_name": user_info.get("given_name"), "family_name": user_info.get("family_name"),
            "picture": user_info.get("picture"),
        }
    except AuthenticationNeededError as e:
        return f"Error: Authentication needed. Please provide your user ID to run setup. Details: {e}"
    except HttpError as error:
        return f"Error: Google API HTTP error getting user profile: {error}"
    except Exception as e:
        return f"Error: An unexpected error occurred getting user profile: {e}"

# Gmail Tools
def _execute_email_search(query: str, max_results: int, label_ids: Optional[List[str]], include_spam_trash: bool) -> list[dict] | str:
    """Internal helper to execute Gmail search."""
    service = get_google_api_service('gmail', 'v1')
    params = {
        'userId': 'me',
        'q': query,
        'maxResults': min(max_results, 50),
        'includeSpamTrash': include_spam_trash
    }
    if label_ids:
        params['labelIds'] = label_ids

    result = service.users().messages().list(**params).execute()
    messages = result.get('messages', [])
    if not messages: return f"No emails found for query: '{query}'"

    details = []
    for msg in messages:
        if msg_id := msg.get('id'):
            m = service.users().messages().get(userId='me', id=msg_id, format='metadata', metadataHeaders=['subject', 'from', 'date']).execute()
            headers = {h['name'].lower(): h['value'] for h in m.get('payload', {}).get('headers', [])}
            details.append({
                "id": m.get('id'), "snippet": m.get('snippet', '').strip(),
                "subject": headers.get('subject', 'N/A'), "from": headers.get('from', 'N/A'),
                "date": headers.get('date', 'N/A')
            })
    return details

def search_emails(query: str, max_results: int = 10, label_ids: Optional[List[str]] = None, include_spam_trash: bool = False) -> list[dict] | str:
    """
    Searches emails with a Gmail query string (e.g., 'from:x', 'subject:y', 'is:unread').
    Can also filter by label_ids (e.g., ['INBOX', 'UNREAD']) and include spam/trash.
    To search for the 'last N emails', provide an empty query string.
    """
    if query is None:
        return "Error: A search query string must be provided, even if empty."
    # Handle "last N emails" case by removing the query string for a general search
    if "last" in query.lower() and "email" in query.lower():
        query = "" # Search all emails, rely on max_results
    try:
        return _execute_email_search(query, max_results, label_ids, include_spam_trash)
    except AuthenticationNeededError as e:
        return f"Error: Authentication needed. {e}"
    except Exception as e:
        return f"Error during email search: {e}"

def search_emails_by_date(comparison: str, year: int, month: int, day: int, max_results: int = 10) -> list[dict] | str:
    """Searches for emails 'before' or 'after' a specific date (YYYY-MM-DD)."""
    if comparison not in ['before', 'after']:
        return "Error: 'comparison' must be 'before' or 'after'."
    try:
        dt = datetime(year, month, day, tzinfo=timezone.utc)
        query = f"{comparison}:{int(dt.timestamp())}"
        return _execute_email_search(query, max_results, None, False)
    except (ValueError, TypeError) as e:
        return f"Error: Invalid date values provided: {e}"
    except AuthenticationNeededError as e:
        return f"Error: Authentication needed. {e}"
    except Exception as e:
        return f"Error during date-based email search: {e}"

def get_email_details(message_id: str) -> dict | str:
    """Retrieves full body/attachments of a specific email by its ID."""
    if not message_id: return "Error: message_id must be provided."
    try:
        service = get_google_api_service('gmail', 'v1')
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        payload = msg.get('payload', {})
        headers = {h['name'].lower(): h['value'] for h in payload.get('headers', [])}

        body, attachments = "", []
        if "parts" in payload:
            for part in payload.get('parts', []):
                if part.get("mimeType") == "text/plain" and "data" in part.get("body", {}):
                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                if part.get("filename"):
                    attachments.append({"filename": part["filename"], "mime_type": part["mimeType"]})
        elif "body" in payload and payload.get("mimeType") == "text/plain":
            body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")

        return {
            "id": msg.get("id"), "subject": headers.get("subject"), "from": headers.get("from"),
            "date": headers.get("date"), "snippet": msg.get("snippet"),
            "body": body.strip() or "[No plain text body found]", "attachments": attachments
        }
    except Exception as e: return f"Error getting email details: {e}"

def send_email(to: str, subject: str, body: str) -> str:
    """Sends an email."""
    try:
        validate_email(to)
        service = get_google_api_service('gmail', 'v1')
        message = MIMEText(body)
        message['to'], message['subject'], message['from'] = to, subject, 'me'
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        sent = service.users().messages().send(userId='me', body={'raw': raw_message}).execute()
        return f"Success! Email sent to {to}. Message ID: {sent['id']}"
    except Exception as e: return f"Error sending email: {e}"

# Calendar Tools
def search_calendar_events(query: Optional[str] = None, time_min: Optional[str] = None, time_max: Optional[str] = None, single_events: bool = True, max_results: int = 10) -> list[dict] | str:
    """
    Searches events on the user's primary calendar. Can filter by query, time_min, and time_max.
    If time_min is not provided, it defaults to the current time to find upcoming events.
    Datetimes MUST be in ISO 8601 format (e.g., '2025-06-15T15:00:00-07:00' or '2025-06-16T10:00:00Z').
    """
    try:
        service = get_google_api_service('calendar', 'v3')
        
        # Default to now if time_min is not specified to find upcoming events
        effective_time_min = time_min if time_min else datetime.utcnow().isoformat() + 'Z'

        params = {
            'calendarId': 'primary',
            'timeMin': effective_time_min,
            'maxResults': max_results,
            'singleEvents': single_events,
            'orderBy': 'startTime'
        }
        if time_max:
            params['timeMax'] = time_max
        if query:
            params['q'] = query

        events_result = service.events().list(**params).execute()
        events = events_result.get('items', [])
        if not events: return "No events found matching the criteria."

        event_list = []
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            event_list.append({
                "summary": event.get("summary", "No Title"),
                "start": start, "end": end, "location": event.get("location", "N/A")
            })
        return event_list
    except Exception as e: return f"Error listing calendar events: {e}"

def create_calendar_event(summary: str, start_datetime: str, end_datetime: str, description: str = '', location: str = '') -> dict | str:
    """
    Creates a new event on the user's primary Google Calendar.
    IMPORTANT: Datetimes MUST be in ISO 8601 format (e.g., '2025-06-15T15:00:00-07:00').
    """
    try:
        service = get_google_api_service('calendar', 'v3')
        event = {
            'summary': summary, 'location': location, 'description': description,
            'start': {'dateTime': start_datetime, 'timeZone': 'UTC'},
            'end': {'dateTime': end_datetime, 'timeZone': 'UTC'},
        }
        created_event = service.events().insert(calendarId='primary', body=event).execute()
        return {"status": "success", "event_link": created_event.get('htmlLink')}
    except Exception as e: return f"Error creating calendar event: {e}"

# Drive Tools
def list_drive_files(query: str = '', max_results: int = 15) -> list[dict] | str:
    """
    Lists files and folders in Google Drive. Can filter with a query.
    Example queries: "name contains 'report'", "mimeType='application/vnd.google-apps.folder'".
    """
    try:
        service = get_google_api_service('drive', 'v3')
        results = service.files().list(
            q=query, pageSize=max_results,
            fields="nextPageToken, files(id, name, mimeType, modifiedTime)"
        ).execute()
        items = results.get('files', [])
        if not items: return "No files found in Google Drive matching the query."
        return [{
            "id": item['id'], "name": item['name'], "type": item['mimeType'],
            "last_modified": item['modifiedTime']
        } for item in items]
    except Exception as e: return f"Error listing Drive files: {e}"

def get_drive_file_metadata(file_id: str) -> dict | str:
    """Gets detailed metadata for a specific file or folder in Google Drive by its ID."""
    if not file_id:
        return "Error: A file_id must be provided."
    try:
        service = get_google_api_service('drive', 'v3')
        fields = "id, name, mimeType, modifiedTime, createdTime, owners(displayName, emailAddress), webViewLink, iconLink"
        file_metadata = service.files().get(fileId=file_id, fields=fields).execute()
        return file_metadata
    except AuthenticationNeededError as e:
        return f"Error: Authentication needed. {e}"
    except HttpError as error:
        if error.resp.status == 404:
            return f"Error: File with ID '{file_id}' not found."
        return f"Error: Google API HTTP error getting file metadata: {error}"
    except Exception as e:
        return f"Error getting Drive file metadata: {e}"


# --- Create ADK FunctionTools ---
setup_google_auth_tool = FunctionTool(func=setup_google_authentication)
get_user_profile_tool = FunctionTool(func=get_user_profile)
send_email_tool = FunctionTool(func=send_email)
search_emails_tool = FunctionTool(func=search_emails)
search_emails_by_date_tool = FunctionTool(func=search_emails_by_date)
get_email_details_tool = FunctionTool(func=get_email_details)
search_calendar_events_tool = FunctionTool(func=search_calendar_events)
create_calendar_event_tool = FunctionTool(func=create_calendar_event)
list_drive_files_tool = FunctionTool(func=list_drive_files)
get_drive_file_metadata_tool = FunctionTool(func=get_drive_file_metadata)


# --- Define ADK Agents ---
<<<<<<< Updated upstream
search_agent = Agent(
    model='gemini-2.0-flash-lite', name='SearchAgent',
    instruction="You are a specialist in using Google Search to find information on the web.",
    tools=[google_search],
)

coding_agent = Agent(
    model='gemini-2.0-flash-lite', name='CodeAgent',
    instruction="You are a specialist in writing and executing Python code snippets.",
    # tools=[built_in_code_execution],
)
gmail_send_agent = Agent(
    model='gemini-2.0-flash-lite', name='GmailSendAgent',
    instruction="You are a specialist agent for sending emails using the 'send_email' tool. You must have all arguments: 'to', 'subject', and 'body'.",
    tools=[send_email_tool],
)
gmail_read_agent = Agent(
=======
# General Purpose Agents
search_agent = Agent(name="SearchAgent", model='gemini-2.0-flash-lite', tools=[google_search])
coding_agent = Agent(name="CodeAgent", model='gemini-2.0-flash-lite', tools=[built_in_code_execution])

# Specialized Google Service Agents
user_profile_agent = Agent(name="UserProfileAgent", model='gemini-2.0-flash-lite', tools=[get_user_profile_tool])
gmail_send_agent = Agent(name="GmailSendAgent", model='gemini-2.0-flash-lite', tools=[send_email_tool])
gmail_search_agent = Agent(
    name="GmailSearchAgent",
>>>>>>> Stashed changes
    model='gemini-2.0-flash-lite',
    instruction="Search emails using text or date. To find the 'last 5 emails', use `search_emails` with max_results=5 and an empty query string.",
    tools=[search_emails_tool, search_emails_by_date_tool]
)
gmail_get_email_agent = Agent(
    name="GmailGetEmailAgent",
    model='gemini-2.0-flash-lite',
    instruction="Use the message_id from a search to fetch a single email's full content.",
    tools=[get_email_details_tool]
)
calendar_read_agent = Agent(name="CalendarReadAgent", model='gemini-2.0-flash-lite', tools=[search_calendar_events_tool])
calendar_write_agent = Agent(name="CalendarWriteAgent", model='gemini-2.0-flash-lite', tools=[create_calendar_event_tool])
drive_search_agent = Agent(name="DriveSearchAgent", model='gemini-2.0-flash-lite', tools=[list_drive_files_tool])
drive_get_file_agent = Agent(
    name="DriveGetFileAgent",
    model='gemini-2.0-flash-lite',
    instruction="Use the file_id from a search to fetch a single file's full metadata.",
    tools=[get_drive_file_metadata_tool]
)

root_agent = Agent(
    name="RootAgent",
    model="gemini-2.0-flash-lite",
    instruction="""You are the main coordinator. Your job is to understand the user's request and delegate to the correct specialist agent.

    *** AUTHENTICATION WORKFLOW (MANDATORY) ***
    1.  The user's prompt will contain a context like `(Context: The user_id is 'some-uuid')`.
    2.  Before using ANY Google tool, you MUST call `setup_google_authentication` with that `user_id`.
    3.  Only after successful authentication can you delegate to a specialist agent.

    *** DELEGATION RULES ***
    -   Web search: `SearchAgent`.
    -   Code execution: `CodeAgent`.
    -   Get user info (name, email): `UserProfileAgent`.
    -   Send an email: `GmailSendAgent`.
    -   Search for emails (by text, date, or 'last N'): `GmailSearchAgent`.
    -   Read a specific email's content (after getting an ID): `GmailGetEmailAgent`.
    -   List or search calendar events: `CalendarReadAgent`.
    -   Create a calendar event: `CalendarWriteAgent`.
    -   List or search for files in Drive: `DriveSearchAgent`.
    -   Get details for a specific file in Drive: `DriveGetFileAgent`.

    *** MULTI-STEP WORKFLOWS ***
    -   **Reading Emails**: First, delegate to `GmailSearchAgent` to find the email and get its `message_id`. Second, delegate to `GmailGetEmailAgent` with the `message_id` to read the content.
    -   **Reading Drive Files**: First, delegate to `DriveSearchAgent` to find the file and get its `id`. Second, delegate to `DriveGetFileAgent` with that `id` to get its details.
    """,
    tools=[
        setup_google_auth_tool,
        agent_tool.AgentTool(agent=gmail_search_agent),
        agent_tool.AgentTool(agent=gmail_get_email_agent),
        agent_tool.AgentTool(agent=calendar_read_agent),
        agent_tool.AgentTool(agent=calendar_write_agent),
        agent_tool.AgentTool(agent=drive_search_agent),
        agent_tool.AgentTool(agent=drive_get_file_agent),
        agent_tool.AgentTool(agent=search_agent),
        agent_tool.AgentTool(agent=coding_agent),
        agent_tool.AgentTool(agent=user_profile_agent),
        agent_tool.AgentTool(agent=gmail_send_agent),
        
    ],
)

# --- Runner Setup ---
APP_NAME = "agents"
session_service = InMemorySessionService()
runner = Runner(agent=root_agent, app_name=APP_NAME, session_service=session_service)

# --- Agent Interaction Loop (Demo) ---
def run_conversation():
    print("\n--- Google Services Super-Agent ---")
    user_id_for_session = os.getenv("DEMO_SUPABASE_USER_ID", "default-demo-user-id-not-set")
    if user_id_for_session == "default-demo-user-id-not-set":
        print("WARNING: DEMO_SUPABASE_USER_ID environment variable not set.")

    adk_user_id = "demo_user"
    adk_session_id = "demo_session_123"
    session_service.create_session(app_name=APP_NAME, user_id=adk_user_id, session_id=adk_session_id)
    print(f"Session ready for Supabase User ID: '{user_id_for_session}'")
    print("Example prompts: 'What's my name?', 'Read my last 3 emails', 'What are my next 5 calendar events?', 'List my files in Drive'.")
    print("Type 'quit' to exit.")
    print("-" * 30)

    while True:
        try:
            query = input("You: ")
            if query.strip().lower() == 'quit': break
            if not query.strip(): continue

            print("Agent thinking...")
            augmented_query = f"{query}\n\n(Context: The user_id for this session is '{user_id_for_session}')"
            content = adk_types.Content(role='user', parts=[adk_types.Part(text=augmented_query)])
            events = runner.run(user_id=adk_user_id, session_id=adk_session_id, new_message=content)

            final_response = "[Agent finished without a text response]"
            for event in events:
                if event.is_final_response():
                    final_response = "".join(part.text for part in event.content.parts if part.text)
                    break

            print(f"\nAgent Response:\n{final_response}")
            print("-" * 30)

        except KeyboardInterrupt: break
        except Exception as e:
             log.error(f"FATAL ERROR in main loop: {e}", exc_info=True)
             print(f"\nERROR: An unexpected issue occurred: {e}")

    print("Exiting agent.")

if __name__ == "__main__":
    run_conversation()
