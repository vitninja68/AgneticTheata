# -*- coding: utf-8 -*-
import os
import base64
import pickle
import logging
import time # Keep for potential future use or debugging delays
import json # For parsing potential HttpError details
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
# Removed: from google_auth_oauthlib.flow import InstalledAppFlow (initial flow handled separately)
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
from google.genai import types as adk_types # Renamed to avoid conflict with python types if any
#from google.ai import generativelanguage as glm # For accessing function call details

# --- Configuration ---
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly'
]
# --- Resolve Paths Relative to This Script ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# CREDENTIALS_FILE is no longer directly needed here for the auth flow, but keep for reference if desired
CREDENTIALS_FILE = os.path.join(SCRIPT_DIR, 'credentials.json')
TOKEN_PICKLE_FILE = os.path.join(SCRIPT_DIR, 'token.pickle') # Expects this file to exist

# OAUTH settings are only needed by the separate authentication script
# OAUTH_REDIRECT_PORT = 8081
# OAUTH_REDIRECT_URI = f'http://localhost:{OAUTH_REDIRECT_PORT}/'

# --- Logging Setup ---
# Increased logging level for ADK/Google API client libraries for more detail
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s')
log = logging.getLogger(__name__)
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR) # Quieten discovery cache logs
logging.getLogger('google.auth.transport.requests').setLevel(logging.WARNING) # Quieten routine token refresh logs unless warning


# --- Global Variables ---
gmail_service = None # Will hold the authenticated Gmail service object

# --- Google Authentication (Modified: Load/Refresh Only) ---
def load_or_refresh_credentials():
    """
    Loads credentials from token.pickle. If expired, attempts to refresh.
    Does NOT initiate the full browser-based OAuth flow. Assumes token.pickle
    was created by the separate authenticate_gmail.py script.

    Returns:
        Valid Credentials object or raises an error if loading/refreshing fails.
    """
    global gmail_service # Allow updating the global service if creds are refreshed
    creds = None
    if not os.path.exists(TOKEN_PICKLE_FILE):
        log.critical(f"CRITICAL ERROR: Authentication token file '{TOKEN_PICKLE_FILE}' not found.")
        log.critical(f"Please run the 'authenticate_gmail.py' script first to generate the token.")
        raise FileNotFoundError(f"'{TOKEN_PICKLE_FILE}' not found. Run authentication script first.")

    try:
        with open(TOKEN_PICKLE_FILE, 'rb') as token:
            creds = pickle.load(token)
        log.info(f"Loaded credentials from {TOKEN_PICKLE_FILE}")
    except (EOFError, pickle.UnpicklingError, Exception) as e:
        log.error(f"Could not load or parse token.pickle: {e}. It might be corrupted.")
        log.critical(f"Please delete '{TOKEN_PICKLE_FILE}' and run 'authenticate_gmail.py' again.")
        raise ConnectionAbortedError(f"Failed to load token file: {e}. Run authentication script again.") from e

    # Check if credentials need refreshing
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            log.info("Credentials expired. Attempting to refresh using refresh token...")
            try:
                creds.refresh(Request())
                log.info("Credentials refreshed successfully.")
                # Save the refreshed token back to the file
                try:
                    with open(TOKEN_PICKLE_FILE, 'wb') as token:
                        pickle.dump(creds, token)
                    log.info(f"Refreshed credentials saved back to {TOKEN_PICKLE_FILE}")
                except Exception as e:
                    log.error(f"Error saving refreshed credentials back to {TOKEN_PICKLE_FILE}: {e}")
                    # Continue with the refreshed creds in memory, but log the save error

                # If the global service object exists, update its credentials
                if gmail_service:
                    # Rebuild the service object with the refreshed credentials
                    try:
                        gmail_service = build('gmail', 'v1', credentials=creds)
                        log.info("Updated existing Gmail service instance with refreshed credentials.")
                    except Exception as build_err:
                         log.error(f"Failed to rebuild Gmail service after token refresh: {build_err}")
                         # Depending on the error, might need to invalidate the service object
                         gmail_service = None


            except Exception as e:
                log.error(f"Failed to refresh token: {e}", exc_info=True)
                log.critical(f"Automatic token refresh failed. The refresh token might be invalid or revoked.")
                log.critical(f"Please delete '{TOKEN_PICKLE_FILE}' and run 'authenticate_gmail.py' again to re-authenticate.")
                raise ConnectionAbortedError(f"Token refresh failed: {e}. Run authentication script again.") from e
        else:
            # Credentials are not valid and cannot be refreshed (e.g., missing refresh token or other issue)
            log.critical("Loaded credentials are invalid and cannot be refreshed.")
            log.critical(f"Please delete '{TOKEN_PICKLE_FILE}' and run 'authenticate_gmail.py' again.")
            raise ConnectionAbortedError("Invalid credentials in token file and cannot refresh. Run authentication script again.")

    # At this point, creds should be valid (either loaded valid or refreshed valid)
    if not creds or not creds.valid:
         # This case should ideally be caught above, but double-check
         msg = "Could not obtain valid Google credentials from token file or refresh process."
         log.error(msg)
         raise ConnectionAbortedError(msg + " Run authentication script again.")

    return creds

def get_gmail_service():
    """Builds and returns an authenticated Gmail API service object. Handles loading/refreshing credentials."""
    global gmail_service
    # Check if service exists and its credentials are still valid
    if gmail_service and gmail_service._http.credentials and gmail_service._http.credentials.valid:
        # Optional: Add a check here to see if credentials object identity matches the one used to build service
        # This handles the case where creds were refreshed but service wasn't updated
        # However, load_or_refresh_credentials now attempts to update the global service, making this less critical
        return gmail_service

    log.info("Gmail service not available or credentials might need check/refresh. Loading/refreshing...")
    # load_or_refresh_credentials will return valid creds or raise an error
    try:
        credentials = load_or_refresh_credentials()
    except (FileNotFoundError, ConnectionAbortedError) as e:
         # Logged sufficiently in load_or_refresh_credentials, just re-raise
         raise e
    except Exception as e:
        log.error(f"Unexpected error during credential loading/refreshing: {e}", exc_info=True)
        raise ConnectionError(f"Unexpected error getting credentials: {e}") from e

    # Check if the service needs to be rebuilt even if it exists (e.g., credentials changed)
    if gmail_service and gmail_service._http.credentials != credentials:
        log.info("Credentials have been updated. Rebuilding Gmail service.")
        gmail_service = None # Force rebuild

    if not gmail_service:
        try:
            # Build or rebuild the service with the valid credentials
            gmail_service = build('gmail', 'v1', credentials=credentials, cache_discovery=False) # Disable cache for robustness
            log.info("Gmail service built/rebuilt successfully.")
        except HttpError as error:
            log.error(f'An HTTP error occurred building the Gmail service: {error}', exc_info=True)
            raise ConnectionError(f'Failed to build Gmail service (HTTPError): {error}') from error
        except Exception as e:
            log.error(f'An unexpected error occurred building the Gmail service: {e}', exc_info=True)
            raise ConnectionError(f'Unexpected error building Gmail service: {e}') from e

    return gmail_service

# --- Gmail API Functions (to be wrapped by FunctionTool) ---
# (No changes needed in the actual API functions themselves for this error)
# --- START: Gmail Functions (Keep these exactly as they were) ---
def send_email(to: str, subject: str, body: str) -> str:
    """
    Sends an email using the authenticated Gmail account.

    Args:
        to: The recipient's email address.
        subject: The subject line of the email.
        body: The plain text content of the email.

    Returns:
        A confirmation message including the Message ID on success,
        or an error message on failure.
    """
    try:
        validation = validate_email(to, check_deliverability=False) # Basic syntax check
        to_email = validation.normalized
    except EmailNotValidError as e:
        log.warning(f"Invalid recipient email address format: {to}. Error: {e}")
        return f"Error: Invalid recipient email address format provided ('{to}'). Please provide a valid email address. Details: {e}"

    try:
        service = get_gmail_service() # Handles auth internally (load/refresh)

        message = MIMEText(body)
        message['to'] = to_email
        message['subject'] = subject
        message['from'] = 'me' # 'me' indicates the authenticated user

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': raw_message}

        sent_message = service.users().messages().send(userId='me', body=create_message).execute()
        log.info(f"Email sent successfully via API. Message ID: {sent_message['id']}")
        return f"Success! Email sent to {to_email} with subject '{subject}'. Message ID: {sent_message['id']}"

    except HttpError as error:
        log.error(f'An HTTP error occurred while sending email: {error}', exc_info=True)
        error_details = "Unknown Google API error"
        try:
            content = getattr(error, 'content', b'{}')
            error_json = json.loads(content.decode('utf-8'))
            error_details = error_json.get('error', {}).get('message', str(error))
        except Exception:
            error_details = str(error)
        # Check for specific auth errors that might suggest re-running the auth script
        if error.resp.status in [401, 403]:
             log.error("Received 401/403 error. Authentication token might be invalid or revoked.")
             return f"Error: Failed to send email due to an Authentication/Authorization error ({error.resp.status}). Please try running the 'authenticate_gmail.py' script again. Details: {error_details}"
        return f"Error: Failed to send email due to a Google API error. Details: {error_details}"
    except (FileNotFoundError, ConnectionError, ConnectionAbortedError) as e:
         log.error(f"Authentication/Connection error during send: {e}")
         # Make the error message guide the user
         if isinstance(e, FileNotFoundError):
             return f"Error: Authentication token file not found. Please run 'authenticate_gmail.py' first. Details: {e}"
         elif isinstance(e, ConnectionAbortedError):
             return f"Error: Authentication failed (invalid token or refresh failed). Please run 'authenticate_gmail.py' again. Details: {e}"
         else: # General ConnectionError
             return f"Error: Failed to connect to Gmail service. Check network or logs. Details: {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred while sending email: {e}', exc_info=True)
        return f"Error: An unexpected error occurred while trying to send the email. Details: {e}"

def search_emails(query: str, max_results: int = 10) -> list[dict] | str:
    """
    Searches for emails in the authenticated user's Gmail account using Gmail query syntax.

    Args:
        query: The search query string (e.g., 'from:boss@example.com subject:urgent', 'in:inbox is:unread').
               THIS ARGUMENT IS REQUIRED.
        max_results: Maximum number of email *messages* (not threads) to return details for. Defaults to 10, max 50.

    Returns:
        A list of dictionaries, each containing details of a found email message
        (id, threadId, snippet, subject, from, date), sorted most recent first by default.
        Returns a string message if no emails are found or if an error occurs.
    """
    # Explicit check for query added for robustness, though the agent *should* provide it.
    if not query or not isinstance(query, str) or not query.strip():
        log.error("search_emails called without a valid query string.")
        return "Error: The search_emails tool was called without providing a search query. Please specify what you want to search for."

    log.info(f"Executing search_emails with query: '{query}' and max_results: {max_results}")

    try:
        service = get_gmail_service() # Handles auth internally (load/refresh)

        # Validate max_results
        try:
            max_results = int(max_results)
            if max_results <= 0:
                 log.warning(f"Invalid max_results value '{max_results}', defaulting to 10.")
                 max_results = 10
            if max_results > 50:
                log.warning("max_results capped at 50 to avoid excessive API calls.")
                max_results = 50
        except (ValueError, TypeError):
             log.warning(f"Invalid type for max_results '{max_results}', defaulting to 10.")
             max_results = 10


        result = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=max_results # Limits the *initial list* of IDs fetched
        ).execute()

        messages = result.get('messages', [])

        if not messages:
            log.info(f"No emails found for query: {query}")
            return f"No emails found matching your query: '{query}'"

        email_details = []
        log.info(f"Found {len(messages)} potential messages for query '{query}'. Fetching details (up to {max_results})...")

        count = 0
        for msg_summary in messages:
            if count >= max_results:
                log.info(f"Reached max_results limit ({max_results}), stopping detail fetch.")
                break
            msg_id = msg_summary.get('id')
            if not msg_id:
                log.warning("Found a message summary without an ID, skipping.")
                continue
            try:
                # Fetch metadata including headers
                msg = service.users().messages().get(
                    userId='me',
                    id=msg_id,
                    format='metadata', # Efficiently fetch only headers and snippet
                    metadataHeaders=['subject', 'from', 'date']
                ).execute()

                headers_list = msg.get('payload', {}).get('headers', [])
                # Robust header parsing
                headers_dict = {}
                for h in headers_list:
                    # Use .get() for safety, handle potential missing keys
                    name = h.get('name')
                    value = h.get('value')
                    if name: # Only add if name exists
                        headers_dict[name.lower()] = value if value is not None else '' # Store empty string if value missing


                details = {
                    "id": msg.get('id'),
                    "threadId": msg.get('threadId'),
                    "snippet": msg.get('snippet', '').strip(),
                    "subject": headers_dict.get('subject', 'N/A'),
                    "from": headers_dict.get('from', 'N/A'),
                    "date": headers_dict.get('date', 'N/A')
                }
                email_details.append(details)
                count += 1
            except HttpError as error:
                 log.error(f"Could not retrieve details for message ID {msg_id}: {error}")
                 # Append error info to the results list
                 error_reason = error._get_reason() if hasattr(error, '_get_reason') else 'Unknown reason'
                 email_details.append({"id": msg_id, "error": f"Could not retrieve details: {error.resp.status} {error_reason}"})
                 count += 1 # Still count towards max_results
                 # Check for auth errors here too
                 if error.resp.status in [401, 403]:
                     log.error("Received 401/403 error during detail fetch. Authentication token might be invalid.")
                     # Return an immediate error message in this case, as further calls will likely fail
                     return f"Error: Authentication/Authorization error ({error.resp.status}) while fetching email details. Please try running 'authenticate_gmail.py' again."
            except Exception as e:
                 log.error(f"Unexpected error retrieving details for message ID {msg_id}: {e}", exc_info=True)
                 email_details.append({"id": msg_id, "error": f"Unexpected error retrieving details: {e}"})
                 count += 1

        log.info(f"Successfully retrieved details for {len(email_details)} emails matching query '{query}'.")
        return email_details

    except HttpError as error:
        log.error(f'An HTTP error occurred during email search list: {error}', exc_info=True)
        error_details = "Unknown Google API error"
        try:
            content = getattr(error, 'content', b'{}')
            error_json = json.loads(content.decode('utf-8'))
            error_details = error_json.get('error', {}).get('message', str(error))
        except Exception:
             error_details = str(error) # Fallback
        # Check for auth errors
        if error.resp.status in [401, 403]:
             log.error("Received 401/403 error during message list. Authentication token might be invalid.")
             return f"Error: Failed to search emails due to an Authentication/Authorization error ({error.resp.status}). Please try running 'authenticate_gmail.py' again. Details: {error_details}"
        return f"Error: Failed to search emails due to a Google API error. Details: {error_details}"
    except (FileNotFoundError, ConnectionError, ConnectionAbortedError) as e:
         log.error(f"Authentication/Connection error during search: {e}")
         if isinstance(e, FileNotFoundError):
             return f"Error: Authentication token file not found. Please run 'authenticate_gmail.py' first. Details: {e}"
         elif isinstance(e, ConnectionAbortedError):
             return f"Error: Authentication failed (invalid token or refresh failed). Please run 'authenticate_gmail.py' again. Details: {e}"
         else: # General ConnectionError
             return f"Error: Failed to connect to Gmail service. Check network or logs. Details: {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred during email search: {e}', exc_info=True)
        return f"Error: An unexpected error occurred while trying to search emails. Details: {e}"

def list_labels() -> list[dict] | str:
    """
    Lists all labels (folders) in the authenticated user's Gmail account.

    Returns:
        A list of dictionaries, each containing label details (id, name, type),
        or an error message string on failure.
    """
    log.info("Executing list_labels...")
    try:
        service = get_gmail_service() # Handles auth internally (load/refresh)

        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        if not labels:
            log.info("No labels found for the user.")
            return "No labels found in your Gmail account."

        label_details = [
            {"id": lbl['id'], "name": lbl['name'], "type": lbl.get('type', 'user')}
            for lbl in labels
        ]
        log.info(f"Retrieved {len(label_details)} labels.")
        return label_details

    except HttpError as error:
        log.error(f'An HTTP error occurred while listing labels: {error}', exc_info=True)
        error_details = "Unknown Google API error"
        try:
            content = getattr(error, 'content', b'{}')
            error_json = json.loads(content.decode('utf-8'))
            error_details = error_json.get('error', {}).get('message', str(error))
        except Exception:
             error_details = str(error) # Fallback
        # Check for auth errors
        if error.resp.status in [401, 403]:
             log.error("Received 401/403 error during list labels. Authentication token might be invalid.")
             return f"Error: Failed to list labels due to an Authentication/Authorization error ({error.resp.status}). Please try running 'authenticate_gmail.py' again. Details: {error_details}"
        return f"Error: Failed to list labels due to a Google API error. Details: {error_details}"
    except (FileNotFoundError, ConnectionError, ConnectionAbortedError) as e:
         log.error(f"Authentication/Connection error during list labels: {e}")
         if isinstance(e, FileNotFoundError):
             return f"Error: Authentication token file not found. Please run 'authenticate_gmail.py' first. Details: {e}"
         elif isinstance(e, ConnectionAbortedError):
             return f"Error: Authentication failed (invalid token or refresh failed). Please run 'authenticate_gmail.py' again. Details: {e}"
         else: # General ConnectionError
             return f"Error: Failed to connect to Gmail service. Check network or logs. Details: {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred while listing labels: {e}', exc_info=True)
        return f"Error: An unexpected error occurred while trying to list labels. Details: {e}"
# --- END: Gmail Functions ---


# --- Create ADK FunctionTools ---
send_email_tool = FunctionTool(
    func=send_email,
    #description="Use this tool to send an email. You MUST provide the recipient's email address ('to'), the subject ('subject'), and the body content ('body')." # Added emphasis
)

search_emails_tool = FunctionTool(
    func=search_emails,
    #description="Use this tool to search for emails in the user's Gmail account. You MUST provide a search query string ('query') using Gmail search operators (like 'from:email@example.com', 'subject:report', 'is:unread'). You can optionally specify the maximum number of results ('max_results', default 10, max 50)." # Added emphasis
)

list_labels_tool = FunctionTool(
    func=list_labels,
    #description="Use this tool to list all available labels (folders) in the user's Gmail account. Takes no arguments." # Added clarification
)


# --- Define ADK Agents ---
# (Agent definitions remain unchanged)
search_agent = Agent(
    model='gemini-2.0-flash-lite', # Using a specific model name - Flash is good for this
    name='SearchAgent',
    instruction="You are a specialist in using Google Search to find information on the web. Use the provided 'google_search' tool effectively.",
    tools=[google_search],
)

# coding_agent = Agent(
    # model='gemini-2.0-flash-lite',
    # name='CodeAgent',
    # instruction="You are a specialist in writing and executing Python code snippets to perform calculations, data manipulation, or other programmatic tasks using the 'built_in_code_execution' tool.",
    # tools=[built_in_code_execution],
# )

gmail_send_agent = Agent(
    model='gemini-2.0-flash-lite', # Use Flash for consistency, should be capable
    name='GmailSendAgent',
    instruction="""You are a specialist agent for sending emails using Gmail via the 'send_email' tool.
    - Your ONLY capability is sending emails.
    - You MUST call the 'send_email' tool to perform the action.
    - CRITICAL: Ensure you extract and provide ALL required arguments for the 'send_email' tool: 'to' (recipient email), 'subject', and 'body'. Ask the user for clarification if any are missing.
    - If the tool returns an error related to authentication (e.g., 401, 403, token file missing, refresh failed), inform the user they might need to run the separate authentication script ('authenticate_gmail.py').
    - Confirm the result (success or non-auth error) back to the user based on the tool's response.""",
    tools=[send_email_tool], # Provide the tool
)

gmail_read_agent = Agent(
    model='gemini-2.0-flash-lite', # Use Flash for consistency
    name='GmailReadAgent',
    instruction="""You are a specialist agent for reading and searching emails and listing labels in Gmail.
    - Your capabilities are searching for emails using the 'search_emails' tool and listing labels using the 'list_labels' tool.
    - CRITICAL: When using 'search_emails', you MUST extract or determine the search query from the user's request and provide it as the 'query' argument to the tool. Ask the user for clarification if the query is unclear or missing. You can also optionally accept 'max_results'.
    - The 'list_labels' tool takes no arguments.
    - Present search results clearly, summarizing key information (sender, subject, snippet, date). Format the list nicely.
    - If any tool returns an error related to authentication (e.g., 401, 403, token file missing, refresh failed), inform the user they might need to run the separate authentication script ('authenticate_gmail.py').
    - Report any other non-auth errors encountered during search or listing.""",
    tools=[search_emails_tool, list_labels_tool], # Provide read/search/list tools
)

root_agent = Agent(
    name="RootAgent",
    model="gemini-2.0-flash-lite", # Use Pro for potentially better routing/understanding
    instruction="""You are the main assistant coordinating tasks between specialist agents. Your capabilities include:
    - Performing web searches by delegating to the SearchAgent.
    - Executing code by delegating to the CodeAgent.
    - Sending emails by delegating to the GmailSendAgent.
    - Reading/searching emails or listing Gmail labels by delegating to the GmailReadAgent.

    Determine the user's intent and delegate the task to the appropriate specialist agent.
    - If the user asks to send an email, gather necessary details (to, subject, body) if missing, then delegate to GmailSendAgent.
    - If the user asks to search emails or list labels, ensure you understand the request (especially the search query), then delegate to GmailReadAgent.
    - If the user asks for general web search, delegate to SearchAgent.
    - If the user asks for code execution, delegate to CodeAgent.

    IMPORTANT: When delegating, make sure you pass all necessary information extracted from the user's request to the specialist agent.
    Summarize the final results received from the specialist agents for the user.
    If a Gmail agent reports an authentication issue, relay that information clearly, suggesting the user run the 'authenticate_gmail.py' script.
    Do NOT attempt to perform the authentication yourself or call the Gmail tools directly.""",
    tools=[ # List AgentTools for delegation
        agent_tool.AgentTool(agent=search_agent),
        # agent_tool.AgentTool(agent=coding_agent),
        agent_tool.AgentTool(agent=gmail_send_agent), # Expose send agent as a tool
        agent_tool.AgentTool(agent=gmail_read_agent)  # Expose read agent as a tool
    ],
)

# --- Runner Setup ---
APP_NAME = "agents"
USER_ID = "user_default" # Consistent user ID helps with token persistence
SESSION_ID = "session_default" # Simple session management

session_service = InMemorySessionService()
session = session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=SESSION_ID)
runner = Runner(agent=root_agent, app_name=APP_NAME, session_service=session_service)

# --- Initial Authentication Check (Modified) ---
def check_initial_token():
    log.info("Checking for existing Google Authentication token...")
    if not os.path.exists(TOKEN_PICKLE_FILE):
         log.warning(f"Token file '{TOKEN_PICKLE_FILE}' not found.")
         log.warning(f"Gmail functions will fail until '{os.path.basename(TOKEN_PICKLE_FILE)}' is created.")
         log.warning("Please run the 'authenticate_gmail.py' script first.")
         return False
    else:
        try:
            # Attempt to load/refresh and build service to catch issues early
            get_gmail_service()
            log.info("Initial token check successful. Token loaded/refreshed and service built.")
            return True
        except (FileNotFoundError, ConnectionAbortedError, ConnectionError) as e:
            log.critical(f"CRITICAL: Failed initial token validation/refresh or service build: {e}")
            log.critical(f"Ensure '{os.path.basename(TOKEN_PICKLE_FILE)}' is valid or run 'authenticate_gmail.py' again.")
            return False # Indicate failure
        except Exception as e:
             log.critical(f"CRITICAL: Unexpected error during initial check: {e}", exc_info=True)
             return False

# --- Agent Interaction Loop ---
def run_conversation():
    print("\n--- Gmail Integrated Agent ---")
    print("Capabilities: Web Search, Code Execution, Send Email, Search Email, List Labels")
    print(f"NOTE: This script requires a valid '{os.path.basename(TOKEN_PICKLE_FILE)}' file.")
    print("Run 'authenticate_gmail.py' first if needed.")
    print("Type 'quit' to exit.")
    print("-" * 30)

    auth_ok = check_initial_token()
    if not auth_ok:
        print("\nWARNING: Initial Google token check failed or token file missing.")
        print(f"Gmail features WILL NOT WORK until a valid '{os.path.basename(TOKEN_PICKLE_FILE)}' exists.")
        print("Please run the 'authenticate_gmail.py' script and then restart this agent.")
        # Decide whether to exit or continue without Gmail functionality
        # For now, let's allow it to continue but warn user repeatedly
        # return # Uncomment to exit immediately if auth fails initially
        print("-" * 30)
    else:
        print("Initial token check successful. Gmail functions should be available.")
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
            content = adk_types.Content(role='user', parts=[adk_types.Part(text=query)])
            # Use the runner to handle the interaction
            events = runner.run(user_id=USER_ID, session_id=SESSION_ID, new_message=content)

            final_response_text = ""
            # Process events to find the final response and log function calls
            for event in events:
                log.debug(f"Runner Event: Type={event.type}, Role={event.content.role}") # Basic event logging

                # --- DEBUGGING: Log Function Calls ---
                if event.is_llm_response() and event.content.parts:
                     for part in event.content.parts:
                        if part.function_call:
                            fc = part.function_call
                            # Convert Struct to dict for easier logging/reading
                            args_dict = dict(fc.args) if fc.args else {}
                            log.info(f"DEBUG: Agent generated Function Call: Name='{fc.name}', Args={json.dumps(args_dict)}")
                # --- END DEBUGGING ---

                # Optional: Log function responses as well
                if event.is_function_response() and event.content.parts:
                     for part in event.content.parts:
                         if part.function_response:
                             fr = part.function_response
                             # Convert Struct to dict/primitive for logging
                             response_data = dict(fr.response) if fr.response else {}
                             log.info(f"DEBUG: Agent received Function Response: Name='{fr.name}', Response={json.dumps(response_data)}")


                if event.is_final_response():
                    if event.content.parts and event.content.parts[0].text:
                        final_response_text = event.content.parts[0].text
                    else:
                         final_response_text = "[Agent finished processing, but no text response was generated]"
                         log.warning(f"Final response event did not contain text: {event}")
                    break

            print("\nAgent Response:")
            print(final_response_text if final_response_text else "[No text content in final response]")

            # Add a check/warning if the response indicates an auth issue
            if "authenticate_gmail.py" in final_response_text:
                print("\n*** Agent reported an authentication issue. You may need to run 'authenticate_gmail.py' again. ***")

            print("-" * 30)

        except KeyboardInterrupt:
             print("\nExiting agent due to keyboard interrupt.")
             break
        except (FileNotFoundError, ConnectionAbortedError) as auth_err:
             # Catch critical auth errors that might occur outside the tool calls (e.g., during initial get_service)
             log.critical(f"A critical authentication error occurred: {auth_err}", exc_info=True)
             print(f"\nERROR: A critical authentication error occurred: {auth_err}")
             print(f"Please ensure '{os.path.basename(TOKEN_PICKLE_FILE)}' exists and is valid.")
             print("Run 'authenticate_gmail.py' to generate or refresh the token.")
             print("Exiting agent now.")
             break # Exit if fundamental auth fails
        except Exception as e:
             # Catch the specific TypeError we were addressing, plus others
             if isinstance(e, TypeError) and 'required positional argument' in str(e):
                 log.error(f"Caught TypeError likely related to missing tool argument: {e}", exc_info=True)
                 print(f"\nERROR: The agent likely failed to provide a required argument to a tool.")
                 print("Check the DEBUG logs above for 'Agent generated Function Call' to see the arguments.")
                 print("You might need to adjust the agent's instructions or rephrase your request.")
             else:
                 log.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
                 print(f"\nERROR: An unexpected issue occurred. Please check the logs. Details: {e}")
             print("-" * 30)
             # Continue loop or break depending on desired robustness
             # break

# --- Main Execution ---
if __name__ == "__main__":
    run_conversation()
