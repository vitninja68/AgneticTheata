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
    built_in_code_execution,
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
TOKEN_PICKLE_FILE = os.path.join(SCRIPT_DIR, 'token.pickle') # Expects this file to exist

# --- Logging Setup ---
# Increased logging level for ADK/Google API client libraries for more detail
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s')
log = logging.getLogger(__name__)
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR) # Quieten discovery cache logs
logging.getLogger('google.auth.transport.requests').setLevel(logging.WARNING) # Quieten routine token refresh logs unless warning

# --- Google Authentication (No Global Service) ---

def load_or_refresh_credentials():
    """
    Loads credentials from token.pickle. If expired, attempts to refresh.
    Does NOT initiate a new OAuth flow. Assumes token.pickle exists.

    Returns:
        A valid Credentials object.
    Raises:
        FileNotFoundError: If token.pickle is not found.
        ConnectionAbortedError: If credentials cannot be loaded or refreshed.
    """
    creds = None
    if not os.path.exists(TOKEN_PICKLE_FILE):
        log.critical(f"CRITICAL ERROR: Authentication token file '{TOKEN_PICKLE_FILE}' not found.")
        log.critical("Please run the 'authenticate_gmail.py' script first to generate the token.")
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
                with open(TOKEN_PICKLE_FILE, 'wb') as token:
                    pickle.dump(creds, token)
                log.info(f"Refreshed credentials saved back to {TOKEN_PICKLE_FILE}")
            except Exception as e:
                log.error(f"Failed to refresh token: {e}", exc_info=True)
                log.critical("Automatic token refresh failed. The refresh token might be invalid or revoked.")
                log.critical(f"Please delete '{TOKEN_PICKLE_FILE}' and run 'authenticate_gmail.py' again.")
                raise ConnectionAbortedError(f"Token refresh failed: {e}. Run authentication script again.") from e
        else:
            log.critical("Loaded credentials are invalid and cannot be refreshed.")
            log.critical(f"Please delete '{TOKEN_PICKLE_FILE}' and run 'authenticate_gmail.py' again.")
            raise ConnectionAbortedError("Invalid credentials in token file and cannot refresh. Run authentication script again.")

    if not creds or not creds.valid:
         msg = "Could not obtain valid Google credentials from token file or refresh process."
         log.error(msg)
         raise ConnectionAbortedError(msg + " Run authentication script again.")

    return creds

def get_gmail_service():
    """
    Creates and returns a new authenticated Gmail API service object.
    This function is called by each tool, ensuring a fresh service object for every operation.

    Returns:
        An authenticated Gmail service object.
    Raises:
        ConnectionError: If the service cannot be built.
        Other exceptions from load_or_refresh_credentials.
    """
    log.info("Attempting to build new Gmail service object...")
    try:
        # Step 1: Get valid credentials. This will raise an error if auth fails.
        credentials = load_or_refresh_credentials()

        # Step 2: Build the service with the valid credentials.
        # Disable cache for robustness, as we are creating a new service each time.
        service = build('gmail', 'v1', credentials=credentials, cache_discovery=False)
        log.info("New Gmail service object built successfully.")
        return service
    except HttpError as error:
        log.error(f'An HTTP error occurred building the Gmail service: {error}', exc_info=True)
        raise ConnectionError(f'Failed to build Gmail service (HTTPError): {error}') from error
    except Exception as e:
        log.error(f'An unexpected error occurred building the Gmail service: {e}', exc_info=True)
        # Re-raise exceptions from load_or_refresh_credentials or other unexpected errors
        raise

# --- Gmail API Functions (Now create their own service) ---

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
        validation = validate_email(to, check_deliverability=False)
        to_email = validation.normalized
    except EmailNotValidError as e:
        log.warning(f"Invalid recipient email address format: {to}. Error: {e}")
        return f"Error: Invalid recipient email address format provided ('{to}'). Please provide a valid email address. Details: {e}"

    try:
        # Each call gets a fresh, authenticated service object
        service = get_gmail_service()

        message = MIMEText(body)
        message['to'] = to_email
        message['subject'] = subject
        message['from'] = 'me'

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
        if error.resp.status in [401, 403]:
             log.error("Received 401/403 error. Authentication token might be invalid or revoked.")
             return f"Error: Failed to send email due to an Authentication/Authorization error ({error.resp.status}). Please try running the 'authenticate_gmail.py' script again. Details: {error_details}"
        return f"Error: Failed to send email due to a Google API error. Details: {error_details}"
    except (FileNotFoundError, ConnectionError, ConnectionAbortedError) as e:
         log.error(f"Authentication/Connection error during send: {e}")
         if isinstance(e, FileNotFoundError):
             return f"Error: Authentication token file not found. Please run 'authenticate_gmail.py' first. Details: {e}"
         elif isinstance(e, ConnectionAbortedError):
             return f"Error: Authentication failed (invalid token or refresh failed). Please run 'authenticate_gmail.py' again. Details: {e}"
         else:
             return f"Error: Failed to connect to Gmail service. Check network or logs. Details: {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred while sending email: {e}', exc_info=True)
        return f"Error: An unexpected error occurred while trying to send the email. Details: {e}"

def search_emails(query: str, max_results: int = 10) -> list[dict] | str:
    """
    Searches for emails in the authenticated user's Gmail account using Gmail query syntax.

    Args:
        query: The search query string (e.g., 'from:boss@example.com subject:urgent'). REQUIRED.
        max_results: Maximum number of email messages to return. Defaults to 10, max 50.

    Returns:
        A list of dictionaries with email details, or a string message on error/no results.
    """
    if not query or not isinstance(query, str) or not query.strip():
        log.error("search_emails called without a valid query string.")
        return "Error: The search_emails tool was called without providing a search query. Please specify what you want to search for."

    log.info(f"Executing search_emails with query: '{query}' and max_results: {max_results}")

    try:
        # Each call gets a fresh, authenticated service object
        service = get_gmail_service()

        try:
            max_results = int(max_results)
            if max_results <= 0:
                 max_results = 10
            if max_results > 50:
                log.warning("max_results capped at 50.")
                max_results = 50
        except (ValueError, TypeError):
             max_results = 10

        result = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
        messages = result.get('messages', [])

        if not messages:
            log.info(f"No emails found for query: {query}")
            return f"No emails found matching your query: '{query}'"

        email_details = []
        log.info(f"Found {len(messages)} potential messages. Fetching details (up to {max_results})...")

        for i, msg_summary in enumerate(messages):
            if i >= max_results:
                break
            msg_id = msg_summary.get('id')
            if not msg_id: continue
            try:
                msg = service.users().messages().get(
                    userId='me',
                    id=msg_id,
                    format='metadata',
                    metadataHeaders=['subject', 'from', 'date']
                ).execute()
                headers = {h['name'].lower(): h['value'] for h in msg.get('payload', {}).get('headers', [])}
                details = {
                    "id": msg.get('id'),
                    "threadId": msg.get('threadId'),
                    "snippet": msg.get('snippet', '').strip(),
                    "subject": headers.get('subject', 'N/A'),
                    "from": headers.get('from', 'N/A'),
                    "date": headers.get('date', 'N/A')
                }
                email_details.append(details)
            except HttpError as error:
                 log.error(f"Could not retrieve details for message ID {msg_id}: {error}")
                 error_reason = getattr(error, '_get_reason', lambda: 'Unknown reason')()
                 email_details.append({"id": msg_id, "error": f"Could not retrieve details: {error.resp.status} {error_reason}"})
                 if error.resp.status in [401, 403]:
                     return f"Error: Authentication/Authorization error ({error.resp.status}) while fetching email details. Please try running 'authenticate_gmail.py' again."
            except Exception as e:
                 log.error(f"Unexpected error retrieving details for message ID {msg_id}: {e}", exc_info=True)
                 email_details.append({"id": msg_id, "error": f"Unexpected error retrieving details: {e}"})

        log.info(f"Successfully retrieved details for {len(email_details)} emails.")
        return email_details

    except HttpError as error:
        log.error(f'An HTTP error occurred during email search list: {error}', exc_info=True)
        error_details = "Unknown Google API error"
        try:
            content = getattr(error, 'content', b'{}')
            error_json = json.loads(content.decode('utf-8'))
            error_details = error_json.get('error', {}).get('message', str(error))
        except Exception:
             error_details = str(error)
        if error.resp.status in [401, 403]:
             log.error("Received 401/403 error. Authentication token might be invalid.")
             return f"Error: Failed to search emails due to an Authentication/Authorization error ({error.resp.status}). Please try running 'authenticate_gmail.py' again. Details: {error_details}"
        return f"Error: Failed to search emails due to a Google API error. Details: {error_details}"
    except (FileNotFoundError, ConnectionError, ConnectionAbortedError) as e:
         log.error(f"Authentication/Connection error during search: {e}")
         if isinstance(e, FileNotFoundError):
             return f"Error: Authentication token file not found. Please run 'authenticate_gmail.py' first. Details: {e}"
         elif isinstance(e, ConnectionAbortedError):
             return f"Error: Authentication failed (invalid token or refresh failed). Please run 'authenticate_gmail.py' again. Details: {e}"
         else:
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
        # Each call gets a fresh, authenticated service object
        service = get_gmail_service()

        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        if not labels:
            log.info("No labels found for the user.")
            return "No labels found in your Gmail account."

        label_details = [{"id": lbl['id'], "name": lbl['name'], "type": lbl.get('type', 'user')} for lbl in labels]
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
             error_details = str(error)
        if error.resp.status in [401, 403]:
             return f"Error: Failed to list labels due to an Authentication/Authorization error ({error.resp.status}). Please try running 'authenticate_gmail.py' again. Details: {error_details}"
        return f"Error: Failed to list labels due to a Google API error. Details: {error_details}"
    except (FileNotFoundError, ConnectionError, ConnectionAbortedError) as e:
         log.error(f"Authentication/Connection error during list labels: {e}")
         if isinstance(e, FileNotFoundError):
             return f"Error: Authentication token file not found. Please run 'authenticate_gmail.py' first. Details: {e}"
         elif isinstance(e, ConnectionAbortedError):
             return f"Error: Authentication failed (invalid token or refresh failed). Please run 'authenticate_gmail.py' again. Details: {e}"
         else:
             return f"Error: Failed to connect to Gmail service. Check network or logs. Details: {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred while listing labels: {e}', exc_info=True)
        return f"Error: An unexpected error occurred while trying to list labels. Details: {e}"

# --- Create ADK FunctionTools ---
send_email_tool = FunctionTool(
    func=send_email,
)
search_emails_tool = FunctionTool(
    func=search_emails,
)
list_labels_tool = FunctionTool(
    func=list_labels,
)

# --- Define ADK Agents ---
search_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='SearchAgent',
    instruction="You are a specialist in using Google Search to find information on the web. Use the provided 'google_search' tool effectively.",
    tools=[google_search],
)

coding_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='CodeAgent',
    instruction="You are a specialist in writing and executing Python code snippets to perform calculations, data manipulation, or other programmatic tasks using the 'built_in_code_execution' tool.",
    tools=[built_in_code_execution],
)

gmail_send_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='GmailSendAgent',
    instruction="""You are a specialist agent for sending emails using Gmail via the 'send_email' tool.
    - Your ONLY capability is sending emails.
    - You MUST call the 'send_email' tool to perform the action.
    - CRITICAL: Ensure you extract and provide ALL required arguments for the 'send_email' tool: 'to' (recipient email), 'subject', and 'body'. Ask the user for clarification if any are missing.
    - If the tool returns an error related to authentication (e.g., 401, 403, token file missing, refresh failed), inform the user they might need to run the separate authentication script ('authenticate_gmail.py').
    - Confirm the result (success or non-auth error) back to the user based on the tool's response.""",
    tools=[send_email_tool],
)

gmail_read_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='GmailReadAgent',
    instruction="""You are a specialist agent for reading and searching emails and listing labels in Gmail.
    - Your capabilities are searching for emails using the 'search_emails' tool and listing labels using the 'list_labels' tool.
    - CRITICAL: When using 'search_emails', you MUST extract or determine the search query from the user's request and provide it as the 'query' argument to the tool. Ask the user for clarification if the query is unclear or missing. You can also optionally accept 'max_results'.
    - The 'list_labels' tool takes no arguments.
    - Present search results clearly, summarizing key information (sender, subject, snippet, date). Format the list nicely.
    - If any tool returns an error related to authentication (e.g., 401, 403, token file missing, refresh failed), inform the user they might need to run the separate authentication script ('authenticate_gmail.py').
    - Report any other non-auth errors encountered during search or listing.""",
    tools=[search_emails_tool, list_labels_tool],
)

root_agent = Agent(
    name="RootAgent",
    model="gemini-2.0-flash-lite",
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
    tools=[
        agent_tool.AgentTool(agent=search_agent),
        agent_tool.AgentTool(agent=coding_agent),
        agent_tool.AgentTool(agent=gmail_send_agent),
        agent_tool.AgentTool(agent=gmail_read_agent)
    ],
)

# --- Runner Setup ---
APP_NAME = "agents"
USER_ID = "user_default"
SESSION_ID = "session_default"

session_service = InMemorySessionService()
session = session_service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=SESSION_ID)
runner = Runner(agent=root_agent, app_name=APP_NAME, session_service=session_service)

# --- Initial Startup Check ---
def check_for_token_file_on_startup():
    """Checks for the token file at startup and warns the user if it's missing."""
    log.info("Checking for existing Google Authentication token file...")
    if not os.path.exists(TOKEN_PICKLE_FILE):
         log.warning(f"Token file '{TOKEN_PICKLE_FILE}' not found.")
         log.warning("Gmail functions will fail until this file is created.")
         log.warning("Please run the 'authenticate_gmail.py' script in a separate terminal.")
         return False
    else:
        log.info(f"Token file '{TOKEN_PICKLE_FILE}' found. Gmail functions should be available.")
        return True

# --- Agent Interaction Loop ---
def run_conversation():
    print("\n--- Gmail Integrated Agent ---")
    print("Capabilities: Web Search, Code Execution, Send Email, Search Email, List Labels")
    print(f"NOTE: This script requires a valid '{os.path.basename(TOKEN_PICKLE_FILE)}' file.")
    print("Run 'authenticate_gmail.py' first if needed.")
    print("-" * 30)

    auth_file_exists = check_for_token_file_on_startup()
    if not auth_file_exists:
        print("\nWARNING: Google token file is missing.")
        print(f"Gmail features WILL NOT WORK until a valid '{os.path.basename(TOKEN_PICKLE_FILE)}' is created.")
        print("Please run the 'authenticate_gmail.py' script and then restart this agent.")
        print("-" * 30)
    else:
        print("Initial token file check successful. Gmail functions are enabled.")
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
            events = runner.run(user_id=USER_ID, session_id=SESSION_ID, new_message=content)

            final_response_text = ""
            for event in events:
                log.debug(f"Runner Event: Type={event.type}, Role={event.content.role}")

                if event.is_llm_response() and event.content.parts:
                     for part in event.content.parts:
                        if part.function_call:
                            fc = part.function_call
                            args_dict = dict(fc.args) if fc.args else {}
                            log.info(f"DEBUG: Agent generated Function Call: Name='{fc.name}', Args={json.dumps(args_dict)}")

                if event.is_function_response() and event.content.parts:
                     for part in event.content.parts:
                         if part.function_response:
                             fr = part.function_response
                             response_data = dict(fr.response) if fr.response else {}
                             log.info(f"DEBUG: Agent received Function Response: Name='{fr.name}', Response={json.dumps(response_data)}")

                if event.is_final_response():
                    final_response_text = "".join(part.text for part in event.content.parts if part.text)
                    if not final_response_text:
                         final_response_text = "[Agent finished processing, but no text response was generated]"
                         log.warning(f"Final response event did not contain text: {event}")
                    break

            print("\nAgent Response:")
            print(final_response_text)

            if "authenticate_gmail.py" in final_response_text:
                print("\n*** Agent reported an authentication issue. You may need to run 'authenticate_gmail.py' again. ***")

            print("-" * 30)

        except KeyboardInterrupt:
             print("\nExiting agent due to keyboard interrupt.")
             break
        except Exception as e:
             if isinstance(e, TypeError) and 'required positional argument' in str(e):
                 log.error(f"Caught TypeError likely related to missing tool argument: {e}", exc_info=True)
                 print("\nERROR: The agent likely failed to provide a required argument to a tool.")
                 print("Check the DEBUG logs for 'Agent generated Function Call' to see the arguments provided.")
             else:
                 log.error(f"An unexpected error occurred in the main loop: {e}", exc_info=True)
                 print(f"\nERROR: An unexpected issue occurred. Please check the logs. Details: {e}")
             print("-" * 30)

# --- Main Execution ---
if __name__ == "__main__":
    run_conversation()