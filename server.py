# server.py

import asyncio
import os
import base64
import pickle
import logging # Use logging for better output control
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError # For basic email validation

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from fastmcp import FastMCP

# --- Configuration ---
# If modifying these scopes, delete the file token.pickle.
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',          # To send emails
    'https://www.googleapis.com/auth/gmail.readonly'       # To read/search emails, list labels, get messages etc.
    # Add more scopes if needed (e.g., modify for trash/drafts):
    # 'https://www.googleapis.com/auth/gmail.modify'
]
CREDENTIALS_FILE = 'credentials.json' # Downloaded from Google Cloud Console
TOKEN_PICKLE_FILE = 'token.pickle' # Stores the user's access and refresh tokens

# !!! IMPORTANT: Define a FIXED port for the OAuth redirect URI !!!
OAUTH_REDIRECT_PORT = 8081 # Choose a port (e.g., 8081, 8888) that's likely free
OAUTH_REDIRECT_URI = f'http://localhost:{OAUTH_REDIRECT_PORT}/'

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Global Variables ---
mcp = FastMCP("Gmail Functions Server")
gmail_service = None # Will hold the authenticated Gmail service object

# --- Google Authentication ---
def authenticate_google():
    """
    Authenticates with Google using OAuth 2.0.
    Handles the token flow using a FIXED redirect URI and returns authenticated credentials.
    Creates or refreshes token.pickle.
    """
    global gmail_service # Allow modification of the global service object
    creds = None
    # The file token.pickle stores the user's access and refresh tokens.
    if os.path.exists(TOKEN_PICKLE_FILE):
        try:
            with open(TOKEN_PICKLE_FILE, 'rb') as token:
                creds = pickle.load(token)
            log.info("Loaded credentials from token.pickle")
        except (EOFError, pickle.UnpicklingError, FileNotFoundError, Exception) as e:
             log.warning(f"Could not load token.pickle: {e}. Will attempt re-authentication.")
             creds = None # Force re-authentication if file is corrupted, empty or other error


    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                log.info("Refreshing expired credentials...")
                creds.refresh(Request())
                log.info("Credentials refreshed successfully.")
                # Update the global service object if it exists
                if gmail_service:
                    gmail_service = build('gmail', 'v1', credentials=creds)
            except Exception as e:
                log.error(f"Failed to refresh token: {e}. Need to re-authenticate.")
                # Delete potentially corrupted token file if refresh fails hard
                if os.path.exists(TOKEN_PICKLE_FILE):
                     try:
                         os.remove(TOKEN_PICKLE_FILE)
                         log.info("Removed potentially invalid token.pickle file.")
                     except OSError as ose:
                         log.error(f"Error removing token.pickle: {ose}")
                creds = None # Force re-authentication if refresh fails
                gmail_service = None # Invalidate the service

        # Only run the flow if we still don't have valid creds
        if not creds or not creds.valid:
            if not os.path.exists(CREDENTIALS_FILE):
                log.critical(f"CRITICAL ERROR: credentials.json not found at '{os.path.abspath(CREDENTIALS_FILE)}'. Download it from Google Cloud Console.")
                return None
            try:
                log.info("No valid credentials found or refresh failed. Starting authentication flow...")
                log.info(f"Ensure the redirect URI '{OAUTH_REDIRECT_URI}' is registered in your Google Cloud Console OAuth Client ID settings.")
                # Use CREDENTIALS_FILE for the flow
                flow = InstalledAppFlow.from_client_secrets_file(
                    CREDENTIALS_FILE, SCOPES)

                # *** Use the FIXED port here ***
                creds = flow.run_local_server(port=OAUTH_REDIRECT_PORT)
                log.info("Authentication successful.")
            except FileNotFoundError:
                 log.critical(f"CRITICAL ERROR: credentials.json not found at '{os.path.abspath(CREDENTIALS_FILE)}'.")
                 return None
            except Exception as e:
                log.error(f"An error occurred during the authentication flow: {e}", exc_info=True) # Log traceback
                return None

        # Save the credentials for the next run
        try:
            with open(TOKEN_PICKLE_FILE, 'wb') as token:
                pickle.dump(creds, token)
            log.info(f"Credentials saved to {TOKEN_PICKLE_FILE}")
        except Exception as e:
            log.error(f"Error saving credentials to {TOKEN_PICKLE_FILE}: {e}")

    if not creds or not creds.valid:
         log.error("Could not obtain valid credentials after authentication attempt.")
         return None

    return creds

def get_gmail_service():
    """Builds and returns an authenticated Gmail API service object. Handles re-authentication."""
    global gmail_service
    # Check if service exists and its credentials are valid
    if gmail_service and gmail_service._http.credentials and gmail_service._http.credentials.valid:
        return gmail_service
    
    # If service exists but creds expired, try refreshing (handled within authenticate_google now)
    # If service doesn't exist or creds invalid/expired and couldn't refresh, authenticate fully.
    log.info("Gmail service not available or credentials invalid/expired. Attempting authentication...")
    credentials = authenticate_google() # This handles loading, refreshing, or full flow

    if not credentials:
        log.error("Failed to obtain valid Google credentials.")
        # Raise an error that can be caught by the tool function
        raise ConnectionError("Failed to authenticate with Google. Cannot get Gmail service.")

    try:
        # Build or rebuild the service with the valid credentials
        gmail_service = build('gmail', 'v1', credentials=credentials)
        log.info("Gmail service built/rebuilt successfully.")
        return gmail_service
    except HttpError as error:
        log.error(f'An HTTP error occurred building the Gmail service: {error}', exc_info=True)
        raise ConnectionError(f'Failed to build Gmail service (HTTPError): {error}') from error
    except Exception as e:
        log.error(f'An unexpected error occurred building the Gmail service: {e}', exc_info=True)
        raise ConnectionError(f'Unexpected error building Gmail service: {e}') from e


# --- FastMCP Tools ---

@mcp.tool()
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
        # Validate email address format
        validation = validate_email(to, check_deliverability=False) # Basic syntax check
        to_email = validation.normalized
    except EmailNotValidError as e:
        log.warning(f"Invalid recipient email address format: {to}. Error: {e}")
        return f"Error: Invalid recipient email address format - {e}"

    try:
        service = get_gmail_service() # Handles auth check/refresh/flow

        message = MIMEText(body)
        message['to'] = to_email
        message['subject'] = subject
        # 'me' is a special value indicating the authenticated user
        message['from'] = 'me'

        # Encode message to base64url format
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': raw_message}

        # Send the email
        sent_message = service.users().messages().send(userId='me', body=create_message).execute()
        log.info(f"Email sent successfully via API. Message ID: {sent_message['id']}")
        return f"Email sent successfully to {to_email}. Message ID: {sent_message['id']}"

    except HttpError as error:
        log.error(f'An HTTP error occurred while sending email: {error}', exc_info=True)
        error_details = "Unknown error"
        try:
            # Attempt to parse more detailed error from Google's response
            content = getattr(error, 'content', b'{}')
            error_json = json.loads(content.decode('utf-8'))
            error_details = error_json.get('error', {}).get('message', str(error))
        except Exception:
             error_details = str(error) # Fallback
        return f"Error sending email: {error_details}"
    except ConnectionError as e:
         # Error from get_gmail_service() during authentication
         log.error(f"Connection/Authentication error: {e}")
         return f"Error: Failed to connect or authenticate with Gmail service. Please check server logs and ensure authentication is complete. Details: {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred while sending email: {e}', exc_info=True)
        return f"Error: An unexpected error occurred - {e}"

@mcp.tool()
def search_emails(query: str, max_results: int = 10) -> list[dict] | str:
    """
    Searches for emails in the authenticated user's Gmail account.

    Args:
        query: The search query string (uses Gmail search operators, e.g., 'from:example@domain.com subject:Urgent').
        max_results: The maximum number of email threads to return. Defaults to 10, max 50.

    Returns:
        A list of dictionaries, each containing details of a found email message (id, threadId, snippet, subject, from, date),
        or an error message string if the search fails or no results are found.
    """
    try:
        service = get_gmail_service() # Handles auth check/refresh/flow

        if not isinstance(max_results, int) or max_results <= 0:
             log.warning(f"Invalid max_results value '{max_results}', defaulting to 10.")
             max_results = 10
        if max_results > 50: # Limit max results to avoid excessive API calls/rate limits
            max_results = 50
            log.warning("max_results capped at 50.")

        # Call the Gmail API to list messages matching the query
        result = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=max_results
        ).execute()

        messages = result.get('messages', [])

        if not messages:
            log.info(f"No emails found for query: {query}")
            return f"No emails found matching your query: '{query}'"

        email_details = []
        log.info(f"Found {len(messages)} potential messages for query '{query}'. Fetching details...")

        # Consider using batch requests for > 5-10 messages for better performance
        # For simplicity, using a loop here.
        for msg_summary in messages:
            msg_id = msg_summary.get('id')
            if not msg_id:
                log.warning("Found a message summary without an ID, skipping.")
                continue
            try:
                # Fetch specific metadata fields for efficiency
                msg = service.users().messages().get(
                    userId='me',
                    id=msg_id,
                    format='metadata',
                    metadataHeaders=['subject', 'from', 'date'] # Request only needed headers
                ).execute()

                # Extract headers safely
                headers_list = msg.get('payload', {}).get('headers', [])
                headers_dict = {h['name'].lower(): h['value'] for h in headers_list if 'name' in h and 'value' in h}

                details = {
                    "id": msg.get('id'),
                    "threadId": msg.get('threadId'),
                    "snippet": msg.get('snippet', '').strip(), # Clean up snippet
                    "subject": headers_dict.get('subject', 'N/A'),
                    "from": headers_dict.get('from', 'N/A'),
                    "date": headers_dict.get('date', 'N/A')
                }
                email_details.append(details)
            except HttpError as error:
                 log.error(f"Could not retrieve details for message ID {msg_id}: {error}")
                 # Optionally append an error marker or just skip
                 email_details.append({"id": msg_id, "error": f"Could not retrieve details: {error.resp.status} {error._get_reason()}"})
            except Exception as e:
                 log.error(f"Unexpected error retrieving details for message ID {msg_id}: {e}", exc_info=True)
                 email_details.append({"id": msg_id, "error": f"Unexpected error retrieving details: {e}"})


        log.info(f"Successfully retrieved details for {len(email_details)} emails matching query '{query}'.")
        return email_details

    except HttpError as error:
        log.error(f'An HTTP error occurred during email search: {error}', exc_info=True)
        error_details = "Unknown error"
        try:
            content = getattr(error, 'content', b'{}')
            error_json = json.loads(content.decode('utf-8'))
            error_details = error_json.get('error', {}).get('message', str(error))
        except Exception:
             error_details = str(error) # Fallback
        return f"Error searching emails: {error_details}"
    except ConnectionError as e:
         # Error from get_gmail_service() during authentication
         log.error(f"Connection/Authentication error during search: {e}")
         return f"Error: Failed to connect or authenticate with Gmail service. Please check server logs and ensure authentication is complete. Details: {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred during email search: {e}', exc_info=True)
        return f"Error: An unexpected error occurred - {e}"

# --- Add other Gmail tools here (list_labels, get_message_body, etc.) ---
# Remember to request appropriate SCOPES if needed (e.g., gmail.modify for trash)

@mcp.tool()
def list_labels() -> list[dict] | str:
    """
    Lists all labels in the authenticated user's Gmail account.

    Returns:
        A list of dictionaries, each containing label details (id, name, type),
        or an error message string on failure.
    """
    try:
        service = get_gmail_service() # Handles auth

        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        if not labels:
            log.info("No labels found for the user.")
            return "No labels found."

        label_details = [{"id": lbl['id'], "name": lbl['name'], "type": lbl.get('type', 'user')} for lbl in labels]
        log.info(f"Retrieved {len(label_details)} labels.")
        return label_details

    except HttpError as error:
        log.error(f'An HTTP error occurred while listing labels: {error}', exc_info=True)
        # Extract error details similarly to other functions
        return f"Error listing labels: {error}"
    except ConnectionError as e:
        log.error(f"Connection/Authentication error: {e}")
        return f"Error: Failed to connect or authenticate with Gmail service. {e}"
    except Exception as e:
        log.error(f'An unexpected error occurred while listing labels: {e}', exc_info=True)
        return f"Error: An unexpected error occurred - {e}"

# --- Server Execution ---
async def main():
    log.info("Attempting initial Google Authentication check...")
    try:
       # Try to authenticate and build the service once at startup
       # This will trigger the OAuth flow if token.pickle doesn't exist or is invalid/expired
       get_gmail_service()
       log.info("Initial authentication check successful or existing token loaded/refreshed.")
    except ConnectionError as e:
        # Log critical error but allow server to start. Tools will fail until fixed.
        log.critical(f"CRITICAL: Initial Google Authentication failed: {e}")
        log.critical("The server will start, but Gmail tools will likely fail.")
        log.critical(f"Ensure '{CREDENTIALS_FILE}' is present and valid.")
        log.critical(f"Ensure the redirect URI '{OAUTH_REDIRECT_URI}' is registered in Google Cloud Console.")
        log.critical("Complete the consent flow in the browser when prompted.")
    except Exception as e:
        log.error(f"Unexpected error during initial authentication setup: {e}", exc_info=True)
        log.warning("Continuing server startup, but Gmail tools may fail.")

    host = "0.0.0.0" # Listen on all available network interfaces
    port = 8080      # Port for the FastMCP server
    log.info(f"Starting FastMCP server on http://{host}:{port}")
    log.info("Ensure the ADK client (adk_client.py) is configured to connect to this address.")
    log.info("Press Ctrl+C to stop the server.")
    await mcp.run_sse_async(host=host, port=port)

if __name__ == "__main__":
    # Add list_labels to the MCP instance explicitly if needed (though @mcp.tool should handle it)
    # mcp.tools["list_labels"] = list_labels 
    # mcp.tools["search_emails"] = search_emails
    # mcp.tools["send_email"] = send_email
    
    # Ensure credentials file path is correct relative to script execution
    script_dir = os.path.dirname(os.path.abspath(__file__))
    CREDENTIALS_FILE = os.path.join(script_dir, CREDENTIALS_FILE)
    TOKEN_PICKLE_FILE = os.path.join(script_dir, TOKEN_PICKLE_FILE)
    
    asyncio.run(main())