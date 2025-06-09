# FILE: agents/agent.py
# -*- coding: utf-8 -*-
import os
import base64
import logging
import json
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.tools import (
    FunctionTool,
    ToolContext,
    agent_tool,
    google_search,
    built_in_code_execution,
)
from google.adk.sessions import InMemorySessionService
from google.genai import types as adk_types

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s')
log = logging.getLogger(__name__)
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)
logging.getLogger('google.auth.transport.requests').setLevel(logging.WARNING)

# --- Google Authentication via Session State ---
def get_gmail_service(tool_context: ToolContext):
    """
    Builds and returns an authenticated Gmail API service object using credentials
    found in the ADK session state. This is the primary way to get the service.
    """
    session_state = tool_context.state
    if not session_state:
        raise ConnectionAbortedError("ADK session state is empty. Cannot find credentials.")

    token_info = session_state.get("google_oauth_token")
    if not token_info or not isinstance(token_info, dict):
        log.critical("'google_oauth_token' not found or is not a dictionary in session state.")
        log.critical("Ensure the backend is correctly injecting the token into the ADK session state.")
        raise ConnectionAbortedError("Google OAuth token not found in session state. Please authenticate via the main application.")

    try:
        creds = Credentials.from_authorized_user_info(info=token_info)
    except (KeyError, ValueError) as e:
        log.error(f"Failed to create Credentials object from session state token info: {e}", exc_info=True)
        log.error(f"Received token info from state: {token_info}")
        raise ConnectionAbortedError(f"Token information in session state is malformed or incomplete. Error: {e}")

    try:
        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
        log.info("Gmail service built successfully using credentials from session state.")
        return service
    except HttpError as error:
        log.error(f'An HTTP error occurred building the Gmail service: {error}', exc_info=True)
        raise ConnectionError(f'Failed to build Gmail service (HTTPError): {error}') from error
    except Exception as e:
        log.error(f'An unexpected error occurred building the Gmail service: {e}', exc_info=True)
        raise ConnectionError(f'Unexpected error building Gmail service: {e}') from e

# --- Gmail API Functions (Modified to accept ToolContext) ---

def send_email(to: str, subject: str, body: str, tool_context: ToolContext) -> str:
    """Sends an email using the authenticated Gmail account for the current session."""
    try:
        validation = validate_email(to, check_deliverability=False)
        to_email = validation.normalized
    except EmailNotValidError as e:
        return f"Error: Invalid recipient email address format: {e}"

    try:
        service = get_gmail_service(tool_context)
        message = MIMEText(body)
        message['to'] = to_email
        message['subject'] = subject
        message['from'] = 'me'
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'raw': raw_message}

        sent_message = service.users().messages().send(userId='me', body=create_message).execute()
        return f"Success! Email sent to {to_email}. Message ID: {sent_message['id']}"
    except (ConnectionAbortedError, ConnectionError) as e:
         return f"Error: Failed to send email due to an Authentication/Connection issue. Please re-authenticate via the web app. Details: {e}"
    except HttpError as error:
        error_details = f"Google API Error {error.resp.status}: {error._get_reason()}"
        return f"Error: Failed to send email due to a Google API error. Details: {error_details}"
    except Exception as e:
        return f"Error: An unexpected error occurred. Details: {e}"

def search_emails(query: str, tool_context: ToolContext, max_results: int = 10) -> list[dict] | str:
    """Searches for emails in the authenticated user's Gmail account."""
    if not query or not isinstance(query, str) or not query.strip():
        return "Error: A search query must be provided."

    try:
        service = get_gmail_service(tool_context)
        max_res = int(max_results) if 0 < int(max_results) <= 50 else 10
        result = service.users().messages().list(userId='me', q=query, maxResults=max_res).execute()
        messages = result.get('messages', [])

        if not messages:
            return f"No emails found matching your query: '{query}'"

        email_details = []
        for msg_summary in messages:
            msg = service.users().messages().get(userId='me', id=msg_summary['id'], format='metadata', metadataHeaders=['subject', 'from', 'date']).execute()
            headers = {h['name'].lower(): h['value'] for h in msg['payload']['headers']}
            email_details.append({
                "id": msg['id'],
                "threadId": msg['threadId'],
                "snippet": msg['snippet'].strip(),
                "subject": headers.get('subject', 'N/A'),
                "from": headers.get('from', 'N/A'),
                "date": headers.get('date', 'N/A'),
            })
        return email_details
    except (ConnectionAbortedError, ConnectionError) as e:
         return f"Error: Failed to search email due to an Authentication/Connection issue. Please re-authenticate via the web app. Details: {e}"
    except HttpError as error:
        error_details = f"Google API Error {error.resp.status}: {error._get_reason()}"
        return f"Error: Failed to search email due to a Google API error. Details: {error_details}"
    except Exception as e:
        return f"Error: An unexpected error occurred during email search. Details: {e}"

def list_labels(tool_context: ToolContext) -> list[dict] | str:
    """Lists all labels (folders) in the authenticated user's Gmail account."""
    log.info("Executing list_labels...")
    try:
        service = get_gmail_service(tool_context)
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        if not labels:
            return "No labels found in your Gmail account."
        return [{"id": lbl['id'], "name": lbl['name'], "type": lbl.get('type', 'user')} for lbl in labels]
    except (ConnectionAbortedError, ConnectionError) as e:
         return f"Error: Failed to list labels. Please re-authenticate via the web app. Details: {e}"
    except HttpError as error:
        error_details = f"Google API Error {error.resp.status}: {error._get_reason()}"
        return f"Error: Failed to list labels due to a Google API error. Details: {error_details}"
    except Exception as e:
        return f"Error: An unexpected error occurred while listing labels. Details: {e}"

# --- Create ADK FunctionTools ---
send_email_tool = FunctionTool(func=send_email)
search_emails_tool = FunctionTool(func=search_emails)
list_labels_tool = FunctionTool(func=list_labels)

# --- Agent Definitions ---
search_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='SearchAgent',
    instruction="You are a specialist in using Google Search to find information on the web. Use the provided 'google_search' tool effectively.",
    tools=[google_search],
)

coding_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='CodeAgent',
    instruction="You are a specialist in writing and executing Python code snippets to perform calculations or data manipulation using the 'built_in_code_execution' tool.",
    tools=[built_in_code_execution],
)

gmail_agent = Agent(
    model='gemini-2.0-flash-lite',
    name='GmailAgent',
    instruction="""You are a specialist agent for interacting with Gmail. Your capabilities are sending emails ('send_email'), searching emails ('search_emails'), and listing labels ('list_labels'). You MUST call the appropriate tool to perform any action. If a tool call fails due to an authentication or connection error, inform the user that they may need to re-authenticate with their Google account through the main web application and try again. For sending emails, ensure you have the recipient ('to'), 'subject', and 'body'. For searching emails, ensure you have a 'query' string.""",
    tools=[send_email_tool, search_emails_tool, list_labels_tool],
)

root_agent = Agent(
    name="RootAgent",
    model="gemini-2.0-flash-lite",
    instruction="""You are the main assistant. Your capabilities are:
    - Web searches via SearchAgent.
    - Code execution via CodeAgent.
    - Gmail actions (sending, searching, listing labels) via GmailAgent.
    Determine the user's intent and delegate to the appropriate specialist agent. Pass all necessary information. Summarize the final results for the user. If the GmailAgent reports an authentication issue, relay that information clearly.""",
    tools=[
        agent_tool.AgentTool(agent=search_agent),
        agent_tool.AgentTool(agent=coding_agent),
        agent_tool.AgentTool(agent=gmail_agent),
    ],
)

# --- Global Runner Setup for the Server ---
# This `runner` is the object the ADK server will use when it receives requests
# from the Go backend. It is exposed to the ADK framework via the agents/__init__.py file.
APP_NAME = "agents"
session_service = InMemorySessionService()
runner = Runner(agent=root_agent, app_name=APP_NAME, session_service=session_service)

# Note: The `if __name__ == "__main__":` block has been removed to avoid confusion.
# This file is intended to be run as a module by an ADK server, not as a direct script.