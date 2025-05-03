# -*- coding: utf-8 -*-
import os
import pickle
import logging
import sys

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError

# --- Configuration ---
# Define the scopes required by the main application
SCOPES = [
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly'
    #'https://www.googleapis.com/auth/drive.readonly',
    #'https://www.googleapis.com/auth/calendar.readonly'
]

# --- Resolve Paths Relative to This Script ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(SCRIPT_DIR, 'credentials.json') # Expect credentials.json in the same folder
TOKEN_PICKLE_FILE = os.path.join(SCRIPT_DIR, 'token.pickle') # Stores the user's access and refresh tokens

# Define a FIXED port for the OAuth redirect URI (Must match Google Cloud Console)
OAUTH_REDIRECT_PORT = 8081 # Or another free port configured in GCP
OAUTH_REDIRECT_URI = f'http://localhost:{OAUTH_REDIRECT_PORT}/'

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Google Authentication Function (Focus on Initial Auth & Save) ---
def authenticate_and_save_token():
    """
    Performs the Google OAuth 2.0 flow to obtain user consent and credentials.
    Saves the credentials (including refresh token) to token.pickle.
    This function is designed to be run interactively when initial authentication
    or re-authentication is needed.
    """
    creds = None
    # 1. Check if a token already exists and is valid (primarily for refresh check)
    if os.path.exists(TOKEN_PICKLE_FILE):
        try:
            with open(TOKEN_PICKLE_FILE, 'rb') as token:
                creds = pickle.load(token)
            log.info(f"Loaded existing credentials from {TOKEN_PICKLE_FILE}")
        except (EOFError, pickle.UnpicklingError, FileNotFoundError, Exception) as e:
            log.warning(f"Could not load token.pickle: {e}. Will attempt re-authentication.")
            creds = None

    # 2. If credentials are not valid (missing, expired, etc.)
    if not creds or not creds.valid:
        # 2a. Try refreshing if possible
        if creds and creds.expired and creds.refresh_token:
            try:
                log.info("Attempting to refresh expired credentials...")
                creds.refresh(Request())
                log.info("Credentials refreshed successfully.")
                # Save the refreshed token immediately
                try:
                    with open(TOKEN_PICKLE_FILE, 'wb') as token:
                        pickle.dump(creds, token)
                    log.info(f"Refreshed credentials saved to {TOKEN_PICKLE_FILE}")
                    return True # Indicate success
                except Exception as e:
                    log.error(f"Error saving refreshed credentials: {e}")
                    # Continue to full auth flow if saving failed
            except Exception as e:
                log.error(f"Failed to refresh token: {e}. Proceeding with full authentication flow.")
                if os.path.exists(TOKEN_PICKLE_FILE):
                    try:
                        os.remove(TOKEN_PICKLE_FILE)
                        log.info("Removed potentially invalid token.pickle file.")
                    except OSError as ose:
                        log.error(f"Error removing token.pickle: {ose}")
                creds = None # Force re-authentication

        # 2b. If refresh failed or wasn't possible, start the full OAuth flow
        if not creds or not creds.valid:
            if not os.path.exists(CREDENTIALS_FILE):
                log.critical(f"CRITICAL ERROR: credentials.json not found at '{CREDENTIALS_FILE}'.")
                log.critical("Please download your OAuth 2.0 Client ID credentials from Google Cloud Console")
                log.critical(f"and place the file in this directory: {SCRIPT_DIR}")
                return False # Indicate failure

            try:
                log.info("Starting full Google Authentication flow...")
                log.info(f"Ensure the redirect URI '{OAUTH_REDIRECT_URI}' is registered in your Google Cloud Console OAuth Client ID settings.")
                print("\n>>> You will likely be directed to your web browser to grant permissions. <<<")
                print(">>> Please follow the instructions in the browser window. <<<")
                print(">>> The local server will start temporarily on port {} to receive the response. <<<\n".format(OAUTH_REDIRECT_PORT))

                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                # run_local_server handles opening the browser and the redirect
                creds = flow.run_local_server(port=OAUTH_REDIRECT_PORT)
                log.info("Authentication successful through browser flow.")

            except FileNotFoundError:
                 log.critical(f"CRITICAL ERROR: credentials.json not found at '{CREDENTIALS_FILE}'. Cannot proceed.")
                 return False # Indicate failure
            except Exception as e:
                log.error(f"An error occurred during the authentication flow: {e}", exc_info=True)
                print(f"\nERROR: Authentication failed. Details: {e}")
                print("Please check console logs and ensure Google Cloud settings are correct.")
                return False # Indicate failure

            # 3. Save the newly obtained credentials
            if creds and creds.valid:
                try:
                    with open(TOKEN_PICKLE_FILE, 'wb') as token:
                        pickle.dump(creds, token)
                    log.info(f"New credentials successfully obtained and saved to {TOKEN_PICKLE_FILE}")
                    return True # Indicate success
                except Exception as e:
                    log.error(f"Error saving new credentials to {TOKEN_PICKLE_FILE}: {e}")
                    print(f"\nERROR: Authentication succeeded but failed to save the token file ({TOKEN_PICKLE_FILE}).")
                    print(f"Check permissions and disk space. Details: {e}")
                    return False # Indicate failure
            else:
                log.error("Authentication flow completed, but did not result in valid credentials.")
                return False # Indicate failure
    else:
        log.info("Existing credentials in token.pickle are still valid. No action needed by this script.")
        return True # Indicate success (token is valid)

# --- Main Execution Block ---
if __name__ == "__main__":
    print("--- Google OAuth 2.0 Token Generator ---")
    print(f"This script will attempt to authenticate with Google using '{os.path.basename(CREDENTIALS_FILE)}'")
    print(f"and save the authorization token to '{os.path.basename(TOKEN_PICKLE_FILE)}' in the directory:")
    print(f"'{SCRIPT_DIR}'")
    print("-" * 40)

    success = authenticate_and_save_token()

    print("-" * 40)
    if success:
        print(f"Authentication process completed. Token file '{os.path.basename(TOKEN_PICKLE_FILE)}' should be present and updated/valid.")
        print("You can now run the main agent application.")
    else:
        print("Authentication process failed. Please check the log messages above for errors.")
        print(f"Ensure '{os.path.basename(CREDENTIALS_FILE)}' exists and is configured correctly in Google Cloud Console.")
        sys.exit(1) # Exit with error code if authentication failed