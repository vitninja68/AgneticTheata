import os
import sys
import pickle
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from dotenv import load_dotenv
from supabase import create_client, Client, ClientOptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from google.oauth2.credentials import Credentials

# --- Configuration ---
# Load environment variables from a .env file
load_dotenv()

# AES-GCM uses a 12-byte nonce, which is prepended to the ciphertext by the Go backend.
NONCE_SIZE = 12
# Google's standard token URI
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"

def decrypt_token(encrypted_hex_str: Optional[str], key_bytes: bytes) -> Optional[str]:
    """
    Decrypts a hex-encoded, AES-GCM encrypted string.
    """
    if not encrypted_hex_str:
        print("[DEBUG] decrypt_token: Input string is empty or None. Returning None.")
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
    except (ValueError, TypeError) as e:
        print(f"Error during decryption pre-check: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Decryption failed. This could be due to an incorrect key or corrupted data. Error: {e}", file=sys.stderr)
        return None


def get_and_save_credentials(user_id_to_fetch: str) -> None:
    """
    Fetches, decrypts, and saves Google OAuth credentials for a user from Supabase.
    """
    print("--- [INFO] Starting Credential Retrieval Process ---")

    # --- 1. Load and Validate Environment Variables ---
    print("\n--- [STEP 1] Loading Environment Variables ---")
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
            print(f"Error: Environment variable '{var}' is not set.", file=sys.stderr); sys.exit(1)
    
    print("[SUCCESS] All required environment variables are loaded.")
    supabase_url = f"https://{db_host[3:]}" if db_host and db_host.startswith("db.") else None
    if not supabase_url: print(f"Error: BLUEPRINT_DB_HOST format is incorrect.", file=sys.stderr); sys.exit(1)
    print(f"[INFO] Constructed Supabase URL: {supabase_url}")
    
    try:
        encryption_key = bytes.fromhex(hex_encryption_key)
        if len(encryption_key) != 32: print(f"Error: TOKEN_ENCRYPTION_KEY must be 32 bytes.", file=sys.stderr); sys.exit(1)
    except (ValueError, TypeError): print("Error: TOKEN_ENCRYPTION_KEY is not valid hex.", file=sys.stderr); sys.exit(1)

    # --- 2. Connect to Supabase and Fetch Token Data ---
    print("\n--- [STEP 2] Fetching Data from Supabase ---")
    try:
        client_options = ClientOptions(schema=db_schema)
        supabase: Client = create_client(supabase_url, supabase_key, options=client_options)
        table_name = 'user_google_tokens'; column_to_query = 'user_id'
        print(f"[INFO] Querying table '{table_name}' in schema '{db_schema}' where '{column_to_query}' = '{user_id_to_fetch}'")
        response = supabase.table(table_name).select('*').eq(column_to_query, user_id_to_fetch).execute()
        if not response.data: print(f"Error: No data found for this ID.", file=sys.stderr); sys.exit(1)
        token_data = response.data[0]
        print("[SUCCESS] Successfully fetched encrypted token data from Supabase.")
    except Exception as e: print(f"Error connecting to Supabase or fetching data: {e}", file=sys.stderr); sys.exit(1)

    # --- 3. Decrypt the Tokens ---
    print("\n--- [STEP 3] Decrypting Tokens ---")
    access_token = decrypt_token(token_data.get('encrypted_access_token'), encryption_key)
    refresh_token = decrypt_token(token_data.get('encrypted_refresh_token'), encryption_key)
    if not access_token: print("Error: Failed to decrypt the access token.", file=sys.stderr); sys.exit(1)
    print("[SUCCESS] Tokens have been decrypted.")

    # --- 4. Create Google Credentials Object ---
    print("\n--- [STEP 4] Assembling Google Credentials Object ---")
    expiry_dt = None
    expiry_str = token_data.get('token_expiry')
    if expiry_str:
        try:
            # Parse the full timestamp with timezone from the database
            aware_dt = datetime.fromisoformat(expiry_str)
            # *** FIX: Convert to a naive UTC datetime object, as the Google library expects ***
            expiry_dt = aware_dt.replace(tzinfo=None)
            print(f"[SUCCESS] Parsed and converted expiry to naive UTC datetime: {expiry_dt}")
        except (ValueError, TypeError):
            print(f"[WARNING] Could not parse expiry timestamp '{expiry_str}'.", file=sys.stderr)

    creds = Credentials(
        token=access_token, refresh_token=refresh_token,
        token_uri=GOOGLE_TOKEN_URI, client_id=google_client_id,
        client_secret=google_client_secret, scopes=token_data.get('scopes'),
        expiry=expiry_dt
    )
    print("[SUCCESS] Credentials object created successfully.")

    # --- 5. Save the Credentials to a Pickle File ---
    print("\n--- [STEP 5] Saving Credentials to File ---")
    try:
        with open('token.pickle', 'wb') as token_file:
            pickle.dump(creds, token_file)
        print("✓ Successfully saved credentials to 'token.pickle'.")
        print("\n--- ✅ Process Complete ---")
    except Exception as e:
        print(f"Error saving credentials to pickle file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python retrieve_token.py <user_id>", file=sys.stderr)
        sys.exit(1)
    id_to_fetch = sys.argv[1]
    get_and_save_credentials(id_to_fetch)