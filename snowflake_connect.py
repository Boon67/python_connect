import os
from pathlib import Path
import snowflake.connector
from snowflake.connector.errors import ProgrammingError, DatabaseError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Helper Function for Key Pair Authentication ---

def _load_and_process_private_key(private_key_path_str, private_key_passphrase_str):
    """
    Loads a private key from a PEM file, decrypts if necessary,
    and returns its PKCS#8 DER encoded bytes.
    These bytes are expected by the Snowflake Connector's 'private_key' parameter.
    """
    private_key_path = Path(private_key_path_str)
    if not private_key_path.is_file():
        raise FileNotFoundError(f"Private key file not found at {private_key_path_str}")

    with open(private_key_path, "rb") as key_file:
        p_key_bytes = key_file.read()

    passphrase_bytes = private_key_passphrase_str.encode() if private_key_passphrase_str else None

    try:
        private_key = serialization.load_pem_private_key(
            p_key_bytes,
            password=passphrase_bytes,
            backend=default_backend()
        )
    except ValueError as e:
        if "Bad decrypt. Incorrect password?" in str(e) or "Could not deserialize key data." in str(e):
            raise ValueError(f"Error loading private key: Incorrect passphrase or invalid key format at {private_key_path_str}. {e}")
        raise

    pkcs8_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pkcs8_private_key

# --- Main Connection Logic ---

def create_snowflake_connection():
    """
    Establishes a connection to Snowflake using the Python Connector.
    It attempts RSA Key Pair authentication first if SNOWFLAKE_PRIVATE_KEY_PATH is set.
    If not, or if key processing fails, it falls back to Username/Password authentication
    if SNOWFLAKE_PASSWORD is set.

    Environment variables:
    - SNOWFLAKE_USER (required)
    - SNOWFLAKE_ACCOUNT (required)

    For RSA Key Pair Authentication (priority):
    - SNOWFLAKE_PRIVATE_KEY_PATH (path to your private key file)
    - SNOWFLAKE_PRIVATE_KEY_PASSPHRASE (optional, if your private key file is encrypted)

    For Username/Password Authentication (fallback):
    - SNOWFLAKE_PASSWORD

    Optional common environment variables:
    - SNOWFLAKE_WAREHOUSE, SNOWFLAKE_DATABASE, SNOWFLAKE_SCHEMA, SNOWFLAKE_ROLE
    """
    try:
        user = os.environ.get('SNOWFLAKE_USER')
        account = os.environ.get('SNOWFLAKE_ACCOUNT')

        if not all([user, account]):
            print("Error: SNOWFLAKE_USER and SNOWFLAKE_ACCOUNT environment variables must be set.")
            return None

        connection_params = {
            "user": user,
            "account": account,
            "warehouse": os.environ.get('SNOWFLAKE_WAREHOUSE'),
            "database": os.environ.get('SNOWFLAKE_DATABASE'),
            "schema": os.environ.get('SNOWFLAKE_SCHEMA'),
            "role": os.environ.get('SNOWFLAKE_ROLE')
        }
        # Filter out None values for optional params, connect() handles them if not present
        connection_params = {k: v for k, v in connection_params.items() if v is not None}


        auth_method_used = ""
        private_key_path_str = os.environ.get('SNOWFLAKE_PRIVATE_KEY_PATH')
        private_key_passphrase = os.environ.get('SNOWFLAKE_PRIVATE_KEY_PASSPHRASE')

        if private_key_path_str:
            print("Attempting RSA Key Pair authentication with Python Connector...")
            try:
                pkcs8_private_key_bytes = _load_and_process_private_key(private_key_path_str, private_key_passphrase)
                connection_params["private_key"] = pkcs8_private_key_bytes
                # The private_key_passphrase for connect() is for when the key *bytes* are encrypted.
                # Our helper _load_and_process_private_key already decrypts the *file*.
                # So, we don't pass private_key_passphrase to connect() here.
                auth_method_used = "RSA Key Pair"
            except FileNotFoundError as e:
                print(f"Key Pair Auth Error: {e}")
                print("Falling back to check for password authentication if SNOWFLAKE_PASSWORD is set.")
            except ValueError as e:
                print(f"Key Pair Auth Error: {e}")
                print("Falling back to check for password authentication if SNOWFLAKE_PASSWORD is set.")
            except Exception as e:
                print(f"An unexpected error occurred during private key processing: {e}")
                print("Falling back to check for password authentication if SNOWFLAKE_PASSWORD is set.")

        if not auth_method_used:
            password = os.environ.get('SNOWFLAKE_PASSWORD')
            if password:
                if private_key_path_str:
                    print("RSA Key Pair authentication failed. Attempting Username/Password authentication as fallback...")
                else:
                    print("SNOWFLAKE_PRIVATE_KEY_PATH not set. Attempting Username/Password authentication...")
                connection_params["password"] = password
                auth_method_used = "Username/Password"
            else:
                if private_key_path_str:
                    print("RSA Key Pair authentication failed, and SNOWFLAKE_PASSWORD is not set for fallback. Cannot connect.")
                    return None
                else:
                    print("Error: Neither SNOWFLAKE_PRIVATE_KEY_PATH nor SNOWFLAKE_PASSWORD environment variable is set.")
                    return None

        if not auth_method_used:
            print("Error: No valid authentication method could be configured.")
            return None

        print(f"Connecting to Snowflake account: {account} as user: {user} using {auth_method_used} with Python Connector...")
        
        conn = snowflake.connector.connect(**connection_params)
        
        print(f"Successfully connected to Snowflake using {auth_method_used} with Python Connector!")
        return conn

    except ProgrammingError as e: # Often for auth issues, bad SQL
        print(f"Snowflake ProgrammingError during connection: {e}")
        return None
    except DatabaseError as e: # General Snowflake DB errors
        print(f"Snowflake DatabaseError during connection: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during connection: {e}")
        return None

def close_snowflake_connection(conn):
    """Closes the Snowflake connection."""
    if conn:
        conn.close()
        print("Snowflake connection closed.")

def main():
    """Main function to demonstrate Snowflake connection and basic operation."""
    snowflake_conn = create_snowflake_connection()

    if snowflake_conn:
        try:
            cursor = snowflake_conn.cursor()
            try:
                cursor.execute("SELECT CURRENT_VERSION()")
                row = cursor.fetchone()
                if row:
                    snowflake_version = row[0]
                    print(f"Snowflake version (via Python Connector): {snowflake_version}")
                else:
                    print("Could not retrieve Snowflake version.")
                
                # Example: Listing databases (requires appropriate permissions)
                # cursor.execute("SHOW DATABASES")
                # print("\nDatabases:")
                # for row in cursor:
                # print(f"- {row[1]}")

            except ProgrammingError as e:
                print(f"Snowflake ProgrammingError during query execution: {e}")
            except DatabaseError as e:
                print(f"Snowflake DatabaseError during query execution: {e}")
            except Exception as e:
                print(f"An error occurred during query execution: {e}")
            finally:
                cursor.close()
        finally:
            close_snowflake_connection(snowflake_conn)
    else:
        print("Failed to create Snowflake connection. Please check your configuration and credentials.")

if __name__ == "__main__":
    # --- Instructions for running this script: ---
    # 1. Make sure you have the necessary libraries installed:
    #    pip install snowflake-connector-python cryptography
    #    # For key pair auth with encrypted keys, you might need the 'keyring' extras:
    #    # pip install "snowflake-connector-python[secure-local-storage,pandas]" (pandas is optional)
    #    # However, this script handles passphrase for the key file directly.
    #
    # 2. Set COMMON environment variables:
    #    export SNOWFLAKE_USER="your_snowflake_login_name"
    #    export SNOWFLAKE_ACCOUNT="your_snowflake_account_identifier"
    #
    #    # Optional common variables:
    #    # export SNOWFLAKE_WAREHOUSE="your_default_warehouse"
    #    # export SNOWFLAKE_DATABASE="your_default_database"
    #    # export SNOWFLAKE_SCHEMA="your_default_schema"
    #    # export SNOWFLAKE_ROLE="your_default_role"
    #
    # 3. Choose ONE authentication method below and set the corresponding environment variables:
    #
    #    --- OPTION A: RSA Key Pair Authentication (Recommended) ---
    #    a. Generate RSA Key Pair (e.g., rsa_key.p8) and assign public key to Snowflake user.
    #       (See previous script versions or Snowflake docs for openssl commands)
    #       The key file should be in PEM format (e.g., starting with -----BEGIN ENCRYPTED PRIVATE KEY-----
    #       or -----BEGIN PRIVATE KEY-----). PKCS#8 format is typical.
    #
    #    b. Set these environment variables:
    #       export SNOWFLAKE_PRIVATE_KEY_PATH="/path/to/your/rsa_key.p8"
    #       # If your private key *file* itself is encrypted with a passphrase, set:
    #       export SNOWFLAKE_PRIVATE_KEY_PASSPHRASE="your_private_key_file_passphrase"
    #
    #    --- OPTION B: Username/Password Authentication ---
    #    a. Set this environment variable:
    #       export SNOWFLAKE_PASSWORD="your_snowflake_password"
    #
    # 4. Run the script:
    #    python your_script_name.py
    #
    # Note on Authentication Priority:
    # The script prioritizes RSA Key Pair authentication. If SNOWFLAKE_PRIVATE_KEY_PATH
    # is set and the key is valid, it will be used. If it's not set, or if key processing fails,
    # the script will then check for SNOWFLAKE_PASSWORD for Username/Password authentication.
    main()