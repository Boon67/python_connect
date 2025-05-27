import os
from pathlib import Path
from snowflake.snowpark import Session
from snowflake.snowpark.exceptions import SnowparkSessionException
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def create_snowpark_session():
    """
    Establishes a Snowpark session with Snowflake, attempting RSA key pair
    authentication first, then falling back to username/password authentication.

    Required environment variables:
    - SNOWFLAKE_USER
    - SNOWFLAKE_ACCOUNT

    For RSA Key Pair Authentication (priority):
    - SNOWFLAKE_PRIVATE_KEY_PATH (path to your private key file)
    - SNOWFLAKE_PRIVATE_KEY_PASSPHRASE (optional, if private key is encrypted)

    For Username/Password Authentication (fallback):
    - SNOWFLAKE_PASSWORD

    Optional common environment variables:
    - SNOWFLAKE_WAREHOUSE
    - SNOWFLAKE_DATABASE
    - SNOWFLAKE_SCHEMA
    - SNOWFLAKE_ROLE
    """
    try:
        user = os.environ.get('SNOWFLAKE_USER')
        account = os.environ.get('SNOWFLAKE_ACCOUNT')

        # Common optional parameters
        warehouse = os.environ.get('SNOWFLAKE_WAREHOUSE')
        database = os.environ.get('SNOWFLAKE_DATABASE')
        schema = os.environ.get('SNOWFLAKE_SCHEMA')
        role = os.environ.get('SNOWFLAKE_ROLE')

        if not all([user, account]):
            print("Error: SNOWFLAKE_USER and SNOWFLAKE_ACCOUNT environment variables must be set.")
            return None

        connection_parameters = {
            "account": account,
            "user": user,
            "warehouse": warehouse,
            "database": database,
            "schema": schema,
            "role": role
        }

        auth_method_used = ""

        # Attempt RSA Key Pair Authentication first
        private_key_path_str = os.environ.get('SNOWFLAKE_PRIVATE_KEY_PATH')
        if private_key_path_str:
            print("Attempting RSA key pair authentication...")
            private_key_passphrase = os.environ.get('SNOWFLAKE_PRIVATE_KEY_PASSPHRASE')
            private_key_path = Path(private_key_path_str)

            if not private_key_path.is_file():
                print(f"Error: Private key file not found at {private_key_path_str}")
                print("Falling back to check for password authentication if SNOWFLAKE_PASSWORD is set.")
                # Proceed to check password auth
            else:
                try:
                    with open(private_key_path, "rb") as key_file:
                        p_key_bytes = key_file.read()

                    passphrase_bytes = private_key_passphrase.encode() if private_key_passphrase else None

                    private_key = serialization.load_pem_private_key(
                        p_key_bytes,
                        password=passphrase_bytes,
                        backend=default_backend()
                    )
                    pkcs8_private_key = private_key.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    connection_parameters["private_key"] = pkcs8_private_key
                    auth_method_used = "RSA Key Pair"
                except Exception as e:
                    print(f"Error reading or parsing private key: {e}")
                    print("Ensure your private key is in PEM format and the passphrase (if any) is correct.")
                    print("Falling back to check for password authentication if SNOWFLAKE_PASSWORD is set.")
                    # Proceed to check password auth, clear potential partial RSA config
                    if "private_key" in connection_parameters:
                        del connection_parameters["private_key"]


        # Attempt Username/Password Authentication if RSA was not successful or not configured
        if not auth_method_used:
            password = os.environ.get('SNOWFLAKE_PASSWORD')
            if password:
                print("Attempting username/password authentication...")
                connection_parameters["password"] = password
                auth_method_used = "Username/Password"
            else:
                if private_key_path_str: # RSA was attempted but failed, and no password
                     print("RSA authentication failed, and SNOWFLAKE_PASSWORD is not set. Cannot connect.")
                     return None
                else: # Neither RSA path nor password was provided
                    print("Error: Neither SNOWFLAKE_PRIVATE_KEY_PATH nor SNOWFLAKE_PASSWORD environment variable is set.")
                    return None

        if not auth_method_used: # Should not happen if logic above is correct, but as a safeguard
            print("Error: No valid authentication method configured.")
            return None

        print(f"Connecting to Snowflake account: {account} as user: {user} using {auth_method_used}...")

        filtered_connection_parameters = {k: v for k, v in connection_parameters.items() if v is not None}
        session = Session.builder.configs(filtered_connection_parameters).create()

        print(f"Successfully created Snowpark session using {auth_method_used}!")
        return session

    except SnowparkSessionException as e:
        print(f"SnowparkSessionException while creating session: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during session creation: {e}")
        return None

def close_snowpark_session(session):
    """Closes the Snowpark session."""
    if session:
        session.close()
        print("Snowpark session closed.")

def main():
    """Main function to demonstrate Snowpark session and basic operation."""
    snowpark_session = create_snowpark_session()

    if snowpark_session:
        try:
            result_rows = snowpark_session.sql("SELECT CURRENT_VERSION()").collect()
            if result_rows and len(result_rows) > 0:
                snowflake_version = result_rows[0][0]
                print(f"Snowflake version (via Snowpark): {snowflake_version}")
            else:
                print("Could not retrieve Snowflake version via Snowpark.")

        except Exception as e:
            print(f"An error occurred during Snowpark operations: {e}")
        finally:
            close_snowpark_session(snowpark_session)
    else:
        print("Failed to create Snowpark session. Please check your configuration and credentials for either RSA key or password.")

if __name__ == "__main__":
    # --- Instructions for running this script: ---
    # 1. Make sure you have the necessary libraries installed:
    #    pip install snowflake-snowpark-python cryptography
    #
    # 2. Set COMMON environment variables:
    #    export SNOWFLAKE_USER="your_snowflake_username"
    #    export SNOWFLAKE_ACCOUNT="your_snowflake_account_identifier"
    #    # Optional common variables:
    #    # export SNOWFLAKE_WAREHOUSE="your_default_warehouse"
    #    # export SNOWFLAKE_DATABASE="your_default_database"
    #    # export SNOWFLAKE_SCHEMA="your_default_schema"
    #    # export SNOWFLAKE_ROLE="your_default_role"
    #
    # 3. Choose ONE authentication method below and set the corresponding environment variables:
    #
    #    --- OPTION A: RSA Key Pair Authentication (Recommended) ---
    #    a. Generate RSA Key Pair and assign public key to Snowflake user (see previous RSA-only script for details).
    #    b. Set these environment variables:
    #       export SNOWFLAKE_PRIVATE_KEY_PATH="/path/to/your/rsa_key.p8"
    #       # If your private key is encrypted, also set:
    #       # export SNOWFLAKE_PRIVATE_KEY_PASSPHRASE="your_private_key_passphrase"
    #       # DO NOT set SNOWFLAKE_PASSWORD if you intend to use RSA key.
    #
    #    --- OPTION B: Username/Password Authentication ---
    #    a. Set this environment variable:
    #       export SNOWFLAKE_PASSWORD="your_snowflake_password"
    #       # Ensure SNOWFLAKE_PRIVATE_KEY_PATH is NOT set or is empty if you intend to use password.
    #
    # 4. Run the script:
    #    python your_script_name.py
    #
    # Note: The script prioritizes RSA key pair authentication. If SNOWFLAKE_PRIVATE_KEY_PATH
    # is set and valid, it will be used. If it's not set or the key is invalid,
    # the script will then check for SNOWFLAKE_PASSWORD.
    main()