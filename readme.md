# Snowflake Python Connector Script

## Overview

This Python script demonstrates how to connect to a Snowflake database using the official `snowflake-connector-python`. It supports two primary methods of authentication:
1.  **RSA Key Pair Authentication** (recommended for security and programmatic access)
2.  **Username/Password Authentication**

The script retrieves the current Snowflake version as a basic test of connectivity. Connection parameters and credentials are managed securely through environment variables.

## Prerequisites

* Python 3.7 or higher.
* `pip` (Python package installer).
* Access to a Snowflake account with a user configured for your chosen authentication method.

## Installation

1.  **Clone or download the script** (e.g., save it as `connect_snowflake.py`).

2.  **Install the required Python libraries**:
    Open your terminal or command prompt and run:
    ```bash
    pip install snowflake-connector-python cryptography
    ```
    * `snowflake-connector-python`: The official Snowflake connector.
    * `cryptography`: Required for handling RSA private keys for key pair authentication.

## Configuration

This script relies on environment variables for all connection parameters and credentials. **Do not hardcode credentials directly into the script.**

### Common Environment Variables

These variables are required or commonly used for both authentication methods:

* `SNOWFLAKE_USER`: Your Snowflake login name.
    * Example: `export SNOWFLAKE_USER="myloginname"`
* `SNOWFLAKE_ACCOUNT`: Your Snowflake account identifier. This can be in the format `your_organization_name-your_account_name` (preferred) or the older account locator format (e.g., `xy12345.us-east-1`).
    * Example: `export SNOWFLAKE_ACCOUNT="myorg-myaccount"`
* `SNOWFLAKE_ROLE` (Optional): The default role to use after connecting.
    * Example: `export SNOWFLAKE_ROLE="SYSADMIN"`
* `SNOWFLAKE_WAREHOUSE` (Optional): The default warehouse to use.
    * Example: `export SNOWFLAKE_WAREHOUSE="COMPUTE_WH"`
* `SNOWFLAKE_DATABASE` (Optional): The default database to connect to.
    * Example: `export SNOWFLAKE_DATABASE="MY_DATABASE"`
* `SNOWFLAKE_SCHEMA` (Optional): The default schema to use within the database.
    * Example: `export SNOWFLAKE_SCHEMA="PUBLIC"`

### Authentication Methods

You need to configure environment variables for **one** of the following authentication methods.

#### 1. RSA Key Pair Authentication (Recommended)

This method uses an RSA private key to authenticate with Snowflake. The corresponding public key must be assigned to your Snowflake user.

##### Generating RSA Keys

If you don't have an RSA key pair, you can generate one using OpenSSL. We recommend using a PKCS#8 formatted key.

1.  **Generate an unencrypted private key (2048-bit RSA, PKCS#8 PEM format):**
    ```bash
    # Generate a traditional RSA private key
    openssl genrsa -out rsa_key.pem 2048

    # Convert it to PKCS#8 format (unencrypted)
    openssl pkcs8 -topk8 -inform PEM -out rsa_key.p8 -in rsa_key.pem -nocrypt
    ```
    Your private key file will be `rsa_key.p8`.

2.  **Generate an encrypted private key (Optional - if you want the key file itself to be password-protected):**
    ```bash
    # Generate a traditional RSA private key, encrypting it with a passphrase
    openssl genrsa -aes256 -out rsa_key_encrypted_pem.pem 2048
    # (You will be prompted to enter and verify a passphrase)

    # Convert it to PKCS#8 format (it will remain encrypted)
    openssl pkcs8 -topk8 -inform PEM -out rsa_key_encrypted.p8 -in rsa_key_encrypted_pem.pem
    # (You will be prompted for the input key's passphrase and can set a new one for the PKCS#8 file, or use the same)
    ```
    Your encrypted private key file will be `rsa_key_encrypted.p8`.

##### Assigning Public Key to Snowflake User

1.  **Extract the public key from your private key file (e.g., `rsa_key.p8`):**
    ```bash
    openssl rsa -in rsa_key.p8 -pubout -out rsa_pub.pem
    ```
    If your private key file (`rsa_key.p8`) is encrypted, you will be prompted for its passphrase.

2.  **Copy the public key content:**
    Open `rsa_pub.pem`. The content will look like:
    ```
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyourPublicKeyData...
    ...
    -----END PUBLIC KEY-----
    ```
    Copy the string *between* `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`. Remove any newline characters from this copied string.

3.  **Assign the public key to your Snowflake user:**
    Execute the following SQL command in Snowflake (e.g., via the Snowflake UI or SnowSQL). Replace `your_login_name` and `your_public_key_string_here`.
    ```sql
    ALTER USER your_login_name SET RSA_PUBLIC_KEY='your_public_key_string_here';
    -- Alternatively, if RSA_PUBLIC_KEY is already in use, you can use RSA_PUBLIC_KEY_2:
    -- ALTER USER your_login_name SET RSA_PUBLIC_KEY_2='your_public_key_string_here';
    ```

##### Environment Variables for RSA Key Pair

* `SNOWFLAKE_PRIVATE_KEY_PATH`: The absolute or relative path to your private key file (e.g., `rsa_key.p8`).
    * Example: `export SNOWFLAKE_PRIVATE_KEY_PATH="/home/user/.ssh/snowflake_rsa_key.p8"`
* `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE` (Optional): If your private key *file* (specified by `SNOWFLAKE_PRIVATE_KEY_PATH`) is encrypted with a passphrase, set this variable to that passphrase.
    * Example: `export SNOWFLAKE_PRIVATE_KEY_PASSPHRASE="mySecretPassphrase"`

#### 2. Username/Password Authentication

##### Environment Variables for Username/Password

* `SNOWFLAKE_PASSWORD`: Your Snowflake user's password.
    * Example: `export SNOWFLAKE_PASSWORD="mySnowflakePassword123!"`

### Authentication Priority

The script prioritizes authentication methods as follows:
1.  **RSA Key Pair Authentication**: If `SNOWFLAKE_PRIVATE_KEY_PATH` is set and the key is valid, this method will be attempted first.
2.  **Username/Password Authentication**: If `SNOWFLAKE_PRIVATE_KEY_PATH` is not set, or if key processing fails, the script will then check for `SNOWFLAKE_PASSWORD` and attempt username/password authentication.

If neither method can be configured based on the set environment variables, the script will report an error.

## Running the Script

Once you have installed the prerequisites and configured the environment variables:
1.  Save the script to a file, for example, `connect_snowflake.py`.
2.  Open your terminal or command prompt.
3.  Navigate to the directory where you saved the script.
4.  Run the script:
    ```bash
    python connect_snowflake.py
    ```

## Example Output

If the connection is successful, you should see output similar to this:


Attempting RSA Key Pair authentication with Python Connector...
Connecting to Snowflake account: SNOWFLAKE_ACCOUNT_NAME as user: SNOWFLAKE_USER using RSA Key Pair with Python Connector...
Successfully connected to Snowflake using RSA Key Pair with Python Connector!
Snowflake version (via Python Connector): 9.14.2
Snowflake connection closed.
Attempting RSA key pair authentication...
Connecting to Snowflake account: SNOWFLAKE_ACCOUNT_NAME as user: SNOWFLAKE_USER using RSA Key Pair...
Successfully created Snowpark session using RSA Key Pair!
Snowflake version (via Snowpark): 9.14.2
Snowpark session closed.
Environment variables set by Bash script.
SNOWFLAKE_USER is: SNOWFLAKE_USER