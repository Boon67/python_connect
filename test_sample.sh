#!/bin/bash

# --- Set your environment variables here ---
export SNOWFLAKE_USER="<your_snowflake_user>"
export SNOWFLAKE_ACCOUNT="<your_snowflake_account>" 
export SNOWFLAKE_ROLE="<your_snowflake_role>" #Optional
export SNOWFLAKE_WAREHOUSE="<your_warhouse_name>" #Optional

# For Password Authentication (uncomment and use if applicable)
# export SNOWFLAKE_PASSWORD="your_snowflake_password_from_bash"

# For RSA Key Pair Authentication (uncomment and use if applicable)
export SNOWFLAKE_PRIVATE_KEY_PATH="secrets/rsa_key.p8"
# export SNOWFLAKE_PRIVATE_KEY_PASSPHRASE="your_key_passphrase_if_any"

python ./snowflake_connect.py
python ./snowpark_connect.py

echo "Environment variables set by Bash script."
echo "SNOWFLAKE_USER is: $SNOWFLAKE_USER" # You can check them in Bash