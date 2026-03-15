#!/bin/bash
set -e

# Linux script to sign Windows Agent using osslsigncode
# This replicates the behavior of sign_agent.ps1 on Linux

EXE_PATH=$1
CERT_NAME="Monitorix"

if [ -z "$EXE_PATH" ]; then
    echo "Usage: ./sign_agent_linux.sh <path_to_exe>"
    exit 1
fi

if [ ! -f "$EXE_PATH" ]; then
    echo "Error: File not found: $EXE_PATH"
    exit 1
fi

echo "--- WatchSec Linux-to-Windows Signer ---"

# 1. Generate Certificates if they don't exist
KEY_FILE="monitorix.key"
CRT_FILE="monitorix.crt"
PFX_FILE="monitorix.pfx"

if [ ! -f "$PFX_FILE" ]; then
    echo "1. Generating Self-Signed Code Signing Certificate..."
    openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CRT_FILE" -days 3650 -nodes -subj "/CN=$CERT_NAME"
    
    echo "2. Exporting to PFX (for osslsigncode)..."
    # Note: Using blank password for internal build cert
    openssl pkcs12 -export -out "$PFX_FILE" -inkey "$KEY_FILE" -in "$CRT_FILE" -passout pass:
fi

# 3. Sign the Executable
echo "3. Signing Executable: $EXE_PATH"
TMP_EXE="${EXE_PATH}.tmp"

# Use osslsigncode to sign
# -t specifies the timestamp server
osslsigncode sign -pkcs12 "$PFX_FILE" -pass "" -n "Monitorix" -t http://timestamp.digicert.com -in "$EXE_PATH" -out "$TMP_EXE"

mv "$TMP_EXE" "$EXE_PATH"

echo "✅ Success! Signed $EXE_PATH"

# 4. Export Public Cert for Root Trust (Matches Windows logic)
# build_win_on_linux.sh expects root_ca.crt
cp "$CRT_FILE" "root_ca.crt"
echo "Public cert exported to root_ca.crt"
