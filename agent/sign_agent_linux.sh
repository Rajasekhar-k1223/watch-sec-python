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

# 1. Generate Root CA if it doesn't exist
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_KEY="$SCRIPT_DIR/root_ca.key"
ROOT_CRT="$SCRIPT_DIR/root_ca.crt"
CERT_KEY="$SCRIPT_DIR/monitorix.key"
CERT_CSR="$SCRIPT_DIR/monitorix.csr"
CERT_CRT="$SCRIPT_DIR/monitorix.crt"
CERT_PFX="$SCRIPT_DIR/monitorix.pfx"

if [ ! -f "$ROOT_CRT" ]; then
    echo "1. Generating Internal Monitorix Root CA..."
    openssl genrsa -out "$ROOT_KEY" 4096
    openssl req -x509 -new -nodes -key "$ROOT_KEY" -sha256 -days 3650 -out "$ROOT_CRT" -subj "/CN=Monitorix Enterprise Root CA/O=Monitorix/C=US"
    echo "✓ Root CA created: $ROOT_CRT"
fi

if [ ! -f "$CERT_PFX" ]; then
    echo "2. Generating Code Signing Certificate (signed by Root CA)..."
    # a. Generate Private Key
    openssl genrsa -out "$CERT_KEY" 4096
    
    # b. Create CSR (Certificate Signing Request)
    openssl req -new -key "$CERT_KEY" -out "$CERT_CSR" -subj "/CN=Monitorix Enterprise/O=Monitorix/C=US"
    
    # c. Sign CSR with Root CA
    # We need a small config for code signing extensions
    cat > "$SCRIPT_DIR/codesign.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = codeSigning
EOF
    
    openssl x509 -req -in "$CERT_CSR" -CA "$ROOT_CRT" -CAkey "$ROOT_KEY" -CAcreateserial -out "$CERT_CRT" -days 3650 -sha256 -extfile "$SCRIPT_DIR/codesign.ext"
    
    # d. Export to PFX (for osslsigncode)
    # Using blank password for automated build pipeline
    openssl pkcs12 -export -out "$CERT_PFX" -inkey "$CERT_KEY" -in "$CERT_CRT" -passout pass:
    
    rm "$CERT_CSR" "$SCRIPT_DIR/codesign.ext"
    echo "✓ Code Signing Certificate created: $CERT_PFX"
fi

# 3. Sign the Executable
echo "3. Signing Executable: $EXE_PATH"
TMP_EXE="${EXE_PATH}.tmp"

# Use osslsigncode to sign
# -t specifies the timestamp server to ensure signature remains valid after cert expiry
osslsigncode sign -pkcs12 "$CERT_PFX" -pass "" -n "Monitorix Enterprise Agent" -t http://timestamp.digicert.com -in "$EXE_PATH" -out "$TMP_EXE"

mv "$TMP_EXE" "$EXE_PATH"

echo "✅ Success! Signed $EXE_PATH with Monitorix Trust Chain."
