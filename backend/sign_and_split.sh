#!/bin/bash
set -e

# Configuration
AGENT_TEMPLATE_DIR="/opt/apps/monitorix/watch-sec-python/backend/storage/AgentTemplate/win-x64"
INPUT_ZIP="monitorix.zip"
PFX_FILE="/opt/apps/monitorix/certs/codesign/monitorix_codesign.pfx"
PASS="monitorix"
MAX_SIZE_MB=50
WORK_DIR="work_temp"

# Ensure tools
if ! command -v osslsigncode &> /dev/null; then
    echo "Error: osslsigncode required."
    exit 1
fi

if [ ! -f "$PFX_FILE" ]; then
    echo "Error: Certificate not found at $PFX_FILE"
    exit 1
fi

cd "$AGENT_TEMPLATE_DIR"

if [ ! -f "$INPUT_ZIP" ]; then
    echo "Error: $INPUT_ZIP not found in $AGENT_TEMPLATE_DIR"
    exit 1
fi

echo "--- 1. Preparation ---"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
echo "[*] Extracting zip..."
unzip -q "$INPUT_ZIP" -d "$WORK_DIR"

echo "--- 2. Signing Binaries ---"
# Find all EXEs in the top level of the extracted dir
find "$WORK_DIR" -maxdepth 2 -name "*.exe" | while read exe; do
    echo "    Signing: $exe"
    osslsigncode sign -pkcs12 "$PFX_FILE" \
                      -pass "$PASS" \
                      -n "Monitorix Enterprise Agent" \
                      -i "https://monitorix.co.in" \
                      -t "http://timestamp.digicert.com" \
                      -in "$exe" \
                      -out "${exe}.signed"
    mv "${exe}.signed" "$exe"
done
echo "[+] Binaries inside Zip Signed."

echo "--- 2b. Signing Installer Stub ---"
INSTALLER_EXE="monitorix-installer.exe"
if [ -f "$INSTALLER_EXE" ]; then
    echo "    Signing: $INSTALLER_EXE"
    osslsigncode sign -pkcs12 "$PFX_FILE" \
                      -pass "$PASS" \
                      -n "Monitorix Enterprise Agent" \
                      -i "https://monitorix.co.in" \
                      -t "http://timestamp.digicert.com" \
                      -in "$INSTALLER_EXE" \
                      -out "${INSTALLER_EXE}.signed"
    mv "${INSTALLER_EXE}.signed" "$INSTALLER_EXE"
    echo "[+] Installer Stub Signed."
else
    echo "[-] Warning: $INSTALLER_EXE not found. Skipping."
fi

echo "--- 3. Re-Packaging ---"
cd "$WORK_DIR"
rm -f "../monitorix_signed.zip"
# Recursively zip everything back
zip -r -q "../monitorix_signed.zip" .
cd ..
rm -rf "$WORK_DIR"

echo "Re-packaged as monitorix_signed.zip"

echo "--- 4. Checking Size & Splitting ---"
TARGET_FILE="monitorix_signed.zip"
SIZE_BYTES=$(stat -c%s "$TARGET_FILE")
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))

echo "Size: ${SIZE_MB}MB (Max: ${MAX_SIZE_MB}MB)"

if [ "$SIZE_MB" -gt "$MAX_SIZE_MB" ]; then
    echo "[!] File is large. Splitting into chunks..."
    # Split into 50MB chunks, suffix .part0, .part1 (using numeric suffixes)
    # split -d -b 50M FILE PREFIX
    # We want result: monitorix.zip.part0, monitorix.zip.part1
    # NOTE: The installer expects `monitorix.exe.part0` currently? No, I will fix installer to match.
    # Let's call the parts `monitorix.zip.part`
    
    split -b 50M -d -a 1 "$TARGET_FILE" "monitorix.zip.part"
    
    # Verify split
    echo "[*] Verifying split integrity..."
    cat monitorix.zip.part* > reassembled.zip
    ORIG_HASH=$(md5sum "$TARGET_FILE" | awk '{print $1}')
    NEW_HASH=$(md5sum reassembled.zip | awk '{print $1}')
    
    if [ "$ORIG_HASH" == "$NEW_HASH" ]; then
        echo "[+] Split verification successful ($ORIG_HASH)"
        rm reassembled.zip
        # Move parts to become the primary artifacts
        # We replace the original separate files with these parts
        # Keep parts.
        rm -f "$TARGET_FILE" # Remove the big zip since we have parts.

        
        # We need to tell downloads.py to serve these.
        echo "[+] Parts created: $(ls monitorix.zip.part*)"
    else
        echo "[-] Split verification FAILED."
        exit 1
    fi
else
    echo "[+] File is small enough. Keeping as single zip."
    mv "$TARGET_FILE" "monitorix.zip"
fi

echo "--- Done ---"
