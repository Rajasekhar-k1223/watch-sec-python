import os
import uuid

def generate_profile():
    # Generate unique UUIDs for the payload
    profile_uuid = str(uuid.uuid4()).upper()
    payload_uuid1 = str(uuid.uuid4()).upper()
    payload_uuid2 = str(uuid.uuid4()).upper()
    payload_uuid3 = str(uuid.uuid4()).upper()
    
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDescription</key>
            <string>Configures Privacy Preferences Policy Control for Monitorix Agent</string>
            <key>PayloadDisplayName</key>
            <string>Privacy Preferences Policy Control</string>
            <key>PayloadIdentifier</key>
            <string>com.monitorix.agent.privacy.{payload_uuid1}</string>
            <key>PayloadOrganization</key>
            <string>Monitorix Security</string>
            <key>PayloadType</key>
            <string>com.apple.TCC.configuration-profile-policy</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid1}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Services</key>
            <dict>
                <!-- Full Disk Access -->
                <key>SystemPolicyAllFiles</key>
                <array>
                    <dict>
                        <key>Allowed</key>
                        <true/>
                        <key>CodeRequirement</key>
                        <string>identifier "com.monitorix.agent"</string>
                        <key>Identifier</key>
                        <string>com.monitorix.agent</string>
                        <key>IdentifierType</key>
                        <string>bundleID</string>
                        <key>StaticCode</key>
                        <false/>
                    </dict>
                    <!-- Also allow the raw python binary executing it -->
                    <dict>
                        <key>Allowed</key>
                        <true/>
                        <key>CodeRequirement</key>
                        <string>identifier "com.apple.python3"</string>
                        <key>Identifier</key>
                        <string>/usr/bin/python3</string>
                        <key>IdentifierType</key>
                        <string>path</string>
                        <key>StaticCode</key>
                        <false/>
                    </dict>
                </array>
                <!-- Screen Recording (Silent Stream) -->
                <key>ScreenCapture</key>
                <array>
                    <dict>
                        <key>Allowed</key>
                        <true/>
                        <key>CodeRequirement</key>
                        <string>identifier "com.monitorix.agent"</string>
                        <key>Identifier</key>
                        <string>com.monitorix.agent</string>
                        <key>IdentifierType</key>
                        <string>bundleID</string>
                        <key>StaticCode</key>
                        <false/>
                    </dict>
                </array>
                <!-- Accessibility (Keylogger) -->
                <key>Accessibility</key>
                <array>
                    <dict>
                        <key>Allowed</key>
                        <true/>
                        <key>CodeRequirement</key>
                        <string>identifier "com.monitorix.agent"</string>
                        <key>Identifier</key>
                        <string>com.monitorix.agent</string>
                        <key>IdentifierType</key>
                        <string>bundleID</string>
                        <key>StaticCode</key>
                        <false/>
                    </dict>
                </array>
            </dict>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Grants necessary TCC permissions to the Monitorix Agent for full functionality without user prompts.</string>
    <key>PayloadDisplayName</key>
    <string>Monitorix Security Agent TCC Payload</string>
    <key>PayloadIdentifier</key>
    <string>com.monitorix.agent.profile.{profile_uuid}</string>
    <key>PayloadOrganization</key>
    <string>Monitorix Security</string>
    <key>PayloadRemovalDisallowed</key>
    <true/>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"""
    
    output_path = os.path.join(os.path.dirname(__file__), "Monitorix_TCC_Profile.mobileconfig")
    with open(output_path, "w") as f:
        f.write(xml)
        
    print(f"[SUCCESS] MDM Profile generated at: {output_path}")
    print("Please upload this .mobileconfig file to Jamf, Intune, or Kandji to silently grant permissions to macOS agents.")

if __name__ == "__main__":
    generate_profile()
