import PyInstaller.__main__
import os
import shutil

# Build Configuration
AGENT_NAME = "watch-sec-agent"
ENTRY_POINT = os.path.join("src", "main.py")

print(f"Building {AGENT_NAME}...")

# Run PyInstaller
PyInstaller.__main__.run([
    ENTRY_POINT,
    '--name=%s' % AGENT_NAME,
    '--onefile',            # Bundle into single exe
    '--noconsole',          # Hide console window (for prod) - Optional, maybe keep for debug
    #'--icon=icon.ico',     # TODO: Add icon
    '--clean',
    '--distpath=dist',
    '--workpath=build',
])

print("Build Complete.")
print(f"Artifact: dist/{AGENT_NAME}.exe")

# Copy config.json to dist for testing
if os.path.exists("config.json"):
    shutil.copy("config.json", "dist/config.json")
    print("Copied config.json to dist")
