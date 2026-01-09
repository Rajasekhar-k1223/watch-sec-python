import PyInstaller.__main__
import os
import shutil

# Build Configuration
AGENT_NAME = "watch-sec-agent"
ENTRY_POINT = os.path.join("src", "main.py")

print(f"Building {AGENT_NAME}...")

import platform
    
# Run PyInstaller
opts = [
    ENTRY_POINT,
    '--name=%s' % AGENT_NAME,
    '--onefile',            # Bundle into single exe
    '--clean',
    '--distpath=dist',
    '--workpath=build',
    '--hidden-import=jaraco.text',
    '--hidden-import=jaraco.classes',
    '--hidden-import=jaraco.functools',
    '--hidden-import=jaraco.context',
    '--hidden-import=platformdirs',
]

if platform.system() == "Windows":
    opts.append('--noconsole') # Hide console on Windows
    ext = ".exe"
else:
    # Linux/Mac usually keep console for status or use nohup, but --noconsole might hide valid logs.
    # Keep console for now or make it configurable. 
    # For a daemon-like agent, --noconsole is often preferred if logging to file.
    # main.py logs to file.
    # opts.append('--noconsole') 
    ext = ""

PyInstaller.__main__.run(opts)

print("Build Complete.")
print(f"Artifact: dist/{AGENT_NAME}{ext}")


# Copy config.json to dist for testing
if os.path.exists("config.json"):
    shutil.copy("config.json", "dist/config.json")
    print("Copied config.json to dist")
