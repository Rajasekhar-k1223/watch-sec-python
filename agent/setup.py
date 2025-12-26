import sys
from cx_Freeze import setup, Executable

# Dependencies
build_exe_options = {
    "packages": ["os", "sys", "asyncio", "socketio", "requests", "psutil", "urllib3", "pyscreenshot", "PIL"],
    "excludes": ["tkinter"],
    "include_files": ["config.json"]  # Include default config
}

# Base for GUI vs Console
base = None
if sys.platform == "win32":
    base = "Win32GUI" # Hides console window

# MSI Options
bdist_msi_options = {
    "upgrade_code": "{E9A0C3B7-1F2A-4B3C-9D4E-5F6H7J8K9L0M}", # Fixed UUID for upgrades
    "add_to_path": True,
    "initial_target_dir": r"[ProgramFilesFolder]\WatchSecAgent",
    "install_icon": "icon.ico" if "icon.ico" in build_exe_options["include_files"] else None,
}

setup(
    name="WatchSecAgent",
    version="2.0.0",
    description="WatchSec Enterprise Security Agent",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options
    },
    executables=[Executable("src/main.py", base=base, target_name="WatchSecAgent.exe")]
)
