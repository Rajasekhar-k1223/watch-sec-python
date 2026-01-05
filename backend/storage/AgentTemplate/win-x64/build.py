
import subprocess
import os
import shutil

def build():
    print("Starting PyInstaller Build...")
    
    # 1. Clean previous build
    if os.path.exists("dist"):
        shutil.rmtree("dist")
    if os.path.exists("build"):
        shutil.rmtree("build")
        
    # 2. Run PyInstaller
    # --onefile: Single EXE
    # --noconsole: Background process
    # --name: Output name
    # src/main.py: Entry point
    
    cmd = [
        "pyinstaller",
        "--noconsole",
        "--onefile",
        "--hidden-import=jaraco.text",
        "--hidden-import=jaraco.classes",
        "--hidden-import=jaraco.context",
        "--hidden-import=jaraco.functools",
        "--hidden-import=pkg_resources",
        "--name", "watch-sec-agent",
        "src/main.py"
    ]
    
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    
    if result.returncode != 0:
        print("Build Failed!")
        exit(1)
        
    print("Build Success!")
    
    # 3. Verify
    output_path = os.path.join("dist", "watch-sec-agent.exe")
    if os.path.exists(output_path):
        size = os.path.getsize(output_path)
        print(f"Artifact created: {output_path} ({size} bytes)")
    else:
        print("Artifact not found!")
        exit(1)

if __name__ == "__main__":
    build()
