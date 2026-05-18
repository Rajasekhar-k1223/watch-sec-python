import os
import subprocess
import platform
import logging
from typing import List, Dict, Any

logger = logging.getLogger("InventoryMonitor")

class InventoryMonitor:
    """[v2.6.0] SBOM Engine: Generates a Software Bill of Materials for the asset."""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def get_installed_packages(self) -> List[Dict[str, str]]:
        """Queries the OS for installed packages and versions."""
        packages = []
        try:
            if platform.system() == "Windows":
                # Use powershell to get installed software
                cmd = ["powershell", "-WindowStyle", "Hidden", "-Command", 
                       "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | ConvertTo-Json"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.stdout:
                    import json
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        for item in data:
                            if item.get("DisplayName"):
                                packages.append({"name": item["DisplayName"], "version": item.get("DisplayVersion", "unknown")})
                    elif isinstance(data, dict):
                        packages.append({"name": data["DisplayName"], "version": data.get("DisplayVersion", "unknown")})
            
            elif platform.system() == "Linux":
                # Try dpkg (Debian/Ubuntu)
                try:
                    result = subprocess.run(["dpkg-query", "-W", "-f=${Package},${Version}\\n"], capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            if "," in line:
                                name, version = line.split(",", 1)
                                packages.append({"name": name, "version": version})
                except:
                    # Try rpm (CentOS/RHEL)
                    result = subprocess.run(["rpm", "-qa", "--queryformat", "%{NAME},%{VERSION}\\n"], capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.splitlines():
                            if "," in line:
                                name, version = line.split(",", 1)
                                packages.append({"name": name, "version": version})
                                
        except Exception as e:
            logger.error(f"Failed to generate SBOM: {e}")
            
        return packages

    def get_python_packages(self) -> List[Dict[str, str]]:
        """Lists installed Python packages (useful for app-level supply chain security)."""
        packages = []
        try:
            import pkg_resources # type: ignore
            for dist in pkg_resources.working_set:
                packages.append({"name": dist.project_name, "version": dist.version})
        except Exception as e:
            logger.error(f"Python SBOM failed: {e}")
        return packages

# Global instance
inventory_engine = None
