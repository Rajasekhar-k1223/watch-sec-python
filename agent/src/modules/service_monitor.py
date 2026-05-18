import subprocess
import platform
import logging
import requests
from typing import Dict, Any, List

logger = logging.getLogger("ServiceMonitor")

class ServiceMonitor:
    """[v2.6.0] Universal Service Monitor: Agnostic tracking for Nginx, Apache, MySQL, etc."""
    
    def __init__(self, critical_services: List[str] = None):
        self.critical_services = critical_services or ["nginx", "apache2", "httpd", "mysql"]
        self.os_type = platform.system()

    def set_monitored_services(self, services: List[str]):
        """Dynamically updates the list of services to track."""
        self.critical_services = services
        logger.info(f"Updated monitored services list: {services}")

    def get_service_statuses(self) -> List[Dict[str, Any]]:
        """Checks the status of critical services across Linux and Windows."""
        results = []
        for service in self.critical_services:
            status = "Unknown"
            try:
                if self.os_type == "Linux":
                    # Use systemctl to check service
                    cmd = ["systemctl", "is-active", service]
                    res = subprocess.run(cmd, capture_output=True, text=True)
                    status = "Running" if res.stdout.strip() == "active" else "Stopped"
                elif self.os_type == "Windows":
                    # Use sc query
                    cmd = ["sc", "query", service]
                    res = subprocess.run(cmd, capture_output=True, text=True)
                    status = "Running" if "RUNNING" in res.stdout else "Stopped"
                
                results.append({"name": service, "status": status})
            except:
                pass # Service might not be installed
        return results

    def check_http_health(self, url: str = "http://localhost:80") -> Dict[str, Any]:
        """Performs a local HTTP health check (Deep Health)."""
        try:
            resp = requests.get(url, timeout=5)
            return {
                "url": url,
                "status": "Healthy" if resp.status_code == 200 else "Unhealthy",
                "code": resp.status_code
            }
        except Exception as e:
            return {
                "url": url,
                "status": "Down",
                "error": str(e)
            }

# Global instance
service_engine = None
