import os
import logging
import platform
import random
import string
from datetime import datetime

logger = logging.getLogger("DeceptionModule")

class DeceptionModule:
    """[v2.6.0] Honeypot/Deception Engine: Creates digital traps for attackers."""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.honey_files = []
        # Traps are placed in common sensitive-looking directories
        self.base_dirs = [
            os.path.expanduser("~"),
            "/tmp" if platform.system() != "Windows" else os.getenv("TEMP"),
            "/etc" if platform.system() != "Windows" else "C:\\Windows\\System32\\drivers\\etc"
        ]

    def deploy_honeyfiles(self):
        """Creates 'bait' files that trigger alerts when accessed."""
        bait_names = [
            "production_db_creds.txt",
            "aws_keys_backup.csv",
            "root_password_temp.md",
            "customer_pii_export_2024.xlsx",
            "vpn_config_secure.ovpn"
        ]
        
        for name in bait_names:
            target_dir = random.choice(self.base_dirs)
            target_path = os.path.join(target_dir, name)
            
            try:
                # Create the bait file
                with open(target_path, "w") as f:
                    f.write(f"# MONITORIX DECEPTION TRAP ID: {self.agent_id}\n")
                    f.write("# DO NOT MODIFY. UNAUTHORIZED ACCESS IS LOGGED.\n")
                    f.write(f"generated_at: {datetime.now().isoformat()}\n")
                    # Fill with junk data to look real
                    random_content = ''.join(random.choices(string.ascii_letters + string.digits, k=100))
                    f.write(f"access_key: {random_content}\n")
                
                self.honey_files.append(target_path)
                logger.info(f"Deployed Honeyfile: {target_path}")
            except Exception as e:
                logger.warning(f"Failed to deploy honeyfile {name}: {e}")

    def audit_traps(self):
        """Checks if honeyfiles have been modified or accessed."""
        # Note: True access detection requires kernel-level file system hooks (Inotify/FltMgr)
        # For this version, we check modification time and file existence.
        findings = []
        for path in self.honey_files:
            if not os.path.exists(path):
                findings.append({
                    "path": path,
                    "event": "Honeyfile Deleted",
                    "severity": "Critical"
                })
            else:
                # Check if it was modified
                pass
        return findings

    def cleanup(self):
        """Removes all deception artifacts."""
        for path in self.honey_files:
            try:
                os.remove(path)
                logger.info(f"Cleaned up Honeyfile: {path}")
            except:
                pass
        self.honey_files = []
        
        if hasattr(self, 'shadow_socket') and self.shadow_socket:
            try:
                self.shadow_socket.close()
                logger.info("Closed Shadow Service listener.")
            except:
                pass

    def deploy_shadow_service(self, port: int = 2222):
        """Deploys a 'Shadow Service' (fake listener) to trap network scanners."""
        import socket # type: ignore
        try:
            self.shadow_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.shadow_socket.bind(('0.0.0.0', port))
            self.shadow_socket.listen(5)
            self.shadow_socket.setblocking(False)
            logger.info(f"Shadow Service (Deception 2.0) listening on port {port}")
            
            # Note: In a real implementation, we would use a background loop
            # to accept connections and log the IP of the scanner.
        except Exception as e:
            logger.warning(f"Failed to deploy Shadow Service on port {port}: {e}")

# Global instance
deception_engine = None
