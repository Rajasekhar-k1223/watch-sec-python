import os # type: ignore
import platform # type: ignore
import subprocess # type: ignore
import logging # type: ignore

logger = logging.getLogger("AVMonitor")

class AVMonitor:
    """[v2.7.0] Antivirus Integration Engine"""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.os_type = platform.system()

    def trigger_quick_scan(self):
        """Triggers a quick scan using the native OS antivirus."""
        logger.info("[SECURITY] Triggering native AV quick scan...")
        try:
            if self.os_type == "Windows":
                # Trigger Windows Defender Quick Scan using PowerShell
                cmd = ["powershell", "-WindowStyle", "Hidden", "-Command", "Start-MpScan -ScanType QuickScan"]
                subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
                logger.info("[SUCCESS] Windows Defender Quick Scan initiated.")
            elif self.os_type == "Darwin":
                # macOS has XProtect which is continuous. We trigger a log dump check instead.
                logger.info("[INFO] Checking macOS XProtect logs...")
                cmd = ["log", "show", "--predicate", 'subsystem == "com.apple.xprotect"', "--last", "10m"]
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif self.os_type == "Linux":
                # Check for ClamAV
                import shutil
                if shutil.which("clamscan"):
                    logger.info("[SUCCESS] ClamAV detected. Triggering scan...")
                    cmd = ["clamscan", "-r", "-i", "/tmp", "/home", "/var/tmp"]
                    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    logger.info("[INFO] Linux AV integration not natively present (ClamAV missing).")
            return True
        except Exception as e:
            logger.error(f"[ERROR] Failed to trigger AV scan: {e}")
            return False
