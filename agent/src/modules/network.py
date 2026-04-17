import socket # type: ignore
import threading # type: ignore
import time # type: ignore
import concurrent.futures # type: ignore
import psutil # type: ignore
from datetime import datetime # type: ignore
from typing import Optional # type: ignore
import requests # type: ignore
from agent_core.privacy_utils import PrivacyRedactor

class NetworkScanner:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None):
        self.local_ip = self._get_local_ip()
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        
        # Whitelist
        self.safe_ports = [80, 443, 53, 445, 139, 135, 3389, 5000, 8000, 8080, 22] # Common ports
        self.safe_procs = ["chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe", "python.exe", "code.exe"]
        self.known_connections = set() # (pid, remote_ip, remote_port)

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    def start(self):
        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_traffic_loop, daemon=True) # type: ignore
        self._thread.start() # type: ignore
        print("[Network] Traffic Analysis Started")

    def stop(self):
        self.is_running = False
        if self._thread:
             self._thread.join(timeout=2) # type: ignore
        print("[Network] Traffic Analysis Stopped")

    def _monitor_traffic_loop(self):
        import random # [v1.8.37] Network Jitter
        while self.is_running:
            try:
                self._check_connections()
            except Exception as e:
                print(f"[Network] Error: {e}")
            
            # [v1.8.37] Randomized Jitter: 5s base +/- 20% (4s to 6s)
            time.sleep(5 * random.uniform(0.8, 1.2)) 

    def _check_connections(self):
        # iterate Inet connections
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                rip = conn.raddr.ip
                rport = conn.raddr.port
                pid = conn.pid or 0
                
                # Basic Whitelist Skip
                if rport in self.safe_ports:
                     continue
                
                # Check Process Name
                try:
                    p = psutil.Process(pid)
                    pname = p.name()
                except:
                    pname = "Unknown"
                    
                if pname.lower() in self.safe_procs:
                     continue
                     
                # Detect New Suspicious Connection
                conn_key = (pid, rip, rport)
                if conn_key not in self.known_connections:
                    self.known_connections.add(conn_key)
                    # Alert!
                    msg = PrivacyRedactor.redact_text(f"Suspicious Connection: {pname} (PID: {pid}) -> {rip}:{rport}")
                    print(f"[DLP] {msg}")
                    self._send_alert("Network Anomaly", msg)
    
    def _send_alert(self, type, details):
        payload = {
            "AgentId": self.agent_id,
            # [v1.8.38] Telemetry Stealth: Key suppression enforced.
            # Signing handled by DataQueue.
            "Type": type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        if self.data_queue:
            self.data_queue.enqueue("/api/events/report", payload)
        else:
            print(f"[Network] [ERROR] No DataQueue available to report anomaly: {type}")

    # --- Subnet Scan (Legacy/OnDemand) ---
    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    def scan_subnet(self):
        print(f"[Net] Scanning Subnet...")
        active_hosts = []
        base = ".".join(self.local_ip.split(".")[:3]) # type: ignore
        target_ips = [f"{base}.{i}" for i in range(1, 20)] 
        
        for ip in target_ips:
            if self.scan_port(ip, 80) or self.scan_port(ip, 443):
                # [v1.8.37] Topology Redaction at the source
                redacted_ip = PrivacyRedactor.redact_text(ip)
                active_hosts.append({"ip": redacted_ip, "status": "Active"})
        return active_hosts
