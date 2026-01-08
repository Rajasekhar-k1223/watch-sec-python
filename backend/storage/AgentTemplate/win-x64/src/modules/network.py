import socket
import threading
import time
import concurrent.futures
import psutil
from datetime import datetime
import requests

class NetworkScanner:
    def __init__(self, agent_id, api_key, backend_url):
        self.local_ip = self._get_local_ip()
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.is_running = False
        self._thread = None
        
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
        self._thread = threading.Thread(target=self._monitor_traffic_loop, daemon=True)
        self._thread.start()
        print("[Network] Traffic Analysis Started")

    def stop(self):
        self.is_running = False
        if self._thread:
             self._thread.join(timeout=2)
        print("[Network] Traffic Analysis Stopped")

    def _monitor_traffic_loop(self):
        while self.is_running:
            try:
                self._check_connections()
            except Exception as e:
                print(f"[Network] Error: {e}")
            time.sleep(5) # Check every 5s

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
                    msg = f"Suspicious Connection: {pname} (PID: {pid}) -> {rip}:{rport}"
                    print(f"[DLP] {msg}")
                    self._send_alert("Network Anomaly", msg)
    
    def _send_alert(self, type, details):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Type": type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            requests.post(f"{self.backend_url}/api/events/report", json=payload, timeout=5, verify=False)
        except: pass

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
        base = ".".join(self.local_ip.split(".")[:3])
        target_ips = [f"{base}.{i}" for i in range(1, 20)] 
        
        for ip in target_ips:
            if self.scan_port(ip, 80) or self.scan_port(ip, 443):
                active_hosts.append({"ip": ip, "status": "Active"})
        return active_hosts
