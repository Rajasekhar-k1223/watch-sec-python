import psutil
import threading
import time
import requests
import json
from datetime import datetime

class NetworkMonitor:
    def __init__(self, agent_id, api_key, backend_url, interval=60):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.interval = interval
        self.running = False
        self.thread = None
        
        # Configuration
        self.upload_threshold_mb = 50 # Alert if > 50MB uploaded in interval
        self.process_cache = {} # pid -> {'up': 0, 'down': 0} needed for delta calculation? 
        # Actually psutil returns cumulative counters. We need diffs.
        
        # Robust Session
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop)
        self.thread.daemon = True
        self.thread.start()
        print("[Network] Monitor Started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def _loop(self):
        # Initial Snapshot
        self.process_cache = self._snapshot_processes()
        
        while self.running:
            time.sleep(self.interval)
            if not self.running: break
            
            try:
                current_snapshot = self._snapshot_processes()
                high_usage_processes = []
                
                # Calculate Deltas
                for pid, counters in current_snapshot.items():
                    if pid in self.process_cache:
                        prev = self.process_cache[pid]
                        # Calc delta (bytes)
                        sent_delta = counters['sent'] - prev['sent']
                        recv_delta = counters['recv'] - prev['recv']
                        
                        sent_mb = sent_delta / (1024 * 1024)
                        
                        # Threshold Check (Exfiltration Logic)
                        if sent_mb > self.upload_threshold_mb:
                            high_usage_processes.append({
                                "process": counters['name'],
                                "pid": pid,
                                "upload_mb": round(sent_mb, 2),
                                "download_mb": round(recv_delta / (1024 * 1024), 2)
                            })
                            
                self.process_cache = current_snapshot
                
                # Report if we found bandwidth hogs
                if high_usage_processes:
                    self._send_alert("HIGH_NETWORK_USAGE", f"Processes exceeding upload limit: {high_usage_processes}")
                    print(f"[Network] Detected High Usage: {high_usage_processes}")
                    
            except Exception as e:
                print(f"[Network] Loop Error: {e}")

    def _snapshot_processes(self):
        """
        Returns { pid: {'name': str, 'sent': int, 'recv': int} }
        """
        snapshot = {}
        for p in psutil.process_iter(['name', 'io_counters']):
            try:
                # io_counters might be None if permission denied or no IO
                if p.info['io_counters']:
                    # Linux uses read_bytes/write_bytes for disk, but connection io is harder per proc without root/nethogs
                    # Wait, psutil.Process().io_counters() is usually DISK I/O on Windows/Linux?
                    # Let's verify documentation.
                    # psutil.net_io_counters() is global.
                    # Per-process network IO is NOT available in standard psutil cross-platform easily?
                    # On Windows, psutil.Process.io_counters() returns Read/Write/Other bytes (Disk usually).
                    # Actually, for Network per process, on Windows specifically, we might need WMI or `netstat` logic or `pcap`.
                    # Standard psutil DOES NOT provide per-process network counters directly on Windows usually.
                    # Workaround: For "MVP", we can monitor Global Traffic spikes.
                    # OR we leave the io_counters as "Data I/O" which includes Disk, which often correlates to exfiltration (copying to USB/Network Share).
                    # Let's check if we can get *connections* and assume traffic? No.
                    
                    # Correction: Tracking "Data Exfiltration" via generic IO is better than nothing.
                    # If a process writes 5GB, it's either Disk or Network (depending on OS implementation layers).
                    # On Windows, IO Counters usually aggregate.
                    
                    # For strict Network per process, we'd need a packet filter driver (WinPcap) which is too heavy.
                    # I will track GLOBAL bandwidth and list ACTIVE connections of new processes.
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # fallback to GLOBAL for now as it's reliable
        net = psutil.net_io_counters()
        return {'global': {'sent': net.bytes_sent, 'recv': net.bytes_recv}}

    def _loop_global(self):
        # Let's refine the loop to use GLOBAL stats + Connection list for context
        last_net = psutil.net_io_counters()
        
        while self.running:
            time.sleep(self.interval)
            try:
                curr_net = psutil.net_io_counters()
                sent_delta = curr_net.bytes_sent - last_net.bytes_sent
                recv_delta = curr_net.bytes_recv - last_net.bytes_recv
                
                sent_mb = sent_delta / (1024 * 1024)
                
                if sent_mb > self.upload_threshold_mb:
                    # High Bandwidth Detected. Who is doing it?
                    # Minimal heuristics: Find processes with ESTABLISHED connections to non-local IPs
                    suspects = []
                    for p in psutil.process_iter(['pid', 'name']):
                        try:
                            # This is expensive, so only do it on alert
                            connections = p.connections()
                            if len(connections) > 0:
                                suspects.append(p.info['name'])
                        except: pass
                    
                    # Top 5 suspects (naive)
                    suspect_str = ", ".join(list(set(suspects))[:5])
                    msg = f"High Upload Detected: {round(sent_mb, 2)}MB in last {self.interval}s. Active Network Apps: {suspect_str}..."
                    self._send_alert("HIGH_NETWORK_USAGE", msg)
                    print(f"[Network] Alert: {msg}")

                last_net = curr_net
            except Exception as e:
                print(f"[Network] Error: {e}")

    def _loop(self):
        self._loop_global()

    def _send_alert(self, event_type, details):
        payload = {
            "AgentId": self.agent_id,
            "TenantApiKey": self.api_key,
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        try:
            self.session.post(f"{self.backend_url}/api/events/report", json=payload, timeout=10, verify=False)
        except Exception as e:
            print(f"[Network] Failed to send alert: {e}")
