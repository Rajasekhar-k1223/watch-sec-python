import psutil # type: ignore
import threading # type: ignore
import time # type: ignore
import json # type: ignore
from datetime import datetime # type: ignore
from agent_core.privacy_utils import PrivacyRedactor

class NetworkMonitor:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None, interval=60):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.interval = interval
        self.running = False
        self.thread = None
        
        # Configuration
        self.upload_threshold_mb = 50 # Alert if > 50MB uploaded in interval
        self.process_cache = {} # pid -> {'up': 0, 'down': 0} needed for delta calculation? 

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop)
        self.thread.daemon = True
        self.thread.start()
        print("[NetworkMonitor] Started")
        self._send_alert("POLICY_APPLIED", "Network Usage Monitoring Active")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def set_enabled(self, enabled: bool):
        if enabled:
            if not self.running:
                self.start()
        else:
            if self.running:
                self.stop()

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
        try:
            # Iterate all processes
            for p in psutil.process_iter(['pid', 'name', 'io_counters']):
                try:
                    # io_counters() is not always available on all platforms for network
                    # On Linux/Windows psutil.Process().io_counters() usually returns DISK io, not net.
                    # Correct way for NET is strictly harder without administrative privileges or specific OS APIs.
                    # However, we can track Open Connections as a proxy for 'Accessing Network'.
                    # For actual BYTES, we might be limited.
                    
                    # Wait, on modern psutil, io_counters() returns disk.
                    # usage of 'net_io_counters' is global.
                    # so the original comment was correct: "psutil per-process network I/O is ... tricky"
                    
                    # Improved Strategy:
                    # We can't easily get bytes-per-process cross-platform without pcap or complex hooks.
                    # BUT we can check open sockets count.
                    pass
                except: pass
        except: pass
        
        # Fallback to Global is acceptable for this scope if per-process bytes are unavailable.
        # But we can at least return the global object to keep the loop working.
        net = psutil.net_io_counters()
        return {'global': {'name': 'Total System', 'sent': net.bytes_sent, 'recv': net.bytes_recv}}

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
                    suspects = []
                    for p in psutil.process_iter(['pid', 'name']):
                        try:
                            connections = p.connections()
                            if len(connections) > 0:
                                suspects.append(p.info['name'])
                        except: pass
                    
                    suspect_list = list(set(suspects))
                    details = {
                        "upload_mb": round(sent_mb, 2),
                        "interval_seconds": self.interval,
                        "suspect_processes": suspect_list[:10] # Top 10 for AI analysis
                    }
                    
                    # [v1.8.34] Security: Redact PII/IP Topology from network alerts
                    redacted_details = PrivacyRedactor.redact_dict(details)
                    self._send_alert("HIGH_NETWORK_USAGE", json.dumps(redacted_details))
                    print(f"[Network] Alert: High Upload ({details['upload_mb']}MB) Suspects: {details['suspect_processes']}")

                last_net = curr_net
            except Exception as e:
                print(f"[Network] Error: {e}")

    def _loop(self):
        self._loop_global()

    def isolate_network(self):
        """Emergency Kill-Switch: Disconnects the machine from the network."""
        import platform # type: ignore
        import subprocess # type: ignore
        
        print(f"[REMEDIATION] ISOLATING NETWORK ON AGENT: {self.agent_id}")
        self._send_alert("NETWORK_ISOLATION_START", "Executing automated network isolation (Kill-Switch).")
        
        os_type = platform.system()
        try:
            if os_type == "Windows":
                # Find the active interface name first
                # netsh interface show interface
                # Then disable it.
                # To be thorough, we can try to disable all 'Enabled' and 'Connected' interfaces.
                cmd = 'powershell -Command "Get-NetAdapter | Where-Object { $_.Status -eq \'Up\' } | Disable-NetAdapter -Confirm:$false"'
                subprocess.run(cmd, shell=True, capture_output=True)
                
            elif os_type == "Linux":
                # Find active interface using ip route
                res = subprocess.run("ip route get 8.8.8.8", shell=True, capture_output=True, text=True)
                if res.returncode == 0:
                    import re # type: ignore
                    match = re.search(r"dev (\S+)", res.stdout)
                    if match:
                        iface = match.group(1)
                        subprocess.run(f"ip link set dev {iface} down", shell=True)
            
            elif os_type == "Darwin":
                # List services and disable them
                cmd = "networksetup -listallnetworkservices | tail -n +2 | xargs -I {} networksetup -setnetworkserviceenabled \"{}\" off"
                subprocess.run(cmd, shell=True)

            self._send_alert("NETWORK_ISOLATED", "Network isolation completed. Host is now offline.")
            return True
        except Exception as e:
            self._send_alert("REMEDIATION_ERROR", f"Failed to isolate network: {e}")
            return False

    def _send_alert(self, event_type, details):
        payload = {
            "AgentId": self.agent_id,
            # [v1.8.38] Telemetry Stealth: Key suppression enforced.
            # Signing handled by DataQueue.
            "Type": event_type,
            "Details": details,
            "Timestamp": datetime.utcnow().isoformat()
        }
        
        if self.data_queue:
            self.data_queue.enqueue("/api/events/report", payload)
        else:
            print(f"[Network] [ERROR] No DataQueue available to report: {event_type}")
