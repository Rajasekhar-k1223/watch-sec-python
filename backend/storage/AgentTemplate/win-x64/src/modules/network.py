import socket
import threading
import time
import logging
import psutil

class NetworkMonitor:
    def __init__(self, sio_client, agent_id):
        self.sio = sio_client
        self.agent_id = agent_id
        self.logger = logging.getLogger("NetworkMonitor")
        self.running = False
        self.thread = None
        self.known_connections = set()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self.logger.info("Network Monitor Started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _monitor_loop(self):
        # Initialize baseline
        self._scan_connections(initial=True)
        
        while self.running:
            try:
                self._scan_connections()
                time.sleep(5) # Poll every 5 seconds
            except Exception as e:
                self.logger.error(f"Network Loop Error: {e}")
                time.sleep(5)

    def _scan_connections(self, initial=False):
        try:
            # key mechanism: (fd, family, type, laddr, raddr, status, pid)
            # We focus on ESTABLISHED connections to remote hosts
            current_conns = psutil.net_connections(kind='inet')
            
            # Filter for meaningful outbound connections (ignore localhost)
            active_remote_conns = []
            for c in current_conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    ip = c.raddr.ip
                    if not ip.startswith("127."):
                        active_remote_conns.append((ip, c.raddr.port, c.pid))

            current_set = set(active_remote_conns)
            
            if not initial:
                new_conns = current_set - self.known_connections
                for ip, port, pid in new_conns:
                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name()
                    except:
                        proc_name = "unknown"
                        
                    self.logger.info(f"New Connection: {proc_name} -> {ip}:{port}")
                    self.sio.emit("agent_event", {
                        "agent_id": self.agent_id,
                        "type": "network_alert",
                        "category": "new_connection",
                        "details": f"Process '{proc_name}' connected to {ip}:{port}",
                        "severity": "info",
                        "timestamp": time.time()
                    })

            self.known_connections = current_set
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")

    # Legacy Scanner Methods (kept if needed for manual scans)
    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
