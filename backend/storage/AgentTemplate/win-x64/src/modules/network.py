import socket
import threading
import concurrent.futures

class NetworkScanner:
    def __init__(self):
        self.local_ip = self._get_local_ip()

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None

    def scan_subnet(self, subnet=None):
        if not subnet:
            # Assume /24 of local IP
            base = ".".join(self.local_ip.split(".")[:3])
            subnet = f"{base}.0/24"
        
        print(f"[Net] Scanning Subnet: {subnet}")
        active_hosts = []
        
        # Simple Logic: Ping widely or scan common ports on neighbors
        # For Python Demo: Just scan neighboring IPs for Port 80/443/22
        base_ip = ".".join(self.local_ip.split(".")[:3])
        
        # Limit scan for speed in demo
        target_ips = [f"{base_ip}.{i}" for i in range(1, 20)] 
        
        for ip in target_ips:
            if self.scan_port(ip, 80) or self.scan_port(ip, 443):
                active_hosts.append({"ip": ip, "status": "Active"})
        
        return active_hosts
