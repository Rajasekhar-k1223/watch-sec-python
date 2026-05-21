import subprocess # type: ignore
import platform # type: ignore
import requests # type: ignore

class NetworkUtils:
    _public_ip_cache = (None, 0) # (IP, Timestamp)

    @classmethod
    def get_public_ip(cls):
        import time # type: ignore
        now = time.time()
        if cls._public_ip_cache[0] and (now - cls._public_ip_cache[1] < 600):
            return cls._public_ip_cache[0]

        try:
            providers = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
            for url in providers:
                try:
                    # [v1.8.29] Security Hardening: SSL verification ENABLED for external lookups
                    resp = requests.get(url, timeout=5, verify=True)
                    if resp.status_code == 200:
                        ip = resp.text.strip()
                        cls._public_ip_cache = (ip, now)
                        return ip
                except: continue
            return cls._public_ip_cache[0] or "Unknown"
        except:
            return cls._public_ip_cache[0] or "Unknown"

    @staticmethod
    def get_wifi_ssid():
        try:
            system = platform.system()
            if system == "Windows":
                cmd = ["netsh", "wlan", "show", "interfaces"]
                output = subprocess.check_output(cmd).decode()
                for line in output.split('\n'):
                    if "SSID" in line and "BSSID" not in line:
                        return line.split(":")[1].strip()
            elif system == "Linux":
                cmd = ["iwgetid", "-r"]
                return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            # Fallback
            return "Ethernet/Unknown"
        except:
            return "Wired/Unknown"
