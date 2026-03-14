import subprocess # type: ignore
import platform # type: ignore
import requests # type: ignore

class NetworkUtils:
    @staticmethod
    def get_public_ip():
        try:
            # Multi-provider fallback for public IP
            providers = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
            for url in providers:
                try:
                    resp = requests.get(url, timeout=2)
                    if resp.status_code == 200:
                        return resp.text.strip()
                except: continue
            return "Unknown"
        except:
            return "Unknown"

    @staticmethod
    def get_wifi_ssid():
        try:
            system = platform.system()
            if system == "Windows":
                cmd = "netsh wlan show interfaces"
                output = subprocess.check_output(cmd, shell=True).decode()
                for line in output.split('\n'):
                    if "SSID" in line and "BSSID" not in line:
                        return line.split(":")[1].strip()
            elif system == "Linux":
                cmd = "iwgetid -r"
                return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
            # Fallback
            return "Ethernet/Unknown"
        except:
            return "Wired/Unknown"
