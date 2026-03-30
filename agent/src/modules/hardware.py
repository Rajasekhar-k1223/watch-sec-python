import platform # type: ignore
import psutil # type: ignore
import subprocess # type: ignore
import os # type: ignore
import logging # type: ignore

class HardwareMonitor:
    def __init__(self):
        self.logger = logging.getLogger("HardwareMonitor")
        self.cpu_model = self._get_cpu_model()
        self.cpu_cores = psutil.cpu_count(logical=False)
        self.cpu_threads = psutil.cpu_count(logical=True)
        self.ram_total = psutil.virtual_memory().total
        # [v1.8.21] Resource Optimization Cache
        self._serial_cache = None
        self._gpu_cache = None

    def _get_cpu_model(self):
        system = platform.system()
        try:
            if system == "Windows":
                 import winreg # type: ignore
                 try:
                     key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") # type: ignore
                     model = winreg.QueryValueEx(key, "ProcessorNameString")[0] # type: ignore
                     winreg.CloseKey(key) # type: ignore
                     return model.strip()
                 except:
                     return platform.processor() 
            elif system == "Darwin":
                # sysctl -n machdep.cpu.brand_string
                command = ["sysctl", "-n", "machdep.cpu.brand_string"]
                return subprocess.check_output(command).decode().strip()
            elif system == "Linux":
                # grep -m 1 'model name' /proc/cpuinfo
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":")[1].strip()
            return platform.processor() 
        except Exception:
            return platform.processor() or "Unknown CPU"

    def _get_serial_number(self):
        try:
            if platform.system() == "Windows":
                import subprocess # type: ignore
                cmd = "wmic bios get serialnumber"
                output = subprocess.check_output(cmd, shell=True).decode().split('\n')
                return output[1].strip()
            elif platform.system() == "Linux":
                with open("/sys/class/dmi/id/product_serial", "r") as f:
                    return f.read().strip()
            elif platform.system() == "Darwin":
                import subprocess # type: ignore
                cmd = "ioreg -l | grep IOPlatformSerialNumber"
                output = subprocess.check_output(cmd, shell=True).decode().strip()
                return output.split('=')[-1].strip().strip('"')
        except:
            pass
        return "Unknown"

    def _get_gpu_details(self):
        try:
            if platform.system() == "Windows":
                import subprocess # type: ignore
                cmd = "wmic path win32_VideoController get name"
                output = subprocess.check_output(cmd, shell=True).decode().split('\n')
                return output[1].strip()
            elif platform.system() == "Darwin":
                import subprocess # type: ignore
                cmd = "system_profiler SPDisplaysDataType | grep -i 'Chipset Model'"
                output = subprocess.check_output(cmd, shell=True).decode().split('\n')[0].strip()
                return output.split(':')[-1].strip()
            # GPU detection on Linux is complex (lspci), skipping for now to prioritize Windows stability
            return "Unknown GPU"
        except:
            return "Unknown"

    def get_installed_software(self):
        """
        Returns a list of installed software.
        Format: [{"Name": "App", "Version": "1.0", "Vendor": "Corp"}]
        """
        software_list = []
        seen_apps = set()

        system = platform.system()
        
        try:
            if system == "Windows":
                import winreg # type: ignore
                # Iterate over Uninstall keys (32-bit and 64-bit)
                roots = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"), # type: ignore
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") # type: ignore
                ]
                
                for hive, subkey in roots:
                    try:
                        key = winreg.OpenKey(hive, subkey) # type: ignore
                        for i in range(0, winreg.QueryInfoKey(key)[0]): # type: ignore
                            try:
                                skey_name = winreg.EnumKey(key, i) # type: ignore
                                skey = winreg.OpenKey(key, skey_name) # type: ignore
                                try:
                                    name = winreg.QueryValueEx(skey, "DisplayName")[0] # type: ignore
                                    version = winreg.QueryValueEx(skey, "DisplayVersion")[0] # type: ignore
                                    publisher = winreg.QueryValueEx(skey, "Publisher")[0] # type: ignore
                                    
                                    if name:
                                        # [FIX] Deduplication Logic
                                        # Use Name-Version as unique key
                                        unique_key = f"{name}-{version}"
                                        if unique_key not in seen_apps:
                                            seen_apps.add(unique_key)
                                            software_list.append({
                                                "Name": name.strip(),
                                                "Version": str(version).strip(),
                                                "Vendor": str(publisher).strip()
                                            })
                                except: pass
                                finally: winreg.CloseKey(skey) # type: ignore
                            except: pass
                        winreg.CloseKey(key) # type: ignore
                    except: pass
                    
            elif system == "Linux":
                # Try dpkg (Debian/Ubuntu)
                try:
                    res = subprocess.run(['dpkg-query', '-W', '-f=${Package},${Version},${Maintainer}\\n'], capture_output=True, text=True)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            parts = line.split(',')
                            if len(parts) >= 2:
                                name = parts[0]
                                version = parts[1]
                                unique_key = f"{name}-{version}"
                                if unique_key not in seen_apps:
                                    seen_apps.add(unique_key)
                                    software_list.append({
                                        "Name": name,
                                        "Version": version,
                                        "Vendor": parts[2] if len(parts) > 2 else "Unknown"
                                    })
                except: pass
                
            elif system == "Darwin":
                 # Simple Applications folder scan
                 # Real pkgutil usage is slower
                 try:
                     apps = os.listdir("/Applications")
                     for app in apps:
                         if app.endswith(".app"):
                             name = app.replace(".app", "")
                             if name not in seen_apps:
                                 seen_apps.add(name)
                                 software_list.append({"Name": name, "Version": "Unknown", "Vendor": "Apple/ThirdParty"})
                 except: pass

        except Exception as e:
            self.logger.error(f"Software scan error: {e}")
            
        return software_list

    def get_complete_specs(self):
        mem = psutil.virtual_memory()
        
        # Disk Usage (Root partition)
        try:
            disk = psutil.disk_usage('/')
            disk_total = round(disk.total / (1024**3), 2)
            disk_free = round(disk.free / (1024**3), 2)
        except:
            disk_total = 0
            disk_free = 0

        # [v1.8.21] Use Cached values for expensive shell/WMI calls
        if not self._serial_cache:
            self._serial_cache = self._get_serial_number()
        if not self._gpu_cache:
            self._gpu_cache = self._get_gpu_details()

        return {
            "CpuModel": self.cpu_model,
            "CpuCores": self.cpu_cores,
            "CpuThreads": self.cpu_threads,
            "RamTotalGB": round(mem.total / (1024**3), 2),
            "RamAvailableGB": round(mem.available / (1024**3), 2),
            "RamUsedGB": round(mem.used / (1024**3), 2),
            "RamPercent": mem.percent,
            "DiskTotalGB": disk_total,
            "DiskFreeGB": disk_free,
            "SerialNumber": self._serial_cache,
            "GpuModel": self._gpu_cache
        }
