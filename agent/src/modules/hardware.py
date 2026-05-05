import platform # type: ignore
import psutil # type: ignore
import time # type: ignore
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
        # [v1.8.27] Software Inventory Cache & Change Detection
        self._software_cache = None
        self._last_software_scan = 0
        self._software_inventory_hash = None # Store a hash of the names/versions

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

    def check_for_software_changes(self):
        """
        Lightweight check to see if the software inventory has likely changed.
        Returns True if a change is detected.
        """
        try:
            current_apps = []
            system = platform.system()
            
            if system == "Windows":
                 import winreg # type: ignore
                 roots = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
                 ]
                 for hive, subkey in roots:
                     try:
                         key = winreg.OpenKey(hive, subkey)
                         num_subkeys = winreg.QueryInfoKey(key)[0]
                         current_apps.append(str(num_subkeys)) # Just the count is a good proxy
                         winreg.CloseKey(key)
                     except: pass
            elif system == "Linux":
                # Fast count of installed packages
                res = subprocess.run(['dpkg-query', '-f', '${binary:Package}\n', '-W'], capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    current_apps.append(str(len(res.stdout.splitlines())))
            elif system == "Darwin":
                # [v1.8.46] MacOS Software Pivot Detection
                if os.path.exists("/Applications"):
                    app_count = len([a for a in os.listdir("/Applications") if a.endswith(".app")])
                    current_apps.append(str(app_count))
            
            current_hash = "|".join(current_apps)
            if self._software_inventory_hash != current_hash:
                self._software_inventory_hash = current_hash
                return True
            return False
        except:
            return True # Assume changed on error

    def get_installed_software(self, force_scan=False):
        """
        Returns a list of installed software.
        Uses a 6-hour cache to drastically reduce memory/CPU overhead.
        """
        current_time = time.time()
        if not force_scan and self._software_cache and (current_time - self._last_software_scan < 21600):
            return self._software_cache

        software_list = []
        seen_apps = set()
        system = platform.system()
        
        try:
            # [INTERNAL HELPER] Generator for registry entries to save memory during scan
            def _win_registry_items(hive, subkey):
                import winreg # type: ignore
                try:
                    key = winreg.OpenKey(hive, subkey)
                    for i in range(0, winreg.QueryInfoKey(key)[0]):
                        try:
                            skey_name = winreg.EnumKey(key, i)
                            yield skey_name, key
                        except: continue
                    winreg.CloseKey(key)
                except: pass

            if system == "Windows":
                import winreg # type: ignore
                roots = [
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
                ]
                
                for hive, subkey in roots:
                    for skey_name, parent_key in _win_registry_items(hive, subkey):
                        try:
                            skey = winreg.OpenKey(parent_key, skey_name)
                            try:
                                name_tuple = winreg.QueryValueEx(skey, "DisplayName")
                                name = name_tuple[0].strip() if name_tuple[0] else None
                                
                                version_tuple = winreg.QueryValueEx(skey, "DisplayVersion")
                                version = str(version_tuple[0]).strip() if version_tuple[0] else "Unknown"
                                
                                pub_tuple = winreg.QueryValueEx(skey, "Publisher")
                                publisher = str(pub_tuple[0]).strip() if pub_tuple[0] else "Unknown"
                                
                                if name:
                                    unique_key = f"{name}-{version}"
                                    if unique_key not in seen_apps:
                                        seen_apps.add(unique_key)
                                        software_list.append({
                                            "Name": name,
                                            "Version": version,
                                            "Vendor": publisher
                                        })
                            except: pass
                            finally: winreg.CloseKey(skey)
                        except: pass
                    
            elif system == "Linux":
                try:
                    res = subprocess.run(['dpkg-query', '-W', '-f=${Package},${Version},${Maintainer}\\n'], capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            parts = line.split(',')
                            if len(parts) >= 2:
                                name, version = parts[0], parts[1]
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
            
        # Update Cache
        self._software_cache = software_list
        self._last_software_scan = current_time
        return software_list

    def get_complete_specs(self):
        return self.get_specs()

    def get_specs(self):
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

        # [v1.8.37] Hardware Data Privacy (HDP)
        # Obfuscate the physical serial number before cloud persistence
        import hashlib
        raw_serial = self._serial_cache if self._serial_cache else "Unknown"
        hdp_serial = hashlib.sha256(f"HDP_SALT_{raw_serial}".encode()).hexdigest()[:24]

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
            "SerialNumber": f"HDP_{hdp_serial}",
            "GpuModel": self._gpu_cache
        }
