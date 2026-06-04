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
        self._bios_cache = None

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

        return "Unknown"

    def _get_serial_number(self):
        try:
            if platform.system() == "Windows":
                import subprocess # type: ignore
                cmd = ["wmic", "bios", "get", "serialnumber"]
                output = subprocess.check_output(cmd).decode().split('\n')
                return output[1].strip()
            elif platform.system() == "Linux":
                with open("/sys/class/dmi/id/product_serial", "r") as f:
                    return f.read().strip()
            elif platform.system() == "Darwin":
                import subprocess # type: ignore
                cmd = ["ioreg", "-l"]
                output_all = subprocess.check_output(cmd).decode()
                output = [line for line in output_all.splitlines() if "IOPlatformSerialNumber" in line][0].strip()
                return output.split('=')[-1].strip().strip('"')
        except:
            pass
        return "Unknown"

    def _get_bios_info(self):
        """[v2.6.5] Collects detailed BIOS/UEFI telemetry."""
        bios = {"Vendor": "Unknown", "Version": "Unknown", "ReleaseDate": "Unknown", "SecureBoot": "Unknown"}
        try:
            system = platform.system()
            if system == "Windows":
                # Get BIOS details via WMIC
                cmd = ["wmic", "bios", "get", "manufacturer,version,releasedate", "/format:list"]
                output = subprocess.check_output(cmd).decode().split('\n')
                for line in output:
                    if "Manufacturer=" in line: bios["Vendor"] = line.split('=')[1].strip()
                    if "Version=" in line: bios["Version"] = line.split('=')[1].strip()
                    if "ReleaseDate=" in line: bios["ReleaseDate"] = line.split('=')[1].strip()[:8]
                
                # Check Secure Boot status via PowerShell
                try:
                    sb_cmd = ["powershell", "-Command", "Confirm-SecureBootUEFI"]
                    sb_res = subprocess.check_output(sb_cmd, stderr=subprocess.DEVNULL).decode().strip()
                    bios["SecureBoot"] = "Enabled" if sb_res.lower() == "true" else "Disabled"
                except:
                    bios["SecureBoot"] = "Not Supported / Hidden"
            
            elif system == "Linux":
                # Vendor/Version from /sys/class/dmi/id/
                paths = {
                    "Vendor": "/sys/class/dmi/id/bios_vendor",
                    "Version": "/sys/class/dmi/id/bios_version",
                    "ReleaseDate": "/sys/class/dmi/id/bios_date"
                }
                for key, path in paths.items():
                    if os.path.exists(path):
                        with open(path, "r") as f: bios[key] = f.read().strip()
                
                # Secure Boot check (Requires mokutil or efivarfs)
                if os.path.exists("/sys/firmware/efi/efivars"):
                    bios["SecureBoot"] = "UEFI Mode"
                    # Try to detect if SecureBoot is actually ON
                    try:
                        import glob
                        # Check for the SecureBoot variable in efivars
                        if glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"):
                             bios["SecureBoot"] = "Enabled (EFI)"
                    except: pass
            
            elif system == "Darwin":
                # Apple doesn't have BIOS, but it has Boot ROM / Firmware Version
                cmd = ["system_profiler", "SPHardwareDataType"]
                output_all = subprocess.check_output(cmd).decode()
                output = [line for line in output_all.splitlines() if "Boot ROM Version" in line][0].strip()
                bios["Version"] = output.split(':')[-1].strip()
                bios["Vendor"] = "Apple Inc."
                bios["SecureBoot"] = "T2/M-Series Secured"

        except Exception as e:
            self.logger.error(f"BIOS collection error: {e}")
            
        return bios

    def _get_gpu_details(self):
        try:
            if platform.system() == "Windows":
                import subprocess # type: ignore
                cmd = ["wmic", "path", "win32_VideoController", "get", "name"]
                output = subprocess.check_output(cmd).decode().split('\n')
                return output[1].strip()
            elif platform.system() == "Darwin":
                import subprocess # type: ignore
                cmd = ["system_profiler", "SPDisplaysDataType"]
                output_all = subprocess.check_output(cmd).decode()
                output_lines = [line for line in output_all.splitlines() if "Chipset Model" in line]
                output = output_lines[0].strip() if output_lines else "Unknown"
                return output.split(':')[-1].strip()
            # GPU detection on Linux is complex (lspci), skipping for now to prioritize Windows stability
            return "Unknown GPU"
        except:
            return "Unknown"

    def check_disk_encryption(self):
        """[v3.0.0] MDM Disk Encryption check."""
        try:
            system = platform.system()
            if system == "Windows":
                # Check BitLocker status
                cmd = ["powershell", "-Command", "Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object -ExpandProperty ProtectionStatus"]
                res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
                return res.lower() == "on"
            elif system == "Darwin":
                # Check FileVault status
                cmd = ["fdesetup", "status"]
                res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
                return "FileVault is On" in res
            elif system == "Linux":
                # Simple check for LUKS on root
                cmd = ["lsblk", "-f"]
                res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
                return "crypto_LUKS" in res
        except Exception as e:
            self.logger.error(f"Disk Encryption check error: {e}")
        return False

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
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
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
                # 1. DPKG (Debian/Ubuntu)
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
                                    software_list.append({"Name": name, "Version": version, "Vendor": parts[2] if len(parts) > 2 else "Unknown"})
                except: pass
                
                # 2. RPM (CentOS/RHEL)
                try:
                    res = subprocess.run(['rpm', '-qa', '--queryformat', '%{NAME},%{VERSION},%{VENDOR}\\n'], capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            parts = line.split(',')
                            if len(parts) >= 2:
                                name, version = parts[0], parts[1]
                                unique_key = f"{name}-{version}"
                                if unique_key not in seen_apps:
                                    seen_apps.add(unique_key)
                                    software_list.append({"Name": name, "Version": version, "Vendor": parts[2] if len(parts) > 2 else "Unknown"})
                except: pass

                # 3. Snap (Ubuntu Ecosystem)
                try:
                    res = subprocess.run(['snap', 'list'], capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        lines = res.stdout.splitlines()
                        for line in lines[1:]: # Skip header
                            parts = line.split()
                            if len(parts) >= 2:
                                name, version = parts[0], parts[1]
                                unique_key = f"{name}-{version}"
                                if unique_key not in seen_apps:
                                    seen_apps.add(unique_key)
                                    software_list.append({"Name": name, "Version": version, "Vendor": parts[4] if len(parts) > 4 else "SnapCraft"})
                except: pass

                # 4. Flatpak (Modern Linux Desktops)
                try:
                    res = subprocess.run(['flatpak', 'list', '--columns=name,version,origin'], capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            parts = line.split('\t')
                            if len(parts) >= 2:
                                name, version = parts[0].strip(), parts[1].strip()
                                unique_key = f"{name}-{version}"
                                if name and unique_key not in seen_apps:
                                    seen_apps.add(unique_key)
                                    software_list.append({"Name": name, "Version": version or "Unknown", "Vendor": parts[2].strip() if len(parts) > 2 else "Flatpak"})
                except: pass
                
            elif system == "Darwin":
                 try:
                     import json
                     res = subprocess.run(['system_profiler', 'SPApplicationsDataType', '-json'], capture_output=True, text=True, timeout=30)
                     if res.returncode == 0:
                         data = json.loads(res.stdout)
                         apps = data.get('SPApplicationsDataType', [])
                         for app in apps:
                             name = app.get('_name', 'Unknown')
                             version = app.get('version', 'Unknown')
                             vendor = app.get('obtained_from', 'Unknown')
                             unique_key = f"{name}-{version}"
                             if unique_key not in seen_apps:
                                 seen_apps.add(unique_key)
                                 software_list.append({"Name": name, "Version": version, "Vendor": vendor})
                 except: pass

        except Exception as e:
            self.logger.error(f"Software scan error: {e}")
            
        # Explicit checks for CLI tools that might not appear in system package managers
        cli_tools = [
            ("Python", ["python3", "--version"]),
            ("Python", ["python", "--version"]),
            ("Node.js", ["node", "--version"]),
            ("Docker", ["docker", "--version"]),
            ("Go", ["go", "version"]),
            ("Java", ["java", "-version"])
        ]
        
        for tool_name, cmd in cli_tools:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if res.returncode == 0:
                    out = res.stdout.strip() or res.stderr.strip()
                    # e.g., "Python 3.10.12", "Docker version 24.0.5, build ced0996"
                    if tool_name == "Docker" and "version" in out.lower():
                        version = out.split()[2] if len(out.split()) > 2 else out
                    else:
                        version = parts[1] if len(parts) > 1 else out
                        
                    version = version.replace(',', '')
                    
                    if not any(s['Name'].lower() == tool_name.lower() for s in software_list):
                        seen_apps.add(f"{tool_name}-{version}")
                        software_list.append({
                            "Name": tool_name,
                            "Version": version,
                            "Vendor": "Open Source",
                            "Type": "CLI"
                        })
            except: pass

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
            "GpuModel": self._gpu_cache,
            "Bios": self._get_bios_info(),
            "DiskEncrypted": self.check_disk_encryption()
        }

    def _get_tpm_id(self):
        """Attempts to retrieve a unique TPM-backed identifier."""
        try:
            system = platform.system()
            if system == "Windows":
                # [SEC v2.1.0] Extract TPM Endorsement Key hash via PowerShell
                cmd = ["powershell", "-Command", "Get-Tpm | Select-Object -ExpandProperty EndorsementKey"]
                output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
                if output: return output
            elif system == "Linux":
                # Check for TPM 2.0 device ID
                tpm_path = "/sys/class/tpm/tpm0/device/id"
                if os.path.exists(tpm_path):
                    with open(tpm_path, "r") as f:
                        return f.read().strip()
        except: pass
        return None

    def get_hardware_fingerprint(self):
        """[v2.1.0] High-fidelity hardware fingerprint with TPM-root-of-trust support."""
        import hashlib
        identifiers = []
        
        # 1. TPM ID (Highest Priority / Strongest Root of Trust)
        tpm_id = self._get_tpm_id()
        if tpm_id:
            identifiers.append(f"TPM_{tpm_id}")
        
        # 2. Motherboard Serial
        if not self._serial_cache:
            self._serial_cache = self._get_serial_number()
        identifiers.append(self._serial_cache if self._serial_cache else "Unknown")
        
        # 3. CPU Model & Cores
        identifiers.append(self.cpu_model)
        identifiers.append(str(self.cpu_cores))
        
        # 4. MAC Addresses
        try:
            addrs = psutil.net_if_addrs()
            for _, snics in sorted(addrs.items()):
                for snic in snics:
                    if snic.family == psutil.AF_LINK:
                        identifiers.append(snic.address)
        except: pass
        
        raw_id = "|".join(identifiers)
        return hashlib.sha256(raw_id.encode()).hexdigest()
