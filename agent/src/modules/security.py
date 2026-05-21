import psutil # type: ignore
import os # type: ignore
import signal # type: ignore
import platform # type: ignore

class ProcessSecurity:
    def get_running_processes(self):
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'username']):
            try:
                procs.append(p.info)
            except:
                pass
        return procs

    def kill_process_by_pid(self, pid: int):
        try:
            p = psutil.Process(pid)
            p.terminate()
            return True, f"Terminated PID {pid}"
        except psutil.NoSuchProcess:
            return False, "Process not found"
        except psutil.AccessDenied:
            return False, "Access Denied"
        except Exception as e:
            return False, str(e)

    def kill_process_by_name(self, name: str):
        killed_count = 0
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if p.info['name'] and name.lower() in p.info['name'].lower():
                    p.terminate()
                    killed_count += 1
            except:
                pass
        return killed_count > 0, f"Killed {killed_count} instances of {name}"

    def get_installed_software(self):
        software_list = []
        if os.name == 'nt':
            try:
                import winreg # type: ignore
                # Scan Registry Keys (Both 32 and 64 bit)
                keys = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                ]
                for key_path in keys:
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key: # type: ignore
                            for i in range(0, winreg.QueryInfoKey(key)[0]): # type: ignore
                                subkey_name = winreg.EnumKey(key, i) # type: ignore
                                with winreg.OpenKey(key, subkey_name) as subkey: # type: ignore
                                    try:
                                        name = winreg.QueryValueEx(subkey, "DisplayName")[0] # type: ignore
                                        version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] # type: ignore
                                        software_list.append({"Name": str(name), "Version": str(version)})
                                    except:
                                        pass
                    except:
                        pass
            except Exception as e:
                print(f"[Sec] Registry Error: {e}")
        elif platform.system() == 'Darwin':
            import subprocess # type: ignore
            try:
                # system_profiler SPApplicationsDataType -json
                cmd = ["system_profiler", "SPApplicationsDataType", "-json"]
                output = subprocess.check_output(cmd).decode()
                import json # type: ignore
                data = json.loads(output)
                apps = data.get('SPApplicationsDataType', [])
                for app in apps:
                    name = app.get('_name', 'Unknown')
                    version = app.get('version', 'Unknown')
                    software_list.append({"Name": name, "Version": version})
            except Exception as e:
                print(f"[Sec] Mac Software Scan Error: {e}")

        else:
            # Linux (Debian/RPM)
            import subprocess # type: ignore
            try:
                # Try dpkg
                cmd = ["dpkg-query", "-W", "-f=${Package} ${Version}\n"]
                output = subprocess.check_output(cmd).decode()
                for line in output.split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            software_list.append({"Name": parts[0], "Version": parts[1]})
            except:
                pass
        
        return software_list
