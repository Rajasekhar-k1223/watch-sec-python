import os # type: ignore
import logging # type: ignore
import base64 # type: ignore
import platform # type: ignore
from datetime import datetime # type: ignore

class FileManager:
    def __init__(self, sio, agent_id, api_key=None, machine_secret=None):
        self.sio = sio
        self.agent_id = agent_id
        self.api_key = api_key
        self.machine_secret = machine_secret
        self.logger = logging.getLogger("FileManager")
        
        # [v1.8.34] Security: Root Jailing
        # Define directories that the agent is allowed to access
        self.safe_roots = [
            os.path.abspath(os.getcwd()),
            os.path.expanduser("~")
        ]
        if platform.system() == "Windows":
             self.safe_roots.append(os.environ.get("ProgramData", "C:\\ProgramData"))
        
        # Register Handlers
        self.sio.on('ListFiles', self.on_list_files)
        self.sio.on('DownloadFile', self.on_download_file)
        self.sio.on('DeleteFile', self.on_delete_file)
        self.enabled = True

    def _is_safe_path(self, path: str) -> bool:
        """Verifies if the path is within the allowed safe roots and NOT in the system blocklist."""
        try:
            # 1. Resolve to true physical path to prevent traversal/symlink bypass
            target = os.path.realpath(os.path.expanduser(path)).lower()
            
            # 2. Global System Blocklist (Anti-Exfiltration)
            forbidden_markers = [
                "windows/system32", "windows/syswow64", "windows/config", 
                "/etc/shadow", "/etc/passwd", "/proc/self", "/dev/mem",
                "config.json", "events.db", "agent_payload.dat", ".ssh/id_rsa",
                "monitorix_service.log", "id_ed25519"
            ]
            for marker in forbidden_markers:
                if marker in target.replace("\\", "/"):
                    self.logger.warning(f"SECURITY BLOCK: Attempt to access forbidden path: {target}")
                    return False

            # 3. Sandbox Jail Check
            for root in self.safe_roots:
                if target.startswith(os.path.realpath(root).lower()):
                    return True
            
            return False
        except: return False

    def _verify_signature(self, action: str, params: dict, timestamp: str, signature: str) -> bool:
        """[v1.8.37] Cryptographic Verification for Administrative File Actions."""
        if not self.api_key or not self.machine_secret:
            return False
            
        import hmac, hashlib, json # type: ignore
        try:
            # Match backend's generate_agent_command_signature logic
            msg_parts = [
                str(action),
                json.dumps(params, sort_keys=True),
                str(timestamp)
            ]
            message = "|".join(msg_parts).encode('utf-8')
            
            # Derive HMAC Key (Sha256(ApiKey + MachineSecret))
            # machine_secret is bytes from main.py
            key = hashlib.sha256(self.api_key.encode() + self.machine_secret).digest()
            
            expected = hmac.new(key, message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        except Exception as e:
            self.logger.error(f"FileManager signature verify error: {e}")
            return False

    async def on_list_files(self, data):
        if not self.enabled: return
        
        path = data.get('path', '.')
        if path == '': path = '.'
        
        # [v1.8.37] Security: Signature & Sandbox Check
        timestamp = data.get('timestamp', '')
        signature = data.get('signature', '')
        if not self._verify_signature("ListFiles", {"path": path}, timestamp, signature):
             self.logger.warning(f"REJECTED: Unsigned ListFiles attempt for {path}")
             return

        if not self._is_safe_path(path):
             self.logger.warning(f"BLOCKED: Attempt to list file outside sandbox: {path}")
             await self.sio.emit('FileList', {
                "AgentId": self.agent_id,
                "path": path,
                "items": [],
                "error": "ACCESS_DENIED: Path is outside the security sandbox."
            })
             return

        abs_path = os.path.abspath(path)
        
        try:
            items = []
            if os.path.exists(abs_path) and os.path.isdir(abs_path):
                for entry in os.scandir(abs_path):
                    try:
                        info = entry.stat()
                        items.append({
                            "name": entry.name,
                            "type": "directory" if entry.is_dir() else "file",
                            "size": info.st_size,
                            "mtime": datetime.fromtimestamp(info.st_mtime).isoformat()
                        })
                    except Exception: continue
            
            await self.sio.emit('FileList', {
                "AgentId": self.agent_id,
                "path": abs_path,
                "items": items
            })
        except Exception as e:
            self.logger.error(f"Error listing files in {abs_path}: {e}")
            await self.sio.emit('FileList', {
                "AgentId": self.agent_id,
                "path": abs_path,
                "items": [],
                "error": str(e)
            })

    async def on_download_file(self, data):
        if not self.enabled: return
        path = data.get('path')
        if not path: return
        
        # [v1.8.37] Security: Signature & Sandbox Check
        timestamp = data.get('timestamp', '')
        signature = data.get('signature', '')
        if not self._verify_signature("DownloadFile", {"path": path}, timestamp, signature):
             self.logger.warning(f"REJECTED: Unsigned DownloadFile attempt for {path}")
             return

        if not self._is_safe_path(path):
             self.logger.warning(f"BLOCKED: Attempt to download file outside sandbox: {path}")
             await self.sio.emit('FileContent', {
                "AgentId": self.agent_id,
                "path": path,
                "error": "ACCESS_DENIED: Path is outside the security sandbox."
            })
             return

        abs_path = os.path.abspath(path)
        try:
            if os.path.exists(abs_path) and os.path.isfile(abs_path):
                # Check file size before reading (limit to 10MB for WebSocket safety)
                if os.path.getsize(abs_path) > 10 * 1024 * 1024:
                     await self.sio.emit('FileContent', {
                        "AgentId": self.agent_id,
                        "path": abs_path,
                        "error": "File too large (Max 10MB)"
                    })
                     return

                with open(abs_path, "rb") as f:
                    content = base64.b64encode(f.read()).decode('utf-8')
                
                await self.sio.emit('FileContent', {
                    "AgentId": self.agent_id,
                    "path": abs_path,
                    "name": os.path.basename(abs_path),
                    "content": content
                })
        except Exception as e:
            self.logger.error(f"Error reading file {abs_path}: {e}")
            await self.sio.emit('FileContent', {
                "AgentId": self.agent_id,
                "path": abs_path,
                "error": str(e)
            })

    async def on_delete_file(self, data):
        if not self.enabled: return
        path = data.get('path')
        if not path: return
        
        # [v1.8.37] Security: Signature & Sandbox Check
        timestamp = data.get('timestamp', '')
        signature = data.get('signature', '')
        if not self._verify_signature("DeleteFile", {"path": path}, timestamp, signature):
             self.logger.warning(f"REJECTED: Unsigned DeleteFile attempt for {path}")
             return

        if not self._is_safe_path(path):
             self.logger.warning(f"BLOCKED: Attempt to delete file outside sandbox: {path}")
             return

        abs_path = os.path.abspath(path)
        try:
            if os.path.exists(abs_path):
                if os.path.isfile(abs_path):
                    os.remove(abs_path)
                else:
                    import shutil # type: ignore
                    shutil.rmtree(abs_path)
                
                # Refresh list
                await self.on_list_files({"path": os.path.dirname(abs_path)})
        except Exception as e:
            self.logger.error(f"Error deleting {abs_path}: {e}")
