
import os # type: ignore
import logging # type: ignore
import base64 # type: ignore
from datetime import datetime # type: ignore

class FileManager:
    def __init__(self, sio, agent_id):
        self.sio = sio
        self.agent_id = agent_id
        self.logger = logging.getLogger("FileManager")
        
        # Register Handlers
        self.sio.on('ListFiles', self.on_list_files)
        self.sio.on('DownloadFile', self.on_download_file)
        self.sio.on('DeleteFile', self.on_delete_file)
        self.enabled = True

    async def on_list_files(self, data):
        if not self.enabled: return
        
        path = data.get('path', '.')
        if path == '': path = '.'
        
        # Security: Normalize path
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
