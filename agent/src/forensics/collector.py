import os
import json
import hashlib
import zipfile
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class ForensicCollector:
    def __init__(self, evidence_dir="evidence"):
        self.evidence_dir = evidence_dir
        os.makedirs(self.evidence_dir, exist_ok=True)
        
    def collect_volatile_data(self, agent_id: str, trigger_reason: str):
        """Layer 11: Collects system state and generates a signed manifest."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M")
        pkg_name = f"{agent_id}_{timestamp}"
        pkg_path = os.path.join(self.evidence_dir, pkg_name)
        os.makedirs(pkg_path, exist_ok=True)
        
        # 1. Collect Mock Data
        self._dump_process_tree(os.path.join(pkg_path, "process_tree.json"))
        
        # 2. Hash files and build Manifest
        manifest = self._build_manifest(agent_id, trigger_reason, pkg_path)
        with open(os.path.join(pkg_path, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
            
        # 3. Zip package
        zip_path = f"{pkg_path}.zip"
        self._zip_directory(pkg_path, zip_path)
        logger.info(f"[FORENSICS] Evidence package created: {zip_path}")
        
    def _dump_process_tree(self, filepath: str):
        # In prod, this uses psutil to dump all running processes
        with open(filepath, "w") as f:
            json.dump([{"pid": 1, "name": "systemd"}], f)
            
    def _build_manifest(self, agent_id: str, trigger: str, pkg_path: str) -> dict:
        chain_of_custody = []
        for root, _, files in os.walk(pkg_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                chain_of_custody.append({
                    "filename": file,
                    "sha256": file_hash,
                    "size_bytes": os.path.getsize(file_path)
                })
                
        return {
            "agent_id": agent_id,
            "trigger": trigger,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "chain_of_custody": chain_of_custody
            # Note: The agent signature would be added here in prod
        }

    def _zip_directory(self, folder_path: str, zip_path: str):
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)
