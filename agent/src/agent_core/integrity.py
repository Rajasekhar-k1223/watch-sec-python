import os
import hashlib
import json
import hmac
import platform

class IntegrityChecker:
    """[v2.0.0] Monitorix Agent Self-Integrity Verification"""
    
    def __init__(self, base_dir, machine_secret):
        self.base_dir = base_dir
        self.machine_secret = machine_secret
        self.manifest_path = os.path.join(base_dir, "manifest.json")

    def verify_agent_integrity(self):
        """Verifies all critical files against a signed manifest."""
        if not os.path.exists(self.manifest_path):
            print("[SECURITY] Manifest missing. Initializing First-Run Baseline...")
            self.generate_manifest()
            return True
        
        try:
            with open(self.manifest_path, "r") as f:
                manifest = json.load(f)
            
            # Verify Manifest Signature
            signature = manifest.get("signature")
            files = manifest.get("files", {})
            
            # Message to verify
            msg = json.dumps(files, sort_keys=True).encode()
            expected_sig = hmac.new(self.machine_secret, msg, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(signature, expected_sig):
                print("[SECURITY ALERT] Manifest signature mismatch! Agent may be tampered.")
                return False
            
            # Verify each file
            for rel_path, expected_hash in files.items():
                abs_path = os.path.join(self.base_dir, rel_path)
                if not os.path.exists(abs_path):
                    print(f"[SECURITY ALERT] Missing critical file: {rel_path}")
                    return False
                
                with open(abs_path, "rb") as f:
                    actual_hash = hashlib.sha256(f.read()).hexdigest()
                
                if actual_hash != expected_hash:
                    print(f"[SECURITY ALERT] File integrity violation: {rel_path}")
                    return False
                    
            print("[SECURITY] Integrity Verification: PASSED")
            return True
        except Exception as e:
            print(f"[SECURITY] Integrity Verification FAILED: {e}")
            return False

    def generate_manifest(self):
        """Generates a new signed manifest based on current file states."""
        critical_files = [
            "src/main.py",
            "src/agent_core/remediation_handler.py",
            "src/agent_core/privacy_utils.py",
            "config.json"
        ]
        
        files_hash = {}
        for f in critical_files:
            p = os.path.join(self.base_dir, f)
            if os.path.exists(p):
                with open(p, "rb") as f_obj:
                    files_hash[f] = hashlib.sha256(f_obj.read()).hexdigest()
        
        msg = json.dumps(files_hash, sort_keys=True).encode()
        signature = hmac.new(self.machine_secret, msg, hashlib.sha256).hexdigest()
        
        manifest = {
            "version": "v2.0.0",
            "files": files_hash,
            "signature": signature,
            "timestamp": platform.node()
        }
        
        with open(self.manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)
        
        # Protect manifest
        try:
            if platform.system() != "Windows":
                os.chmod(self.manifest_path, 0o600)
        except: pass
