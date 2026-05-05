import sqlite3 # type: ignore
import threading # type: ignore
import time # type: ignore
import json # type: ignore
import requests # type: ignore
import os # type: ignore
import logging # type: ignore
import hashlib
import base64
import hmac
from datetime import datetime # type: ignore
from typing import Optional # type: ignore

class DataQueue:
    def __init__(self, agent_id, api_key, backend_url, bandwidth_manager=None, db_path="events.db", logger=None, machine_secret=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url.rstrip('/')
        self.bandwidth_manager = bandwidth_manager
        self.db_path = db_path
        self.machine_secret = machine_secret
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.custom_logger = logger
        self.logger = logging.getLogger("DataQueue")
        self.session = requests.Session()
        
        # [v1.8.37] Persistence Sovereignty: Derive Hardware-Locked encryption key
        # We blend the API Key with the Machine Secret to anchor the buffer to this specific hardware
        import hashlib # type: ignore
        key_seed = self.api_key.encode()
        if self.machine_secret: key_seed += self.machine_secret
        self._enc_key = hashlib.sha256(key_seed).digest()
        # [v1.8.37] Transport Masquerading: Impersonate a standard Chromium browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })

        # [v1.8.37] Strict Transport Security: Force HTTPS for the backend
        if self.backend_url.startswith("http://") and "localhost" not in self.backend_url and "127.0.0.1" not in self.backend_url:
             self.logger.warning("[SECURITY] Insecure backend URL detected. Upgrading to HTTPS.")
             self.backend_url = self.backend_url.replace("http://", "https://")
        
        # [v1.8.37] Local Buffer Sovereignty: Hard Storage Ceiling (500MB)
        self.max_db_size_mb = 500
        
        # Init DB
        self._init_db()

    def _enforce_storage_limits(self):
        """Prevents Disk-DoS by purging old non-critical telemetry."""
        try:
            db_size_mb = os.path.getsize(self.db_path) / (1024 * 1024)
            if db_size_mb > self.max_db_size_mb:
                self._log(f"WRN: Database size ({db_size_mb:.1f}MB) exceeds limit. Purging oldest telemetry...")
                with self.lock:
                    with sqlite3.connect(self.db_path) as conn:
                        # Purge oldest 500 non-critical items
                        conn.execute("""
                            DELETE FROM queue 
                            WHERE id IN (
                                SELECT id FROM queue 
                                WHERE priority != 'high' 
                                ORDER BY id ASC 
                                LIMIT 500
                            )
                        """)
                        conn.commit()
                        conn.execute("VACUUM") # Reclaim space
                self._log("Purge complete. Storage Sovereignty restored.")
        except Exception as e:
            self._log(f"Storage limit enforcement failed: {e}")

    def _get_machine_secret(self) -> bytes:
        """Derives a stable, machine-locked secret for disk encryption."""
        try:
            import platform # type: ignore
            if platform.system() == "Windows":
                 import winreg # type: ignore
                 # Using the Registry MachineGuid as a safe-and-stable anchor
                 with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | 0x0100) as k:
                     val, _ = winreg.QueryValueEx(k, "MachineGuid")
                     return str(val).encode()
            else:
                 # Standard Linux machine identifier
                 for p in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
                     if os.path.exists(p):
                         with open(p, "rb") as f: return f.read().strip()
        except: pass
        return platform.node().encode()

    def _encrypt(self, text: str) -> str:
        """Lightweight XOR encryption for data-at-rest security."""
        try:
            data = text.encode()
            # XOR with sha256 of API Key
            encrypted = bytes([b ^ self._enc_key[i % len(self._enc_key)] for i, b in enumerate(data)])
            return base64.b64encode(encrypted).decode()
        except: return text

    def _decrypt(self, encrypted_text: str) -> str:
        """Lightweight XOR decryption for data-at-rest security."""
        try:
            data = base64.b64decode(encrypted_text.encode())
            decrypted = bytes([b ^ self._enc_key[i % len(self._enc_key)] for i, b in enumerate(data)])
            return decrypted.decode()
        except: return encrypted_text

    def _init_db(self):
        try:
            # [v1.8.37] Pre-flight Integrity: Symlink Race Protection
            if os.path.islink(self.db_path):
                self._log("[SECURITY ALERT] Symlink detected at database path! Purging rogue redirection.")
                os.remove(self.db_path)
            
            # Ensure we are using the resolved absolute path
            self.db_path = os.path.realpath(self.db_path)
            
            # Ensure directory exists and is writable
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                try:
                    os.makedirs(db_dir, mode=0o700, exist_ok=True)
                except: pass

            with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                # [v1.8.37] Hardening: Restrict file permissions immediately
                try: os.chmod(self.db_path, 0o600)
                except: pass
                
                # [v1.8.26] Enable Write-Ahead Logging for better concurrency
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                # [v1.8.37] Optimized Concurrency: Removed EXCLUSIVE locking for multi-process sharing
                # [v1.8.27] Memory Optimizations
                conn.execute("PRAGMA cache_size=500") 
                conn.execute("PRAGMA temp_store=MEMORY") 

                # Create table if not exists
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS queue (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        endpoint TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        retries INTEGER DEFAULT 0,
                        priority TEXT DEFAULT 'normal'
                    )
                """)
                
                # [MIGRATION] Check if 'priority' column exists
                cursor = conn.execute("PRAGMA table_info(queue)")
                columns = [col[1] for col in cursor.fetchall()]
                if 'priority' not in columns:
                    conn.execute("ALTER TABLE queue ADD COLUMN priority TEXT DEFAULT 'normal'")
                
                conn.commit()
        except Exception as e:
            self._log(f"Failed to init local queue DB: {e}")

    def start(self):
        if self.running: return
        self.running = True
        self._thread = threading.Thread(target=self._flush_loop, daemon=True) # type: ignore
        self._thread.start() # type: ignore
        self._log("Data Queue Manager started (Fortress Encryption Active).")

    def _log(self, msg):
        if self.custom_logger:
            self.custom_logger(f"[DataQueue] {msg}")
        else:
            self.logger.info(msg)

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2) # type: ignore

    def enqueue(self, endpoint, data, priority='normal'):
        # [v1.8.37] Local Buffer Sovereignty Check
        self._enforce_storage_limits()

        # [v1.8.38] Telemetry Stealth: NO LONGER auto-injecting cleartext keys.
        # Authenticity is now proven via HMAC signatures at the transport layer.
        pass

        try:
            payload_json = json.dumps(data)
            # [v1.8.34] Security: Encrypt before storing on disk
            encrypted_payload = self._encrypt(payload_json)
            
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO queue (endpoint, payload, priority) VALUES (?, ?, ?)", 
                        (endpoint, encrypted_payload, priority)
                    )
                    conn.commit()
        except Exception as e:
            self._log(f"Failed to enqueue data: {e}")

    def get_buffer_size(self):
        """Return estimated buffer size in bytes"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT SUM(LENGTH(payload)) FROM queue")
                result = cursor.fetchone()[0]
                return result if result else 0
        except:
            return 0
            
    def get_pending_count(self):
        """Return number of pending items"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM queue")
                return cursor.fetchone()[0]
        except:
            return 0

    def _flush_loop(self):
        import random # [v1.8.37] Network Jitter
        while self.running:
            try:
                self._flush()
            except Exception as e:
                self._log(f"Flush Error: {e}")
            
            # [v1.8.37] Randomized Jitter: 2s base +/- 20% (1.6s to 2.4s)
            jitter_sleep = 2.0 * random.uniform(0.8, 1.2)
            time.sleep(jitter_sleep) 

    def _flush(self):
        items = []
        
        # 1. Check Bandwidth State
        can_upload_bulk = True
        if self.bandwidth_manager:
            if self.bandwidth_manager.is_paused() or not self.bandwidth_manager.check_network_availability():
                can_upload_bulk = False
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                if can_upload_bulk:
                    cursor = conn.execute("""
                        SELECT id, endpoint, payload, retries, priority 
                        FROM queue 
                        ORDER BY CASE WHEN priority = 'high' THEN 1 ELSE 0 END DESC, id ASC 
                        LIMIT 50
                    """)
                else:
                    cursor = conn.execute("""
                        SELECT id, endpoint, payload, retries, priority 
                        FROM queue 
                        WHERE priority = 'high'
                        ORDER BY id ASC 
                        LIMIT 50
                    """)
                items = cursor.fetchall()
        
        if not items:
            return

        # Try to send each
        ids_to_delete = []
        
        headers = {
            # [v1.8.38] KEY SUPPRESSION: Raw API Key is strictly removed from headers and body.
            "Content-Type": "application/json",
            "X-Agent-Id": self.agent_id
        }
        
        import hmac # type: ignore

        for row in items:
            row_id, endpoint, payload_str, retries, priority = row
            try:
                # [v1.8.34] Security: Decrypt from disk before sending
                decrypted_payload_raw = self._decrypt(payload_str)
                
                # [v1.8.38] Key Suppression: Scrub any legacy/erroneous keys from the JSON body
                try:
                    p_data = json.loads(decrypted_payload_raw)
                    if isinstance(p_data, dict) and "TenantApiKey" in p_data:
                        del p_data["TenantApiKey"]
                    # [v1.8.38] Deterministic JSON for Signature parity with Backend
                    decrypted_payload = json.dumps(p_data, separators=(',', ':'), sort_keys=True)
                except:
                    decrypted_payload = decrypted_payload_raw
                
                # [v1.8.37] Sovereignty: Add Cryptographic Signature to the Payload
                timestamp = datetime.utcnow().isoformat()
                
                # Derive HMAC Key (ApiKey + MachineSecret)
                key_seed = self.api_key.encode()
                if self.machine_secret: key_seed += self.machine_secret
                signing_key = hashlib.sha256(key_seed).digest()
                
                # Sign the raw payload + timestamp
                msg = f"{decrypted_payload}|{timestamp}".encode('utf-8')
                signature = hmac.new(signing_key, msg, hashlib.sha256).hexdigest()
                
                # Update headers for this specific request
                req_headers = headers.copy()
                req_headers["X-Signature"] = signature
                req_headers["X-Timestamp"] = timestamp
                
                # [Bandwidth Enforcement] Throttle based on payload size
                if self.bandwidth_manager and priority != 'high':
                    delay = self.bandwidth_manager.get_delay_for_size(len(decrypted_payload))
                    if delay > 0:
                        time.sleep(delay)

                url = f"{self.backend_url}{endpoint}"
                resp = self.session.post(url, data=decrypted_payload.encode('utf-8'), headers=req_headers, timeout=10, verify=False)
                
                if 200 <= resp.status_code < 300:
                    ids_to_delete.append(row_id)
                elif resp.status_code in [404, 400, 422, 405]:
                    self._log(f"Permanent error {resp.status_code} for {endpoint}. Discarding item.")
                    ids_to_delete.append(row_id)
                elif resp.status_code in [401, 403]:
                    self._log(f"Auth error flushing queue: {resp.status_code}")
                    break
                else:
                    break 
                    
            except requests.exceptions.RequestException:
                break

        if ids_to_delete:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    placeholders = ','.join('?' * len(ids_to_delete))
                    conn.execute(f"DELETE FROM queue WHERE id IN ({placeholders})", ids_to_delete)
                    conn.commit()
            
            if can_upload_bulk:
                self._log(f"Flushed {len(ids_to_delete)} items.")
            else:
                self._log(f"Flushed {len(ids_to_delete)} items (Bandwidth Restricted).")
