
import sqlite3 # type: ignore
import threading # type: ignore
import time # type: ignore
import json # type: ignore
import requests # type: ignore
import os # type: ignore
import logging # type: ignore
from datetime import datetime # type: ignore
from typing import Optional # type: ignore

class DataQueue:
    def __init__(self, agent_id, api_key, backend_url, bandwidth_manager=None, db_path="events.db", logger=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url.rstrip('/')
        self.bandwidth_manager = bandwidth_manager
        self.db_path = db_path
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
        self.custom_logger = logger
        self.logger = logging.getLogger("DataQueue")
        self.session = requests.Session()
        
        # Init DB
        self._init_db()

    def _init_db(self):
        try:
            # Ensure directory exists and is writable
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            if db_dir and not os.path.exists(db_dir):
                try:
                    os.makedirs(db_dir, exist_ok=True)
                except: pass

            with sqlite3.connect(self.db_path) as conn:
                # [v1.8.26] Enable Write-Ahead Logging for better concurrency
                # Synchronous=NORMAL is recommended for WAL mode for better performance.
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")

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
                
                # [MIGRATION] Check if 'priority' column exists, add if not
                cursor = conn.execute("PRAGMA table_info(queue)")
                columns = [col[1] for col in cursor.fetchall()]
                if 'priority' not in columns:
                    self._log("Migrating DB: Adding priority column...")
                    conn.execute("ALTER TABLE queue ADD COLUMN priority TEXT DEFAULT 'normal'")
                
                conn.commit()
        except Exception as e:
            self._log(f"Failed to init local queue DB: {e}")

    def start(self):
        if self.running: return
        self.running = True
        self._thread = threading.Thread(target=self._flush_loop, daemon=True) # type: ignore
        self._thread.start() # type: ignore
        self._log("Data Queue Manager started (Priority Mode).")

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
        """
        Add data to the local queue.
        endpoint: relative URL (e.g. '/api/agent/activity')
        data: dict payload
        priority: 'normal' or 'high' (high bypasses bandwidth pause)
        """
        # [NEW] Auto-inject API Key if missing
        if isinstance(data, dict) and "TenantApiKey" not in data:
            data["TenantApiKey"] = self.api_key

        try:
            payload_json = json.dumps(data)
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        "INSERT INTO queue (endpoint, payload, priority) VALUES (?, ?, ?)", 
                        (endpoint, payload_json, priority)
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
        while self.running:
            try:
                self._flush()
            except Exception as e:
                self._log(f"Flush Error: {e}")
            
            time.sleep(2) # [v1.8.19] Reduced from 5s for better responsiveness

    def _flush(self):
        items = []
        # self._log("Debug: _flush loop tick")
        
        # 1. Check Bandwidth State
        can_upload_bulk = True
        if self.bandwidth_manager:
            # If paused or network busy, we only allow HIGH priority
            if self.bandwidth_manager.is_paused() or not self.bandwidth_manager.check_network_availability():
                can_upload_bulk = False
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                if can_upload_bulk:
                    # Fetch everything (High + Normal), prioritized by High first
                    # Ordering: High Priority first (descending), then FIFO (id asc)
                    # We map 'high' to 1, others to 0 for sorting
                    cursor = conn.execute("""
                        SELECT id, endpoint, payload, retries, priority 
                        FROM queue 
                        ORDER BY CASE WHEN priority = 'high' THEN 1 ELSE 0 END DESC, id ASC 
                        LIMIT 50
                    """)
                else:
                    # ONLY Fetch High Priority
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
            "X-Tenant-Api-Key": self.api_key, 
            "Content-Type": "application/json",
            "X-Agent-Id": self.agent_id
        }

        for row in items:
            row_id, endpoint, payload_str, retries, priority = row
            try:
                # [Bandwidth Enforcement] Throttle based on payload size
                if self.bandwidth_manager and priority != 'high':
                    delay = self.bandwidth_manager.get_delay_for_size(len(payload_str))
                    if delay > 0:
                        time.sleep(delay)

                url = f"{self.backend_url}{endpoint}"
                resp = self.session.post(url, data=payload_str, headers=headers, timeout=5, verify=False)
                
                if 200 <= resp.status_code < 300:
                    ids_to_delete.append(row_id)
                elif resp.status_code in [404, 400, 422, 405]:
                    # Permanent Client Error. Discard.
                    self._log(f"Permanent error {resp.status_code} for {endpoint}. Discarding item.")
                    ids_to_delete.append(row_id)
                elif resp.status_code in [401, 403]:
                    self._log(f"Auth error flushing queue: {resp.status_code}")
                    break
                else:
                    break # Server error (500), stop batch
                    
            except requests.exceptions.RequestException:
                break

        # Delete sent items in the SAME connection used for the read (single lock acquisition)
        if ids_to_delete:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    placeholders = ','.join('?' * len(ids_to_delete))
                    conn.execute(f"DELETE FROM queue WHERE id IN ({placeholders})", ids_to_delete)
                    conn.commit()
            
            if can_upload_bulk:
                self._log(f"Flushed {len(ids_to_delete)} items.")
            else:
                self._log(f"Flushed {len(ids_to_delete)} CRITICAL items (Bandwidth Restricted).")
