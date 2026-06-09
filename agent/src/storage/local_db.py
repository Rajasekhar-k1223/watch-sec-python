import os
import sqlite3
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class LocalDB:
    def __init__(self, db_path="data/events.sqlite"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initializes the local SQLite buffer schemas."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Layer 4: Offline Telemetry Buffer
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telemetry_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Layer 9: Local Policy Cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS policy_cache (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                policy_json TEXT NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Layer 10: Local Command Queue
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_queue (
                command_id TEXT PRIMARY KEY,
                command_type TEXT NOT NULL,
                payload_json TEXT,
                status TEXT DEFAULT 'PENDING',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def queue_event(self, event_type: str, payload: dict):
        """Safely buffers an event to the local disk if offline."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enforce size limits (Layer 4 constraint) - simple FIFO
        cursor.execute('SELECT COUNT(*) FROM telemetry_queue')
        count = cursor.fetchone()[0]
        if count > 100000:
            cursor.execute('DELETE FROM telemetry_queue WHERE id IN (SELECT id FROM telemetry_queue ORDER BY id ASC LIMIT 1000)')
            
        cursor.execute(
            'INSERT INTO telemetry_queue (event_type, payload_json) VALUES (?, ?)',
            (event_type, json.dumps(payload))
        )
        conn.commit()
        conn.close()

    def fetch_pending_events(self, limit=100):
        """Fetches a batch of buffered events to send to the backend."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT id, event_type, payload_json, timestamp FROM telemetry_queue ORDER BY id ASC LIMIT ?', (limit,))
        rows = cursor.fetchall()
        
        events = []
        for row in rows:
            events.append({
                "db_id": row[0],
                "event_type": row[1],
                "payload": json.loads(row[2]),
                "timestamp": row[3]
            })
            
        conn.close()
        return events
        
    def delete_events(self, ids: list):
        """Deletes events from the buffer after successful upload."""
        if not ids:
            return
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        placeholders = ','.join('?' for _ in ids)
        cursor.execute(f'DELETE FROM telemetry_queue WHERE id IN ({placeholders})', ids)
        conn.commit()
        conn.close()
