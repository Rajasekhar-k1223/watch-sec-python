import os
from clickhouse_driver import Client

class ClickHouseClient:
    def __init__(self):
        self.client = None
        self.url = os.getenv("CLICKHOUSE_URL", "clickhouse://localhost:9000/monitorix")
        
    def connect(self):
        try:
            # Parse simple clickhouse://user:pass@host:port/db URL
            host = "localhost"
            port = 9000
            user = "default"
            password = ""
            database = "monitorix"
            
            if "@" in self.url:
                creds, address = self.url.replace("clickhouse://", "").split("@")
                user, password = creds.split(":")
                host, port_db = address.split(":")
                port = int(port_db.split("/")[0])
                database = port_db.split("/")[1]
                
            self.client = Client(
                host=host,
                port=port,
                user=user,
                password=password,
                database=database
            )
            
            # Test connection
            self.client.execute("SELECT 1")
            
            print(f"[ClickHouse] Connected to {host}:{port}")
            self.init_schema()
        except Exception as e:
            print(f"[ClickHouse] Failed to connect: {e}")
            self.client = None

    def init_schema(self):
        if not self.client:
            return
            
        # Create foundational MergeTree table for high-throughput telemetry
        self.client.execute('''
            CREATE TABLE IF NOT EXISTS monitorix_telemetry_raw (
                event_id UUID,
                agent_id String,
                tenant_id String,
                event_type LowCardinality(String),
                timestamp DateTime64(3),
                payload String
            ) ENGINE = MergeTree()
            ORDER BY (tenant_id, agent_id, timestamp)
        ''')
        print("[ClickHouse] Schema initialized")

    def insert_telemetry(self, records: list):
        if not self.client:
            return False
            
        try:
            # records should be a list of tuples matching the schema
            self.client.execute(
                'INSERT INTO monitorix_telemetry_raw (event_id, agent_id, tenant_id, event_type, timestamp, payload) VALUES', 
                records
            )
            return True
        except Exception as e:
            print(f"[ClickHouse] Insert error: {e}")
            return False

    def search_telemetry(self, keyword: str, limit: int = 100):
        if not self.client:
            return []
            
        try:
            # positionCaseInsensitive is extremely fast for unstructured JSON payload scanning
            # clickhouse-driver binds variables with %(var)s syntax
            query = """
                SELECT event_id, agent_id, event_type, timestamp, payload 
                FROM monitorix_telemetry_raw 
                WHERE positionCaseInsensitive(payload, %(keyword)s) > 0 
                ORDER BY timestamp DESC 
                LIMIT %(limit)s
            """
            result = self.client.execute(query, {"keyword": keyword, "limit": limit})
            return result
        except Exception as e:
            print(f"[ClickHouse] Search error: {e}")
            return []

clickhouse_db = ClickHouseClient()
