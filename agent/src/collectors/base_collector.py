from abc import ABC, abstractmethod
import logging
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class BaseCollector(ABC):
    def __init__(self, db_queue, config=None):
        self.db = db_queue
        self.config = config or {}
        self.is_running = False

    @abstractmethod
    async def start(self):
        """Bind to the OS and begin yielding events."""
        pass

    @abstractmethod
    async def stop(self):
        """Unhook from the OS gracefully."""
        pass

    def emit(self, event_type: str, payload_data: dict):
        """Standardized method to push to the local SQLite event bus."""
        event_schema = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "os": "python_mock",
            "data": payload_data
        }
        self.db.queue_event(event_type, event_schema)
