import socketio # type: ignore
import os # type: ignore

REDIS_URL = os.environ.get("CELERY_BROKER_URL", "redis://172.18.0.8:6379/0")

# 1. Async Server (Used by FastAPI)
sio = socketio.AsyncServer(
    async_mode='asgi', 
    cors_allowed_origins='*',
    client_manager=socketio.AsyncRedisManager(REDIS_URL), # Enable cross-process communication
    max_http_buffer_size=5*1024*1024,
    ping_timeout=60
)

# 2. Sync Manager (Used by Celery Tasks)
sio_sync = socketio.RedisManager(REDIS_URL)
