import socketio

# Shared Socket.IO Server Instance
# Shared Socket.IO Server Instance
sio = socketio.AsyncServer(
    async_mode='asgi', 
    cors_allowed_origins='*', 
    max_http_buffer_size=5*1024*1024, # 5MB limit for large frames
    ping_timeout=60
)
