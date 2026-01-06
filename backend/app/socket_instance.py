import socketio

# Shared Socket.IO Server Instance
# Shared Socket.IO Server Instance
sio = socketio.AsyncServer(
    async_mode='asgi', 
    cors_allowed_origins='*', # Allow all origins for agent/frontend connectivity
    max_http_buffer_size=5*1024*1024, # 5MB limit for large frames
    ping_timeout=60
)
