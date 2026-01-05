from .socket_instance import sio

@sio.event
async def connect(sid, environ):
    print(f"[Socket.IO] Client Connected: {sid}")

@sio.event
async def disconnect(sid):
    print(f"[Socket.IO] Client Disconnected: {sid}")

@sio.on('join')
async def on_join(sid, data):
    """
    Allow clients to join specific rooms (e.g. AgentId for remote streaming).
    data: { 'room': 'agent_id' }
    """
    room = data.get('room')
    if room:
        print(f"[Socket.IO] Client {sid} joined room: {room}")
        sio.enter_room(sid, room)
    else:
        print(f"[Socket.IO] Join request missing room from {sid}")
