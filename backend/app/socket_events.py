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
        await sio.enter_room(sid, room)
    else:
        print(f"[Socket.IO] Join request missing room from {sid}")

@sio.on('agent_event')
async def on_agent_event(sid, data):
    """
    Receive generic events from agents (USB, Network, Security)
    and broadcast them to the dashboard.
    """
    # print(f"[Event] {data.get('type')} from {data.get('agent_id')}: {data.get('details')}")
    # Broadcast to 'dashboard' room (Frontend should join this)
    # Also broadcast to specific tenant room if implemented
    await sio.emit('new_alert', data, room='dashboard')
