import socketio
import asyncio
import time

# Configurations
BACKEND_URL = "http://localhost:8000"
AGENT_ID = "TEST-AGENT-001"
FRONTEND_TOKEN = "test-token"

# 1. Mock Agent Client
agent_sio = socketio.AsyncClient()

@agent_sio.event
async def connect():
    print("[Agent] Connected")
    await agent_sio.emit('join_room', {'room': AGENT_ID})
    print(f"[Agent] Joined Room: {AGENT_ID}")

@agent_sio.on('start_stream')
async def on_start_stream(data):
    print(f"[Agent] RECEIVED COMMAND: start_stream from {data}")
    # Simulate sending a frame back
    print("[Agent] Sending stream_frame...")
    await agent_sio.emit('stream_frame', {'agentId': AGENT_ID, 'image': 'BASE64_FAKE_IMAGE_DATA'})

@agent_sio.on('stop_stream')
async def on_stop_stream(data):
    print("[Agent] RECEIVED COMMAND: stop_stream")

# 2. Mock Frontend Client
frontend_sio = socketio.AsyncClient()

@frontend_sio.event
async def connect():
    print("[Frontend] Connected")
    await frontend_sio.emit('join_room', {'room': AGENT_ID})
    print(f"[Frontend] Joined Room: {AGENT_ID}")

@frontend_sio.on('receive_stream_frame')
async def on_frame(data):
    print(f"[Frontend] SUCCESS! Received Frame from {data.get('agentId')}. Data Len: {len(data.get('image'))}")
    # Test Complete
    print("--- TEST PASSED: Full Round Trip Successful ---")
    
async def run_test():
    try:
        # Start Connections
        await agent_sio.connect(BACKEND_URL)
        await frontend_sio.connect(BACKEND_URL)
        
        # Give time to join rooms
        await asyncio.sleep(1)
        
        # Frontend triggers Stream
        print("[Frontend] Emitting start_stream...")
        await frontend_sio.emit('start_stream', {'agentId': AGENT_ID})
        
        # Wait for reply
        await asyncio.sleep(2)
        
        await agent_sio.disconnect()
        await frontend_sio.disconnect()
        
    except Exception as e:
        print(f"TEST FAILED: {e}")

if __name__ == "__main__":
    asyncio.run(run_test())
