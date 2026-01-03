
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends
from typing import Dict, List
import json
import logging

# Logger
logger = logging.getLogger("RemoteHub")

class ConnectionManager:
    def __init__(self):
        # Map agent_id -> Agent WebSocket
        self.active_agents: Dict[str, WebSocket] = {}
        # Map agent_id -> List of Admin WebSockets (viewers)
        self.active_admins: Dict[str, List[WebSocket]] = {}

    async def connect_agent(self, websocket: WebSocket, agent_id: str):
        await websocket.accept()
        self.active_agents[agent_id] = websocket
        if agent_id not in self.active_admins:
            self.active_admins[agent_id] = []
        logger.info(f"Agent {agent_id} connected for Remote Control.")

    def disconnect_agent(self, agent_id: str):
        if agent_id in self.active_agents:
            del self.active_agents[agent_id]
        logger.info(f"Agent {agent_id} disconnected.")
        # Notify admins?

    async def connect_admin(self, websocket: WebSocket, agent_id: str):
        await websocket.accept()
        if agent_id not in self.active_admins:
            self.active_admins[agent_id] = []
        self.active_admins[agent_id].append(websocket)
        logger.info(f"Admin connected to view Agent {agent_id}.")

    def disconnect_admin(self, websocket: WebSocket, agent_id: str):
        if agent_id in self.active_admins:
            if websocket in self.active_admins[agent_id]:
                self.active_admins[agent_id].remove(websocket)

    async def broadcast_to_admins(self, agent_id: str, data: bytes):
        # Send screen frame (bytes) to all listening admins
        if agent_id in self.active_admins:
            for connection in self.active_admins[agent_id]:
                try:
                    await connection.send_bytes(data)
                except Exception as e:
                    logger.error(f"Error broadcasting to admin: {e}")

    async def send_to_agent(self, agent_id: str, message: str):
        # Send control command (JSON) to agent
        if agent_id in self.active_agents:
            try:
                await self.active_agents[agent_id].send_text(message)
            except Exception as e:
                logger.error(f"Error sending to agent {agent_id}: {e}")

manager = ConnectionManager()
router = APIRouter()

@router.websocket("/ws/agent/{agent_id}")
async def websocket_endpoint_agent(websocket: WebSocket, agent_id: str, api_key: str = None):
    # TODO: Validate api_key against DB or Tenant config
    if not api_key:
        logger.warning(f"Agent {agent_id} tried to connect without API Key.")
        # await websocket.close(code=1008) # Policy Violation
        # return
    
    logger.info(f"Agent {agent_id} connecting with Key: {api_key[:5]}***")
    await manager.connect_agent(websocket, agent_id)
    try:
        while True:
            # Receive video frame (binary)
            data = await websocket.receive_bytes()
            # Broadcast to all admins watching this agent
            await manager.broadcast_to_admins(agent_id, data)
    except WebSocketDisconnect:
        manager.disconnect_agent(agent_id)
    except Exception as e:
        logger.error(f"Agent WS Error: {e}")
        manager.disconnect_agent(agent_id)

@router.websocket("/ws/admin/{agent_id}")
async def websocket_endpoint_admin(websocket: WebSocket, agent_id: str):
    # TODO: Add token validation
    await manager.connect_admin(websocket, agent_id)
    try:
        while True:
            # Receive control commands (mouse/keyboard) from Admin
            data = await websocket.receive_text()
            # Forward to Agent
            await manager.send_to_agent(agent_id, data)
    except WebSocketDisconnect:
        manager.disconnect_admin(websocket, agent_id)
    except Exception as e:
        logger.error(f"Admin WS Error: {e}")
        manager.disconnect_admin(websocket, agent_id)
