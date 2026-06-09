import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)

class LocalSDKServer:
    def __init__(self, socket_path="/tmp/monitorix_sdk.sock"):
        self.socket_path = socket_path
        self.clients = set()
        
    async def start_server(self):
        """Layer 15: Starts the UNIX domain socket for local Federation."""
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
            
        server = await asyncio.start_unix_server(self._handle_client, path=self.socket_path)
        logger.info(f"[SDK] Federation Server listening on {self.socket_path}")
        
        async with server:
            await server.serve_forever()
            
    async def _handle_client(self, reader, writer):
        # In prod, the client must present a Federation Token for authentication
        client_addr = writer.get_extra_info('peername')
        logger.info(f"[SDK] New local connection from {client_addr}")
        self.clients.add(writer)
        
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                # Handle filter requests from client here
        except asyncio.CancelledError:
            pass
        finally:
            logger.info(f"[SDK] Client disconnected: {client_addr}")
            self.clients.remove(writer)
            writer.close()
            
    async def broadcast_event(self, event: dict):
        """Streams an event to all connected SDK clients."""
        if not self.clients:
            return
            
        payload = json.dumps(event) + "\n"
        for writer in list(self.clients):
            try:
                writer.write(payload.encode())
                await writer.drain()
            except Exception as e:
                logger.error(f"[SDK] Failed to send to client: {e}")
                self.clients.remove(writer)
                writer.close()
