import asyncio # type: ignore
import logging # type: ignore
import time # type: ignore
import math # type: ignore
from typing import Optional, Any

logger = logging.getLogger("webrtc")


        
class WebRTCManager:
    def __init__(self, sio, agent_id):
        self.sio = sio
        self.agent_id = agent_id
        self.pc: Any = None
        self.track: Any = None
        
    async def start_stream(self):
        print("[WebRTC] Starting Stream...")
        
        # --- LAZY LOAD MEDIA LIBRARIES ---
        import av # type: ignore
        import mss # type: ignore
        import numpy as np # type: ignore
        from fractions import Fraction # type: ignore
        from aiortc import MediaStreamTrack, RTCPeerConnection # type: ignore
        
        class ScreenVideoStreamTrack(MediaStreamTrack):
            kind = "video"
            def __init__(self):
                print("[StreamTrack] Initializing ScreenVideoStreamTrack...", flush=True)
                super().__init__()
                try:
                    self.sct = mss.mss()
                    if len(self.sct.monitors) > 1:
                        self.monitor = self.sct.monitors[1]
                    else:
                        self.monitor = self.sct.monitors[0]
                    print(f"[StreamTrack] MSS Initialized. Monitor: {self.monitor}", flush=True)
                except Exception as e:
                    print(f"[StreamTrack] MSS Init Error: {e}", flush=True)
                    self.monitor = None
                if not self.monitor:
                     print("[StreamTrack] No monitor detected!", flush=True)
                self._timestamp = 0
                self.start_time = None
            async def next_timestamp(self):
                VIDEO_CLOCK_RATE = 90000
                VIDEO_PTIME = 1 / 30
                VIDEO_TIME_BASE = Fraction(1, VIDEO_CLOCK_RATE)
                if getattr(self, 'start_time', None) is None:
                    self.start_time = time.time()
                    self._timestamp = 0
                else:
                    self._timestamp += int(VIDEO_PTIME * VIDEO_CLOCK_RATE)
                return self._timestamp, VIDEO_TIME_BASE
            async def recv(self):
                try:
                    if self.readyState != "live":
                        raise Exception("Track is not live")
                    pts, time_base = await self.next_timestamp()
                    try:
                        sct_img = self.sct.grab(self.monitor)
                    except Exception as e:
                        print(f"[StreamTrack] Grab failed, re-initializing mss: {e}", flush=True)
                        self.sct = mss.mss() # type: ignore
                        if len(self.sct.monitors) > 1:
                            self.monitor = self.sct.monitors[1]
                        else:
                            self.monitor = self.sct.monitors[0]
                        sct_img = self.sct.grab(self.monitor)
                    from PIL import Image # type: ignore
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    
                    # Optimization: Limit resolution to 720p (1280px) to save RAM and Bandwidth
                    if img.width > 1280:
                        ratio = 1280 / img.width
                        new_h = int(img.height * ratio)
                        img = img.resize((1280, new_h), Image.Resampling.BILINEAR)
                        
                    img_np = np.array(img)
                    frame = av.VideoFrame.from_ndarray(img_np, format="rgb24") # type: ignore
                    frame.pts = pts
                    frame.time_base = time_base
                    return frame
                except Exception as e:
                    print(f"[StreamTrack] Final error in recv(): {e}", flush=True)
                    raise e

        if self.pc:
            await self.stop_stream()
            
        self.pc = RTCPeerConnection()
        
        # Add Track & Force Transceiver (SendOnly)
        self.track = ScreenVideoStreamTrack()
        self.pc.addTransceiver(self.track, direction="sendonly")
        
        # Create Offer
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)
        
        # Wait for ICE gathering to complete or timeout
        # aiortc gathers candidates automatically in the background.
        # We can wait for 'complete' state or just proceed if we have candidates.
        count = 0
        while self.pc.iceGatheringState != "complete" and count < 10:
            await asyncio.sleep(0.5)
            count += 1
            
        # Emit Offer
        print(f"[WebRTC] Emitting Offer. Gathering State: {self.pc.iceGatheringState}")
        payload = {
            "target": self.agent_id,
            "sdp": self.pc.localDescription.sdp,
            "type": self.pc.localDescription.type
        }
        await self.sio.emit('webrtc_offer', payload)
        
    async def handle_answer(self, sdp_data):
        print(f"[WebRTC] Received Answer Type: {sdp_data.get('type')}", flush=True)
        
        if not self.pc:
             print("[WebRTC] Ignored Answer: No PC initialized", flush=True)
             return
             
        if self.pc.signalingState == "stable":
             print("[WebRTC] Ignored Answer: Signaling state is already stable", flush=True)
             return

        if self.pc.signalingState == "closed":
             print("[WebRTC] Ignored Answer: PeerConnection is closed", flush=True)
             return

        from aiortc import RTCSessionDescription # type: ignore
        rem_desc = RTCSessionDescription(
            sdp=sdp_data['sdp'],
            type=sdp_data['type']
        )
        
        @self.pc.on("connectionstatechange")
        async def on_connectionstatechange():
            print(f"[WebRTC] Connection State: {self.pc.connectionState}", flush=True)

        @self.pc.on("iceconnectionstatechange")
        async def on_iceconnectionstatechange():
            print(f"[WebRTC] ICE Connection State: {self.pc.iceConnectionState}", flush=True)

        await self.pc.setRemoteDescription(rem_desc)
            
    async def handle_ice_candidate(self, data):
        candidate = data.get('candidate')
        if candidate and self.pc:
            try:
                # Proper parsing of JSON candidate from Frontend
                # Frontend sends: { candidate: "...", sdpMid: "...", sdpMLineIndex: ... }
                cand_str = candidate.get('candidate', '')
                sdp_mid = candidate.get('sdpMid')
                sdp_mline_index = candidate.get('sdpMLineIndex')
                
                # Parse the candidate string to extract fields for aiortc.RTCIceCandidate
                # Format: candidate:foundation component protocol priority ip port typ type ...
                parts = cand_str.split()
                if len(parts) >= 8:
                    foundation = parts[0].split(':')[1]
                    component = int(parts[1])
                    protocol = parts[2]
                    priority = int(parts[3])
                    ip = parts[4]
                    port = int(parts[5])
                    type = parts[7]
                    
                    from aiortc import RTCIceCandidate # type: ignore
                    ice = RTCIceCandidate(
                        component=component,
                        foundation=foundation,
                        ip=ip,
                        port=port,
                        priority=priority,
                        protocol=protocol,
                        type=type,
                        sdpMid=sdp_mid,
                        sdpMLineIndex=sdp_mline_index
                    )
                    await self.pc.addIceCandidate(ice)
                    print(f"[WebRTC] Added ICE Candidate: {ip}:{port} ({protocol})", flush=True)
                else:
                     print(f"[WebRTC] Skipped malformed candidate: {cand_str}", flush=True)
            except Exception as e:
                print(f"[WebRTC] ICE Add Error: {e}", flush=True)
                print(f"[WebRTC] Failed to add ICE: {e}")
            
    async def stop_stream(self):
        print("[WebRTC] Stopping Stream")
        if self.pc:
            await self.pc.close()
            self.pc = None
        if self.track:
            self.track.stop()
            self.track = None
