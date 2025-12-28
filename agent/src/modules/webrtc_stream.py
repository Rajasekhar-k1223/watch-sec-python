import asyncio
import logging
import time
import math
import av
import mss
import numpy as np
from fractions import Fraction
from aiortc import MediaStreamTrack, RTCPeerConnection, RTCSessionDescription, RTCIceCandidate
from aiortc.contrib.media import MediaPlayer

logger = logging.getLogger("webrtc")

class ScreenVideoStreamTrack(MediaStreamTrack):
    """
    A video stream track that captures the screen using mss.
    """
    kind = "video"

    def __init__(self):
        print("[StreamTrack] Initializing ScreenVideoStreamTrack...", flush=True)
        super().__init__()
        try:
            self.sct = mss.mss()
            self.monitor = self.sct.monitors[1] # Primary monitor
            print(f"[StreamTrack] MSS Initialized. Monitor: {self.monitor}", flush=True)
        except Exception as e:
            print(f"[StreamTrack] MSS Init Error: {e}", flush=True)
        if not self.monitor:
             print("[StreamTrack] No monitor detected!", flush=True)
             
        self._timestamp = 0
        self.start_time = None

    async def next_timestamp(self):
        # Implement custom timestamp logic if base class fails
        VIDEO_CLOCK_RATE = 90000
        VIDEO_PTIME = 1 / 30  # 30fps
        VIDEO_TIME_BASE = Fraction(1, VIDEO_CLOCK_RATE)
        
        if self.start_time is None:
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
            print(f"[StreamTrack] recv() called. PTS: {pts}", flush=True)
            
            # Capture Screen
            sct_img = self.sct.grab(self.monitor)
            img_np = np.array(sct_img)
            frame_bgr = img_np[:, :, :3]

            # Create AV Frame
            frame = av.VideoFrame.from_ndarray(frame_bgr, format="bgr24")
            frame.pts = pts
            frame.time_base = time_base
            
            if pts % 60 == 0:
                print(f"[StreamTrack] Sending Frame: {frame.width}x{frame.height} | PTS: {pts}", flush=True)
            
            return frame
        except Exception as e:
            print(f"[StreamTrack] Error in recv(): {e}", flush=True)
            raise e
        
class WebRTCManager:
    def __init__(self, sio, agent_id):
        self.sio = sio
        self.agent_id = agent_id
        self.pc = None
        self.track = None
        
    async def start_stream(self):
        print("[WebRTC] Starting Stream...")
        if self.pc:
            await self.stop_stream()
            
        self.pc = RTCPeerConnection()
        
        # Add Track & Force Transceiver (SendOnly)
        # addTransceiver creates the sender, so addTrack is redundant/conflicting if we want to set direction explicitly here.
        self.track = ScreenVideoStreamTrack()
        self.pc.addTransceiver(self.track, direction="sendonly")
        
        # ICE Handling
        @self.pc.on("icecandidate")
        async def on_icecandidate(candidate):
            # Note: aiortc doesn't emit 'icecandidate' event like JS?
            # Actually, it gathers automatically. We assume Trickle ICE if implemented, 
            # OR we simply wait for gathering complete (easy mode).
            # For simplicity: Send offer, let aiortc gather candidates in the SDP if possible.
            # But normally we rely on on_ice_gathering_state_change
            pass
            
        # Create Offer
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)
        
        # Emit Offer
        print("[WebRTC] Emitting Offer...")
        print(f"[WebRTC] Offer SDP: {self.pc.localDescription.sdp}", flush=True) # DEBUG SDP
        payload = {
            "target": self.agent_id,
            "sdp": self.pc.localDescription.sdp,
            "type": self.pc.localDescription.type
        }
        await self.sio.emit('webrtc_offer', payload)
        
    async def handle_answer(self, sdp_data):
        print(f"[WebRTC] Received Answer Type: {sdp_data.get('type')}", flush=True)
        print(f"[WebRTC] Answer SDP: {sdp_data.get('sdp')}", flush=True) # DEBUG SDP
        
        if not self.pc:
             print("[WebRTC] Ignored Answer: No PC initialized", flush=True)
             return
             
        if self.pc.signalingState == "stable":
             print("[WebRTC] Ignored Answer: Signaling state is already stable (Duplicate answer?)", flush=True)
             return

        if self.pc.signalingState == "closed":
             print("[WebRTC] Ignored Answer: PeerConnection is closed", flush=True)
             return

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
