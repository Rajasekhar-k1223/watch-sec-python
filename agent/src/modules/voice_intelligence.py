import os # type: ignore
import time # type: ignore
import threading # type: ignore

import requests # type: ignore
import traceback # type: ignore
from datetime import datetime # type: ignore
from typing import Optional, Any # type: ignore

class SpeechMonitor:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.policy_enabled = False  # Set by policy engine before starting
        self.notified_user = False
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.sample_rate = 44100
        self.duration = 30  # Seconds per chunk
        
    def start(self):
        if self.running: return
        if not self.policy_enabled:
            print("[Speech] Voice monitoring disabled by policy. Not starting.")
            return
        self.running = True
        self.thread = threading.Thread(target=self._record_loop, daemon=True)
        self.thread.start()
        
        if not self.notified_user:
            # Privacy notification
            print("[Speech] Privacy Notice: Voice monitoring is active for enterprise security.")
            self.notified_user = True

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def _record_loop(self):
        while self.running:
            try:
                import sounddevice as sd # type: ignore
                import wave # type: ignore
                import numpy as np # type: ignore
                
                # 1. Record Audio
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"speech_{timestamp}.wav"
                
                # print(f"[Speech] Recording {self.duration}s...")
                recording = sd.rec(int(self.duration * self.sample_rate), 
                                 samplerate=self.sample_rate, channels=1)
                sd.wait()  # Wait until recording is finished
                
                # 2. Save Temporary File (16-bit PCM)
                # Sounddevice returns float32, we convert to int16 for standard WAV
                audio_int16 = (recording * 32767).astype(np.int16)
                with wave.open(filename, 'w') as wv:
                    wv.setnchannels(1)  # Mono
                    wv.setsampwidth(2)  # 2 bytes for 16-bit
                    wv.setframerate(self.sample_rate)
                    wv.writeframes(audio_int16.tobytes())
                
                # 3. Upload
                self._upload_audio(filename)
                
                # 4. Cleanup
                if os.path.exists(filename):
                    os.remove(filename)
                    
            except Exception as e:
                print(f"[Speech] Error: {e}")
                time.sleep(10) # Backoff

    def _upload_audio(self, filepath):
        if not os.path.exists(filepath): return
        
        # Enforce max chunk size (5MB)
        if os.path.getsize(filepath) > 5 * 1024 * 1024:
            print("[Speech] Chunk exceeds 5MB limit, discarding.")
            return
            
        try:
            if self.data_queue:
                import base64
                with open(filepath, 'rb') as f:
                    audio_b64 = base64.b64encode(f.read()).decode('utf-8')
                    
                self.data_queue.enqueue(
                    endpoint="/api/speech/upload",
                    data={"filename": os.path.basename(filepath), "audio_b64": audio_b64, "agent_id": self.agent_id},
                    priority='normal'
                )
            else:
                print("[Speech] No data_queue available for secure upload.")
        except Exception as e:
            print(f"[Speech] Queueing Failed: {e}")
