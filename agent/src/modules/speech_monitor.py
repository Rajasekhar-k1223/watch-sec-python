import os # type: ignore
import time # type: ignore
import threading # type: ignore
import sounddevice as sd # type: ignore
import wave # type: ignore
import numpy as np # type: ignore
import requests # type: ignore
import traceback # type: ignore
from datetime import datetime # type: ignore
from typing import Optional, Any # type: ignore

class SpeechMonitor:
    def __init__(self, agent_id, api_key, backend_url):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.sample_rate = 44100
        self.duration = 30  # Seconds per chunk
        
    def start(self):
        if self.running: return
        self.running = True
        self.thread = threading.Thread(target=self._record_loop, daemon=True)
        self.thread.start()
        print("[Speech] Started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def _record_loop(self):
        while self.running:
            try:
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
        
        try:
            with open(filepath, 'rb') as f:
                files = {'file': (filepath, f, 'audio/wav')}
                headers = {'X-Tenant-Api-Key': self.api_key}
                # Using the generic upload endpoint or specific speech one
                url = f"{self.backend_url}/api/speech/upload/{self.agent_id}"
                
                requests.post(url, files=files, headers=headers, verify=False, timeout=30)
                # print(f"[Speech] Uploaded {filepath}")
        except Exception as e:
            print(f"[Speech] Upload Failed: {e}")
