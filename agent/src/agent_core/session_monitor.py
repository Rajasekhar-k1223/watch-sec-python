import platform # type: ignore
from typing import Any # type: ignore
import time # type: ignore
import logging # type: ignore
import threading # type: ignore

class SessionMonitor:
    def __init__(self, on_lock=None, on_unlock=None, logger=None):
        self.on_lock = on_lock
        self.on_unlock = on_unlock
        self.logger = logger or print
        self.running = False
        self.thread: Any = None
        self.is_locked = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        self.logger("[SessionMonitor] Started.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

    def _monitor_loop(self):
        if platform.system() == "Windows":
            self._windows_monitor()
        else:
            # For Linux/Mac, we can ignore or use basic idle checks
            # but usually screenshort doesn't "fail" with popups there.
            pass

    def _windows_monitor(self):
        import ctypes # type: ignore
        user32 = ctypes.windll.user32 # type: ignore
        
        while self.running:
            try:
                # OpenInputDesktop check is a reliable way to detect Lock/Secure Desktop
                # If it returns 0, the desktop is likely locked or showing a secure prompt (UAC)
                h_desktop = user32.OpenInputDesktop(0, False, 0x0100) # READ_CONTROL
                
                currently_locked = (h_desktop == 0)
                
                if h_desktop:
                    user32.CloseDesktop(h_desktop)

                if currently_locked and not self.is_locked:
                    self.is_locked = True
                    self.logger("[SessionMonitor] System Locked detected")
                    if self.on_lock: self.on_lock()
                    
                elif not currently_locked and self.is_locked:
                    self.is_locked = False
                    self.logger("[SessionMonitor] System Unlocked detected")
                    if self.on_unlock: self.on_unlock()

            except Exception as e:
                self.logger(f"[SessionMonitor] Windows Error: {e}")
            
            time.sleep(5) # Lightweight polling
