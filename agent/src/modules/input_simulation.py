import logging # type: ignore
import json # type: ignore
from pynput.mouse import Button, Controller as MouseController # type: ignore
from pynput.keyboard import Key, Controller as KeyboardController # type: ignore
import mss # type: ignore

class InputSimulator:
    def __init__(self):
        self.logger = logging.getLogger("InputSimulator")
        self.mouse = MouseController()
        self.keyboard = KeyboardController()
        self.sct = mss.mss()
        
        # Cache screen size
        monitor = self.sct.monitors[1]
        self.screen_width = monitor['width']
        self.screen_height = monitor['height']
        self.logger.info(f"InputSimulator initialized. Screen: {self.screen_width}x{self.screen_height}")

    def handle_input(self, data):
        try:
            cmd_type = data.get("type")
            if not cmd_type: return

            if cmd_type == "mousemove":
                x = int(data["x"] * self.screen_width)
                y = int(data["y"] * self.screen_height)
                self.mouse.position = (x, y)
                
            elif cmd_type == "click":
                x = int(data["x"] * self.screen_width)
                y = int(data["y"] * self.screen_height)
                button_name = data.get("button", "left")
                
                # Move first
                self.mouse.position = (x, y)
                
                button = Button.left
                if button_name == "right": button = Button.right
                elif button_name == "middle": button = Button.middle
                
                self.mouse.click(button)
                
            elif cmd_type == "keypress":
                key_name = data.get("key")
                if not key_name: return
                
                # Handle special keys
                key = self._get_key(key_name)
                if key:
                    self.keyboard.press(key)
                    self.keyboard.release(key)
                else:
                    self.keyboard.type(key_name)

            elif cmd_type == "lock":
                self._lock_workstation()

            elif cmd_type == "curtain":
                enabled = data.get("enabled", False)
                self._toggle_curtain_mode(enabled)

        except Exception as e:
            self.logger.error(f"Input Simulation Error: {e}")

    def _lock_workstation(self):
        import platform # type: ignore
        import subprocess # type: ignore
        try:
            if platform.system() == "Windows":
                import ctypes # type: ignore
                ctypes.windll.user32.LockWorkStation() # type: ignore
            elif platform.system() == "Linux":
                subprocess.run(["xdg-screensaver", "lock"], check=False)
            elif platform.system() == "Darwin":
                cmd = ["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"]
                subprocess.run(cmd, check=False)
            self.logger.info(f"Workstation lock executed on {platform.system()}")
        except Exception as e:
            self.logger.error(f"Failed to lock workstation: {e}")

    def _toggle_curtain_mode(self, enable):
        """Blocks local input and turns off monitor."""
        import platform # type: ignore
        import subprocess # type: ignore
        try:
            if platform.system() == "Windows":
                import ctypes # type: ignore
                # 1. Block Input (Requires Admin)
                ctypes.windll.user32.BlockInput(enable) # type: ignore
                # 2. Toggle Monitor (2 = Off, -1 = On)
                HWND_BROADCAST = 0xFFFF
                WM_SYSCOMMAND = 0x0112
                SC_MONITORPOWER = 0xF170
                power_setting = 2 if enable else -1
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, power_setting) # type: ignore
            elif platform.system() == 'Linux':
                if enable:
                    subprocess.run(["xset", "dpms", "force", "off"], check=False)
                else:
                    subprocess.run(["xset", "dpms", "force", "on"], check=False)
                    subprocess.run(["xset", "s", "reset"], check=False)
            elif platform.system() == 'Darwin':
                if enable:
                    subprocess.run(["pmset", "displaysleepnow"], check=False)
                else:
                    subprocess.run(["caffeinate", "-u", "-t", "1"], check=False)
            self.logger.info(f"Curtain Mode {'enabled' if enable else 'disabled'} on {platform.system()}")
        except Exception as e:
            self.logger.error(f"Failed to toggle curtain mode: {e}")

    def _get_key(self, name):
        # Map common names to pynput Keys
        name = name.lower()
        mapping = {
            "enter": Key.enter,
            "space": Key.space,
            "backspace": Key.backspace,
            "tab": Key.tab,
            "esc": Key.esc,
            "escape": Key.esc,
            "up": Key.up,
            "down": Key.down,
            "left": Key.left,
            "right": Key.right,
            "shift": Key.shift,
            "ctrl": Key.ctrl,
            "alt": Key.alt,
            "meta": Key.cmd,
            "cmd": Key.cmd,
            "win": Key.cmd,
            "f1": Key.f1, "f2": Key.f2, "f3": Key.f3, "f4": Key.f4,
            "f5": Key.f5, "f6": Key.f6, "f7": Key.f7, "f8": Key.f8,
            "f9": Key.f9, "f10": Key.f10, "f11": Key.f11, "f12": Key.f12,
        }
        return mapping.get(name)
