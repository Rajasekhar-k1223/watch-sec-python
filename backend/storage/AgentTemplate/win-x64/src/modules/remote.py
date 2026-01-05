import threading
import time

try:
    import pyautogui
    PYAUTOGUI_AVAILABLE = True
    # Fail-safe
    pyautogui.FAILSAFE = False
except ImportError:
    PYAUTOGUI_AVAILABLE = False
    print("[Remote] PyAutoGUI not found. Remote control disabled.")

class RemoteController:
    def __init__(self):
        self.screen_width = 0
        self.screen_height = 0
        if PYAUTOGUI_AVAILABLE:
            self.screen_width, self.screen_height = pyautogui.size()

    def handle_input(self, data):
        if not PYAUTOGUI_AVAILABLE:
            return
        
        try:
            cmd_type = data.get('type')
            
            if cmd_type == 'click':
                x_pct = data.get('x', 0)
                y_pct = data.get('y', 0)
                button = data.get('button', 'left')
                
                # Convert % to pixels
                x = int(x_pct * self.screen_width)
                y = int(y_pct * self.screen_height)
                
                pyautogui.click(x, y, button=button)
                
            elif cmd_type == 'keypress':
                key = data.get('key')
                # Map special keys if needed
                if key:
                    pyautogui.press(key)
            
            elif cmd_type == 'type':
                text = data.get('text')
                if text:
                    pyautogui.write(text)
                    
            elif cmd_type == 'scroll':
                dy = data.get('dy', 0)
                pyautogui.scroll(dy * 100) # Scale up
                
        except Exception as e:
            print(f"[Remote] Input Error: {e}")
