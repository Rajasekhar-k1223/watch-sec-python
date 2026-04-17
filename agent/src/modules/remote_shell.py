import os # type: ignore
import platform # type: ignore
if platform.system() != "Windows":
    import pty # type: ignore
else:
    pty = None # type: ignore
import subprocess # type: ignore
import threading # type: ignore
import select # type: ignore
import logging # type: ignore
import json # type: ignore
import asyncio # type: ignore
import hmac
import hashlib
from datetime import datetime # type: ignore

class RemoteShell:
    def __init__(self, sio, agent_id, api_key=None, machine_secret=None, data_queue=None):
        self.sio = sio
        self.agent_id = agent_id
        self.api_key = api_key
        self.machine_secret = machine_secret
        self.data_queue = data_queue
        self.logger = logging.getLogger("RemoteShell")
        self.fd: int | None = None
        self.pid: int | None = None
        self.enabled = False
        
        # Register Handlers
        self.sio.on('ShellInput', self.on_shell_input)
        self.sio.on('ShellResize', self.on_shell_resize)
        
    def set_enabled(self, enabled: bool):
        self.enabled = enabled
        if not enabled:
            self.stop_shell()

    def _report_audit(self, text):
        """Audits shell input for forensic accountability."""
        if not self.data_queue: return
        try:
            payload = {
                "AgentId": self.agent_id,
                "Type": "SHELL_COMMAND",
                "Details": f"Remote Shell Input: {text.strip()}",
                "Timestamp": datetime.utcnow().isoformat()
            }
            self.data_queue.enqueue("/api/events/report", payload, priority='high')
        except: pass

    def start_shell(self):
        if self.pid:
            return

        if pty is None:
            self.logger.warning("PTY Shell is not supported on this platform.")
            return

        self.logger.info("Starting Persistent PTY Shell...")
        
        # Fork the PTY
        self.pid, self.fd = pty.fork()
        
        if self.pid == 0: # Child process
            # Set some environment variables
            os.environ["TERM"] = "xterm-256color"
            os.environ["SHELL"] = "/bin/bash"
            
            # Start the shell
            # Note: os.execlp expects path, arg0, arg1...
            os.execlp("/bin/bash", "/bin/bash", "--login")
        else: # Parent process
            # Start a background thread to read from PTY
            thread = threading.Thread(target=self._read_pty, daemon=True)
            thread.start()

    def _read_pty(self):
        self.logger.info("PTY Read Loop Started")
        while self.pid:
            try:
                # Use select to wait for data
                if self.fd is None: break
                r, _, _ = select.select([self.fd], [], [], 0.1)
                if self.fd in r:
                    data = os.read(self.fd, 1024)
                    if not data:
                        break
                    
                    # Emit to backend
                    asyncio.run_coroutine_threadsafe(
                        self.sio.emit('ShellOutput', {
                            'AgentId': self.agent_id,
                            'Output': data.decode('utf-8', errors='replace')
                        }),
                        self.sio.loop
                    )
            except Exception as e:
                self.logger.error(f"PTY Read Error: {e}")
                break
        
        self.logger.info("PTY Read Loop Finished")
        self.stop_shell()

    async def on_shell_input(self, data):
        if not self.enabled: return
        
        # [v1.8.37] Command Sovereignty: Signature Verification
        text = data.get('input', '')
        timestamp = data.get('timestamp', '')
        signature = data.get('signature', '')

        if not text or not timestamp or not signature:
            self.logger.warning("Unsigned shell input rejected.")
            return

        if not self._verify_signature(text, timestamp, signature):
            self.logger.error("Shell signature verification FAILED. Potential spoofing attempt.")
            self._report_audit("SECURITY CRITICAL: Unauthorized remote shell input signature rejected.")
            return

        # [v1.8.37] Command Sovereignty: Input Validation & Shell Lockdown
        import re
        forbidden_patterns = [
            r"\brm\b", r"\bformat\b", r"\bmkfs\b", r"\bparted\b", r"\bsudo\b", 
            r"\bsu\b", r"\bchmod\b", r"\bchown\b", r"\bpasswd\b", r"\bdel\b",
            r">", r">>", r"|", r"&", r";", r"`", r"\$"
        ]
        
        # We allow simple characters for interactive use, but block command triggers
        # If the input looks like a potential breakout or subversion, we kill the session
        for pattern in forbidden_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                self._report_audit(f"SECURITY VIOLATION: Blocked forbidden pattern '{pattern}' in shell input.")
                self.stop_shell()
                return

        if not self.pid:
            self.start_shell()
            
        # [v1.8.34] Security: Audit shell commands
        self._report_audit(text)
        
        if self.fd is not None:
            try:
                os.write(self.fd, text.encode('utf-8'))
            except Exception as e:
                self.logger.error(f"PTY Write Error: {e}")

    async def on_shell_resize(self, data):
        if not self.fd: return
        import fcntl # type: ignore
        import termios # type: ignore
        import struct # type: ignore
        
        cols = data.get('cols', 80)
        rows = data.get('rows', 24)
        
        # TIOCSWINSZ
        if self.fd is not None:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)

    def stop_shell(self):
        if self.pid is not None and self.fd is not None:
            try:
                os.close(self.fd)
                os.kill(self.pid, 15) # SIGTERM
            except: pass
            self.pid = None
            self.fd = None

    def _verify_signature(self, text, timestamp, signature) -> bool:
        """Verifies the HMAC signature for shell input."""
        if not self.api_key or not self.machine_secret:
            return False
            
        try:
            # Match backend's generate_agent_command_signature logic
            msg_parts = [
                "ShellInput",
                json.dumps({"input": text}, sort_keys=True),
                str(timestamp)
            ]
            message = "|".join(msg_parts).encode('utf-8')
            
            # Derive HMAC Key (Sha256(ApiKey + MachineSecret))
            key = hashlib.sha256(self.api_key.encode() + self.machine_secret).digest()
            
            expected = hmac.new(key, message, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        except Exception as e:
            self.logger.error(f"Signature verify error: {e}")
            return False
