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

class RemoteShell:
    def __init__(self, sio, agent_id):
        self.sio = sio
        self.agent_id = agent_id
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
                    # We use asyncio.run_coroutine_threadsafe if sio is async
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
        
        if not self.pid:
            self.start_shell()
            
        text = data.get('input')
        if text and self.fd is not None:
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
