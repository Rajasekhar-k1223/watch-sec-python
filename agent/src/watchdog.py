#!/usr/bin/env python3
import sys
import os
import time
import subprocess
import platform

def log(msg):
    # Try to write to a basic log without heavy imports
    try:
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "watchdog.log")
        with open(log_path, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except:
        pass

def is_process_alive(pid):
    """Check if a process is alive in a lightweight, cross-platform way."""
    try:
        if platform.system() == "Windows":
            import ctypes
            # PROCESS_QUERY_INFORMATION = 0x0400
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x0400, False, pid)
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            kernel32.CloseHandle(handle)
            # STILL_ACTIVE is 259
            return exit_code.value == 259
        else:
            # On Linux/macOS, sending signal 0 does not kill it, but checks if we can send signals (if it exists)
            os.kill(pid, 0)
            return True
    except OSError:
        return False
    except Exception:
        return False

def main():
    if len(sys.argv) < 3:
        log("Error: Watchdog started with insufficient arguments.")
        sys.exit(1)

    parent_pid = int(sys.argv[1])
    agent_cmd = sys.argv[2:]
    
    log(f"Watchdog initialized. Monitoring PID {parent_pid} for command: {agent_cmd}")

    while True:
        if not is_process_alive(parent_pid):
            log(f"ALERT: Parent agent (PID {parent_pid}) has died or was killed! Initiating self-healing...")
            try:
                # Wait briefly to ensure file locks are released
                time.sleep(1)
                
                # Restart the agent. Note: The new agent will spawn a new watchdog, so this watchdog can exit.
                creationflags = 0x08000000 if platform.system() == "Windows" else 0
                subprocess.Popen(
                    agent_cmd,
                    creationflags=creationflags,
                    close_fds=True
                )
                log("Self-healing successful. Watchdog terminating.")
                sys.exit(0)
            except Exception as e:
                log(f"FATAL: Failed to restart agent: {e}")
                # Don't exit here, keep trying every 10 seconds
                time.sleep(10)
                continue
                
        time.sleep(5) # Poll every 5 seconds

if __name__ == "__main__":
    main()
