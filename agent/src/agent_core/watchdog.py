import os # type: ignore
import time # type: ignore
import subprocess # type: ignore
import sys # type: ignore
import psutil # type: ignore
import platform # type: ignore
import logging # type: ignore

def setup_watchdog_logging(base_dir):
    log_file = os.path.join(base_dir, "monitorix_watchdog.log")
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def run_watchdog(main_pid, target_exe, base_dir):
    setup_watchdog_logging(base_dir)
    sys_p = platform.system()
    logging.info(f"Watchdog started. Monitoring PID: {main_pid}, Target: {target_exe} ({sys_p})")
    
    main_process = None
    try:
        main_process = psutil.Process(main_pid)
    except psutil.NoSuchProcess:
        logging.error(f"Target PID {main_pid} not found. Watchdog exiting.")
        return

    # [v1.8.50] Sovereign Heartbeat Setup (macOS)
    sovereign_mmap = None
    if sys_p == "Darwin":
        try:
            import mmap
            hb_path = os.path.join(base_dir, ".sovereign_hb")
            if os.path.exists(hb_path):
                with open(hb_path, "r+b") as f:
                    sovereign_mmap = mmap.mmap(f.fileno(), 1)
        except Exception as e:
            logging.error(f"Failed to access Sovereign Heartbeat: {e}")

    # --- SOVEREIGN MONITORING LOOP ---
    last_heartbeat_time = time.time()
    
    while True:
        try:
            # High-Frequency Polling for Sovereign parity
            time.sleep(0.5) 

            # 1. PID Check
            is_alive = main_process.is_running() and main_process.status() != psutil.STATUS_ZOMBIE
            
            # 2. Heartbeat Check (macOS)
            if sovereign_mmap:
                try:
                    pulse = sovereign_mmap[0]
                    if pulse == 1:
                        last_heartbeat_time = time.time()
                        sovereign_mmap[0] = 0 # Reset pulse for agent to set again
                except: pass
                
                # If heartbeat flatlines for > 3 seconds, fire emergency
                if time.time() - last_heartbeat_time > 3.0:
                    is_alive = False

            if not is_alive:
                logging.critical("SOVEREIGN ALERT: Agent termination detected. Initiating Hard-Lock Response...")
                trigger_sovereign_panic(sys_p)
                break 
            
        except Exception as e:
            logging.error(f"Watchdog Loop Error: {e}")
            time.sleep(1)

def trigger_sovereign_panic(sys_p):
    """Executes the final kernel-level defense response."""
    if sys_p == "Linux":
        if os.getuid() == 0:
            try:
                # Bit 128 (c) is for crash/panic
                with open("/proc/sysrq-trigger", "w") as f:
                    f.write("c") 
            except Exception as e:
                logging.error(f"Failed to trigger Linux SysRq Panic: {e}")
    
    elif sys_p == "Darwin":
        try:
            # Attempt reboot, fallback to soft-panic
            subprocess.run(["reboot"], capture_output=True)
            # Soft-Panic fallback: Hang the system with CPU loop
            while True: pass 
        except:
            while True: pass

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: watchdog.py <PID> <EXE_PATH> <BASE_DIR>")
        sys.exit(1)
        
    pid = int(sys.argv[1])
    exe = sys.argv[2]
    bdir = sys.argv[3]
    run_watchdog(pid, exe, bdir)
