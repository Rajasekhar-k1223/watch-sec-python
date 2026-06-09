import sys
import argparse
import logging
import asyncio

# Setup basic logging for the entry point
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("MonitorixEntry")

def main():
    # Force PyInstaller to bundle multimedia and surveillance modules
    try:
        import src.modules.visual_activity
        import src.modules.webrtc_stream
        import src.modules.remote_desktop
        import src.modules.voice_intelligence
        import src.modules.clipboard_monitor
        import src.modules.input_audit
        import src.modules.input_simulation
    except ImportError as e:
        logger.debug(f"Module import warning (safe to ignore if building): {e}")

    parser = argparse.ArgumentParser(description="Monitorix Sovereign Edge Agent")
    parser.add_argument("--role", choices=["supervisor", "worker", "updater", "cli"], default="supervisor", 
                        help="The role this process should assume.")
    
    args = parser.parse_args()
    
    if args.role == "supervisor":
        logger.info("Starting Monitorix Supervisor...")
        from src.core.supervisor import Supervisor
        sup = Supervisor()
        sup.start()
        
    elif args.role == "worker":
        logger.info("Starting Monitorix Worker...")
        from src.core.worker import Worker
        w = Worker()
        asyncio.run(w.run())
        
    elif args.role == "updater":
        logger.info("Starting Monitorix Updater...")
        from src.core.updater import AgentUpdater
        upd = AgentUpdater()
        upd.check_for_updates("stable")
        
    elif args.role == "cli":
        logger.info("Monitorix Local CLI mode active.")
        print("Monitorix Local CLI Tool v2.1.0")

if __name__ == "__main__":
    main()
