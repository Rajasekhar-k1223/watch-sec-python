
import threading # type: ignore
import time # type: ignore
import logging # type: ignore
import datetime # type: ignore
import os # type: ignore
import platform # type: ignore

# Conditional Import for Windows
try:
    import win32print # type: ignore
    HAS_WIN32PRINT = True
except ImportError:
    HAS_WIN32PRINT = False

class PrinterMonitorStrategy:
    def __init__(self, agent_id, api_key, backend_url, data_queue):
        self.agent_id = agent_id
        self.api_key = api_key
        self.backend_url = backend_url
        self.data_queue = data_queue
        self.running = False
        self._thread = None
        self.logger = logging.getLogger(self.__class__.__name__)

    def start(self):
        raise NotImplementedError

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _report_print(self, printer, user, doc_name):
        payload = {
            "AgentId": self.agent_id,
            "ActivityType": "Print",
            "ProcessName": "Spooler/CUPS",
            "WindowTitle": f"Printing: {doc_name}",
            "RiskLevel": "Normal",
            "Category": "DLP:Print",
            "IdleSeconds": 0,
            "DurationSeconds": 0,
            "Timestamp": datetime.datetime.utcnow().isoformat(),
            "Url": printer
        }
        
        # DLP Keyword Check
        high_risk_keywords = ["confidential", "secret", "salary", "password", "invoice", "internal only", "restricted", "project", "contract", "legal", "financial"]
        if any(x in doc_name.lower() for x in high_risk_keywords):
            payload["RiskLevel"] = "High"
            payload["Category"] = "DLP:RestrictedPrint"

        if self.data_queue:
            self.data_queue.enqueue("/api/events/activity", payload)


class LinuxCupsStrategy(PrinterMonitorStrategy):
    def __init__(self, agent_id, api_key, backend_url, data_queue):
        super().__init__(agent_id, api_key, backend_url, data_queue)
        self.log_path = "/var/log/cups/page_log"

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._tail_cups_log, daemon=True)
        self._thread.start()
        self.logger.info("Linux Printer Monitor (CUPS) Started.")

    def _tail_cups_log(self):
        # Allow some time for permission checks or log rotation
        if not os.path.exists(self.log_path):
            # Try to handle cases where file might be created later
            pass

        while self.running:
            if not os.path.exists(self.log_path):
                 time.sleep(5)
                 continue

            try:
                with open(self.log_path, "r") as f:
                    f.seek(0, 2) # Start at end
                    
                    while self.running:
                        line = f.readline()
                        if not line:
                            time.sleep(1)
                            continue
                        self._parse_line(line)
            except Exception as e:
                self.logger.error(f"Error reading CUPS log: {e}")
                time.sleep(5)

    def _parse_line(self, line):
        # Format: printer user job-id [date] page-num num-copies job-billing job-originating-host-name job-name media sides
        try:
            parts = line.split(" ")
            if len(parts) > 6:
                printer = parts[0]
                user = parts[1]
                # job_id = parts[2]
                # Heuristic for picking out job name (it's often the last non-metadata field)
                # This is tricky because job name can contain spaces. 
                # Standard CUPS page_log format:
                # printer user job-id [date] page-num num-copies job-billing job-originating-host-name job-name media sides
                # We can try to grab from index 8 up to -2
                doc_name = " ".join(parts[8:-2]) 
                
                self._report_print(printer, user, doc_name)
        except: pass


class WindowsPrinterStrategy(PrinterMonitorStrategy):
    def __init__(self, agent_id, api_key, backend_url, data_queue):
        super().__init__(agent_id, api_key, backend_url, data_queue)
        self.seen_jobs = set()

    def start(self):
        if not HAS_WIN32PRINT:
            self.logger.error("pywin32 not installed. Monitoring disabled.")
            return
            
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.logger.info("Windows Printer Monitor Started.")

    def _loop(self):
        while self.running:
            try:
                self._check_printers()
            except Exception as e:
                self.logger.error(f"Printer Loop Error: {e}")
            time.sleep(5.0)

    def _check_printers(self):
        flags = win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS
        printers = win32print.EnumPrinters(flags)
        
        current_job_ids = set()

        for (flags, description, name, comment) in printers:
            try:
                phandle = win32print.OpenPrinter(name)
                try:
                    jobs = win32print.EnumJobs(phandle, 0, -1, 1)
                    for job in jobs:
                        job_id = f"{name}_{job['JobId']}"
                        current_job_ids.add(job_id)

                        if job_id not in self.seen_jobs:
                            self._log_print_job(name, job)
                            self.seen_jobs.add(job_id)
                finally:
                    win32print.ClosePrinter(phandle)
            except: pass
        
        self.seen_jobs = self.seen_jobs.intersection(current_job_ids)

    def _log_print_job(self, printer_name, job):
        doc_name = job.get('pDocument', 'Unknown')
        user = job.get('pUserName', 'Unknown')
        # pages = job.get('TotalPages', 0)
        self._report_print(printer_name, user, doc_name)


class PrinterMonitor:
    def __init__(self, agent_id, api_key, backend_url, data_queue=None):
        self.strategy = None
        os_type = platform.system()
        
        if os_type == "Windows":
            self.strategy = WindowsPrinterStrategy(agent_id, api_key, backend_url, data_queue)
        elif os_type in ["Linux", "Darwin"]:
            self.strategy = LinuxCupsStrategy(agent_id, api_key, backend_url, data_queue)
        else:
            logging.getLogger("PrinterMonitor").info(f"Unsupported Platform: {os_type}")

    def start(self):
        if self.strategy:
            self.strategy.start()

    def stop(self):
        if self.strategy:
            self.strategy.stop()

    def set_enabled(self, enabled: bool):
        # Support dynamic enabling/disabling via facade
        if self.strategy:
            if enabled:
                if not self.strategy.running:
                    self.strategy.start()
            else:
                if self.strategy.running:
                    self.strategy.stop()
