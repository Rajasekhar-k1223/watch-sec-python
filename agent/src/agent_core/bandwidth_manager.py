import time # type: ignore
import psutil # type: ignore
import datetime # type: ignore
import json # type: ignore
from .utils import compress_payload # type: ignore

class BandwidthManager:
    def __init__(self):
        self.config = {
            "max_rate_kbps": 0,
            "business_hours": {"enabled": False, "start": "09:00", "end": "17:00", "throttle_percent": 30},
            "compression_enabled": True,
            "min_available_bandwidth_mbps": 5
        }
        self.paused_until = 0
        self.check_interval = 5
        self.last_check = 0
        self.current_upload_allowed = True
        self.data_queue = None # Link to DataQueue instance

    def set_data_queue(self, dq):
        self.data_queue = dq
    
    def update_config(self, new_config):
        """Update bandwidth configuration"""
        if isinstance(new_config, str):
             try:
                 new_config = json.loads(new_config)
             except:
                 return
        self.config.update(new_config)
        print(f"[Bandwidth] Config updated: {self.config}")

    def pause_uploads(self, duration_minutes):
        """Pause uploads for a specific duration"""
        self.paused_until = time.time() + (duration_minutes * 60)
        print(f"[Bandwidth] Uploads paused until {datetime.datetime.fromtimestamp(self.paused_until)}")

    def is_paused(self):
        """Check if manual pause is active"""
        if time.time() < self.paused_until:
            return True
        return False

    def is_business_hours(self):
        """Check if current time is within business hours"""
        if not self.config.get("business_hours", {}).get("enabled", False):
            return False
            
        now = datetime.datetime.now().time()
        try:
            start = datetime.datetime.strptime(self.config["business_hours"]["start"], "%H:%M").time()
            end = datetime.datetime.strptime(self.config["business_hours"]["end"], "%H:%M").time()
            return start <= now <= end
        except:
            return False

    def get_max_rate_kbps(self):
        """Get effective max rate considering business hours"""
        max_rate = float(self.config.get("max_rate_kbps", 0))
        if max_rate <= 0: return 0 # Unlimited

        if self.is_business_hours():
            throttle_pct = self.config.get("business_hours", {}).get("throttle_percent", 30)
            # If throttle_percent is 30, we reduce speed BY 30% (so 70% remains)
            # Wait, usually throttle means "reduce TO". Let's clarify our logic.
            # In Dashboards, it usually means "reduce rate BY X%".
            # Let's say it's "Max Rate during business hours is (100 - X)% of total"
            factor = (100.0 - throttle_pct) / 100.0
            return max_rate * factor
        
        return max_rate

    def get_delay_for_size(self, size_bytes):
        """Calculate required sleep in seconds for a given payload size to maintain max rate"""
        rate_kbps = self.get_max_rate_kbps()
        if rate_kbps <= 0:
            return 0
        
        # Rate is in KB/s. Convert to bytes/s
        rate_bps = rate_kbps * 1024
        
        # Time = Size / Rate
        return size_bytes / rate_bps

    def check_network_availability(self):
        """Check if network is free enough to upload"""
        # 1. Check if paused
        if self.is_paused():
            self.current_upload_allowed = False
            return False

        # Throttle telemetry checks to avoid CPU spike
        if time.time() - self.last_check < self.check_interval:
            return self.current_upload_allowed

        self.last_check = time.time()
        
        # 2. Check Available Bandwidth
        try:
            # Simple heuristic: Check if machine is already busy with other stuff
            # min_available_bandwidth_mbps can be used as a threshold
            min_avail = self.config.get("min_available_bandwidth_mbps", 5)
            
            net_io = psutil.net_io_counters()
            time.sleep(0.1)
            net_io_2 = psutil.net_io_counters()
            bytes_total_recent = (net_io_2.bytes_sent - net_io.bytes_sent) + (net_io_2.bytes_recv - net_io.bytes_recv)
            current_usage_mbps = bytes_total_recent * 8 / 1024 / 1024 / 0.1 # over 0.1s
            
            # If we think we are on a 100Mbps link and we want 5Mbps free... 
            # This is hard to get perfectly without knowing link speed.
            # We use a sane cap: If system is using > 80Mbps, we assume it's busy.
            if current_usage_mbps > 80: 
                 self.current_upload_allowed = False
                 return False
                 
        except Exception as e:
            pass
            
        self.current_upload_allowed = True
        return True

    def prepare_payload(self, data):
        """Compress data if enabled"""
        payload = data
        if self.config.get("compression_enabled", True):
            payload = compress_payload(data)
        return payload
        
    def get_stats(self):
        """Get current bandwidth stats"""
        status = "active"
        reason = ""
        
        if self.is_paused():
            status = "paused"
            reason = "Manual Pause"
        elif not self.current_upload_allowed:
            status = "paused"
            reason = "Network Busy"
        elif self.is_business_hours():
            status = "throttled"
            reason = "Business Hours"
            
        buffered = 0
        if self.data_queue:
            buffered = self.data_queue.get_buffer_size()
        
        return {
            "status": status,
            "reason": reason,
            "buffered_bytes": buffered,
            "max_rate_kbps": self.get_max_rate_kbps(),
            "timestamp": time.time()
        }
