import sys # type: ignore
import os # type: ignore
import json # type: ignore
import time # type: ignore
from datetime import datetime, timedelta # type: ignore

# Mock psutil since it might not be in the environment or could fail
class MockPsutil:
    class MockNetIO:
        def __init__(self):
            self.bytes_sent = 1000
            self.bytes_recv = 1000
    
    @staticmethod
    def net_io_counters():
        return MockPsutil.MockNetIO()

sys.modules['psutil'] = MockPsutil

# Mock .utils for compress_payload
class MockUtils:
    @staticmethod
    def compress_payload(data):
        return data

sys.modules['.utils'] = MockUtils
sys.modules['core.utils'] = MockUtils

# Add agent src to path
sys.path.append('/opt/apps/monitorix/watch-sec-python/agent/src')

from agent_core.bandwidth_manager import BandwidthManager # type: ignore

def test_bandwidth_logic():
    print("--- Testing BandwidthManager Logic ---")
    bw = BandwidthManager()
    
    # 1. Test Unlimited (0)
    bw.update_config({"max_rate_kbps": 0})
    delay = bw.get_delay_for_size(1024 * 10) # 10KB
    print(f"Delay for 10KB (Unlimited): {delay}s (Expected: 0s)")
    assert delay == 0
    
    # 2. Test Fixed Rate (100 KB/s)
    bw.update_config({"max_rate_kbps": 100})
    delay = bw.get_delay_for_size(1024 * 50) # 50KB
    # 50KB / 100KB/s = 0.5s
    print(f"Delay for 50KB (100 KB/s): {delay}s (Expected: 0.5s)")
    assert abs(delay - 0.5) < 0.01
    
    # 3. Test Business Hours Throttling
    # Set business hours to include "now"
    now = datetime.now()
    start_str = (now - timedelta(hours=1)).strftime("%H:%M")
    end_str = (now + timedelta(hours=1)).strftime("%H:%M")
    
    bw.update_config({
        "max_rate_kbps": 100,
        "business_hours": {
            "enabled": True,
            "start": start_str,
            "end": end_str,
            "throttle_percent": 50 # Reduce TO 50% (Wait, my logic was factor = (100-throttle)/100, which is reduce BY. Let's check)
        }
    })
    
    # Factor = (100 - 50) / 100 = 0.5. Effective rate = 50 KB/s
    delay = bw.get_delay_for_size(1024 * 50) # 50KB
    # 50KB / 50KB/s = 1.0s
    print(f"Delay for 50KB during Biz Hours (100 KB/s, 50% throttle): {delay}s (Expected: 1.0s)")
    assert abs(delay - 1.0) < 0.01

    # 4. Test Pause Logic
    bw.pause_uploads(10) # 10 mins
    print(f"Is Paused (Just set 10m): {bw.is_paused()} (Expected: True)")
    assert bw.is_paused() == True
    
    # 5. Check network availability
    is_avail = bw.check_network_availability()
    print(f"Network Available (While Paused): {is_avail} (Expected: False)")
    assert is_avail == False

    print("--- ALL TESTS PASSED ---")

if __name__ == "__main__":
    test_bandwidth_logic()
