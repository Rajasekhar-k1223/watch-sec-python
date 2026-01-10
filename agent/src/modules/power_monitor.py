import psutil
import logging

class PowerMonitor:
    def __init__(self):
        self.logger = logging.getLogger("PowerMonitor")

    def get_status(self):
        """
        Returns a dict with:
        - battery_percent (int)
        - power_plugged (bool)
        - time_left_min (int) or -1 (Unknown/Unlimited)
        """
        try:
            battery = psutil.sensors_battery()
            if battery:
                plugged = battery.power_plugged
                percent = int(battery.percent)
                secs = battery.secsleft
                
                # secsleft can be psutil.POWER_TIME_UNLIMITED or psutil.POWER_TIME_UNKNOWN
                time_left_min = -1
                if secs != psutil.POWER_TIME_UNLIMITED and secs != psutil.POWER_TIME_UNKNOWN:
                    time_left_min = int(secs / 60)

                return {
                    "battery_percent": percent,
                    "power_plugged": plugged,
                    "time_left_min": time_left_min
                }
            else:
                # No battery (Desktop)
                return {
                    "battery_percent": 100,
                    "power_plugged": True,
                    "time_left_min": -1 # Unlimited
                }
        except Exception as e:
            self.logger.error(f"Failed to get power status: {e}")
            return None
