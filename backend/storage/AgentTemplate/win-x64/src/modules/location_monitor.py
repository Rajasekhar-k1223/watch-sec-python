
import requests
import threading
import time
import logging

class LocationMonitor:
    def __init__(self, interval=3600): # Check every hour
        self.interval = interval
        self.logger = logging.getLogger("LocationMonitor")
        self.lat = 0.0
        self.lon = 0.0
        self.country = "Unknown"
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.logger.info("Location Monitor Started")

    def stop(self):
        self.running = False
        
    def get_location(self):
        return self.lat, self.lon, self.country

    def _loop(self):
        # Initial check immediately
        self._check_location()
        
        while self.running:
            for _ in range(self.interval):
                if not self.running: break
                time.sleep(1)
            
            if self.running:
                self._check_location()

    def _check_location(self):
        try:
            # FREE API: ip-api.com (No SSL for free tier usually, but lets try)
            # Use http to avoid SSL issues on old systems with free tier
            response = requests.get("http://ip-api.com/json/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    self.lat = data.get("lat", 0.0)
                    self.lon = data.get("lon", 0.0)
                    self.country = data.get("country", "Unknown")
                    # self.logger.info(f"Location Updated: {self.country} ({self.lat}, {self.lon})")
        except Exception as e:
            self.logger.error(f"Failed to fetch location: {e}")
