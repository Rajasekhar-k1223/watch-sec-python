
import requests # type: ignore
from typing import Optional # type: ignore
import threading # type: ignore
import time # type: ignore
import logging # type: ignore

class LocationMonitor:
    def __init__(self, interval=3600): # Check every hour
        self.interval = interval
        self.logger = logging.getLogger("LocationMonitor")
        self.lat = 0.0
        self.lon = 0.0
        self.country = "Unknown"
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True) # type: ignore
        self.thread.start() # type: ignore
        self.logger.info("Location Monitor Started")

    def stop(self):
        self.running = False

    def set_enabled(self, enabled: bool):
        if enabled and not self.running:
            self.start()
        elif not enabled and self.running:
            self.stop()
        
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
        # List of public GeoIP APIs to try in order
        providers = [
            "http://ip-api.com/json/",
            "https://ipapi.co/json/",
            "https://freeipapi.com/api/json",
            "https://ipwho.is/" # [NEW] Fallback
        ]
        
        for url in providers:
            try:
                # self.logger.info(f"Attempting location fetch from {url}")
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    
                    lat, lon, country = 0.0, 0.0, "Unknown"
                    success = False

                    # Handle different API response formats
                    if "lat" in data and "lon" in data: # ip-api.com / ipapi.co
                        lat = data.get("lat")
                        lon = data.get("lon")
                        country = data.get("country_name") or data.get("country", "Unknown")
                        success = True
                    elif "latitude" in data and "longitude" in data: # freeipapi.com / ipwho.is
                        lat = data.get("latitude")
                        lon = data.get("longitude")
                        country = data.get("countryName") or data.get("country", "Unknown")
                        success = True
                    
                    if success and isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                         self.lat = float(lat)
                         self.lon = float(lon)
                         self.country = country
                         return # Success!
                        
            except Exception as e:
                # self.logger.warning(f"Location provider {url} failed: {e}")
                continue
                
        # self.logger.error("All location providers failed.")
