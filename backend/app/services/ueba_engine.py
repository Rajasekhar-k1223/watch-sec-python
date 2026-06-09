import json
import math
import datetime
from sqlalchemy.orm import Session
from app.db.models import UebaBaseline

class UebaEngine:
    
    def build_baselines(self, db: Session):
        """
        Background task to scan historical data and build normal behavior models.
        In a real scenario, this would query ActivityLogs and EventLogs over 30 days.
        """
        # Stub: Generate a mock baseline for an entity
        entities = ["admin@tenant1.com", "AGENT-XDR-1"]
        
        for entity in entities:
            existing = db.query(UebaBaseline).filter(UebaBaseline.EntityId == entity).first()
            if not existing:
                existing = UebaBaseline(
                    EntityId=entity,
                    EntityType="User" if "@" in entity else "Device",
                    TenantId=1
                )
                db.add(existing)
            
            # Mock baseline metrics
            profile_data = {
                "common_ips": ["192.168.1.50", "203.0.113.10"],
                "login_hours": {"start": 8, "end": 18, "timezone": "UTC"},
                "common_processes": ["chrome.exe", "msedge.exe", "winword.exe"],
                "avg_daily_bytes_out": 50000000 # 50 MB
            }
            existing.ProfileDataJson = json.dumps(profile_data)
            existing.LastUpdated = datetime.datetime.utcnow()
            
        db.commit()

    def _calculate_distance(self, ip1: str, ip2: str) -> float:
        """
        Stub: Calculate physical distance between two IPs.
        Requires GeoIP DB in production. Returns arbitrary km distance.
        """
        if ip1 == ip2:
            return 0.0
        # If different subnets, mock a far distance
        return 2500.0

    def evaluate_event(self, db: Session, entity_id: str, event_data: dict) -> dict:
        """
        Evaluate a real-time event against the established baseline.
        Returns a dict of anomalies detected and an anomaly_score (0-100).
        """
        baseline = db.query(UebaBaseline).filter(UebaBaseline.EntityId == entity_id).first()
        if not baseline:
            return {"score": 0, "anomalies": []}
            
        profile = json.loads(baseline.ProfileDataJson)
        anomalies = []
        score = 0
        
        # 1. Evaluate Login Hours
        if "timestamp" in event_data:
            try:
                # Stub timestamp parsing
                event_time = datetime.datetime.fromisoformat(event_data["timestamp"].replace("Z", "+00:00"))
                hour = event_time.hour
                start = profile.get("login_hours", {}).get("start", 0)
                end = profile.get("login_hours", {}).get("end", 24)
                
                if hour < start or hour > end:
                    anomalies.append("Out of hours activity")
                    score += 20
            except Exception:
                pass
                
        # 2. Evaluate Impossible Travel
        if "ip_address" in event_data and "last_login_ip" in event_data and "last_login_time" in event_data:
            dist_km = self._calculate_distance(event_data["ip_address"], event_data["last_login_ip"])
            if dist_km > 500:
                # Check time delta
                time_diff_hours = 1.0 # Stub, normally calculate from timestamps
                speed = dist_km / time_diff_hours
                if speed > 1000: # Faster than a commercial jet
                    anomalies.append(f"Impossible travel detected ({speed} km/h)")
                    score += 80
                    
        # 3. Evaluate Unknown Processes
        if "process_name" in event_data:
            common = profile.get("common_processes", [])
            if common and event_data["process_name"] not in common:
                anomalies.append(f"Rare process execution: {event_data['process_name']}")
                score += 15

        return {
            "score": min(score, 100),
            "anomalies": anomalies
        }

ueba_engine = UebaEngine()
