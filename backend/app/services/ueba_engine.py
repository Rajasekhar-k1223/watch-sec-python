import json
import math
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import UebaBaseline

class UebaEngine:

    async def build_baselines(self, db: AsyncSession):
        from app.db.models import Agent, User
        agents = (await db.execute(select(Agent.AgentId))).scalars().all()
        users = (await db.execute(select(User.Email))).scalars().all()
        
        entities = list(agents) + list(users)

        for entity in entities:
            existing = (await db.execute(select(UebaBaseline).where(UebaBaseline.EntityId == entity))).scalars().first()
            if not existing:
                existing = UebaBaseline(
                    EntityId=entity,
                    EntityType="User" if "@" in entity else "Device",
                    TenantId=1
                )
                db.add(existing)

            profile_data = {
                "common_ips": ["192.168.1.50", "203.0.113.10"],
                "login_hours": {"start": 8, "end": 18, "timezone": "UTC"},
                "common_processes": ["chrome.exe", "msedge.exe", "winword.exe"],
                "avg_daily_bytes_out": 50000000
            }
            existing.ProfileDataJson = json.dumps(profile_data)
            existing.LastUpdated = datetime.datetime.utcnow()

        await db.commit()

    def _calculate_distance(self, ip1: str, ip2: str) -> float:
        if ip1 == ip2:
            return 0.0
        return 2500.0

    async def evaluate_event(self, db: AsyncSession, entity_id: str, event_data: dict) -> dict:
        baseline = (await db.execute(select(UebaBaseline).where(UebaBaseline.EntityId == entity_id))).scalars().first()
        if not baseline:
            return {"score": 0, "anomalies": []}

        profile = json.loads(baseline.ProfileDataJson)
        anomalies = []
        score = 0

        if "timestamp" in event_data:
            try:
                event_time = datetime.datetime.fromisoformat(event_data["timestamp"].replace("Z", "+00:00"))
                hour = event_time.hour
                start = profile.get("login_hours", {}).get("start", 0)
                end = profile.get("login_hours", {}).get("end", 24)
                if hour < start or hour > end:
                    anomalies.append("Out of hours activity")
                    score += 20
            except Exception:
                pass

        if "ip_address" in event_data and "last_login_ip" in event_data and "last_login_time" in event_data:
            dist_km = self._calculate_distance(event_data["ip_address"], event_data["last_login_ip"])
            if dist_km > 500:
                time_diff_hours = 1.0
                speed = dist_km / time_diff_hours
                if speed > 1000:
                    anomalies.append(f"Impossible travel detected ({speed} km/h)")
                    score += 80

        if "process_name" in event_data:
            common = profile.get("common_processes", [])
            if common and event_data["process_name"] not in common:
                anomalies.append(f"Rare process execution: {event_data['process_name']}")
                score += 15

        final_score = min(score, 100)
        
        if final_score > 70:
            try:
                from app.services.dispatcher_service import dispatcher
                import asyncio
                event = {
                    "source": "ueba_engine",
                    "signal": "HighRiskInsiderThreat",
                    "severity": "Critical" if final_score >= 90 else "High",
                    "context": {
                        "entity_id": entity_id,
                        "risk_score": final_score,
                        "anomalies": anomalies
                    }
                }
                asyncio.create_task(dispatcher.dispatch_siem_webhook(db, entity_id, event))
            except Exception as e:
                print(f"[UEBA] Error dispatching alert: {e}")

        return {"score": final_score, "anomalies": anomalies}

ueba_engine = UebaEngine()
