import json
import re
import os
import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import DetectionRule, DetectionAlert

async def forward_to_siem(alert_data: dict):
    siem_url = os.getenv("SIEM_WEBHOOK_URL", "https://siem.internal.corp/hooks/monitorix")
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(siem_url, json=alert_data, timeout=5)
    except Exception as e:
        print(f"[SIEM Forwarder] Failed to forward alert: {e}")

class SigmaEvaluator:
    def __init__(self):
        self.rules_cache = []

    async def load_rules(self, db: AsyncSession):
        active_rules = (await db.execute(select(DetectionRule).where(DetectionRule.IsActive == True))).scalars().all()
        self.rules_cache.clear()

        for rule in active_rules:
            try:
                if "selection:" in rule.RuleContent:
                    pattern = r"(?i)powershell.*-enc"
                    self.rules_cache.append({
                        "id": rule.Id,
                        "pattern": re.compile(pattern),
                        "tactic": rule.MitreTactic,
                        "technique": rule.MitreTechnique
                    })
            except Exception:
                pass

    async def evaluate_telemetry(self, db: AsyncSession, telemetry_payload: dict, agent_id: str):
        if not self.rules_cache:
            await self.load_rules(db)

        process_name = telemetry_payload.get("process_name", "")
        cmdline = telemetry_payload.get("cmdline", "")
        search_target = f"{process_name} {cmdline}"

        alerts_generated = []

        for rule in self.rules_cache:
            if rule["pattern"].search(search_target):
                alert = DetectionAlert(
                    AgentId=agent_id,
                    RuleId=rule["id"],
                    TelemetryId=telemetry_payload.get("log_id", 0),
                    MatchedContent=search_target
                )
                db.add(alert)
                alerts_generated.append(alert)

        if alerts_generated:
            await db.commit()
            
            # [Integration] Trigger SOAR Playbooks for alerts
            from .soar_engine import soar_engine
            # Fetch default playbook (e.g., ID 1)
            # In a real system, you would query playbooks matching the alert tactic
            for alert in alerts_generated:
                # 1. Trigger internal SOAR playbook
                try:
                    await soar_engine.trigger_playbook(db, playbook_id=1, target_agent_id=agent_id)
                except Exception as e:
                    print(f"[SOAR ERROR] Failed to trigger playbook for alert {alert.Id}: {e}")
                
                # 2. Forward to external SIEM
                await forward_to_siem({
                    "alert_id": alert.Id,
                    "agent_id": alert.AgentId,
                    "rule_id": alert.RuleId,
                    "matched_content": alert.MatchedContent,
                    "severity": "High",
                    "source": "Monitorix EDR"
                })

        return alerts_generated

    async def process_telemetry_event(self, db: AsyncSession, event: dict, agent_id: str):
        """Analyze rich SIEM events from the Rust agent and trigger alerts."""
        event_type = event.get("EventType", "")
        
        alert_generated = None
        
        if event_type == "VPNDetectionAudit":
            if event.get("vpn_active") is True:
                details = event.get("details", "")
                alert_generated = DetectionAlert(
                    AgentId=agent_id,
                    RuleId=9001, # Internal hardcoded rule ID for VPN detection
                    TelemetryId=0,
                    MatchedContent=f"Unauthorized VPN Interface Detected: {details}"
                )
                
        elif event_type == "CrashDumpAudit":
            count = event.get("crash_dumps_count", 0)
            if count > 0:
                alert_generated = DetectionAlert(
                    AgentId=agent_id,
                    RuleId=9002, 
                    TelemetryId=0,
                    MatchedContent=f"System Instability: {count} crash dumps detected."
                )

        elif event_type == "FirewallComplianceReport":
            if event.get("firewall_enabled") is False:
                alert_generated = DetectionAlert(
                    AgentId=agent_id,
                    RuleId=9003,
                    TelemetryId=0,
                    MatchedContent="CRITICAL: Host Firewall is DISABLED!"
                )

        if alert_generated:
            db.add(alert_generated)
            await db.commit()
            print(f"[DETECTION ENGINE] Alert Generated for {agent_id}: {alert_generated.MatchedContent}")
            
            # Automatically trigger SOAR playbook for critical alerts
            from .soar_engine import soar_engine
            try:
                # Using Playbook ID 1 as default isolation playbook
                await soar_engine.trigger_playbook(db, playbook_id=1, target_agent_id=agent_id)
                print(f"[SOAR ENGINE] Playbook #1 triggered for Agent {agent_id}")
            except Exception as e:
                print(f"[SOAR ERROR] Failed to trigger playbook: {e}")

detection_engine = SigmaEvaluator()
