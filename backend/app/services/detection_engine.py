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

        from datetime import datetime, timedelta
        from sqlalchemy import desc

        alerts_generated = []
        new_alerts = []
        cutoff = datetime.utcnow() - timedelta(minutes=5)

        for rule in self.rules_cache:
            if rule["pattern"].search(search_target):
                # [DEDUPLICATION] Collapse recurring triggers within 5-minute window
                existing = (await db.execute(
                    select(DetectionAlert).where(
                        DetectionAlert.AgentId == agent_id,
                        DetectionAlert.RuleId == rule["id"],
                        DetectionAlert.MatchedContent == search_target,
                        DetectionAlert.Timestamp >= cutoff
                    ).order_by(desc(DetectionAlert.Id)).limit(1)
                )).scalars().first()

                if existing:
                    existing.HitCount = (existing.HitCount or 1) + 1
                    existing.LastSeenAt = datetime.utcnow()
                    alerts_generated.append(existing)
                else:
                    alert = DetectionAlert(
                        AgentId=agent_id,
                        RuleId=rule["id"],
                        TelemetryId=telemetry_payload.get("log_id", 0),
                        MatchedContent=search_target,
                        HitCount=1,
                        LastSeenAt=datetime.utcnow()
                    )
                    db.add(alert)
                    alerts_generated.append(alert)
                    new_alerts.append(alert)

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
                
                # 3. [NEW] Automatically trigger AI Copilot Report Generation
                import asyncio
                from .ai_copilot import ai_engine
                from app.db.session import AsyncSessionLocal
                async def run_ai_bg(alert_id: int):
                    async with AsyncSessionLocal() as bg_db:
                        try:
                            await ai_engine.generate_incident_report(bg_db, alert_id)
                        except Exception as e:
                            print(f"[AI ERROR] Failed to generate AI report: {e}")
                asyncio.create_task(run_ai_bg(alert.Id))

        return alerts_generated

    async def process_telemetry_event(self, db: AsyncSession, event: dict, agent_id: str):
        """Analyze rich SIEM events from the Rust agent and trigger alerts."""
        event_type = event.get("EventType", "")
        
        alert_generated = None

        # ── Real-time Threat Intelligence IOC Matching ────────────────────────
        # For ANY event with a remote IP or domain, check against the IOC cache
        remote_ip = event.get("RemoteIp") or event.get("remote_ip") or event.get("DestinationIp")
        remote_domain = event.get("Domain") or event.get("domain") or event.get("RemoteDomain")
        try:
            from .threat_intel_pipeline import ti_pipeline
            if remote_ip:
                if await ti_pipeline.is_malicious("IPv4", remote_ip):
                    alert_generated = DetectionAlert(
                        AgentId=agent_id,
                        RuleId=9007,
                        TelemetryId=0,
                        MatchedContent=(
                            f"[ThreatIntel] Outbound connection to known-malicious IP: {remote_ip} "
                            f"(EventType: {event_type})"
                        )
                    )
            elif remote_domain and not alert_generated:
                if await ti_pipeline.is_malicious("Domain", remote_domain):
                    alert_generated = DetectionAlert(
                        AgentId=agent_id,
                        RuleId=9007,
                        TelemetryId=0,
                        MatchedContent=(
                            f"[ThreatIntel] DNS query to known-malicious domain: {remote_domain} "
                            f"(EventType: {event_type})"
                        )
                    )
        except Exception as ti_err:
            print(f"[ThreatIntel Match Error] {ti_err}")

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

        elif event_type == "FileIntegrityAlert":
            filepath = event.get("FilePath", "Unknown")
            alert_generated = DetectionAlert(
                AgentId=agent_id,
                RuleId=9004, 
                TelemetryId=0,
                MatchedContent=f"File Integrity Violation: {filepath} was modified or deleted."
            )

        elif event_type == "PcapCaptureCompleted":
            # The agent sends the pcap file directly over the offline queue
            file_b64 = event.get("FileB64")
            filename = event.get("FilePath", "capture.pcap")
            if file_b64:
                import base64
                import os
                import asyncio
                
                # Save the file
                target_dir = os.path.join("storage/pcaps", agent_id)
                os.makedirs(target_dir, exist_ok=True)
                file_path = os.path.join(target_dir, filename)
                
                try:
                    with open(file_path, "wb") as buffer:
                        buffer.write(base64.b64decode(file_b64))
                except Exception as e:
                    print(f"[PCAP] Failed to save pcap: {e}")
                
                # We do a basic synchronous check for demonstration (though async is preferred)
                try:
                    with open(file_path, "rb") as f:
                        content = f.read()
                    if b"password=" in content.lower() or b"malicious-payload" in content.lower() or b"cmd.exe" in content.lower():
                        alert_generated = DetectionAlert(
                            AgentId=agent_id,
                            RuleId=9005,
                            TelemetryId=0,
                            MatchedContent=f"PCAP Forensics: Cleartext credential or threat found in {filename}!"
                        )
                except:
                    pass

        elif event_type == "MemoryDumpCompleted":
            # The agent sends the memory dump directly over the offline queue
            file_b64 = event.get("FileB64")
            filename = event.get("FilePath", "memdump.dmp")
            if file_b64:
                import base64
                import os
                
                # Save the file
                target_dir = os.path.join("storage/memdumps", agent_id)
                os.makedirs(target_dir, exist_ok=True)
                file_path = os.path.join(target_dir, filename)
                
                try:
                    with open(file_path, "wb") as buffer:
                        buffer.write(base64.b64decode(file_b64))
                except Exception as e:
                    print(f"[MemoryDump] Failed to save memory dump: {e}")

        elif event_type == "SandboxThreatPrevented":
            # Event emitted by the agent when a file fails sandbox verification
            filename = event.get("Filename", "Unknown")
            reason = event.get("Reason", "Malicious file detected")
            alert_generated = DetectionAlert(
                AgentId=agent_id,
                RuleId=9008,
                TelemetryId=0,
                MatchedContent=f"RedRainbow Sandbox prevented execution of {filename}. Reason: {reason}"
            )

        elif event_type == "WebmailActivity":
            risk = event.get("RiskLevel", "Normal")
            if risk in ("High", "Critical"):
                subject = event.get("Subject", "Unknown")
                body = event.get("BodyPreview", "")
                alert_generated = DetectionAlert(
                    AgentId=agent_id,
                    RuleId=9006,
                    TelemetryId=0,
                    MatchedContent=(
                        f"[WebMail DLP] Sensitive data detected in webmail session. "
                        f"Subject: '{subject}' | Body snippet: {body[:200]}"
                    )
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
                
            # [NEW] Automatically trigger AI Copilot Report Generation
            import asyncio
            from .ai_copilot import ai_engine
            from app.db.session import AsyncSessionLocal
            async def run_ai_bg(alert_id: int):
                async with AsyncSessionLocal() as bg_db:
                    try:
                        await ai_engine.generate_incident_report(bg_db, alert_id)
                    except Exception as e:
                        print(f"[AI ERROR] Failed to generate AI report: {e}")
            asyncio.create_task(run_ai_bg(alert_generated.Id))

detection_engine = SigmaEvaluator()
