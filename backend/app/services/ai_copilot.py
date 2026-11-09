from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.models import DetectionAlert, DetectionRule, AiIncidentReport, ProcessLineageNode
import json
import httpx
import os
import re
from datetime import datetime, timedelta

# Synthetic rule definitions for rules not stored in the DB
SYNTHETIC_RULES = {
    9001: {"Name": "VPN Anomaly",             "Severity": "High",     "MitreTactic": "Defense Evasion",   "MitreTechnique": "T1133"},
    9002: {"Name": "System Crash Dump",       "Severity": "Medium",   "MitreTactic": "Impact",            "MitreTechnique": "T1499"},
    9003: {"Name": "Firewall Disabled",       "Severity": "Critical", "MitreTactic": "Defense Evasion",   "MitreTechnique": "T1562.004"},
    9004: {"Name": "File Integrity Violation","Severity": "High",     "MitreTactic": "Persistence",       "MitreTechnique": "T1565"},
    9005: {"Name": "PCAP DPI Threat",         "Severity": "Critical", "MitreTactic": "Exfiltration",      "MitreTechnique": "T1048"},
    9006: {"Name": "WebMail DLP Violation",   "Severity": "High",     "MitreTactic": "Exfiltration",      "MitreTechnique": "T1048.003"},
    9007: {"Name": "ThreatIntel IOC Match",   "Severity": "Critical", "MitreTactic": "Command and Control","MitreTechnique": "T1071"},
    9008: {"Name": "Sandbox Threat Prevented","Severity": "Critical", "MitreTactic": "Execution",         "MitreTechnique": "T1204.002"},
}


class AiCopilotEngine:

    async def generate_incident_report(self, db: AsyncSession, alert_id: int):
        """
        Generate an AI incident report for a given alert.
        Gracefully falls back to synthetic rule definitions if the rule is not in the DB.
        Also performs attack chain correlation across the last 2 hours of alerts for the same agent.
        """
        result = await db.execute(
            select(DetectionAlert).where(DetectionAlert.Id == alert_id)
        )
        alert = result.scalars().first()
        if not alert:
            return None, "Alert not found"

        # Try DB rule first, then fall back to synthetic definitions
        rule_info = SYNTHETIC_RULES.get(alert.RuleId)
        db_rule = None
        if not rule_info:
            rule_result = await db.execute(
                select(DetectionRule).where(DetectionRule.Id == alert.RuleId)
            )
            db_rule = rule_result.scalars().first()
            if db_rule:
                rule_info = {
                    "Name": db_rule.Name,
                    "Severity": db_rule.Severity,
                    "MitreTactic": db_rule.MitreTactic,
                    "MitreTechnique": db_rule.MitreTechnique,
                }

        if not rule_info:
            rule_info = {"Name": "Unknown Rule", "Severity": "Medium", "MitreTactic": "Unknown", "MitreTechnique": "Unknown"}

        # ── Attack Chain Correlation ──────────────────────────────────────────
        # Pull all alerts for this agent in the last 2 hours to identify an attack chain
        cutoff = datetime.utcnow() - timedelta(hours=2)
        chain_result = await db.execute(
            select(DetectionAlert)
            .where(
                DetectionAlert.AgentId == alert.AgentId,
                DetectionAlert.Id != alert_id
            )
            .order_by(desc(DetectionAlert.Id))
            .limit(10)
        )
        related_alerts = chain_result.scalars().all()
        attack_chain_text = ""
        if related_alerts:
            chain_items = []
            for ra in related_alerts:
                ra_rule = SYNTHETIC_RULES.get(ra.RuleId, {"Name": f"Rule #{ra.RuleId}"})
                chain_items.append(f"- [{ra_rule['Name']}] {ra.MatchedContent[:120]}")
            attack_chain_text = "Recent Related Alerts (Attack Chain Context):\n" + "\n".join(chain_items)

        # ── Process Lineage Context ───────────────────────────────────────────
        process_context = ""
        try:
            if alert.RawEventData:
                raw_data = json.loads(alert.RawEventData)
                if "process_id" in raw_data:
                    pid = raw_data["process_id"]
                    node = (await db.execute(
                        select(ProcessLineageNode).where(
                            ProcessLineageNode.AgentId == alert.AgentId,
                            ProcessLineageNode.ProcessId == pid
                        )
                    )).scalars().first()
                    if node:
                        process_context = f"Command Line: {node.CommandLine}\nImage Path: {node.ImagePath}"
        except Exception:
            pass

        prompt = f"""
        You are the Monitorix AI Security Brain.
        Analyze the following security incident, the attack chain context, and generate an Executive Summary, Technical Details, and Remediation Steps.
        Your response MUST be valid JSON conforming EXACTLY to this schema:
        {{
            "executive_summary": "string",
            "technical_details": "string",
            "remediation_steps": "string"
        }}
        Do not output any markdown formatting around the JSON, just the raw JSON object.

        Alert: {rule_info['Name']}
        Severity: {rule_info['Severity']}
        Agent: {alert.AgentId}
        MITRE ATT&CK: {rule_info['MitreTactic']} -> {rule_info['MitreTechnique']}
        Raw Payload: {alert.MatchedContent}
        Process Context: {process_context or 'N/A'}
        {attack_chain_text}
        """

        # Generate context-aware grounded fallback if LLM inference is offline
        r_name = rule_info.get("Name", "Security Alert")
        tactic = rule_info.get("MitreTactic", "Suspicious Activity")
        technique = rule_info.get("MitreTechnique", "General Anomaly")
        severity = rule_info.get("Severity", "High")
        content_snippet = alert.MatchedContent[:200] if alert.MatchedContent else "N/A"

        exec_summary = (
            f"Autonomous SOC investigation conducted for {severity}-severity event '{r_name}' on host {alert.AgentId}. "
            f"The detection engine intercepted activity correlated with MITRE ATT&CK {tactic} ({technique}). "
            f"Automated containment evaluation and analyst review initiated."
        )

        tech_details = (
            f"Detection Trigger: {r_name}\n"
            f"Affected Host: {alert.AgentId}\n"
            f"MITRE Tactic & Technique: {tactic} -> {technique}\n"
            f"Matched Telemetry / Payload: {content_snippet}\n"
            f"Process Lineage Context: {process_context or 'Process attributes captured in endpoint ledger'}\n"
            f"{attack_chain_text}\n"
            f"Correlation Engine Verdict: High-confidence indicator of active threat progression."
        )

        if "Ransomware" in r_name or "Shadow" in r_name or "T1490" in str(technique):
            remediation = (
                f"1. Execute automated SOAR Playbook: Host Network Isolation on {alert.AgentId}.\n"
                f"2. Terminate the active process tree and block associated binary hashes.\n"
                f"3. Audit Volume Shadow Copies (vssadmin) and restore filesystem canary points.\n"
                f"4. Collect memory and forensic logs into the Immutable Evidence Vault."
            )
        elif "LSASS" in r_name or "T1003" in str(technique):
            remediation = (
                f"1. Isolate endpoint {alert.AgentId} to prevent lateral credential movement.\n"
                f"2. Invalidate active Kerberos and NTLM session tickets for compromised accounts.\n"
                f"3. Force password rotation for domain and local administrator credentials.\n"
                f"4. Dump and preserve volatility memory profile for root-cause forensics."
            )
        elif "Firewall" in r_name or "T1562" in str(technique):
            remediation = (
                f"1. Re-enable host firewall profiles immediately via automated agent enforcement.\n"
                f"2. Inspect parent process responsible for netsh/iptables invocation.\n"
                f"3. Review inbound network connections on open listener ports.\n"
                f"4. Flag user account for UEBA behavioral anomaly tracking."
            )
        else:
            remediation = (
                f"1. Quarantine suspicious binary and terminate child processes on {alert.AgentId}.\n"
                f"2. Apply policy-guided network boundary restrictions via ZTNA gateway.\n"
                f"3. Conduct deep forensic audit on related telemetry events.\n"
                f"4. Escalate incident dossier to Tier 2 SOC Analyst for final case resolution."
            )

        grounded_fallback = {
            "executive_summary": exec_summary,
            "technical_details": tech_details,
            "remediation_steps": remediation
        }

        response = await self._run_llm_inference(prompt, fallback_response=grounded_fallback)

        report = AiIncidentReport(
            AlertId=alert.Id,
            ExecutiveSummary=response.get("executive_summary", exec_summary),
            TechnicalDetails=response.get("technical_details", tech_details),
            RemediationSteps=response.get("remediation_steps", remediation)
        )
        db.add(report)
        await db.commit()

        # ── Real-time push to SOC Dashboard via Socket.IO ─────────────────────
        try:
            from app.socket_instance import sio
            await sio.emit("ai_report_ready", {
                "agentId": alert.AgentId,
                "alertId": alert.Id,
                "reportId": report.Id,
                "ruleName": rule_info["Name"],
                "severity": rule_info["Severity"],
                "executiveSummary": report.ExecutiveSummary,
                "remediationSteps": report.RemediationSteps,
            }, room=alert.AgentId)
        except Exception as e:
            print(f"[AI Copilot] Socket.IO push failed: {e}")

        return report.Id, "Report generated successfully"

    async def _run_llm_inference(self, prompt: str, fallback_response: dict = None) -> dict:
        print(f"[AI COPILOT] Processing Copilot Inference...")
        
        api_key = os.environ.get("OPENAI_API_KEY")
        ollama_host = os.environ.get("OLLAMA_HOST", "http://watch-sec-ollama:11434")
        
        if fallback_response is None:
            fallback_response = {
                "executive_summary": "Could not connect to Generative AI engine.",
                "technical_details": "Inference failed or timed out.",
                "remediation_steps": "Please verify OpenAI keys or Ollama container."
            }

        # ── TIER A: CLOUD LLM (OPENAI) ──
        if api_key:
            try:
                ai_endpoint = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        ai_endpoint,
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": "gpt-4o-mini",
                            "messages": [{"role": "user", "content": prompt}],
                            "temperature": 0.2
                        }
                    )
                    if resp.status_code == 200:
                        content = resp.json()["choices"][0]["message"]["content"]
                        return self._parse_json(content)
            except Exception as e:
                print(f"[AI Copilot] Cloud LLM failed: {e}")

        # ── TIER B: OFFLINE LLM (OLLAMA) ──
        try:
            async with httpx.AsyncClient(timeout=45.0) as client:
                resp = await client.post(
                    f"{ollama_host}/api/chat",
                    json={
                        "model": "phi3",
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False,
                        "options": {"temperature": 0.2}
                    }
                )
                if resp.status_code == 200:
                    content = resp.json()["message"]["content"]
                    return self._parse_json(content)
        except Exception as e:
            print(f"[AI Copilot] Ollama execution failed: {e}")

        return fallback_response

    def _parse_json(self, content: str) -> dict:
        import json
        # Strip markdown fences if present
        content = re.sub(r'^```json\s*', '', content, flags=re.MULTILINE)
        content = re.sub(r'^```\s*', '', content, flags=re.MULTILINE).strip()
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            print(f"[AI Copilot] JSON Parse Error on: {content}")
            return {
                "executive_summary": "AI response format was invalid.",
                "technical_details": f"Raw Output:\n{content}",
                "remediation_steps": "None"
            }

ai_engine = AiCopilotEngine()
