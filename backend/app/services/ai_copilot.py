from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import DetectionAlert, DetectionRule, AiIncidentReport, ProcessLineageNode
import json
import httpx
import os
import re

class AiCopilotEngine:

    async def generate_incident_report(self, db: AsyncSession, alert_id: int):
        result = await db.execute(
            select(DetectionAlert, DetectionRule)
            .join(DetectionRule, DetectionAlert.RuleId == DetectionRule.Id)
            .where(DetectionAlert.Id == alert_id)
        )
        row = result.first()
        if not row:
            return None, "Alert not found"
            
        alert, rule = row

        process_context = ""
        try:
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
        Analyze the following incident and generate an Executive Summary, Technical Details, and Remediation Steps.
        Your response MUST be valid JSON conforming EXACTLY to this schema:
        {{
            "executive_summary": "string",
            "technical_details": "string",
            "remediation_steps": "string"
        }}
        Do not output any markdown formatting around the JSON, just the raw JSON object.

        Alert: {rule.Name}
        Severity: {rule.Severity}
        Agent: {alert.AgentId}
        MITRE: {rule.MitreTactic} -> {rule.MitreTechnique}
        Raw Payload: {alert.MatchedContent}
        Process Context: {process_context}
        """

        response = await self._run_llm_inference(prompt)

        report = AiIncidentReport(
            AlertId=alert.Id,
            ExecutiveSummary=response["executive_summary"],
            TechnicalDetails=response["technical_details"],
            RemediationSteps=response["remediation_steps"]
        )
        db.add(report)
        await db.commit()

        return report.Id, "Report generated successfully"

    async def _run_llm_inference(self, prompt: str) -> dict:
        print(f"[AI COPILOT] Processing Copilot Inference...")
        
        api_key = os.environ.get("OPENAI_API_KEY")
        ollama_host = os.environ.get("OLLAMA_HOST", "http://watch-sec-ollama:11434")
        
        fallback_response = {
            "executive_summary": "Could not connect to Generative AI engine.",
            "technical_details": "Inference failed or timed out.",
            "remediation_steps": "Please verify OpenAI keys or Ollama container."
        }

        # ── TIER A: CLOUD LLM (OPENAI) ──
        if api_key:
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        "https://api.openai.com/v1/chat/completions",
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
