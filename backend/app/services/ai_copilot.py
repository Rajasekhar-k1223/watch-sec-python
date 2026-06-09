from sqlalchemy.orm import Session
from app.db.models import DetectionAlert, AiIncidentReport, ProcessLineageNode
import json

class AiCopilotEngine:
    
    def generate_incident_report(self, db: Session, alert_id: int):
        """
        RAG Pipeline: Aggregates context around an alert and passes it
        to the LLM for report generation.
        """
        # 1. Retrieve the Alert
        alert = db.query(DetectionAlert).filter(DetectionAlert.Id == alert_id).first()
        if not alert:
            return None, "Alert not found"
            
        # 2. Gather Context (Retrieval)
        # Fetch process context if the alert was process-based
        process_context = ""
        try:
            raw_data = json.loads(alert.RawEventData)
            if "process_id" in raw_data:
                pid = raw_data["process_id"]
                node = db.query(ProcessLineageNode).filter(
                    ProcessLineageNode.AgentId == alert.AgentId,
                    ProcessLineageNode.ProcessId == pid
                ).first()
                if node:
                    process_context = f"Command Line: {node.CommandLine}\nImage Path: {node.ImagePath}"
        except:
            pass

        # 3. Construct System Prompt
        prompt = f"""
        You are the Monitorix AI Security Brain.
        Analyze the following incident and generate an Executive Summary, Technical Details, and Remediation Steps.
        
        Alert: {alert.RuleName}
        Severity: {alert.Severity}
        Agent: {alert.AgentId}
        MITRE: {alert.MitreTactic} -> {alert.MitreTechnique}
        
        Process Context: {process_context}
        """
        
        # 4. Invoke LLM (Mocked for Prototype)
        response = self._mock_llm_inference(prompt)
        
        # 5. Save Report
        report = AiIncidentReport(
            AlertId=alert.Id,
            ExecutiveSummary=response["executive_summary"],
            TechnicalDetails=response["technical_details"],
            RemediationSteps=response["remediation_steps"]
        )
        db.add(report)
        db.commit()
        
        return report.Id, "Report generated successfully"

    def _mock_llm_inference(self, prompt: str) -> dict:
        """
        Simulates an LLM (like Llama 3) processing the RAG prompt.
        """
        print(f"[AI COPILOT] Processing RAG prompt:\n{prompt}")
        
        return {
            "executive_summary": "The system detected suspicious execution behavior matching a known MITRE technique. A process was spawned using obscured command-line arguments indicative of a script-based attack or living-off-the-land (LotL) technique.",
            "technical_details": "The alert was triggered by the Sigma Rules engine due to an anomaly in the process tree. The process utilized base64 encoding to bypass static command-line inspection.",
            "remediation_steps": "1. Isolate the affected endpoint via the SOAR dashboard.\n2. Terminate the offending process ID.\n3. Hunt for the provided SHA256 hash across the rest of the fleet."
        }

ai_engine = AiCopilotEngine()
