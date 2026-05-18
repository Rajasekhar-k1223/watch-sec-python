from fastapi import APIRouter, Depends, HTTPException # type: ignore
from pydantic import BaseModel # type: ignore
from ..services.ai_service import ai_service # type: ignore
from .deps import get_current_user # type: ignore
from ..db.models import User, Agent, EventLog, Vulnerability, ActivityLog # type: ignore
from ..db.session import get_db # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy import select, func # type: ignore

router = APIRouter()

class AnalysisRequest(BaseModel):
    text: str

class TrainingRequest(BaseModel):
    text: str
    category: str

@router.post("/analyze")
async def analyze_medical_text(
    req: AnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    result = ai_service.predict(req.text)
    return {"result": result}

@router.post("/train")
async def train_medical_model(
    req: TrainingRequest,
    current_user: User = Depends(get_current_user)
):
    success = ai_service.learn(req.text, req.category)
    return {"status": "Learned", "message": "Model updated with new case."}

class SecurityAnalysisRequest(BaseModel):
    logs: str # Raw log text

@router.post("/security/analyze")
async def analyze_security_event(
    req: SecurityAnalysisRequest,
    current_user: User = Depends(get_current_user)
):
    # Generic Anomaly Detection Logic
    # 1. Keyword Heuristics
    risk_score = 0
    triggers = []
    
    keywords = {
        "failed login": 10,
        "sudo": 5,
        "shadow": 20,
        "delete": 2,
        "encrypt": 15
    }
    
    text_lower = req.logs.lower()
    for kw, score in keywords.items():
        if kw in text_lower:
            risk_score += score
            triggers.append(kw)
            
    risk_level = "Low"
    if risk_score > 10: risk_level = "Medium"
    if risk_score > 30: risk_level = "High"
    if risk_score > 50: risk_level = "Critical"
    
    return {
        "RiskScore": risk_score,
        "RiskLevel": risk_level,
        "Triggers": triggers,
        "Recommendation": "Isolate Host" if risk_level in ["High", "Critical"] else "Monitor"
    }

class IncidentSummaryRequest(BaseModel):
    agent_id: str
    lookback_hours: int = 24

@router.post("/incident/summarize")
async def summarize_incident(
    req: IncidentSummaryRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """[v2.1.0] Generates a human-readable summary of recent security events for an agent from the live SQL database."""
    # 1. Fetch Real EventLogs from SQL Database
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(hours=req.lookback_hours)
    
    stmt = select(EventLog).where(
        EventLog.AgentId == req.agent_id,
        EventLog.Timestamp >= cutoff
    )
    res = await db.execute(stmt)
    db_events = res.scalars().all()
    
    # Map SQL models to dictionary list
    events = []
    for e in db_events:
        events.append({
            "Type": e.Type or "Unknown",
            "Details": e.Details or "",
            "Timestamp": e.Timestamp.isoformat() if e.Timestamp else datetime.utcnow().isoformat(),
            "Severity": e.Severity or "Medium"
        })
    
    # Fallback to a clean descriptive status if no recent event logs exist for this agent
    if not events:
        return {
            "AgentId": req.agent_id,
            "Summary": "No significant operational anomalies or security event logs registered for this agent in the requested lookback window. Platform posture is completely nominal.",
            "ThreatAssessment": {"Score": 0, "Level": "Normal", "TopRisks": []},
            "RemediationSteps": [
                "Continue standard system monitoring",
                "Ensure agent network connectivity is active",
                "Verify policy compliance status"
            ]
        }
        
    summary = ai_service.generate_incident_summary(events)
    threat_assessment = ai_service.calculate_threat_score(req.agent_id, events)
    
    # Calculate smart remediation suggestions dynamically based on active categories!
    remediation_steps = ["Establish baseline behavior and continue standard monitoring"]
    has_auth = any("auth" in e["Type"].lower() or "login" in e["Details"].lower() for e in events)
    has_dlp = any("dlp" in e["Type"].lower() or "usb" in e["Type"].lower() for e in events)
    has_network = any("network" in e["Type"].lower() or "c2" in e["Details"].lower() for e in events)
    
    if has_auth:
        remediation_steps.append("Enforce multi-factor authentication (MFA) and lock accounts on ssh SSH failure bursts")
    if has_dlp:
        remediation_steps.append("Block unauthorized USB read/write operations via EDR storage policy control")
    if has_network:
        remediation_steps.append("Isolate agent system from the local area network (LAN) immediately to prevent lateral spread")
        
    return {
        "AgentId": req.agent_id,
        "Summary": summary,
        "ThreatAssessment": threat_assessment,
        "RemediationSteps": remediation_steps
    }

@router.post("/incident/simulate")
async def simulate_incident(
    req: IncidentSummaryRequest,
    current_user: User = Depends(get_current_user)
):
    """[v2.5.0] Returns a demo AI threat assessment using realistic simulated events — for UI testing and demos."""
    from datetime import datetime, timedelta
    now = datetime.utcnow()

    demo_events = [
        {"Type": "Auth Failure",    "Details": "Failed SSH login for user root from 185.220.101.42 (Tor exit node)", "Timestamp": (now - timedelta(minutes=45)).isoformat(), "Severity": "High"},
        {"Type": "Auth Failure",    "Details": "Failed SSH login for user admin from 185.220.101.42",                "Timestamp": (now - timedelta(minutes=44)).isoformat(), "Severity": "High"},
        {"Type": "Auth Failure",    "Details": "Failed SSH login for user postgres from 185.220.101.42",             "Timestamp": (now - timedelta(minutes=43)).isoformat(), "Severity": "High"},
        {"Type": "Auth Failure",    "Details": "Failed SSH login for user ubuntu from 185.220.101.42",               "Timestamp": (now - timedelta(minutes=42)).isoformat(), "Severity": "High"},
        {"Type": "Auth Failure",    "Details": "Failed SSH login for user guest from 185.220.101.42",                "Timestamp": (now - timedelta(minutes=41)).isoformat(), "Severity": "High"},
        {"Type": "Auth Failure",    "Details": "Failed SSH login for user oracle from 185.220.101.42",               "Timestamp": (now - timedelta(minutes=40)).isoformat(), "Severity": "High"},
        {"Type": "DLP Match",       "Details": "USB mass storage device inserted. File copy: payroll_2026_Q1.xlsx → G:\\",  "Timestamp": (now - timedelta(minutes=30)).isoformat(), "Severity": "Critical"},
        {"Type": "DLP Match",       "Details": "Shadow vault violation: /etc/shadow read by process python3 (PID 9812)", "Timestamp": (now - timedelta(minutes=28)).isoformat(), "Severity": "Critical"},
        {"Type": "Network Alert",   "Details": "Outbound connection to known C2 IP: 45.33.32.156:4444 (Shodan-flagged)",   "Timestamp": (now - timedelta(minutes=15)).isoformat(), "Severity": "Critical"},
        {"Type": "Process Exec",    "Details": "Suspicious binary execution: /tmp/.x64 spawned by bash (PPID: 9812)",       "Timestamp": (now - timedelta(minutes=10)).isoformat(), "Severity": "High"},
    ]

    summary = ai_service.generate_incident_summary(demo_events)
    threat_assessment = ai_service.calculate_threat_score(req.agent_id, demo_events)

    remediation_steps = [
        "IMMEDIATELY isolate this agent from the network to prevent further lateral movement",
        "Revoke all active SSH sessions and rotate credentials for all service accounts",
        "Block removable media write access via USB DLP policy enforcement",
        "Engage threat hunting team to triage the suspected reverse shell process: /tmp/.x64",
        "Submit C2 IP 45.33.32.156 to firewall block list and threat intelligence platform",
        "Preserve forensic memory image before any system remediation"
    ]

    return {
        "AgentId": req.agent_id,
        "Summary": summary,
        "ThreatAssessment": threat_assessment,
        "RemediationSteps": remediation_steps,
        "_simulated": True
    }


class AssistantChatRequest(BaseModel):
    query: str

@router.post("/assistant/chat")
async def security_assistant_chat(
    req: AssistantChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """[v2.6.0] Interactive LLM-based Security Assistant with live SQL mapping."""
    return await ai_service.generate_conversational_response(req.query, current_user, db)

@router.get("/dataset")
async def get_training_dataset(
    current_user: User = Depends(get_current_user)
):
    """[NEW] Get all raw training data for EDR local ML audibility and inspection."""
    import os
    import pandas as pd
    data_path = "storage/security_data.csv"
    if not os.path.exists(data_path):
        return {"records": []}
    try:
        df = pd.read_csv(data_path)
        # Avoid pandas NaN issues by replacing them with empty strings
        df = df.fillna("")
        records = df.to_dict(orient="records")
        return {"records": records}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

