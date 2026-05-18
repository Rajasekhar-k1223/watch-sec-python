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
    current_user: User = Depends(get_current_user)
):
    """[v2.1.0] Generates a human-readable summary of recent security events for an agent."""
    # 1. Fetch Events (Mocked for demo, should fetch from DB)
    from datetime import datetime, timedelta
    mock_events = [
        {"Type": "Auth Failure", "Details": "Failed login for root from 192.168.1.50", "Timestamp": (datetime.utcnow() - timedelta(minutes=10)).isoformat()},
        {"Type": "DLP Match", "Details": "USB Copy detected: payroll_2026.xlsx", "Timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat()},
        {"Type": "Network Alert", "Details": "Outbound connection to known C2 IP: 45.33.22.11", "Timestamp": datetime.utcnow().isoformat()}
    ]
    
    summary = ai_service.generate_incident_summary(mock_events)
    threat_assessment = ai_service.calculate_threat_score(req.agent_id, mock_events)
    
    return {
        "AgentId": req.agent_id,
        "Summary": summary,
        "ThreatAssessment": threat_assessment,
        "RemediationSteps": [
            "Disable network adapter via remediation handler",
            "Revoke all active sessions for User: root",
            "Trigger full malware scan on Agent storage"
        ]
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

