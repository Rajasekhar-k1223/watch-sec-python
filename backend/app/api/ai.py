from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from ..services.ai_service import ai_service
from .deps import get_current_user
from ..db.models import User

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
