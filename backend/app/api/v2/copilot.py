from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import AiIncidentReport, User
from app.services.ai_copilot import ai_engine
from app.api.deps import get_current_user

router = APIRouter()

@router.post("/summarize/{alert_id}")
async def generate_summary(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Triggers the RAG pipeline to pull context and generate an LLM incident report.
    """
    report_id, msg = ai_engine.generate_incident_report(db, alert_id)
    if not report_id:
        raise HTTPException(status_code=404, detail=msg)
        
    return {"status": "success", "report_id": report_id, "message": msg}

@router.get("/reports/{alert_id}")
async def get_report(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Retrieves the generated AI report for a specific alert.
    """
    report = db.query(AiIncidentReport).filter(AiIncidentReport.AlertId == alert_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated yet.")
        
    return {
        "alert_id": report.AlertId,
        "executive_summary": report.ExecutiveSummary,
        "technical_details": report.TechnicalDetails,
        "remediation_steps": report.RemediationSteps,
        "generated_at": report.GeneratedAt
    }
