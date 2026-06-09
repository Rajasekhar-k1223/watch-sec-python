from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import SavedHunt, InvestigationWorkspace, InvestigationEvidence, User
from app.api.deps import get_current_user
from pydantic import BaseModel
import datetime

router = APIRouter()

class SearchPayload(BaseModel):
    query: str
    time_range: str = "24h" # e.g. 24h, 7d, 30d

class SavedHuntRequest(BaseModel):
    name: str
    description: str
    query: str

class WorkspaceRequest(BaseModel):
    title: str

class EvidenceRequest(BaseModel):
    telemetry_id: int
    telemetry_type: str
    note: str = ""

@router.post("/search")
async def execute_search(payload: SearchPayload, current_user: User = Depends(get_current_user)):
    # Stub: Translate Lucene/KQL syntax into Mongo/Elastic query
    # Mocking results for architecture demonstration
    mock_results = [
        {"id": 101, "type": "Process", "agent": "AGENT-1", "data": "powershell.exe -w hidden", "timestamp": datetime.datetime.utcnow().isoformat()},
        {"id": 102, "type": "Network", "agent": "AGENT-1", "data": "TCP 4444 -> 10.0.0.5", "timestamp": datetime.datetime.utcnow().isoformat()},
        {"id": 103, "type": "DNS", "agent": "AGENT-2", "data": "malicious-c2.com", "timestamp": datetime.datetime.utcnow().isoformat()}
    ]
    return {"status": "success", "hits": len(mock_results), "results": mock_results}

@router.get("/saved")
async def list_saved_hunts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    hunts = db.query(SavedHunt).order_by(desc(SavedHunt.CreatedAt)).all()
    return hunts

@router.post("/saved")
async def create_saved_hunt(request: SavedHuntRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    hunt = SavedHunt(
        Name=request.name,
        Description=request.description,
        QueryString=request.query,
        CreatedBy=current_user.Username
    )
    db.add(hunt)
    db.commit()
    return {"status": "success", "hunt_id": hunt.Id}

@router.get("/workspaces")
async def list_workspaces(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    workspaces = db.query(InvestigationWorkspace).order_by(desc(InvestigationWorkspace.CreatedAt)).all()
    return workspaces

@router.post("/workspaces")
async def create_workspace(request: WorkspaceRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = InvestigationWorkspace(
        Title=request.title,
        OwnerId=current_user.Username
    )
    db.add(ws)
    db.commit()
    return {"status": "success", "workspace_id": ws.Id}

@router.post("/workspaces/{workspace_id}/evidence")
async def add_evidence(workspace_id: int, request: EvidenceRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = db.query(InvestigationWorkspace).filter(InvestigationWorkspace.Id == workspace_id).first()
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")
        
    evidence = InvestigationEvidence(
        WorkspaceId=ws.Id,
        TelemetryId=request.telemetry_id,
        TelemetryType=request.telemetry_type,
        AnalystNote=request.note
    )
    db.add(evidence)
    db.commit()
    return {"status": "success", "evidence_id": evidence.Id}

@router.get("/workspaces/{workspace_id}/timeline")
async def get_timeline(workspace_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    evidence = db.query(InvestigationEvidence).filter(InvestigationEvidence.WorkspaceId == workspace_id)\
                 .order_by(InvestigationEvidence.AddedAt).all()
                 
    # In a real system, we would join these TelemetryIds back to the actual logs
    # For now we return the structured timeline
    return {"workspace_id": workspace_id, "timeline": evidence}
