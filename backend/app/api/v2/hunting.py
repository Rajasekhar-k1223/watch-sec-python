from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.clickhouse import clickhouse_db
from app.db.models import SavedHunt, InvestigationWorkspace, InvestigationEvidence, User
from app.api.deps import get_current_user
from pydantic import BaseModel
import datetime

router = APIRouter()

class SearchPayload(BaseModel):
    query: str
    time_range: str = "24h"

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
async def execute_search(payload: SearchPayload, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Parse basic keyword
    keyword = payload.query.replace("process.name:", "").replace("\"", "").strip()
    
    # Query ClickHouse Data Lake for the keyword across all raw telemetry payloads
    rows = clickhouse_db.search_telemetry(keyword, limit=100)
    
    results = []
    for row in rows:
        event_id, agent_id, event_type, timestamp, payload_str = row
        results.append({
            "id": str(event_id),
            "type": event_type,
            "agent": agent_id,
            "data": payload_str,
            "timestamp": timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp)
        })
        
    return {"status": "success", "hits": len(results), "results": results}

@router.get("/saved")
async def list_saved_hunts(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    hunts = (await db.execute(select(SavedHunt).order_by(desc(SavedHunt.CreatedAt)))).scalars().all()
    return hunts

@router.post("/saved")
async def create_saved_hunt(request: SavedHuntRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    hunt = SavedHunt(
        Name=request.name,
        Description=request.description,
        QueryString=request.query,
        CreatedBy=current_user.Username
    )
    db.add(hunt)
    await db.commit()
    return {"status": "success", "hunt_id": hunt.Id}

@router.get("/workspaces")
async def list_workspaces(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    workspaces = (await db.execute(select(InvestigationWorkspace).order_by(desc(InvestigationWorkspace.CreatedAt)))).scalars().all()
    return workspaces

@router.post("/workspaces")
async def create_workspace(request: WorkspaceRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = InvestigationWorkspace(
        Title=request.title,
        OwnerId=current_user.Username
    )
    db.add(ws)
    await db.commit()
    return {"status": "success", "workspace_id": ws.Id}

@router.post("/workspaces/{workspace_id}/evidence")
async def add_evidence(workspace_id: int, request: EvidenceRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = (await db.execute(select(InvestigationWorkspace).where(InvestigationWorkspace.Id == workspace_id))).scalars().first()
    if not ws:
        raise HTTPException(status_code=404, detail="Workspace not found")

    evidence = InvestigationEvidence(
        WorkspaceId=ws.Id,
        TelemetryId=request.telemetry_id,
        TelemetryType=request.telemetry_type,
        AnalystNote=request.note
    )
    db.add(evidence)
    await db.commit()
    return {"status": "success", "evidence_id": evidence.Id}

@router.get("/workspaces/{workspace_id}/timeline")
async def get_timeline(workspace_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    evidence = (await db.execute(
        select(InvestigationEvidence)
        .where(InvestigationEvidence.WorkspaceId == workspace_id)
        .order_by(InvestigationEvidence.AddedAt)
    )).scalars().all()
    return {"workspace_id": workspace_id, "timeline": evidence}
