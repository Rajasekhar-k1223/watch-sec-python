from fastapi import APIRouter, Depends, HTTPException, Body # type: ignore
from fastapi.responses import Response, StreamingResponse # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy.orm import selectinload # type: ignore
from typing import List, Optional # type: ignore
from pydantic import BaseModel # type: ignore
from datetime import datetime # type: ignore
import base64 # type: ignore
import io # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import MailLog, MailAttachment, Tenant, User, Agent # type: ignore
from .deps import get_current_user # type: ignore
from .agents import verify_feature_access # type: ignore

router = APIRouter()

class AttachmentDto(BaseModel):
    FileName: str
    ContentType: str
    Content: str # Base64 encoded string
    Size: int

class MailLogDto(BaseModel):
    AgentId: str
    TenantApiKey: str
    Sender: str
    Recipient: str
    Subject: str
    BodyPreview: Optional[str] = None
    HasAttachments: bool = False
    AttachmentNames: Optional[str] = None
    Timestamp: datetime = datetime.utcnow()
    Attachments: List[AttachmentDto] = []

@router.get("/{agent_id}", response_model=List[dict])
async def get_agent_mail_logs(
    agent_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    date_range: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(MailLog)\
        .options(selectinload(MailLog.Attachments))\
        .where(MailLog.AgentId == agent_id)
    
    # [SECURITY] Plan Check
    res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = res_a.scalars().first()
    if agent:
        res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = res_t.scalars().first()
        if tenant:
            verify_feature_access(tenant.Plan, "MailMonitorEnabled")
    
    # [NEW] Handle Date Range
    from datetime import timedelta # type: ignore
    if date_range:
        now = datetime.utcnow()
        if date_range == "24h":
            start_date = (now - timedelta(hours=24)).isoformat()
        elif date_range == "7d":
            start_date = (now - timedelta(days=7)).isoformat()
        elif date_range == "30d":
            start_date = (now - timedelta(days=30)).isoformat()
    
    if start_date:
        try:
            dt_start = datetime.fromisoformat(start_date.replace("Z", ""))
            query = query.where(MailLog.Timestamp >= dt_start)
        except: pass
    
    if end_date:
        try:
            dt_end = datetime.fromisoformat(end_date.replace("Z", ""))
            query = query.where(MailLog.Timestamp <= dt_end)
        except: pass

    query = query.order_by(MailLog.Timestamp.desc()).limit(200)
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return [{
        "Id": l.Id,
        "AgentId": l.AgentId,
        "Sender": l.Sender,
        "Recipient": l.Recipient,
        "Subject": l.Subject,
        "BodyPreview": l.BodyPreview,
        "HasAttachments": l.HasAttachments,
        "RiskLevel": l.RiskLevel,
        "Timestamp": l.Timestamp,
        "Attachments": [{"Id": a.Id, "FileName": a.FileName, "Size": a.Size} for a in l.Attachments]
    } for l in logs]

@router.get("/attachment/{attachment_id}")
async def download_attachment(
    attachment_id: int,
    db: AsyncSession = Depends(get_db)
    # Removing Auth for ease of download via browser link, or add token to query param
):
    result = await db.execute(select(MailAttachment).where(MailAttachment.Id == attachment_id))
    att = result.scalars().first()
    
    if not att:
        raise HTTPException(status_code=404, detail="Attachment not found")
        
    try:
        # Decode Base64
        file_bytes = base64.b64decode(att.Content)
        return StreamingResponse(
            io.BytesIO(file_bytes), 
            media_type=att.ContentType or "application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={att.FileName}"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decode file: {str(e)}")

@router.post("/")
async def log_mail(
    dto: MailLogDto,
    db: AsyncSession = Depends(get_db)
):
    # Tenant Validation
    result = await db.execute(select(Tenant).where(Tenant.ApiKey == dto.TenantApiKey))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # [SECURITY] Plan Check
    verify_feature_access(tenant.Plan, "MailMonitorEnabled")

    # Simple Analysis (DLP)
    risk = "Normal"
    suspicious_domains = ["gmail.com", "yahoo.com", "hotmail.com"]
    if any(d in dto.Recipient.lower() for d in suspicious_domains) and dto.HasAttachments:
        risk = "High"

    new_log = MailLog(
        AgentId=dto.AgentId,
        Sender=dto.Sender,
        Recipient=dto.Recipient,
        Subject=dto.Subject,
        BodyPreview=dto.BodyPreview,
        HasAttachments=dto.HasAttachments,
        AttachmentNames=dto.AttachmentNames,
        RiskLevel=risk,
        Timestamp=dto.Timestamp
    )
    
    db.add(new_log)
    await db.flush() # Generate ID for Attachments
    
    # Process Attachments
    if dto.Attachments:
        for att_dto in dto.Attachments:
            new_att = MailAttachment(
                MailLogId=new_log.Id,
                FileName=att_dto.FileName,
                ContentType=att_dto.ContentType,
                Content=att_dto.Content,
                Size=att_dto.Size
            )
            db.add(new_att)
            
    await db.commit()
    return {"status": "Logged", "risk": risk}
