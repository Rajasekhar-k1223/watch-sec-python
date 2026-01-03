from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import base64
import io

from ..db.session import get_db
from ..db.models import MailLog, MailAttachment, Tenant, User
from .deps import get_current_user

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

@router.get("/", response_model=List[dict])
async def get_all_mail_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(MailLog).options(selectinload(MailLog.Attachments)).order_by(MailLog.Timestamp.desc()).limit(100)
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
