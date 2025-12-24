from fastapi import APIRouter, Depends, HTTPException
from typing import List
from motor.motor_asyncio import AsyncIOMotorClient

from ..db.session import get_mongo_db
from ..schemas import MailLog
from .deps import get_current_user
from ..db.models import User

router = APIRouter()

@router.get("/", response_model=List[MailLog])
async def get_mail_logs(
    mongo: AsyncIOMotorClient = Depends(get_mongo_db),
    current_user: User = Depends(get_current_user)
):
    # TODO: Add Tenant Filter (check which Agents belong to Tenant)
    # For now, SuperAdmin sees all or we trust frontend filter?
    # Ideally: Find all AgentIds for this Tenant, then $in query.
    
    db = mongo["watchsec"]
    collection = db["mail_logs"]
    
    cursor = collection.find({}).sort("Timestamp", -1).limit(100)
    logs = await cursor.to_list(length=100)
    return logs
