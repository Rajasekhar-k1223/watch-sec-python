from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime
import json
import random

from ..db.session import get_db
from ..db.models import OCRLog, User
from ..api.deps import get_current_user

router = APIRouter()

@router.get("/ocr")
async def get_ocr_logs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(OCRLog).order_by(OCRLog.Timestamp.desc()).limit(100))
    logs = result.scalars().all()
    
    # Parse JSON string back to list for response
    response_data = []
    for log in logs:
        log_dict = {
            "id": log.Id,
            "agentId": log.AgentId,
            "screenshotId": log.ScreenshotId,
            "extractedText": log.ExtractedText,
            "confidence": log.Confidence,
            "sensitiveKeywordsFound": json.loads(log.SensitiveKeywordsFound) if log.SensitiveKeywordsFound else [],
            "timestamp": log.Timestamp.isoformat()
        }
        response_data.append(log_dict)
        
    return response_data

@router.post("/ocr/process/simulated-screen-123")
async def simulate_ocr(
    agentId: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Simulation Logic
    sample_texts = [
        "Confidential Project X Plan: Budget $5M",
        "Recipe for chocolate cake: Flour, Sugar, Cocoa",
        "Invoice #9991 for Client ABC. Total: $500",
        "Social Security Number: 123-45-6789 (Do not share)",
        "Meeting notes: Discuss Q3 targets",
    ]
    
    text = random.choice(sample_texts)
    confidence = random.uniform(0.7, 0.99)
    
    sensitive_words = ["Confidential", "Project X", "Social Security", "SSN"]
    found_keywords = [word for word in sensitive_words if word in text]
    
    new_log = OCRLog(
        AgentId=agentId,
        ScreenshotId=f"scr_{random.randint(1000,9999)}.jpg",
        ExtractedText=text,
        Confidence=confidence,
        SensitiveKeywordsFound=json.dumps(found_keywords)
    )
    
    db.add(new_log)
    await db.commit()
    
    return {"status": "processed", "found": found_keywords}
