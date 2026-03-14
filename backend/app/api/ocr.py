from fastapi import APIRouter, Depends, HTTPException # type: ignore
from sqlalchemy.orm import Session # type: ignore
from sqlalchemy.future import select # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from typing import List, Optional # type: ignore
from datetime import datetime # type: ignore
import json # type: ignore
import random # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import OCRLog, User # type: ignore
from ..api.deps import get_current_user # type: ignore

router = APIRouter()

@router.get("/ocr")
async def get_ocr_logs(
    agent_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    date_range: Optional[str] = None,
    q: Optional[str] = None, # Search Query
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(OCRLog).order_by(OCRLog.Timestamp.desc())
    
    if agent_id:
        query = query.where(OCRLog.AgentId == agent_id)
    
    # [NEW] Handle Date Range
    from datetime import timedelta      # type: ignore
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
            query = query.where(OCRLog.Timestamp >= dt_start)
        except: pass
    
    if end_date:
        try:
            dt_end = datetime.fromisoformat(end_date.replace("Z", ""))
            query = query.where(OCRLog.Timestamp <= dt_end)
        except: pass

    if q:
        query = query.where(OCRLog.ExtractedText.ilike(f"%{q}%"))

    query = query.limit(100)
    result = await db.execute(query)
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

@router.post("/ocr/process/real")
async def process_ocr(
    agentId: str,
    screenshot_id: str,
    db: AsyncSession = Depends(get_db),
    # current_user: User = Depends(get_current_user) # Agent might call this
):
    import pytesseract # type: ignore
    from PIL import Image # type: ignore
    import os # type: ignore

    # 1. Resolve Image Path
    # Assuming screenshots are stored in 'storage/screenshots/{agentId}/{screenshot_id}'
    # Or 'storage/screenshots/{screenshot_id}' depending on screenshots.py logic.
    # We will assume a standard path for now or check common locations.
    
    import glob # type: ignore
    base_path = "/app/storage/Screenshots"
    file_path = None
    
    # Aggressively search for the filename anywhere under base_path
    search_pattern = os.path.join(base_path, "**", screenshot_id)
    matches = glob.glob(search_pattern, recursive=True)
    
    if matches:
        file_path = matches[0]
            
    if not file_path:
        raise HTTPException(status_code=404, detail=f"Screenshot not found: {screenshot_id}")

    try:
        # 2. Perform OCR
        # Timeout to prevent hanging
        text = pytesseract.image_to_string(Image.open(file_path), timeout=10)
        
        # 3. Analyze Text
        sensitive_words = ["Confidential", "Internal Use Only", "SSN", "Password", "Credit Card", "Restricted", "Salary", "Invoice", "Project", "Contract", "Legal", "Financial"]
        found_keywords = [word for word in sensitive_words if word.lower() in text.lower()]
        
        confidence = 1.0 # Tesseract confidence requires image_to_data, simplified for now
        
        # 4. Save Log
        new_log = OCRLog(
            AgentId=agentId,
            ScreenshotId=screenshot_id,
            ExtractedText=text[:5000], # Limit size
            Confidence=confidence,
            SensitiveKeywordsFound=json.dumps(found_keywords)
        )
        
        db.add(new_log)
        await db.commit()
        
        return {"status": "processed", "found": found_keywords, "text_preview": text[:100]}
        
    except Exception as e:
        print(f"OCR Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
