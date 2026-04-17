from app.core.celery_app import celery_app # type: ignore
from sqlalchemy import create_engine # type: ignore
from sqlalchemy.orm import sessionmaker # type: ignore
from app.db.models import OCRLog, Agent # type: ignore
from app.db.session import settings # type: ignore
import json # type: ignore
import logging # type: ignore
import pytesseract # type: ignore
from PIL import Image # type: ignore
import os # type: ignore
from datetime import datetime # type: ignore

# Setup Sync DB Connection for Celery
sync_url = settings.DATABASE_URL.replace("sqlite+aiosqlite", "sqlite").replace("postgresql+asyncpg", "postgresql")
engine = create_engine(sync_url)
Session = sessionmaker(bind=engine)

logger = logging.getLogger("Celery-OCR")

@celery_app.task
def process_ocr_background(agent_id: str, screenshot_id: str, file_path: str):
    """
    Background Task to perform OCR on a screenshot and save results to OCRLog.
    Enhanced with PII Regex detection and Risk Scoring.
    """
    import re # type: ignore
    from app.db.models import Notification # type: ignore

    if not os.path.exists(file_path):
        logger.error(f"OCR Task failed: File not found at {file_path}")
        return

    session = Session()
    try:
        # 1. Perform OCR
        text_content = pytesseract.image_to_string(Image.open(file_path), timeout=30)
        
        # 2. Analyze Text for Sensitive Keywords & Regex Patterns
        sensitive_words = ["Confidential", "Internal Use Only", "Restricted", "Salary", "Invoice", "Project", "Contract", "Legal", "Financial"]
        found_keywords = [word for word in sensitive_words if word.lower() in text_content.lower()]
        
        # [NEW] Regex Patterns for PII
        patterns = {
            "Social Security Number": r"\d{3}-\d{2}-\d{4}",
            "Credit Card": r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",
            "API Key": r"[a-zA-Z0-9_\-]{32,}",
            "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "IP Address": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        }
        
        pii_found = []
        for label, pattern in patterns.items():
            if re.search(pattern, text_content):
                pii_found.append(label)
        
        # 3. Calculate Risk Level
        risk_level = "Normal"
        category = "General"
        
        if pii_found:
            risk_level = "Critical" if any(p in ["Social Security Number", "Credit Card", "API Key"] for p in pii_found) else "High"
            category = "PII"
        elif found_keywords:
            risk_level = "High"
            category = "Confidential"
            
        # [SECURITY] [v1.8.37] Centralized Server-Side Redaction
        from app.core.privacy import BackendPrivacyRedactor
        sanitized_text = BackendPrivacyRedactor.redact_text(text_content)

        # 4. Save to DB
        new_log = OCRLog(
            AgentId=agent_id,
            ScreenshotId=screenshot_id,
            ExtractedText=sanitized_text[:5000],
            Confidence=1.0,
            SensitiveKeywordsFound=json.dumps(found_keywords + pii_found),
            RiskLevel=risk_level,
            Category=category,
            Timestamp=datetime.utcnow()
        )
        session.add(new_log)
        
        # 5. [NEW] Trigger Notification for High/Critical Risk
        if risk_level in ["High", "Critical"]:
            # Fetch TenantId for the agent
            agent = session.query(Agent).filter(Agent.AgentId == agent_id).first()
            tenant_id = agent.TenantId if agent else None
            
            notif = Notification(
                TenantId=tenant_id,
                AgentId=agent_id,
                Title=f"DLP Alert: {risk_level} Risk Detected",
                Message=f"Sensitive data ({', '.join(pii_found or found_keywords)}) identified in screenshot {screenshot_id} on agent {agent_id}.",
                Type=risk_level,
                CreatedAt=datetime.utcnow()
            )
            session.add(notif)
            
            # [PROACTIVE] Attempt real-time broadcast via SocketIO if possible 
            # (Requires importing sio inside the task or using a shared relay)
            try:
                from app.socket_instance import sio_sync # type: ignore
                sio_sync.emit('NewNotification', {
                    "id": 0, "title": notif.Title, "message": notif.Message, "type": risk_level, "agentId": agent_id
                }, room=f"tenant_{tenant_id}")

                # [NEW] Trigger Automated Remediation Playbooks
                from app.core.remediation import evaluate_remediation # type: ignore
                evaluate_remediation(session, tenant_id, agent_id, {
                    "event_type": "DLP_FINDING",
                    "risk_level": risk_level,
                    "category": category,
                    "findings": pii_found or found_keywords
                })
            except Exception as se:
                logger.warning(f"Failed to emit real-time notification/remediation: {se}")

        session.commit()
        logger.info(f"OCR processed for Agent {agent_id}. Risk: {risk_level}. Found: {len(found_keywords + pii_found)} items.")
        
    except Exception as e:
        logger.error(f"OCR Error for Agent {agent_id}: {e}")
        session.rollback()
    finally:
        # [v1.8.37] Forensic Cleanup: Purge raw unredacted screenshots from disk
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.info(f"Purged raw screenshot: {file_path}")
            except Exception as pe:
                logger.error(f"Failed to purge raw screenshot: {pe}")
        session.close()
