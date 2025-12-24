from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime

# --- MongoDB Models ---

class SecurityEventLog(BaseModel):
    AgentId: str
    Type: str
    Details: str
    Timestamp: datetime
    Metadata: Optional[dict] = None

class ActivityLog(BaseModel):
    AgentId: str
    TenantId: Optional[int] = None
    ActivityType: str # "AppFocus", "UrlVisit", "Idle"
    WindowTitle: str
    ProcessName: str
    Url: Optional[str] = None
    DurationSeconds: float
    Timestamp: datetime
    RiskScore: Optional[float] = 0.0
    RiskLevel: Optional[str] = "Normal"

class MailLog(BaseModel):
    AgentId: str
    Sender: str
    Recipients: List[str]
    Subject: str
    HasAttachments: bool
    Timestamp: datetime

class OCRLog(BaseModel):
    AgentId: str
    ScreenshotId: str
    ExtractedText: str
    Confidence: float
    SensitiveKeywordsFound: List[str]
    Timestamp: datetime

# --- DTOs ---

class ActivityLogDto(BaseModel):
    AgentId: str
    TenantApiKey: str
    ActivityType: str
    WindowTitle: str
    ProcessName: str
    Url: Optional[str] = None
    DurationSeconds: float
    Timestamp: datetime

class ScreenshotDto(BaseModel):
    Filename: str
    Date: str
    Timestamp: datetime
    IsAlert: bool
    Url: str
