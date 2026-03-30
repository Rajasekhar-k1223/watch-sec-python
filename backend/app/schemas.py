from pydantic import BaseModel # type: ignore
from typing import Optional, List, Any # type: ignore
from datetime import datetime # type: ignore

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
    WindowTitle: Optional[str] = "Unknown"
    ProcessName: Optional[str] = "Unknown"
    Url: Optional[str] = None
    DurationSeconds: float
    IdleSeconds: float = 0.0
    Category: Optional[str] = "Neutral"
    ProductivityScore: Optional[float] = 0.0
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
    TenantApiKey: Optional[str] = None
    ActivityType: str
    WindowTitle: Optional[str] = "Unknown"
    ProcessName: Optional[str] = "Unknown"
    Url: Optional[str] = None
    DurationSeconds: float
    IdleSeconds: float = 0.0
    Category: Optional[str] = "Neutral"
    ProductivityScore: Optional[float] = 0.0
    Timestamp: datetime

    class Config:
        extra = "allow"

class ScreenshotDto(BaseModel):
    Filename: str
    Date: str
    Timestamp: datetime
    IsAlert: bool
    Url: str

class AgentSettingsUpdate(BaseModel):
    ScreenshotQuality: Optional[int] = 80
    ScreenshotResolution: Optional[str] = "Original"
    MaxScreenshotSize: Optional[int] = 0
    BlockedApps: Optional[List[str]] = [] # [NEW]
    ShadowPaths: Optional[List[str]] = [] # [NEW] Enterprise Shadow Vault
    ScreenshotInterval: Optional[int] = 60 # [NEW] v1.8.20

class AgentHeartbeat(BaseModel):
    AgentId: str
    TenantApiKey: str
    Status: str = "Online"
    Hostname: str = "Unknown"
    CpuUsage: float = 0.0
    MemoryUsage: float = 0.0
    Timestamp: Optional[Any] = None
    InstalledSoftwareJson: Optional[str] = "[]"
    LocalIp: Optional[str] = None
    Gateway: Optional[str] = None
    PowerStatus: Optional[dict] = None
    Hardware: Optional[dict] = None
    Version: Optional[str] = "v1.3.0"
    JustStarted: bool = False
    Latitude: Optional[float] = 0.0
    Longitude: Optional[float] = 0.0
    Country: Optional[str] = None
    DiskUsage: Optional[float] = 0.0
    TopProcessesJson: Optional[str] = "[]"

class AgentUpdateFailedRequest(BaseModel):
    AgentId: str
    Reason: str

class AgentUpdateLogRequest(BaseModel):
    AgentId: str
    Log: str


