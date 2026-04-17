from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON, Index # type: ignore
from sqlalchemy.dialects.mysql import LONGTEXT # type: ignore
from sqlalchemy.orm import relationship # type: ignore
from datetime import datetime # type: ignore
from .session import Base # type: ignore

class Tenant(Base):
    __tablename__ = "Tenants"
    
    Id = Column(Integer, primary_key=True, index=True)
    Name = Column(String(255), default="")
    ApiKey = Column(String(255), default="")
    Plan = Column(String(50), default="Starter")
    AgentLimit = Column(Integer, default=5)
    NextBillingDate = Column(DateTime, default=datetime.utcnow)
    TrustedDomainsJson = Column(Text, default="[]") 
    TrustedIPsJson = Column(Text, default="[]")
    RegistrationIp = Column(String(50), nullable=True)
    AdminEmail = Column(String(255), nullable=True) # [v1.7.1] Mandatory for new registrations
    MaintenanceWindowJson = Column(Text, default="{}") # [v1.8.0] Scheduled update configuration
    
    # Bandwidth Configuration [NEW]
    bandwidth_config = Column(JSON, default={
        "max_rate_kbps": 0,  # 0 = unlimited
        "business_hours": {
            "enabled": False,
            "start": "09:00",
            "end": "17:00",
            "throttle_percent": 30
        },
        "compression_enabled": True,
        "min_available_bandwidth_mbps": 5
    })
    
    # [NEW] Stripe Integration
    StripeCustomerId = Column(String(255), nullable=True, index=True)
    SubscriptionStatus = Column(String(50), default="active") # active, past_due, canceled, incomplete

    # [NEW] Reporting Configuration
    ReportingConfigJson = Column(JSON, default={"frequency": "daily", "last_sent": None})

class FeatureTrial(Base):
    """Track 1-hour trial usage for premium features per tenant"""
    __tablename__ = "FeatureTrials"
    
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=False, index=True)
    FeatureName = Column(String(100), nullable=False)  # e.g., "LiveStreamEnabled"
    TrialStartedAt = Column(DateTime, default=datetime.utcnow, nullable=False)
    TrialExpiresAt = Column(DateTime, nullable=False)
    IsActive = Column(Boolean, default=True, index=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "Users"

    Id = Column(Integer, primary_key=True, index=True)
    Username = Column(String(255), unique=True)
    PasswordHash = Column(String(255))
    Role = Column(String(50), default="Analyst")
    TenantId = Column(Integer, nullable=True)

class Agent(Base):
    __tablename__ = "Agents"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(255), unique=True, index=True)
    TenantId = Column(Integer, nullable=False)
    ScreenshotsEnabled = Column(Boolean, default=False)
    LocationTrackingEnabled = Column(Boolean, default=False) # [NEW] User Toggle
    GeolocationEnabled = Column(Boolean, default=True) # [NEW] v1.8.27
    UsbBlockingEnabled = Column(Boolean, default=False) # [NEW] DLP Requirement User Toggle
    NetworkMonitoringEnabled = Column(Boolean, default=False) # [NEW] DLP Requirement
    FileDlpEnabled = Column(Boolean, default=False) # [NEW] DLP Requirement
    
    # Feature Toggles [NEW]
    ActivityMonitorEnabled = Column(Boolean, default=True)
    KeyloggerEnabled = Column(Boolean, default=False)
    ClipboardMonitorEnabled = Column(Boolean, default=False)
    AppBlockerEnabled = Column(Boolean, default=False)
    BrowserEnforcerEnabled = Column(Boolean, default=False)
    PrinterMonitorEnabled = Column(Boolean, default=False)
    ShadowMonitorEnabled = Column(Boolean, default=False)
    LiveStreamEnabled = Column(Boolean, default=False)
    RemoteShellEnabled = Column(Boolean, default=False)
    MailMonitorEnabled = Column(Boolean, default=False)
    SpeechMonitorEnabled = Column(Boolean, default=False) # [NEW] Enterprise Feature
    VulnerabilityIntelligenceEnabled = Column(Boolean, default=False) # [NEW] Enterprise Feature
    
    LastSeen = Column(DateTime, default=datetime.utcnow)
    Hostname = Column(String(255), default="Unknown")
    PublicIp = Column(String(50), nullable=True)
    Latitude = Column(Float, nullable=True)
    Longitude = Column(Float, nullable=True)
    Country = Column(Text, nullable=True)
    InstalledSoftwareJson = Column(LONGTEXT, nullable=True)
    LocalIp = Column(String(50), default="0.0.0.0")
    Gateway = Column(String(50), default="Unknown")
    PowerStatusJson = Column(Text, nullable=True) # [NEW] Battery info
    HardwareJson = Column(LONGTEXT, nullable=True) # [NEW] CPU/RAM/Disk details
    NetworkInMbps = Column(Float, default=0.0) # [NEW]
    NetworkOutMbps = Column(Float, default=0.0) # [NEW]
    BlockedAppsJson = Column(Text, default="[]") # [NEW] Feature 7: App Blocker
    ShadowPathsJson = Column(Text, default="[]") # [NEW] Enterprise Shadow Vault Paths
    
    # [NEW] Policy Assignment
    PolicyId = Column(Integer, ForeignKey("Policies.Id"), nullable=True)
    
    # Versioning [NEW]
    Version = Column(String(50), default="v1.2.2")
    TargetVersion = Column(String(50), default="v1.2.2")
    
    # Telemetry [NEW]
    CpuUsage = Column(Float, default=0.0)
    MemoryUsage = Column(Float, default=0.0)
    SoftwareCount = Column(Integer, default=0) # [v1.8.37] Parity Sync
    
    # Screenshot Settings
    ScreenshotQuality = Column(Integer, default=80)
    ScreenshotResolution = Column(String(50), default="Original")
    MaxScreenshotSize = Column(Integer, default=0) # KB, 0=Unlimited
    ScreenshotInterval = Column(Integer, default=60) # [NEW] v1.8.20
    
    # Deletion State
    IsPendingUninstall = Column(Boolean, default=False)
    
    # [v1.8.1 Patch 2] Update Status Tracking
    UpdateStatus = Column(String(50), default="idle")
    LastUpdateAttempt = Column(DateTime, nullable=True)
    UpdateFailureReason = Column(Text, nullable=True)
    MachineId = Column(String(255), nullable=True)

class AgentReportEntity(Base):
    __tablename__ = "AgentReports"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(255), index=True)
    TenantId = Column(Integer, index=True)
    Status = Column(String(50))
    CpuUsage = Column(Float)
    MemoryUsage = Column(Float)
    DiskUsage = Column(Float, default=0.0) # [NEW]
    SoftwareCount = Column(Integer, default=0) # [v1.8.37] Parity Sync
    NetworkInMbps = Column(Float, default=0.0) # [NEW] v1.8.26
    NetworkOutMbps = Column(Float, default=0.0) # [NEW] v1.8.26
    TopProcessesJson = Column(LONGTEXT, nullable=True) # [NEW]
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Composite indexes for fast time-filtered queries (hottest table)
    __table_args__ = (
        Index('ix_agent_reports_agentid_ts', 'AgentId', 'Timestamp'),
        Index('ix_agent_reports_tenantid_ts', 'TenantId', 'Timestamp'),
    )

class AuditLog(Base):
    __tablename__ = "AuditLogs"

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer)
    Actor = Column(String(255))
    Action = Column(String(255))
    Target = Column(String(255))
    Details = Column(Text)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class Policy(Base):
    __tablename__ = "Policies"

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer)
    Name = Column(String(255))
    RulesJson = Column(Text, default="[]")
    Actions = Column(String(255), default="Log")
    IsActive = Column(Boolean, default=True)
    BlockedAppsJson = Column(Text, default="[]")
    BlockedWebsitesJson = Column(Text, default="[]")
    RemediationJson = Column(Text, default="[]") # [NEW] Automated response playbooks
    BandwidthJson = Column(Text, default="{}") # [NEW] Policy-Based Bandwidth Control
    ScreenshotInterval = Column(Integer, default=60) # [NEW] v1.8.20
    GeolocationEnabled = Column(Boolean, default=True) # [NEW] v1.8.27
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class SystemSetting(Base):
    __tablename__ = "SystemSettings"

    Key = Column(String(255), primary_key=True, index=True)
    Value = Column(Text, default="")
    Category = Column(String(50), default="General")
    Description = Column(String(255), nullable=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class OCRLog(Base):
    __tablename__ = "OCRLogs"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    ScreenshotId = Column(String(255), nullable=True)
    ExtractedText = Column(Text, default="")
    Confidence = Column(Float, default=0.0)
    # Storing as JSON string
    SensitiveKeywordsFound = Column(Text, default="[]") 
    RiskLevel = Column(String(50), default="Normal") # [NEW] Normal, High, Critical
    Category = Column(String(50), default="General") # [NEW] PII, Financial, Health, etc.
    Timestamp = Column(DateTime, default=datetime.utcnow)

class Notification(Base):
    __tablename__ = "Notifications"

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, nullable=True, index=True)
    AgentId = Column(String(50), nullable=True, index=True)
    Title = Column(String(255))
    Message = Column(Text)
    Type = Column(String(50), default="Info") # Info, Warning, Error, Critical
    IsRead = Column(Boolean, default=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class ThesaurusEntry(Base):
    __tablename__ = "ThesaurusEntries"

    Id = Column(Integer, primary_key=True, index=True)
    Keyword = Column(String(100), index=True, nullable=False)
    # Storing list of synonyms as JSON string e.g. ["term1", "term2"]
    Synonyms = Column(Text, default="[]")
    Category = Column(String(50), default="General")
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class EventLog(Base):
    __tablename__ = "EventLogs"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    Type = Column(String(50), default="Unknown")
    Details = Column(Text, default="")
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    # Storing raw JSON if needed, or specific fields
    RawData = Column(Text, nullable=True)

class ActivityLog(Base):
    __tablename__ = "ActivityLogs"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    TenantId = Column(Integer, nullable=True, index=True)
    ActivityType = Column(String(50))
    ProcessName = Column(String(255), nullable=True)
    WindowTitle = Column(Text, nullable=True)
    Url = Column(Text, nullable=True)
    DurationSeconds = Column(Float, default=0.0)
    IdleSeconds = Column(Float, default=0.0) # [NEW]
    Category = Column(String(50), default="Neutral") # [NEW]
    ProductivityScore = Column(Float, default=0.0) # [NEW]
    RiskScore = Column(Float, default=0.0)
    RiskLevel = Column(String(50), default="Normal")
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Composite index for fast per-agent time-filtered activity queries
    __table_args__ = (
        Index('ix_activity_logs_agentid_ts', 'AgentId', 'Timestamp'),
        Index('ix_activity_logs_tenantid_ts', 'TenantId', 'Timestamp'),
    )

class SpeechLog(Base):
    __tablename__ = "SpeechLogs"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    AudioUrl = Column(String(255), nullable=True) # Path to stored wav/mp3
    TranscribedText = Column(Text, default="")
    Confidence = Column(Float, default=0.0)
    DurationSeconds = Column(Float, default=0.0)
    # Storing list of flagged keywords found as JSON
    FlaggedKeywordsJson = Column(Text, default="[]") 
    Timestamp = Column(DateTime, default=datetime.utcnow)

class HashBank(Base):
    __tablename__ = "HashBanks"

    Id = Column(Integer, primary_key=True, index=True)
    Hash = Column(String(255), unique=True, index=True) # MD5, SHA1, or SHA256
    Type = Column(String(50), default="SHA256")
    Reputation = Column(String(50), default="Malicious") # Malicious, Safe, Suspicious
    Description = Column(String(255), nullable=True)
    Source = Column(String(100), default="Manual") # Manual, Feed, User
    AddedBy = Column(String(100), nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class DigitalFingerprint(Base):
    __tablename__ = "DigitalFingerprints"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True)
    HardwareId = Column(String(255), index=True) # Unique HWID
    OS = Column(String(100))
    # Storing extended properties (BIOS serial, CPU ID etc) if needed
    PropertiesJson = Column(Text, default="{}") 
    Status = Column(String(50), default="Authorized") # Authorized, Revoked, Flagged
    FirstSeen = Column(DateTime, default=datetime.utcnow)
    LastSeen = Column(DateTime, default=datetime.utcnow)

class SavedSearch(Base):
    __tablename__ = "SavedSearches"

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True)
    Name = Column(String(100), nullable=False)
    QueryJson = Column(Text, default="{}") # Stores the search filters
    Category = Column(String(50), default="General")
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class MailLog(Base):
    __tablename__ = "MailLogs"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    Sender = Column(String(255))
    Recipient = Column(String(255))
    Subject = Column(String(255))
    BodyPreview = Column(Text, nullable=True) # First 500 chars
    HasAttachments = Column(Boolean, default=False)
    AttachmentNames = Column(Text, nullable=True) # Comma separated
    RiskLevel = Column(String(50), default="Normal") # Normal, High, Critical
    Timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Explicit Relationship
    Attachments = relationship("MailAttachment", back_populates="MailLog", cascade="all, delete-orphan")

class MailAttachment(Base):
    __tablename__ = "MailAttachments"

    Id = Column(Integer, primary_key=True, index=True)
    MailLogId = Column(Integer, ForeignKey("MailLogs.Id"))
    FileName = Column(String(255))
    ContentType = Column(String(100))
    Content = Column(Text) # Storing as Base64 String
    Size = Column(Integer) # Bytes
    
    
    MailLog = relationship("MailLog", back_populates="Attachments")

class Vulnerability(Base):
    __tablename__ = "Vulnerabilities"

    Id = Column(Integer, primary_key=True, index=True)
    CVE = Column(String(50), index=True, nullable=False) # e.g. CVE-2023-1234
    AffectedProduct = Column(String(255), index=True, nullable=False) # e.g. "Chrome"
    MinVersion = Column(String(50), nullable=True) # e.g. "100.0"
    MaxVersion = Column(String(50), nullable=True) # e.g. "115.0"
    Severity = Column(String(50), default="High") # Critical, High, Medium, Low
    Description = Column(Text, default="")
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class SessionRecording(Base):
    __tablename__ = "SessionRecordings"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True, nullable=False)
    Type = Column(String(50), default="RemoteDesktop") # RemoteDesktop, LiveStream
    StartTime = Column(DateTime, default=datetime.utcnow)
    EndTime = Column(DateTime, nullable=True)
    DurationSeconds = Column(Integer, default=0)
    VideoFilePath = Column(String(500), nullable=False) # Local storage path
    FileSize = Column(Integer, default=0) # Bytes

class ShadowedFile(Base):
    __tablename__ = "ShadowedFiles"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    OriginalPath = Column(Text)
    FileName = Column(String(255))
    StoragePath = Column(String(500)) # Path on server
    FileSize = Column(Integer)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class Screenshot(Base):
    __tablename__ = "Screenshots"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=True)
    Filename = Column(String(255), nullable=False)
    DateFolder = Column(String(50), index=True) # e.g. "20260312"
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    Size = Column(Integer, default=0)
    IsAlert = Column(Boolean, default=False)
    Url = Column(String(500))
    ThumbnailUrl = Column(String(500), nullable=True)

class ReportFile(Base):
    __tablename__ = "ReportFiles"

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, index=True, nullable=False)
    Filename = Column(String(255), nullable=False)
    Path = Column(String(500), nullable=False)
    Size = Column(Integer, default=0)
    GeneratedAt = Column(DateTime, default=datetime.utcnow, index=True)
    DownloadUrl = Column(String(500))
