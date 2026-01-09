from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .session import Base

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
    UsbBlockingEnabled = Column(Boolean, default=False) # [NEW] DLP Requirement User Toggle
    NetworkMonitoringEnabled = Column(Boolean, default=False) # [NEW] DLP Requirement
    FileDlpEnabled = Column(Boolean, default=False) # [NEW] DLP Requirement
    LastSeen = Column(DateTime, default=datetime.utcnow)
    Hostname = Column(String(255), default="Unknown")
    PublicIp = Column(String(50), nullable=True)
    Latitude = Column(Float, default=0.0)
    Longitude = Column(Float, default=0.0)
    Country = Column(Text, nullable=True)
    InstalledSoftwareJson = Column(Text, nullable=True)
    LocalIp = Column(String(50), default="0.0.0.0")
    Gateway = Column(String(50), default="Unknown")
    
    # Screenshot Settings
    ScreenshotQuality = Column(Integer, default=80)
    ScreenshotResolution = Column(String(50), default="Original")
    MaxScreenshotSize = Column(Integer, default=0) # KB, 0=Unlimited

class AgentReportEntity(Base):
    __tablename__ = "AgentReports"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(255))
    TenantId = Column(Integer)
    Status = Column(String(50))
    CpuUsage = Column(Float)
    MemoryUsage = Column(Float)
    Timestamp = Column(DateTime, default=datetime.utcnow)

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
    Timestamp = Column(DateTime, default=datetime.utcnow)

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
    Timestamp = Column(DateTime, default=datetime.utcnow)
    # Storing raw JSON if needed, or specific fields
    RawData = Column(Text, nullable=True)

class ActivityLog(Base):
    __tablename__ = "ActivityLogs"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    TenantId = Column(Integer, nullable=True)
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
    Timestamp = Column(DateTime, default=datetime.utcnow)

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
