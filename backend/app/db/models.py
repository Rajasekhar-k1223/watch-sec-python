from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON, Index # type: ignore
from sqlalchemy.dialects.mysql import LONGTEXT # type: ignore
from sqlalchemy.orm import relationship # type: ignore
from datetime import datetime # type: ignore
from .session import Base # type: ignore

class Tenant(Base):
    __tablename__ = "Tenants"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
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
    
    # [v2.6.0] Sovereign Lockdown Management
    IsLocked = Column(Boolean, default=False)
    UnlockKeyHash = Column(String(255), nullable=True)
    LockdownReason = Column(Text, nullable=True) # [v2.6.8] Audit justification for banner
    
    # [NEW] Enterprise Agentless Check
    AgentlessEnabled = Column(Boolean, default=True)
    
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

    # [v2.2.0] Enterprise Integration Configurations
    SsoConfigJson = Column(JSON, default={}) # SAML/OIDC Metadata & Mapping
    SiemConfigJson = Column(JSON, default={"enabled": False, "type": "syslog", "endpoint": "", "api_key": ""})
    
    # [v2.6.0] Compliance & Privacy
    DataRetentionDays = Column(Integer, default=90) # GDPR/SOC2/HIPAA Compliance
    
    # [v2.6.0] External Integrations
    WebhookUrl = Column(String(500), nullable=True) # Slack/Teams/PagerDuty
    
    # [NEW] Reporting Configuration
    ReportingConfigJson = Column(JSON, default={"frequency": "daily", "last_sent": None})

class FeatureTrial(Base):
    """Track 1-hour trial usage for premium features per tenant"""
    __tablename__ = "FeatureTrials"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=False, index=True)
    FeatureName = Column(String(100), nullable=False)  # e.g., "LiveStreamEnabled"
    TrialStartedAt = Column(DateTime, default=datetime.utcnow, nullable=False)
    TrialExpiresAt = Column(DateTime, nullable=False)
    IsActive = Column(Boolean, default=True, index=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "Users"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    Username = Column(String(255), unique=True)
    Email = Column(String(255), unique=True, nullable=True)
    PasswordHash = Column(String(255))
    Role = Column(String(50), default="Analyst")
    TenantId = Column(Integer, nullable=True)

class Agent(Base):
    __tablename__ = "Agents"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(255), unique=True, index=True)
    TenantId = Column(Integer, nullable=False)
    # Feature Toggles [Renamed for Enterprise Compliance]
    ActivityMonitorEnabled = Column(Boolean, default=True)
    InputAuditEnabled = Column(Boolean, default=False) # Old: KeyloggerEnabled
    ClipboardAuditEnabled = Column(Boolean, default=False) # Old: ClipboardMonitorEnabled
    AppEnforcementEnabled = Column(Boolean, default=False) # Old: AppBlockerEnabled
    BrowserComplianceEnabled = Column(Boolean, default=False) # Old: BrowserEnforcerEnabled
    PrintAuditEnabled = Column(Boolean, default=False) # Old: PrinterMonitorEnabled
    ShadowAuditEnabled = Column(Boolean, default=False) # Old: ShadowMonitorEnabled
    SessionForensicEnabled = Column(Boolean, default=False) # Old: LiveStreamEnabled
    RemoteRemediationEnabled = Column(Boolean, default=False) # Old: RemoteShellEnabled
    MailIntelligenceEnabled = Column(Boolean, default=False) # Old: MailMonitorEnabled
    VoiceIntelligenceEnabled = Column(Boolean, default=False) # Old: SpeechMonitorEnabled
    VisualActivityEnabled = Column(Boolean, default=False) # Old: ScreenshotsEnabled
    LocationAuditEnabled = Column(Boolean, default=True) # Old: GeolocationEnabled
    UsbComplianceEnabled = Column(Boolean, default=False) # Old: UsbBlockingEnabled
    NetworkAuditEnabled = Column(Boolean, default=False) # Old: NetworkMonitoringEnabled
    DataLossPreventionEnabled = Column(Boolean, default=False) # Old: FileDlpEnabled
    VulnerabilityIntelligenceEnabled = Column(Boolean, default=False) # [NEW] Enterprise Feature
    MonitoringConsentRequired = Column(Boolean, default=False) # [NEW] Compliance Notification

    # SQLAlchemy Synonyms for Backward Compatibility
    from sqlalchemy.orm import synonym # type: ignore
    KeyloggerEnabled = synonym("InputAuditEnabled")
    ClipboardMonitorEnabled = synonym("ClipboardAuditEnabled")
    AppBlockerEnabled = synonym("AppEnforcementEnabled")
    BrowserEnforcerEnabled = synonym("BrowserComplianceEnabled")
    PrinterMonitorEnabled = synonym("PrintAuditEnabled")
    ShadowMonitorEnabled = synonym("ShadowAuditEnabled")
    LiveStreamEnabled = synonym("SessionForensicEnabled")
    RemoteShellEnabled = synonym("RemoteRemediationEnabled")
    MailMonitorEnabled = synonym("MailIntelligenceEnabled")
    SpeechMonitorEnabled = synonym("VoiceIntelligenceEnabled")
    ScreenshotsEnabled = synonym("VisualActivityEnabled")
    GeolocationEnabled = synonym("LocationAuditEnabled")
    LocationTrackingEnabled = synonym("LocationAuditEnabled")
    UsbBlockingEnabled = synonym("UsbComplianceEnabled")
    NetworkMonitoringEnabled = synonym("NetworkAuditEnabled")
    FileDlpEnabled = synonym("DataLossPreventionEnabled")
    
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
    DiskEncrypted = Column(Boolean, default=False) # [NEW] MDM Disk Encryption
    NetworkInMbps = Column(Float, default=0.0) # [NEW]
    NetworkOutMbps = Column(Float, default=0.0) # [NEW]
    BlockedAppsJson = Column(Text, default="[]") # [NEW] Feature 7: App Blocker
    ShadowPathsJson = Column(Text, default="[]") # [NEW] Enterprise Shadow Vault Paths
    
    MachineId = Column(String(255), nullable=True) # [v1.8.44] Hardware-specific ID
    ClusterName = Column(String(100), nullable=True) # [v2.6.0] Grouping for Replicas/ASG
    AgentRole = Column(String(50), default="Standalone") # [v2.6.0] Standalone, Primary, Replica
    IsSharedSystem = Column(Boolean, default=False) # [v2.6.0] True for RDS/Shared Servers
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
    HardwareFingerprint = Column(String(255), nullable=True, index=True) # [v2.0.0] TPM/Hardware identity
    AutoPatchEnabled = Column(Boolean, default=False)
    ThreatScore = Column(Integer, default=0) # [v2.1.0] AI Risk Assessment
    RiskLevel = Column(String(50), default="Normal") # [v2.1.0] AI Risk Assessment
    BehavioralMetadataJson = Column(LONGTEXT, nullable=True) # [v2.7.5] Human Intelligence Analytics
    RequireMtls = Column(Boolean, default=False) # [Layer 1] Require mTLS authentication
    TpmHash = Column(String(255), nullable=True) # [Layer 1] TPM Attestation Hash

class RefreshToken(Base):
    """Store hashed refresh tokens for session rotation [v2.0.0]"""
    __tablename__ = "RefreshTokens"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    Id = Column(Integer, primary_key=True, index=True)
    UserId = Column(Integer, ForeignKey("Users.Id"), nullable=False, index=True)
    TokenHash = Column(String(255), nullable=False, index=True)
    ExpiresAt = Column(DateTime, nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    RevokedAt = Column(DateTime, nullable=True)
    UserAgent = Column(String(255), nullable=True)
    IpAddress = Column(String(50), nullable=True)

class AgentReportEntity(Base):
    __tablename__ = "AgentReports"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer)
    Actor = Column(String(255))
    Action = Column(String(255))
    Target = Column(String(255))
    Details = Column(Text)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class Policy(Base):
    __tablename__ = "Policies"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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

    # [v2.6.8] Autonomous Defense Controls
    AutonomousRemediationEnabled = Column(Boolean, default=False)
    ThreatScoreThreshold = Column(Integer, default=90) # 0-100
    ExclusionsJson = Column(Text, default="[]") # [v2.6.9] AI Whitelisting
    ProductivityJson = Column(Text, default="{}") # [v2.7.5] Human Intelligence Mapping

class SystemSetting(Base):
    __tablename__ = "SystemSettings"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Key = Column(String(255), primary_key=True, index=True)
    Value = Column(Text, default="")
    Category = Column(String(50), default="General")
    Description = Column(String(255), nullable=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class OCRLog(Base):
    __tablename__ = "OCRLogs"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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

class AgentSoftware(Base):
    __tablename__ = "AgentSoftware"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    Name = Column(String(255))
    Version = Column(String(100))
    Type = Column(String(50)) # 'OS', 'Python', 'Node', etc.
    VulnerabilityCount = Column(Integer, default=0)
    LatestVersion = Column(String(100), nullable=True) # [NEW]
    Severity = Column(String(50), default="None") # [NEW] Critical, High, Medium, Low, None
    HasPatchAvailable = Column(Boolean, default=False) # [NEW]
    LastSeen = Column(DateTime, default=datetime.utcnow)



class YaraRule(Base):
    __tablename__ = "yara_rules"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"))
    Name = Column(String(100))
    RuleContent = Column(Text)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class Notification(Base):
    __tablename__ = "Notifications"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    Keyword = Column(String(100), index=True, nullable=False)
    # Storing list of synonyms as JSON string e.g. ["term1", "term2"]
    Synonyms = Column(Text, default="[]")
    Category = Column(String(50), default="General")
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class EventLog(Base):
    __tablename__ = "EventLogs"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    Type = Column(String(50), default="Unknown")
    Details = Column(Text, default="")
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    Status = Column(String(50), default="Open") # [v2.2.0] Open, In-Progress, Resolved, Risk-Accepted
    Severity = Column(String(20), default="Medium") # [v2.2.0] Low, Medium, High, Critical
    RawData = Column(Text, nullable=True)

class ActivityLog(Base):
    __tablename__ = "ActivityLogs"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True)
    Name = Column(String(100), nullable=False)
    QueryJson = Column(Text, default="{}") # Stores the search filters
    Category = Column(String(50), default="General")
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class MailLog(Base):
    __tablename__ = "MailLogs"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    MailLogId = Column(Integer, ForeignKey("MailLogs.Id"))
    FileName = Column(String(255))
    ContentType = Column(String(100))
    Content = Column(Text) # Storing as Base64 String
    Size = Column(Integer) # Bytes
    
    
    MailLog = relationship("MailLog", back_populates="Attachments")

class Vulnerability(Base):
    __tablename__ = "Vulnerabilities"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    OriginalPath = Column(Text)
    FileName = Column(String(255))
    StoragePath = Column(String(500)) # Path on server
    FileSize = Column(Integer)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class Screenshot(Base):
    __tablename__ = "Screenshots"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, index=True, nullable=False)
    Filename = Column(String(255), nullable=False)
    Path = Column(String(500), nullable=False)
    Size = Column(Integer, default=0)
    GeneratedAt = Column(DateTime, default=datetime.utcnow, index=True)
    DownloadUrl = Column(String(500))

class ApiKey(Base):
    """Long-lived API keys for SDK and Service integrations"""
    __tablename__ = "ApiKeys"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    Name = Column(String(100), nullable=False) # e.g. "Python SDK Key"
    KeyHash = Column(String(255), index=True, nullable=False) # SHA256 of the token
    Prefix = Column(String(10), nullable=False) # e.g. "mk_abc1" for UI identification
    RawKey = Column(String(255), nullable=True) # [SECURITY WARNING] User explicitly requested to store raw key for total copy functionality
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    ExpiresAt = Column(DateTime, nullable=True) # None = Never expires
    LastUsedAt = Column(DateTime, nullable=True)
    AllowedIpsJson = Column(Text, default="[]") # [SECURITY] IP Whitelist array

class SoftwareRequest(Base):
    __tablename__ = "SoftwareRequests"
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    SoftwareName = Column(String(255), nullable=False)
    Reason = Column(Text, nullable=True)
    Status = Column(String(50), default="PENDING") # PENDING, APPROVED, DENIED, COMPLETED, FAILED
    RequestedAt = Column(DateTime, default=datetime.utcnow, index=True)

class AgentRegistrationToken(Base):
    __tablename__ = "AgentRegistrationTokens"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    TokenHash = Column(String(255), index=True, nullable=False) # SHA256 of the 6-digit PIN
    ExpiresAt = Column(DateTime, nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class DeviceCertificate(Base):
    __tablename__ = "DeviceCertificates"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    SerialNumber = Column(String(128), unique=True, index=True, nullable=False)
    PublicKeyHash = Column(String(255), nullable=False)
    TpmAttestationData = Column(Text, nullable=True) # Proof of hardware origin
    IssuedAt = Column(DateTime, default=datetime.utcnow)
    ExpiresAt = Column(DateTime, nullable=False)
    RevokedAt = Column(DateTime, nullable=True)
    RevocationReason = Column(String(255), nullable=True)
    Status = Column(String(50), default="ACTIVE") # ACTIVE, REVOKED, EXPIRED

class DeviceRiskProfile(Base):
    __tablename__ = "DeviceRiskProfiles"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), unique=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True)
    
    # Vector Scores (0-100)
    UserRiskScore = Column(Float, default=0.0)
    ProcessRiskScore = Column(Float, default=0.0)
    DeviceRiskScore = Column(Float, default=0.0)
    NetworkRiskScore = Column(Float, default=0.0)
    BehavioralRiskScore = Column(Float, default=0.0)
    ThreatIntelRiskScore = Column(Float, default=0.0)
    
    # Aggregated
    TotalRiskScore = Column(Float, default=0.0)
    RiskLevel = Column(String(20), default="Low") # Low, Medium, High, Critical
    
    LastCalculatedAt = Column(DateTime, default=datetime.utcnow)

class ThreatFeed(Base):
    __tablename__ = "ThreatFeeds"
    Id = Column(Integer, primary_key=True, index=True)
    Name = Column(String(255), unique=True)
    SourceUrl = Column(String(500))
    FeedType = Column(String(50)) # TAXII, MISP, CSV, JSON
    PollIntervalMinutes = Column(Integer, default=1440)
    LastSync = Column(DateTime, nullable=True)
    IsActive = Column(Boolean, default=True)

class IndicatorOfCompromise(Base):
    __tablename__ = "IndicatorsOfCompromise"
    Id = Column(Integer, primary_key=True, index=True)
    IndicatorValue = Column(String(500), index=True) # The actual hash, IP, or domain
    IndicatorType = Column(String(50), index=True) # IPv4, Domain, URL, SHA256, MD5, Email
    FeedId = Column(Integer, ForeignKey("ThreatFeeds.Id"), nullable=True)
    Severity = Column(String(50), default="High")
    Confidence = Column(Integer, default=50) # 0-100
    ValidUntil = Column(DateTime, nullable=True) # Decay model
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class DetectionRule(Base):
    __tablename__ = "DetectionRules"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=True) # Null = Global
    Name = Column(String(255), nullable=False)
    Type = Column(String(50), default="Sigma") # Sigma, YARA, Correlation
    Category = Column(String(100)) # e.g., Credential Dumping, Persistence
    MitreTactic = Column(String(100)) # e.g., TA0006 (Credential Access)
    MitreTechnique = Column(String(100)) # e.g., T1003 (OS Credential Dumping)
    Severity = Column(String(50), default="High")
    RuleContent = Column(Text, nullable=False) # The raw Sigma YAML or YARA string
    IsActive = Column(Boolean, default=True)

class DetectionAlert(Base):
    __tablename__ = "DetectionAlerts"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    RuleId = Column(Integer, ForeignKey("DetectionRules.Id"))
    TelemetryId = Column(Integer) # Link back to the ActivityLog or Network log
    MatchedContent = Column(Text) # The specific cmdline or file that triggered the rule
    Status = Column(String(50), default="New") # New, Investigating, False Positive, Confirmed
    Timestamp = Column(DateTime, default=datetime.utcnow)

class UebaBaseline(Base):
    __tablename__ = "UebaBaselines"
    Id = Column(Integer, primary_key=True, index=True)
    EntityId = Column(String(255), index=True) # E.g., User email, AgentId
    EntityType = Column(String(50)) # "User" or "Device"
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True)
    
    # Baseline JSON payload storing statistical norms (mean, stddev, common IPs)
    # e.g., {"common_ips": ["1.2.3.4", "5.6.7.8"], "login_hours": {"start": 8, "end": 18}}
    ProfileDataJson = Column(Text, default="{}")
    
    LastUpdated = Column(DateTime, default=datetime.utcnow)

class SoarPlaybook(Base):
    __tablename__ = "SoarPlaybooks"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=True)
    Name = Column(String(255), nullable=False)
    TriggerCondition = Column(String(255)) # e.g. "RiskLevel == Critical"
    ActionsJson = Column(Text) # Array of actions: [{"action": "LockDevice"}]
    RequiresApproval = Column(Boolean, default=False)
    IsActive = Column(Boolean, default=True)

class SoarActionExecution(Base):
    __tablename__ = "SoarActionExecutions"
    Id = Column(Integer, primary_key=True, index=True)
    PlaybookId = Column(Integer, ForeignKey("SoarPlaybooks.Id"), nullable=True)
    TargetAgentId = Column(String(50), index=True)
    ActionType = Column(String(100)) # "KillProcess", "LockDevice", etc.
    Status = Column(String(50), default="Pending") # Pending, Executing, Success, Failed, RolledBack
    ExecutedBy = Column(String(100), default="System") # System or AdminId
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class SoarApprovalQueue(Base):
    __tablename__ = "SoarApprovalQueue"
    Id = Column(Integer, primary_key=True, index=True)
    ExecutionId = Column(Integer, ForeignKey("SoarActionExecutions.Id"))
    Status = Column(String(50), default="Pending") # Pending, Approved, Denied
    ApproverId = Column(String(100), nullable=True)
    RequestedAt = Column(DateTime, default=datetime.utcnow)
    ResolvedAt = Column(DateTime, nullable=True)

class SavedHunt(Base):
    __tablename__ = "SavedHunts"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=True)
    Name = Column(String(255), nullable=False)
    Description = Column(Text, nullable=True)
    QueryString = Column(Text, nullable=False)
    CreatedBy = Column(String(100), nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class InvestigationWorkspace(Base):
    __tablename__ = "InvestigationWorkspaces"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=True)
    Title = Column(String(255), nullable=False)
    Status = Column(String(50), default="Open") # Open, Closed
    OwnerId = Column(String(100), nullable=False)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class InvestigationEvidence(Base):
    __tablename__ = "InvestigationEvidence"
    Id = Column(Integer, primary_key=True, index=True)
    WorkspaceId = Column(Integer, ForeignKey("InvestigationWorkspaces.Id"))
    TelemetryId = Column(Integer)
    TelemetryType = Column(String(50)) # Process, Network, File, DNS
    AnalystNote = Column(Text, nullable=True)
    AddedAt = Column(DateTime, default=datetime.utcnow)

class ProcessLineageNode(Base):
    __tablename__ = "ProcessLineageNodes"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    
    # Process Identifiers
    ProcessId = Column(Integer, index=True)
    ParentProcessId = Column(Integer, index=True, nullable=True)
    
    # Metadata
    ProcessName = Column(String(255))
    CommandLine = Column(Text)
    ImagePath = Column(String(500))
    Sha256 = Column(String(64), nullable=True)
    
    # Threat Intelligence & Detection
    MitreTactic = Column(String(100), nullable=True)
    MitreTechnique = Column(String(100), nullable=True)
    IsMalicious = Column(Boolean, default=False)
    
    Timestamp = Column(DateTime, default=datetime.utcnow)

class DlpRule(Base):
    __tablename__ = "DlpRules"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=True)
    Name = Column(String(100), nullable=False) # e.g. "Credit Cards"
    Category = Column(String(50)) # PII, PHI, Secrets
    Pattern = Column(String(500), nullable=False) # Regex string
    IsActive = Column(Boolean, default=True)

class DlpPolicy(Base):
    __tablename__ = "DlpPolicies"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=True)
    Name = Column(String(100), nullable=False)
    TargetChannelsJson = Column(Text) # ["USB", "Clipboard", "Email"]
    Action = Column(String(50), default="Alert") # Alert, Block, Audit
    IsActive = Column(Boolean, default=True)

class DlpPolicyRuleLink(Base):
    __tablename__ = "DlpPolicyRuleLinks"
    Id = Column(Integer, primary_key=True, index=True)
    PolicyId = Column(Integer, ForeignKey("DlpPolicies.Id"))
    RuleId = Column(Integer, ForeignKey("DlpRules.Id"))

class DlpViolation(Base):
    __tablename__ = "DlpViolations"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True)
    PolicyId = Column(Integer, ForeignKey("DlpPolicies.Id"))
    RuleId = Column(Integer, ForeignKey("DlpRules.Id"))
    Channel = Column(String(50)) # e.g. "USB"
    MatchedContentObfuscated = Column(Text) # E.g., "4532 **** **** 1234"
    ActionTaken = Column(String(50)) # Alerted, Blocked
    Timestamp = Column(DateTime, default=datetime.utcnow)

class CloudMetadata(Base):
    __tablename__ = "CloudMetadata"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True, unique=True)
    Provider = Column(String(50)) # AWS, Azure, GCP
    AccountId = Column(String(100))
    Region = Column(String(50))
    Zone = Column(String(50))
    InstanceId = Column(String(100))
    InstanceType = Column(String(100))
    IamRole = Column(String(255))
    TagsJson = Column(Text)
    LastSeen = Column(DateTime, default=datetime.utcnow)

class ContainerAsset(Base):
    __tablename__ = "ContainerAssets"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    ContainerId = Column(String(255), index=True, unique=True)
    ImageName = Column(String(500))
    ImageHash = Column(String(255))
    State = Column(String(50)) # Running, Stopped
    IsPrivileged = Column(Boolean, default=False)
    PortsJson = Column(Text)
    MountsJson = Column(Text)
    LastSeen = Column(DateTime, default=datetime.utcnow)

class KubernetesAsset(Base):
    __tablename__ = "KubernetesAssets"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    ClusterName = Column(String(255))
    Namespace = Column(String(255))
    PodName = Column(String(255))
    NodeName = Column(String(255))
    ServiceAccount = Column(String(255))
    LabelsJson = Column(Text)
    LastSeen = Column(DateTime, default=datetime.utcnow)

class CloudSecuritySignal(Base):
    __tablename__ = "CloudSecuritySignals"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    ResourceType = Column(String(50)) # Container, K8s, CloudVM
    ResourceId = Column(String(255))
    SignalType = Column(String(100)) # e.g. ExposedDockerSocket
    Severity = Column(String(50))
    Timestamp = Column(DateTime, default=datetime.utcnow)

class RansomwareIncident(Base):
    __tablename__ = "RansomwareIncidents"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    ProcessId = Column(Integer)
    FilePath = Column(String(500), nullable=True)
    HeuristicMatched = Column(String(100)) # MassFileRename, VssadminDeletion, HighEntropy
    Severity = Column(String(50), default="Critical")
    IsActive = Column(Boolean, default=True)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class RansomwareMitigationLog(Base):
    __tablename__ = "RansomwareMitigationLogs"
    Id = Column(Integer, primary_key=True, index=True)
    IncidentId = Column(Integer, ForeignKey("RansomwareIncidents.Id"), index=True)
    ActionTaken = Column(String(100)) # ProcessKilled, HostQuarantined
    Success = Column(Boolean, default=True)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class DeceptionCampaign(Base):
    __tablename__ = "DeceptionCampaigns"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=True)
    Name = Column(String(255), nullable=False)
    Type = Column(String(50)) # File, Credential, NetworkShare
    PayloadTemplate = Column(Text, nullable=True) # e.g. "username=admin\npassword=fake123"
    IsActive = Column(Boolean, default=True)

class HoneyToken(Base):
    __tablename__ = "HoneyTokens"
    Id = Column(Integer, primary_key=True, index=True)
    CampaignId = Column(Integer, ForeignKey("DeceptionCampaigns.Id"))
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    TokenPath = Column(String(500), index=True) # E.g., C:\Users\Admin\passwords.txt
    TokenHash = Column(String(64), nullable=True)
    DeployedAt = Column(DateTime, default=datetime.utcnow)

class DeceptionAlert(Base):
    __tablename__ = "DeceptionAlerts"
    Id = Column(Integer, primary_key=True, index=True)
    TokenId = Column(Integer, ForeignKey("HoneyTokens.Id"))
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    ProcessId = Column(Integer)
    Action = Column(String(50)) # Read, Modified, Executed, LoginAttempt
    Timestamp = Column(DateTime, default=datetime.utcnow)

class ForensicEvidence(Base):
    __tablename__ = "ForensicEvidence"
    Id = Column(Integer, primary_key=True, index=True)
    WorkspaceId = Column(Integer, ForeignKey("InvestigationWorkspaces.Id"), nullable=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    Filename = Column(String(255))
    Type = Column(String(50)) # MemoryDump, Pcap, Screenshot, Mft
    StorageUri = Column(String(500)) # S3 URI
    Sha256Hash = Column(String(64))
    SizeInBytes = Column(Integer)
    Status = Column(String(50), default="PendingUpload") # PendingUpload, Verified, Corrupted
    IsLegalHold = Column(Boolean, default=False)
    UploadedAt = Column(DateTime, default=datetime.utcnow)

class ChainOfCustodyLog(Base):
    __tablename__ = "ChainOfCustodyLogs"
    Id = Column(Integer, primary_key=True, index=True)
    EvidenceId = Column(Integer, ForeignKey("ForensicEvidence.Id"), index=True)
    Action = Column(String(100)) # Uploaded, Downloaded, HashVerified, LegalHoldApplied
    PerformedBy = Column(String(100)) # Admin / System
    Timestamp = Column(DateTime, default=datetime.utcnow)

class AiCopilotSession(Base):
    __tablename__ = "AiCopilotSessions"
    Id = Column(Integer, primary_key=True, index=True)
    WorkspaceId = Column(Integer, ForeignKey("InvestigationWorkspaces.Id"), nullable=True)
    AdminId = Column(String(100))
    StartedAt = Column(DateTime, default=datetime.utcnow)

class AiCopilotMessage(Base):
    __tablename__ = "AiCopilotMessages"
    Id = Column(Integer, primary_key=True, index=True)
    SessionId = Column(Integer, ForeignKey("AiCopilotSessions.Id"), index=True)
    Role = Column(String(50)) # User, System, Assistant
    Content = Column(Text)
    TokensUsed = Column(Integer, default=0)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class AiIncidentReport(Base):
    __tablename__ = "AiIncidentReports"
    Id = Column(Integer, primary_key=True, index=True)
    AlertId = Column(Integer, ForeignKey("DetectionAlerts.Id"), index=True)
    ExecutiveSummary = Column(Text)
    TechnicalDetails = Column(Text)
    RemediationSteps = Column(Text)
    GeneratedAt = Column(DateTime, default=datetime.utcnow)

class FederatedTrust(Base):
    __tablename__ = "FederatedTrusts"
    Id = Column(Integer, primary_key=True, index=True)
    PlatformName = Column(String(100), unique=True, index=True) # SentinelX, UniCloudOps, RedRainbow
    ApiKeyHash = Column(String(255), nullable=False)
    PermissionsJson = Column(Text) # e.g. ["ReadTelemetry", "TriggerSoar", "WriteIntel"]
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class AgentlessEndpoint(Base):
    __tablename__ = "AgentlessEndpoints"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    IpAddress = Column(String(50), nullable=False)
    Hostname = Column(String(255), nullable=True)
    OsType = Column(String(50), default="Linux") # Linux, Windows
    MacAddress = Column(String(50), nullable=True)
    SshHostKeyFingerprint = Column(Text, nullable=True) # Trust on First Use (TOFU)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    LastSeen = Column(DateTime, default=datetime.utcnow)

class AgentlessCredential(Base):
    __tablename__ = "AgentlessCredentials"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    EndpointId = Column(Integer, ForeignKey("AgentlessEndpoints.Id"), nullable=False)
    AuthType = Column(String(50), default="SSH_KEY") # SSH_KEY, PASSWORD, WINRM
    Username = Column(String(255), nullable=False)
    EncryptedPassword = Column(Text, nullable=True) # AES-256-GCM Vault Data
    EncryptedKey = Column(Text, nullable=True) # AES-256-GCM Vault Data
    CreatedAt = Column(DateTime, default=datetime.utcnow)

