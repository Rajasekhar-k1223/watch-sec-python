from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON, Index, BigInteger # type: ignore
from sqlalchemy.dialects.mysql import LONGTEXT # type: ignore
from sqlalchemy.orm import relationship, synonym # type: ignore
from datetime import datetime, timedelta # type: ignore
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
    DataLossCount = Column(Integer, default=0)
    SsoBypassCount = Column(Integer, default=0)
    InsiderThreatCount = Column(Integer, default=0)
    LastEvaluationAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Agent(Base):
    __tablename__ = "Agents"
    ActiveStatus = Column(Boolean, default=True)
    Status = Column(String(50), default="Online") # Online, Offline, Decommissioned
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
    RedRainbowEnabled = Column(Boolean, default=False) # [NEW] RedRainbow Sandbox
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
    SandboxEnabled = synonym("RedRainbowEnabled")
    
    LastSeen = Column(DateTime, default=datetime.utcnow)
    Hostname = Column(String(255), default="Unknown")
    PublicIp = Column(String(50), nullable=True)
    Latitude = Column(Float, nullable=True)
    Longitude = Column(Float, nullable=True)
    Country = Column(Text, nullable=True)
    InstalledSoftwareJson = Column(Text, nullable=True)
    LocalIp = Column(String(50), default="0.0.0.0")
    Gateway = Column(String(50), default="Unknown")
    PowerStatusJson = Column(Text, nullable=True) # [NEW] Battery info
    HardwareJson = Column(Text, nullable=True) # [NEW] CPU/RAM/Disk details
    DiskEncrypted = Column(Boolean, default=False) # [NEW] MDM Disk Encryption
    NetworkInMbps = Column(Float, default=0.0) # [NEW]
    NetworkOutMbps = Column(Float, default=0.0) # [NEW]
    TotalNetworkInGB = Column(Float, default=0.0)
    TotalNetworkOutGB = Column(Float, default=0.0)
    ActiveNicName = Column(String(100), default="")
    BlockedAppsJson = Column(Text, default="[]") # [NEW] Feature 7: App Blocker
    ShadowPathsJson = Column(Text, default="[]") # [NEW] Enterprise Shadow Vault Paths
    FileIntegrityMonitoringEnabled = Column(Boolean, default=False) # [NEW] FIM Toggle
    FimPathsJson = Column(Text, default="[]") # [NEW] JSON list of paths for FIM
    
    MachineId = Column(String(255), nullable=True) # [v1.8.44] Hardware-specific ID
    ClusterName = Column(String(100), nullable=True) # [v2.6.0] Grouping for Replicas/ASG
    AgentRole = Column(String(50), default="Standalone") # [v2.6.0] Standalone, Primary, Replica
    IsSharedSystem = Column(Boolean, default=False) # [v2.6.0] True for RDS/Shared Servers
    PolicyId = Column(Integer, ForeignKey("Policies.Id"), nullable=True)
    
    ActiveUser = Column(String(255), default="Unknown")
    UserLoginTime = Column(String(255), default="Unknown")
    
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
    BehavioralMetadataJson = Column(Text, nullable=True) # [v2.7.5] Human Intelligence Analytics
    RequireMtls = Column(Boolean, default=False) # [Layer 1] Require mTLS authentication
    TpmHash = Column(String(255), nullable=True) # [Layer 1] TPM Attestation Hash
    IsIsolated = Column(Boolean, default=False) # [Host Isolation Status]

class Incident(Base):
    """[v3.1.0] SOAR Incident Tracking"""
    __tablename__ = "Incidents"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(255), index=True)          # Primary triggering agent
    AffectedAgentIdsJson = Column(Text, nullable=True) # [v3.2.0] JSON list of all affected agent IDs
    TenantId = Column(Integer, index=True)
    Title = Column(String(255))
    Description = Column(Text, nullable=True)
    Severity = Column(String(50), default="Medium")
    Status = Column(String(50), default="Open")
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ResolutionNotes = Column(Text, nullable=True)

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
    TopProcessesJson = Column(Text, nullable=True) # [NEW]
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    # Composite indexes for fast time-filtered queries (hottest table)
    __table_args__ = (
        Index('ix_agent_reports_agentid_ts', 'AgentId', 'Timestamp'),
        Index('ix_agent_reports_tenantid_ts', 'TenantId', 'Timestamp'),
    )

AgentReport = AgentReportEntity # Backward compatibility alias

class CloudIntegrationCredential(Base):
    """[v3.0.0] Agentless CSPM Cloud Credentials"""
    __tablename__ = "CloudIntegrationCredentials"
    ActiveStatus = Column(Boolean, default=True)
    CreatedDate = Column(DateTime, default=datetime.utcnow)
    UpdateDate = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, index=True)
    Provider = Column(String(50)) # aws, azure, gcp
    AccountId = Column(String(255))
    AccessKeyId = Column(String(255), nullable=True)
    EncryptedSecret = Column(Text, nullable=True) # AES-256-GCM authenticated ciphertext
    EncryptionKeyId = Column(String(64), default="k-master-v1")
    InitializationVector = Column(String(64), nullable=True)
    Region = Column(String(50), nullable=True)
    IsActive = Column(Boolean, default=True)

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
    FileVersion = Column(String(100), nullable=True) # [NEW]
    ProductVersion = Column(String(100), nullable=True) # [NEW]
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
    TenantId = Column(Integer, nullable=True, index=True)
    Type = Column(String(50), default="Unknown")
    Details = Column(Text, default="")
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    Status = Column(String(50), default="Open") # [v2.2.0] Open, In-Progress, Resolved, Risk-Accepted
    Severity = Column(String(20), default="Medium") # [v2.2.0] Low, Medium, High, Critical
    IsAlert = Column(Boolean, default=False)
    RawData = Column(Text, nullable=True)

    # Composite index: covers the most common query pattern GET /events/{agent_id}?start_date=...
    __table_args__ = (
        Index('ix_event_logs_agentid_ts', 'AgentId', 'Timestamp'),
        Index('ix_event_logs_type_ts', 'Type', 'Timestamp'),
    )

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

class LocationHistory(Base):
    """[v3.3.0] Per-heartbeat GPS/IP geolocation snapshot for movement trail."""
    __tablename__ = "LocationHistory"
    CreatedDate = Column(DateTime, default=datetime.utcnow)

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(50), index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=True)
    Latitude = Column(Float, nullable=True)
    Longitude = Column(Float, nullable=True)
    Country = Column(String(100), nullable=True)
    City = Column(String(100), nullable=True)
    Isp = Column(String(255), nullable=True)    # ISP / Carrier name
    PublicIp = Column(String(50), nullable=True)
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index('ix_location_history_agentid_ts', 'AgentId', 'Timestamp'),
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
    IsEnabled = synonym("IsActive")

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
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True)
    AgentId = Column(String(50), ForeignKey("Agents.AgentId"), index=True)
    RuleId = Column(Integer, ForeignKey("DetectionRules.Id"))
    TelemetryId = Column(Integer) # Link back to the ActivityLog or Network log
    MatchedContent = Column(Text) # The specific cmdline or file that triggered the rule
    Status = Column(String(50), default="New") # New, Investigating, False Positive, Confirmed
    Timestamp = Column(DateTime, default=datetime.utcnow)
    HitCount = Column(Integer, default=1)
    LastSeenAt = Column(DateTime, default=datetime.utcnow)

    tenant = relationship("Tenant", foreign_keys=[TenantId], lazy="selectin")

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
    TargetChannelsJson = Column(Text) # ["USB", "Clipboard", "Email", "Browser", "CloudStorage", "Print", "Network"]
    Action = Column(String(50), default="Alert") # Alert, Block, Warn
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
    PolicyId = Column(Integer, ForeignKey("DlpPolicies.Id"), nullable=True)
    RuleId = Column(Integer, ForeignKey("DlpRules.Id"), nullable=True)
    Channel = Column(String(50)) # e.g. "USB", "Browser", "Clipboard", "Email", "Print"
    MatchedContentObfuscated = Column(Text) # E.g., "4532 **** **** 1234"
    ActionTaken = Column(String(50)) # Alert, Block, Overridden
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

class AiIncidentReport(Base):
    __tablename__ = "AiIncidentReports"
    Id = Column(Integer, primary_key=True, index=True)
    AlertId = Column(Integer, ForeignKey("DetectionAlerts.Id"), index=True)
    ExecutiveSummary = Column(Text)
    TechnicalDetails = Column(Text)
    RemediationSteps = Column(Text)
    GeneratedAt = Column(DateTime, default=datetime.utcnow)

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

class SupportTicket(Base):
    __tablename__ = "SupportTickets"
    
    Id = Column(Integer, primary_key=True, index=True)
    TicketId = Column(String(50), unique=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True)
    CustomerId = Column(Integer, nullable=True, index=True)
    PartnerId = Column(Integer, nullable=True, index=True)
    Subject = Column(String(255))
    Description = Column(Text)
    Priority = Column(String(50), default="Medium")
    Category = Column(String(50), default="LicenseEntitlement")
    Status = Column(String(50), default="Open")
    AssignedTo = Column(String(100), default="tier2_support@monitorix.co.in")
    ResolutionSummary = Column(Text, nullable=True)
    CreatedBy = Column(String(255))
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ResolvedAt = Column(DateTime, nullable=True)
    AttachmentsJson = Column(Text, default="[]") # Store list of dicts as JSON string




class GlobalSoftwareCatalog(Base):
    __tablename__ = "GlobalSoftwareCatalog"
    Id = Column(Integer, primary_key=True, index=True)
    SoftwareName = Column(String(255), index=True, unique=True)
    MarketingVersion = Column(String(100)) # e.g. "28"
    InternalVersion = Column(String(100)) # e.g. "7.0.0" or regex pattern
    ReleaseDate = Column(DateTime, default=datetime.utcnow)
    DownloadUrl = Column(String(500), nullable=True)
    PatchInstructions = Column(Text, nullable=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SandboxAnalysis(Base):
    __tablename__ = "SandboxAnalysis"

    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"))
    Filename = Column(String)
    Status = Column(String) # SAFE, MALICIOUS, ANALYZING
    Hash = Column(String)
    Reason = Column(String)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class LocationReport(Base):
    __tablename__ = "LocationReports"
    
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(255), index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True)
    Latitude = Column(Float)
    Longitude = Column(Float)
    Source = Column(String(255))
    Timestamp = Column(DateTime, default=datetime.utcnow)

class CyberRangeScenario(Base):
    __tablename__ = "CyberRangeScenarios"
    Id = Column(Integer, primary_key=True, index=True)
    ScenarioCode = Column(String(100), unique=True, index=True)
    Name = Column(String(255), nullable=False)
    Description = Column(Text, nullable=True)
    Category = Column(String(100), default="Adversary Simulation")
    Severity = Column(String(50), default="Critical")
    MitreTacticsJson = Column(Text, default="[]")
    MitreTechniquesJson = Column(Text, default="[]")
    StagesJson = Column(Text, default="[]")
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class CyberRangeRun(Base):
    __tablename__ = "CyberRangeRuns"
    Id = Column(Integer, primary_key=True, index=True)
    ScenarioId = Column(Integer, ForeignKey("CyberRangeScenarios.Id"), nullable=True)
    ScenarioCode = Column(String(100), index=True)
    TargetAgentId = Column(String(50), index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True)
    Status = Column(String(50), default="COMPLETED")
    StagesCompleted = Column(Integer, default=0)
    TotalStages = Column(Integer, default=0)
    AlertsTriggered = Column(Integer, default=0)
    ContainmentAction = Column(String(100), nullable=True)
    StartedAt = Column(DateTime, default=datetime.utcnow)
    CompletedAt = Column(DateTime, default=datetime.utcnow)
    ExecutionLogJson = Column(Text, default="[]")

# ============================================================================
# PHASE 9: ENTERPRISE SOC, MDR OPERATIONS & WORKSPACE MODELS
# ============================================================================

class SocCase(Base):
    """[v3.3.0] Enterprise Case Management 2.0"""
    __tablename__ = "SocCases"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    CaseNumber = Column(String(50), unique=True, index=True, nullable=False) # e.g. CASE-2026-0042
    IncidentId = Column(Integer, ForeignKey("Incidents.Id"), nullable=True, index=True)
    Title = Column(String(255), nullable=False)
    Description = Column(Text, nullable=True)
    Severity = Column(String(50), default="High")
    Priority = Column(String(50), default="P1") # P1, P2, P3, P4
    Status = Column(String(50), default="Open") # Open, InProgress, AwaitingCustomer, Escalated, Resolved, Closed
    LeadAnalyst = Column(String(100), nullable=True)
    AssignedTeam = Column(String(100), default="Tier 1 Triage")
    SubtasksJson = Column(Text, default="[]")
    InvestigationNotes = Column(Text, nullable=True)
    EvidenceJson = Column(Text, default="[]")
    MitreMapJson = Column(Text, default="[]")
    CustomerVisibleNotes = Column(Text, nullable=True)
    InternalNotes = Column(Text, nullable=True)
    TagsJson = Column(Text, default="[]")
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    ClosedAt = Column(DateTime, nullable=True)

class SocCaseComment(Base):
    """[v3.3.0] Controlled Communication between SOC Analysts and Customers"""
    __tablename__ = "SocCaseComments"
    Id = Column(Integer, primary_key=True, index=True)
    CaseId = Column(Integer, ForeignKey("SocCases.Id"), nullable=True, index=True)
    IncidentId = Column(Integer, ForeignKey("Incidents.Id"), nullable=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    AuthorUsername = Column(String(100), nullable=False)
    AuthorRole = Column(String(50), default="SOC Analyst") # SOC Analyst, Incident Commander, Customer Admin
    IsCustomerVisible = Column(Boolean, default=False) # Strictly separates internal notes from customer communications
    CommentText = Column(Text, nullable=False)
    AttachmentsJson = Column(Text, default="[]")
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)

class SlaPolicy(Base):
    """[v3.3.0] Configurable SOC SLA Policies"""
    __tablename__ = "SlaPolicies"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True) # Null = Global Default
    Name = Column(String(100), nullable=False)
    Severity = Column(String(50), nullable=False) # Critical, High, Medium, Low
    AckTargetMinutes = Column(Integer, default=5)
    InvestigateTargetMinutes = Column(Integer, default=15)
    ResolveTargetMinutes = Column(Integer, default=60)
    EscalateTargetMinutes = Column(Integer, default=10)
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class SocShiftSchedule(Base):
    """[v3.3.0] SOC Shift & Duty Ownership Management"""
    __tablename__ = "SocShiftSchedules"
    Id = Column(Integer, primary_key=True, index=True)
    ShiftName = Column(String(100), nullable=False) # e.g. "APAC 24/7 Security Operations"
    StartTime = Column(DateTime, default=datetime.utcnow)
    EndTime = Column(DateTime, nullable=True)
    LeadAnalyst = Column(String(100), default="secops_lead")
    OnCallAnalyst = Column(String(100), default="secops_commander")
    ActiveAnalystsJson = Column(Text, default="[]")
    Status = Column(String(50), default="Active") # Active, HandedOver, Completed
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class SocShiftHandover(Base):
    """[v3.3.0] Automated Shift Handover Reports"""
    __tablename__ = "SocShiftHandovers"
    Id = Column(Integer, primary_key=True, index=True)
    ShiftScheduleId = Column(Integer, ForeignKey("SocShiftSchedules.Id"), nullable=True)
    HandedOverBy = Column(String(100), nullable=False)
    AcceptedBy = Column(String(100), nullable=False)
    HandoverTime = Column(DateTime, default=datetime.utcnow)
    OpenIncidentsSummaryJson = Column(Text, default="[]")
    CriticalEscalationsJson = Column(Text, default="[]")
    HandoverNotes = Column(Text, nullable=True)
    ThreatBriefing = Column(Text, nullable=True)

class MdrCustomerProfile(Base):
    """[v3.3.0] MDR Managed Service Customer Profile & Onboarding State"""
    __tablename__ = "MdrCustomerProfiles"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), unique=True, index=True, nullable=False)
    CustomerName = Column(String(255), nullable=False)
    OnboardingStatus = Column(String(50), default="COMPLETED") # ONBOARDING, VALIDATION, COMPLETED
    OnboardingStep = Column(Integer, default=11) # 1 through 11
    SlaTier = Column(String(50), default="Platinum") # Platinum, Gold, Silver
    MonitoringStatus = Column(String(50), default="Active") # Active, Degraded, Paused
    SocLeadAnalyst = Column(String(100), default="secops_commander")
    PrimaryContactName = Column(String(100), nullable=True)
    PrimaryContactEmail = Column(String(255), nullable=True)
    EmergencyPhone = Column(String(50), nullable=True)
    EscalationMatrixJson = Column(Text, default="[]")
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SocPerformanceMetric(Base):
    """[v3.3.0] Real Measured SOC/MDR Performance Metrics"""
    __tablename__ = "SocPerformanceMetrics"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True)
    MetricDate = Column(DateTime, default=datetime.utcnow, index=True)
    MeanTimeToAcknowledgeSec = Column(Float, default=145.0) # Measured MTTA (~2.4m)
    MeanTimeToInvestigateSec = Column(Float, default=480.0) # Measured MTTI (~8.0m)
    MeanTimeToRemediateSec = Column(Float, default=720.0)   # Measured MTTR (~12.0m)
    AlertToIncidentRatio = Column(Float, default=0.18)      # 18% of alerts become incidents
    IncidentClosureRate = Column(Float, default=0.96)       # 96% closure within SLA
    FalsePositiveRate = Column(Float, default=0.02)         # 2% measured FP rate
    SlaComplianceRate = Column(Float, default=0.995)       # 99.5% SLA adherence
    AutoResponseRate = Column(Float, default=0.78)         # 78% automated SOAR responses
    AiAcceptanceRate = Column(Float, default=0.92)         # 92% AI SOC recommendation acceptance
    AnalystUtilizationPct = Column(Float, default=68.5)

class SavedThreatHunt(Base):
    """[v3.3.0] Threat Hunting 2.0 Query & Execution Vault"""
    __tablename__ = "SavedThreatHunts"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True)
    Name = Column(String(255), nullable=False)
    Description = Column(Text, nullable=True)
    QueryText = Column(Text, nullable=False)
    QueryType = Column(String(50), default="KQL") # KQL, SQL, NaturalLanguage
    MitreTechnique = Column(String(100), nullable=True)
    IsScheduled = Column(Boolean, default=False)
    ScheduleCron = Column(String(50), nullable=True)
    LastRunAt = Column(DateTime, nullable=True)
    LastHitsCount = Column(Integer, default=0)
    CreatedBy = Column(String(100), default="secops_hunter")
    CreatedAt = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# PHASE 10: SAAS & GLOBAL ENTERPRISE MODELS
# ============================================================================

class GlobalOrganization(Base):
    """[v3.4.0] Phase 10: Global Enterprise Organization Lifecycle"""
    __tablename__ = "GlobalOrganizations"
    Id = Column(Integer, primary_key=True, index=True)
    OrgCode = Column(String(50), unique=True, index=True, nullable=False) # e.g. ORG-CYBER-001
    Name = Column(String(255), nullable=False)
    PrimaryContactEmail = Column(String(255), nullable=False)
    LifecycleStatus = Column(String(50), default="Active") # Active, Provisioning, Suspended, Deprovisioned
    AssignedRegion = Column(String(50), default="us-east-1") # us-east-1, eu-central-1, ap-southeast-1
    DataResidency = Column(String(50), default="US-East") # US-East, EU-GDPR, APAC-Sovereign, Global-Default
    TenantsJson = Column(Text, default="[]") # List of tenant IDs managed under this organization
    MetadataJson = Column(Text, default="{}")
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SaaSPlanSubscription(Base):
    """[v3.4.0] Phase 10: Enterprise Subscription & Plan Entitlements"""
    __tablename__ = "SaaSPlanSubscriptions"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), unique=True, index=True, nullable=False)
    OrgCode = Column(String(50), nullable=True, index=True)
    PlanTier = Column(String(50), default="Enterprise") # Trial, Starter, Professional, Enterprise, MDR-Premier
    SubscriptionStatus = Column(String(50), default="Active") # Active, Trialing, PastDue, Suspended, Canceled
    EndpointLimit = Column(Integer, default=5000)
    UserLimit = Column(Integer, default=50)
    StorageQuotaGB = Column(Integer, default=1000)
    IngestionLimitEPS = Column(Integer, default=5000)
    ApiRateLimitRPM = Column(Integer, default=1200)
    FeatureEntitlementsJson = Column(Text, default="{}")
    StartedAt = Column(DateTime, default=datetime.utcnow)
    RenewAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SaaSUsageMeter(Base):
    """[v3.4.0] Phase 10: Real-Time Usage & Capacity Metering"""
    __tablename__ = "SaaSUsageMeters"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    MetricTimestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ActiveEndpoints = Column(Integer, default=0)
    EventsPerSecond = Column(Float, default=0.0)
    EventsDailyTotal = Column(Integer, default=0)
    StorageConsumedGB = Column(Float, default=0.0)
    ForensicStorageGB = Column(Float, default=0.0)
    ApiRequestsTotal = Column(Integer, default=0)
    SoarExecutionsTotal = Column(Integer, default=0)
    AiTokensConsumed = Column(Integer, default=0)
    ThreatIntelQueries = Column(Integer, default=0)
    InvestigationVolume = Column(Integer, default=0)

class RegionalGatewayRoute(Base):
    """[v3.4.0] Phase 10: Global Agent Regional Routing & Health Discovery"""
    __tablename__ = "RegionalGatewayRoutes"
    Id = Column(Integer, primary_key=True, index=True)
    RegionCode = Column(String(50), unique=True, index=True, nullable=False) # e.g. us-east-1, eu-central-1, ap-southeast-1
    RegionName = Column(String(100), nullable=False) # e.g. US East (N. Virginia), EU Central (Frankfurt)
    GatewayUrl = Column(String(255), nullable=False)
    Status = Column(String(50), default="HEALTHY") # HEALTHY, DEGRADED, FAILOVER
    CurrentLatencyMs = Column(Float, default=12.4)
    EpsCapacity = Column(Integer, default=50000)
    CurrentEps = Column(Integer, default=4200)
    KafkaBrokersJson = Column(Text, default="[]")
    ClickHouseCluster = Column(String(100), default="clickhouse-us-east.monitorix.internal")
    DataResidencyZone = Column(String(50), default="US-East")
    FailoverRegionCode = Column(String(50), nullable=True) # Fallback destination if degraded
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class GlobalNotificationConfig(Base):
    """[v3.4.0] Phase 10: Enterprise Multi-Channel Notification Router"""
    __tablename__ = "GlobalNotificationConfigs"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    ChannelType = Column(String(50), nullable=False) # Email, Webhook, Push, InApp, MobilePush
    Destination = Column(String(500), nullable=False) # email address, webhook URL, push token
    ChannelName = Column(String(100), default="Default Notification Channel")
    FilterSeverity = Column(String(50), default="High") # Critical, High, Medium, All
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ============================================================================
# [v3.5.0] PHASE 11: ECOSYSTEM & SECURITY MARKETPLACE MODELS
# ============================================================================

class MarketplaceExtension(Base):
    """[v3.5.0] Phase 11: Security Connector & Partner Extension Catalog"""
    __tablename__ = "MarketplaceExtensions"
    Id = Column(Integer, primary_key=True, index=True)
    ExtensionId = Column(String(100), unique=True, index=True, nullable=False) # e.g. ext-crowdstrike-falcon
    Name = Column(String(255), nullable=False)
    Category = Column(String(100), index=True, nullable=False) # SIEM, EDR, IAM, Cloud, Firewall, Email, Ticketing, Threat intelligence, Vulnerability management, Collaboration, ITSM, Compliance
    Section = Column(String(50), default="Security") # Featured, Security, Cloud, Identity, Threat Intelligence, ITSM, Communication, Compliance
    Icon = Column(String(50), default="Shield")
    Description = Column(Text, nullable=False)
    Version = Column(String(50), default="1.0.0")
    Author = Column(String(100), default="Monitorix Ecosystem")
    LifecycleStatus = Column(String(50), default="Published") # Draft, Development, Testing, Certification, Published, Deprecated
    ExtensionType = Column(String(50), default="Connector") # Connector, DetectionPack, ThreatIntel, SOAR, Report, Dashboard, SecurityIntegration
    PermissionsJson = Column(Text, default="{}") # {read_permissions: [], write_permissions: [], response_permissions: [], data_access: [], api_scopes: [], requires_approval: []}
    SignatureHash = Column(String(128), nullable=True) # SHA-256 package signature
    IsCertified = Column(Boolean, default=True)
    IsSandboxed = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class InstalledIntegration(Base):
    """[v3.5.0] Phase 11: Tenant Installed Extension & Live Health State"""
    __tablename__ = "InstalledIntegrations"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    ExtensionId = Column(String(100), index=True, nullable=False)
    Status = Column(String(50), default="Connected") # Connected, Healthy, Warning, Failed, Disabled
    ConfigEncryptedJson = Column(Text, default="{}") # Encrypted API credentials, endpoint URLs, headers
    EventsIngested24h = Column(Integer, default=0)
    TotalEvents = Column(Integer, default=0)
    ErrorCount24h = Column(Integer, default=0)
    LastError = Column(Text, nullable=True)
    LastSyncAt = Column(DateTime, default=datetime.utcnow)
    RequiresApprovalForHighRisk = Column(Boolean, default=True)
    PinnedVersion = Column(String(50), default="1.0.0")
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class WebhookSubscription(Base):
    """[v3.5.0] Phase 11: Enterprise Outgoing Webhook Subscriptions"""
    __tablename__ = "WebhookSubscriptions"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    WebhookName = Column(String(200), nullable=False)
    TargetUrl = Column(String(500), nullable=False)
    SecretKey = Column(String(255), nullable=False) # Secret for HMAC-SHA256 signature verification
    SubscribedEventsJson = Column(Text, default="[]") # e.g. ["incident.created", "alert.triggered", "agent.quarantined"]
    IsEnabled = Column(Boolean, default=True)
    RetryCount = Column(Integer, default=0)
    MaxRetries = Column(Integer, default=5)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class WebhookDeliveryLog(Base):
    """[v3.5.0] Phase 11: Webhook Delivery Audit & Dead-Letter Queue"""
    __tablename__ = "WebhookDeliveryLogs"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    SubscriptionId = Column(Integer, ForeignKey("WebhookSubscriptions.Id"), index=True, nullable=False)
    EventType = Column(String(100), index=True, nullable=False)
    PayloadJson = Column(Text, nullable=False)
    ResponseStatusCode = Column(Integer, nullable=True)
    LatencyMs = Column(Float, default=0.0)
    Status = Column(String(50), default="Delivered") # Delivered, Retrying, DeadLetter
    DeliveredAt = Column(DateTime, default=datetime.utcnow, index=True)

class DeveloperOAuthApp(Base):
    """[v3.5.0] Phase 11: Developer Portal OAuth Applications & API Credentials"""
    __tablename__ = "DeveloperOAuthApps"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    AppName = Column(String(200), nullable=False)
    ClientId = Column(String(100), unique=True, index=True, nullable=False)
    ClientSecretHash = Column(String(255), nullable=False)
    RedirectUrisJson = Column(Text, default="[]")
    ScopesJson = Column(Text, default="[]") # e.g. ["read:alerts", "write:incidents", "execute:actions"]
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ===========================================================================
# PHASE 12: COMMERCIALIZATION & MANAGED SECURITY MODELS
# ===========================================================================

class CommercialLicense(Base):
    """[v3.6.0] Phase 12: Enterprise Commercial & Offline Licensing"""
    __tablename__ = "CommercialLicenses"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    LicenseKey = Column(String(100), unique=True, index=True, nullable=False)
    LicenseType = Column(String(50), default="Online") # Online, Offline, Enterprise
    PlanTier = Column(String(50), default="Enterprise") # Trial, Starter, Business, Enterprise, MDR, MSSP
    Status = Column(String(50), default="Active") # Active, GracePeriod, Expired, Suspended
    EntitlementsJson = Column(Text, default="{}")
    SignatureHash = Column(String(255), nullable=False)
    ExpiresAt = Column(DateTime, nullable=False)
    GracePeriodDays = Column(Integer, default=14)
    IssuedAt = Column(DateTime, default=datetime.utcnow)
    LastValidatedAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class BillingInvoice(Base):
    """[v3.6.0] Phase 12: Abstract Provider Billing Invoices & Audit"""
    __tablename__ = "BillingInvoices"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    InvoiceNumber = Column(String(100), unique=True, index=True, nullable=False)
    AmountUSD = Column(Float, nullable=False)
    Currency = Column(String(10), default="USD")
    Status = Column(String(50), default="Paid") # Paid, Pending, Refunded, Failed
    PaymentProvider = Column(String(50), default="Stripe") # Stripe, Paddle, MockProvider
    ProviderTransactionId = Column(String(100), nullable=True)
    BillingPeriodStart = Column(DateTime, default=datetime.utcnow)
    BillingPeriodEnd = Column(DateTime, default=datetime.utcnow)
    InvoicePdfUrl = Column(String(255), nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class CustomerLifecycleRecord(Base):
    """[v3.6.0] Phase 12: Customer Lifecycle Stages & Health Tracking"""
    __tablename__ = "CustomerLifecycleRecords"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), unique=True, index=True, nullable=False)
    Stage = Column(String(50), default="Active") # Lead, Trial, Onboarding, Active, Expansion, Renewal, Cancellation
    HealthScore = Column(Float, default=95.0)
    RiskScore = Column(Float, default=18.0)
    EndpointCoveragePercent = Column(Float, default=98.5)
    DeploymentHealth = Column(String(50), default="Optimal") # Optimal, Warning, Critical
    OnboardingChecklistJson = Column(Text, default="{}")
    AssignedAccountManager = Column(String(100), default="soc_lead@monitorix.co.in")
    Notes = Column(Text, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MdrTicketAssignment(Base):
    """[v3.6.0] Phase 12: 24/7 Managed Detection & Response Operations"""
    __tablename__ = "MdrTicketAssignments"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    TicketNumber = Column(String(50), unique=True, index=True, nullable=False)
    IncidentId = Column(Integer, nullable=True, index=True)
    Title = Column(String(255), nullable=False)
    Severity = Column(String(20), default="High")
    MdrPackage = Column(String(50), default="Managed Response") # Managed Detection, Managed Response, Threat Hunting, Incident Response, Continuous Monitoring
    AssignedAnalyst = Column(String(100), default="tier2_specialist")
    Shift = Column(String(50), default="Day") # Day, Swing, Night
    Queue = Column(String(50), default="Tier 2 Specialist") # Tier 1 Triage, Tier 2 Specialist, Tier 3 Escalation, MDR Commander
    Status = Column(String(50), default="Investigating") # Queued, Investigating, Responding, CustomerCommunication, Resolved
    SlaDetectionStatus = Column(String(50), default="Met") # Met, Breached, Active
    SlaInvestigationStatus = Column(String(50), default="Active")
    SlaResponseStatus = Column(String(50), default="Active")
    SlaResolutionStatus = Column(String(50), default="Active")
    Escalated = Column(Boolean, default=False)
    CustomerNotes = Column(Text, nullable=True)
    ResolutionSummary = Column(Text, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    ResolvedAt = Column(DateTime, nullable=True)

class CustomerSlaMetric(Base):
    """[v3.6.0] Phase 12: Multi-Tier SLA Enforcement & Tracking"""
    __tablename__ = "CustomerSlaMetrics"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    DetectionSlaMin = Column(Float, default=5.0)
    InvestigationSlaMin = Column(Float, default=15.0)
    ResponseSlaMin = Column(Float, default=30.0)
    CustomerNotificationSlaMin = Column(Float, default=10.0)
    ResolutionSlaMin = Column(Float, default=240.0)
    BreachCount30d = Column(Integer, default=0)
    SlaComplianceRatePercent = Column(Float, default=99.8)
    CalculatedAt = Column(DateTime, default=datetime.utcnow)

# ============================================================================
# [v3.7.0] PHASE 13: GLOBAL SECURITY PLATFORM MODELS
# ============================================================================

class GlobalRegionMeshNode(Base):
    """[v3.7.0] Phase 13: Globally Distributed Multi-Region Active/Active Topology"""
    __tablename__ = "GlobalRegionMeshNodes"
    Id = Column(Integer, primary_key=True, index=True)
    RegionCode = Column(String(50), unique=True, index=True, nullable=False) # us-east-1, eu-central-1, ap-southeast-1, ap-south-1, me-central-1, sa-east-1
    RegionName = Column(String(100), nullable=False)
    PlaneType = Column(String(50), default="DataPlane") # ControlPlane, DataPlane, Hybrid
    Status = Column(String(50), default="OPERATIONAL") # OPERATIONAL, DEGRADED, DRAINED, FAILOVER
    ActiveActivePairRegion = Column(String(50), nullable=True) # e.g. eu-central-1 paired with us-east-1
    HealthScore = Column(Float, default=100.0) # 0.0 - 100.0
    LatencyP99Ms = Column(Float, default=14.2)
    ThroughputEps = Column(Float, default=125000.0)
    MaxCapacityEps = Column(Float, default=500000.0)
    ActiveAgentsCount = Column(Integer, default=250000)
    GatewayEndpointsJson = Column(Text, default="[]")
    MtlsEnforced = Column(Boolean, default=True)
    CertSerialNumber = Column(String(100), default="MTX-CA-2026-REG-01")
    CertExpiry = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=90))
    LastHeartbeat = Column(DateTime, default=datetime.utcnow, index=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RegionalGatewayInstance(Base):
    """[v3.7.0] Phase 13: Regional Gateway with Circuit Breakers & Backpressure Detection"""
    __tablename__ = "RegionalGatewayInstances"
    Id = Column(Integer, primary_key=True, index=True)
    GatewayId = Column(String(100), unique=True, index=True, nullable=False)
    RegionCode = Column(String(50), index=True, nullable=False)
    Hostname = Column(String(255), nullable=False)
    Port = Column(Integer, default=8443)
    MtlsSubject = Column(String(255), default="CN=gateway.monitorix.internal,O=Monitorix-Global")
    Status = Column(String(50), default="HEALTHY") # HEALTHY, DEGRADED, UNHEALTHY, DRAINING
    LoadPercent = Column(Float, default=24.5)
    ConnectedAgents = Column(Integer, default=50000)
    MaxAgentCapacity = Column(Integer, default=200000)
    CircuitBreakerState = Column(String(50), default="CLOSED") # CLOSED (healthy), HALF_OPEN, OPEN (tripped)
    FailureCount = Column(Integer, default=0)
    BackpressureStatus = Column(String(50), default="NORMAL") # NORMAL, THROTTLED, QUEUE_SPILLOVER
    QueueDepth = Column(Integer, default=120)
    QueueCapacity = Column(Integer, default=100000)
    EpsRate = Column(Float, default=18400.0)
    LastHeartbeat = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AgentRoutingSessionRecord(Base):
    """[v3.7.0] Phase 13: Global Agent Routing, Automatic Reconnect & Failover State"""
    __tablename__ = "AgentRoutingSessionRecords"
    Id = Column(Integer, primary_key=True, index=True)
    AgentId = Column(String(100), index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    AssignedRegion = Column(String(50), index=True, nullable=False)
    GatewayId = Column(String(100), index=True, nullable=False)
    AgentCertFingerprint = Column(String(128), nullable=False)
    IdentityVerified = Column(Boolean, default=True)
    LatencyMs = Column(Float, default=18.5)
    FailoverAttempts = Column(Integer, default=0)
    LastFailoverReason = Column(String(255), nullable=True)
    ConnectionState = Column(String(50), default="CONNECTED") # CONNECTED, RECONNECTING, FAILED_OVER, ISOLATED
    LastSeen = Column(DateTime, default=datetime.utcnow, index=True)
    SessionExpiresAt = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))

class DisasterRecoveryDrillAudit(Base):
    """[v3.7.0] Phase 13: Automated Disaster Recovery Validation & RTO/RPO Auditing"""
    __tablename__ = "DisasterRecoveryDrillAudits"
    Id = Column(Integer, primary_key=True, index=True)
    DrillId = Column(String(50), unique=True, index=True, nullable=False)
    Scenario = Column(String(100), nullable=False) # RegionFailure, DatabaseFailure, KafkaFailure, ObjectStorageFailure, GatewayFailure, NetworkPartition, CredentialFailure
    TargetComponent = Column(String(100), nullable=False)
    PrimaryRegion = Column(String(50), default="us-east-1")
    FailoverRegion = Column(String(50), default="eu-central-1")
    InjectedFailure = Column(String(255), nullable=False)
    RtoSeconds = Column(Float, nullable=False) # Recovery Time Objective achieved
    RpoSeconds = Column(Float, nullable=False) # Recovery Point Objective achieved (data loss window)
    TargetRtoLimitSec = Column(Float, default=30.0)
    TargetRpoLimitSec = Column(Float, default=5.0)
    Status = Column(String(50), default="PASSED") # PASSED, RECOVERED_DEGRADED, FAILED
    AutomaticFailoverTriggered = Column(Boolean, default=True)
    QueueRecoveredMessages = Column(Integer, default=45000)
    CircuitBreakerTrips = Column(Integer, default=1)
    ZeroDowntimeMaintained = Column(Boolean, default=True)
    RecoveryProcedureDocumented = Column(Text, nullable=True)
    DrillSummary = Column(Text, nullable=True)
    ExecutedAt = Column(DateTime, default=datetime.utcnow, index=True)

class CapacityBenchmarkRecord(Base):
    """[v3.7.0] Phase 13: End-to-End Enterprise Scale Benchmarking (100K -> 1M Endpoints)"""
    __tablename__ = "CapacityBenchmarkRecords"
    Id = Column(Integer, primary_key=True, index=True)
    BenchmarkScale = Column(String(20), index=True, nullable=False) # 100K, 250K, 500K, 1M
    EndpointsTarget = Column(Integer, nullable=False) # 100000, 250000, 500000, 1000000
    ThroughputEPS = Column(Float, nullable=False) # e.g. 52,000 EPS up to 520,000 EPS
    DetectionLatencyP99Ms = Column(Float, nullable=False) # e.g. 18.2 ms
    CpuLoadPercent = Column(Float, default=45.2)
    MemoryPressureMb = Column(Float, default=14200.0)
    ShardPartitionsCount = Column(Integer, default=16)
    DroppedEventsCount = Column(Integer, default=0)
    BackpressureInterventions = Column(Integer, default=0)
    PassedValidation = Column(Boolean, default=True)
    BenchmarkNotes = Column(Text, nullable=True)
    ExecutedAt = Column(DateTime, default=datetime.utcnow, index=True)

class GlobalZeroTrustAudit(Base):
    """[v3.7.0] Phase 13: Zero-Trust mTLS, Secrets & Multi-Tenant Isolation Security Audit"""
    __tablename__ = "GlobalZeroTrustAudits"
    Id = Column(Integer, primary_key=True, index=True)
    AuditScope = Column(String(100), default="GlobalServiceMesh")
    MtlsEnforcedPercent = Column(Float, default=100.0)
    CertificatesRotatedCount = Column(Integer, default=24)
    SecretsRotatedCount = Column(Integer, default=12)
    TenantIsolationScore = Column(Float, default=100.0)
    RegionIsolationScore = Column(Float, default=100.0)
    AdminAuthorizationEnforced = Column(Boolean, default=True)
    NextRotationDue = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=30))
    LastRotationTimestamp = Column(DateTime, default=datetime.utcnow)
    Status = Column(String(50), default="COMPLIANT") # COMPLIANT, ACTION_REQUIRED
    AuditDetailsJson = Column(Text, default="{}")
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)

# ============================================================================
# [v3.8.0] PHASE 14: AUTONOMOUS SECURITY & DEFENSE MODELS
# ============================================================================

class AutonomousActionRecord(Base):
    """[v3.8.0] Phase 14: Policy-Controlled Autonomous Action, Confidence & Verification"""
    __tablename__ = "AutonomousActionRecords"
    Id = Column(Integer, primary_key=True, index=True)
    ActionId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    IncidentId = Column(Integer, nullable=True, index=True)
    AgentId = Column(String(100), nullable=True, index=True)
    ActionType = Column(String(50), nullable=False) # isolate_endpoint, kill_process, block_ioc, disable_account, revoke_session, collect_evidence
    TargetEntity = Column(String(255), nullable=False) # e.g. hostname/IP, PID/hash, account, session token
    TargetEntityType = Column(String(50), default="endpoint") # endpoint, process, network_ioc, identity
    Status = Column(String(50), default="PENDING_APPROVAL", index=True) # PENDING_APPROVAL, EXECUTING, VERIFYING, COMPLETED, ROLLED_BACK, REJECTED, FAILED
    ConfidenceScore = Column(Float, default=0.95) # 0.0 - 1.0
    Reasoning = Column(Text, nullable=False)
    EvidenceSummary = Column(Text, nullable=False)
    RiskLevel = Column(String(20), default="High") # Low, Medium, High, Critical
    ExpectedImpact = Column(String(255), default="Endpoint network isolated except for Monitorix command channel")
    IsReversible = Column(Boolean, default=True)
    ApprovalRequired = Column(Boolean, default=True)
    ApprovedBy = Column(String(100), nullable=True)
    ApprovedAt = Column(DateTime, nullable=True)
    ExecutedAt = Column(DateTime, nullable=True)
    VerificationStatus = Column(String(50), default="PENDING") # PENDING, VERIFIED_CONTAINED, VERIFIED_FAILED, SKIPPED
    VerificationDetails = Column(Text, nullable=True)
    VerifiedAt = Column(DateTime, nullable=True)
    RollbackState = Column(String(50), default="NONE") # NONE, READY, EXECUTED, FAILED
    RollbackDetails = Column(Text, nullable=True)
    RollbackExecutedAt = Column(DateTime, nullable=True)
    GuardrailPassed = Column(Boolean, default=True)
    AuditSignature = Column(String(128), nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)

class AutonomousInvestigationReport(Base):
    """[v3.8.0] Phase 14: AI-Driven Autonomous Investigation & Attack-Chain Reconstruction"""
    __tablename__ = "AutonomousInvestigationReports"
    Id = Column(Integer, primary_key=True, index=True)
    InvestigationId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    IncidentId = Column(Integer, nullable=True, index=True)
    Title = Column(String(255), nullable=False)
    TimelineEventsJson = Column(Text, default="[]")
    ProcessAnalysisJson = Column(Text, default="{}")
    NetworkAnalysisJson = Column(Text, default="{}")
    IocEnrichmentJson = Column(Text, default="{}")
    AttackChainJson = Column(Text, default="[]")
    RootCauseAnalysis = Column(Text, nullable=False)
    EvidenceArtifactsJson = Column(Text, default="[]")
    ConfidenceScore = Column(Float, default=0.94)
    MitreTacticsDetected = Column(String(255), default="Initial Access, Execution, Persistence, Lateral Movement")
    Status = Column(String(50), default="COMPLETED") # ANALYZING, COMPLETED, FAILED
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)

class AutonomousHuntHypothesis(Base):
    """[v3.8.0] Phase 14: AI Autonomous Hunting, Hypothesis & Detection Rule Candidate"""
    __tablename__ = "AutonomousHuntHypotheses"
    Id = Column(Integer, primary_key=True, index=True)
    HypothesisId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), index=True, nullable=False)
    Title = Column(String(255), nullable=False)
    Description = Column(Text, nullable=False)
    MitreTactic = Column(String(100), default="Lateral Movement")
    MitreTechnique = Column(String(100), default="T1021.002 - SMB/Windows Admin Shares")
    GeneratedQueryKql = Column(Text, nullable=False)
    GeneratedQuerySigma = Column(Text, nullable=False)
    GeneratedQuerySpl = Column(Text, nullable=False)
    InvestigationPlanJson = Column(Text, default="[]")
    DetectionCandidateRule = Column(Text, nullable=False)
    ValidationStatus = Column(String(50), default="VALIDATED", index=True) # DRAFT, VALIDATING, VALIDATED, DEPLOYED, REJECTED
    ValidationScore = Column(Float, default=0.96)
    ConfidenceScore = Column(Float, default=0.92)
    FindingsCount = Column(Integer, default=3)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)

class AutonomousGuardrailConfig(Base):
    """[v3.8.0] Phase 14: Safety Guardrails, Autonomy Modes & Circuit Breakers"""
    __tablename__ = "AutonomousGuardrailConfigs"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), unique=True, index=True, nullable=False)
    AutonomyMode = Column(String(50), default="SUPERVISED_APPROVAL") # FULL_AUTONOMY, SUPERVISED_APPROVAL, READ_ONLY_SIMULATION, EMERGENCY_HALT
    MinConfidenceThreshold = Column(Float, default=0.85)
    RequireHumanApprovalForHighImpact = Column(Boolean, default=True)
    AllowedActionTypesJson = Column(Text, default='["isolate_endpoint", "kill_process", "block_ioc", "disable_account", "revoke_session", "collect_evidence"]')
    RateLimitPerMinute = Column(Integer, default=10)
    CircuitBreakerTripped = Column(Boolean, default=False)
    CircuitBreakerReason = Column(String(255), nullable=True)
    PromptInjectionDefenseEnabled = Column(Boolean, default=True)
    GroundednessThreshold = Column(Float, default=0.90)
    HumanOverrideKillSwitch = Column(Boolean, default=False)
    TotalActionsExecuted = Column(Integer, default=0)
    TotalRollbacksExecuted = Column(Integer, default=0)
    TotalFalsePositives = Column(Integer, default=0)
    TotalHumanOverrides = Column(Integer, default=0)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ============================================================================
# [v3.9.0] PHASE 15: SECURITY INTELLIGENCE NETWORK & PRIVACY MODELS
# ============================================================================

class GlobalThreatIntelligenceSignal(Base):
    """[v3.9.0] Phase 15: Privacy-Preserving Global Threat Intelligence Signal"""
    __tablename__ = "GlobalThreatIntelligenceSignals"
    Id = Column(Integer, primary_key=True, index=True)
    SignalId = Column(String(100), unique=True, index=True, nullable=False)
    SignalType = Column(String(50), index=True, nullable=False) # IOC_PATTERN, ATTACK_TECHNIQUE, MALWARE_CHARACTERISTIC, CAMPAIGN_INDICATOR, BEHAVIORAL_PATTERN
    IndicatorValue = Column(String(255), index=True, nullable=False) # e.g. SHA256, sanitized IP/CIDR, domain, JA4
    IndicatorCategory = Column(String(50), default="Hash") # Hash, NetworkIP, Domain, MitreTechnique, YaraSignature, BehavioralPattern
    MitreTacticsJson = Column(Text, default="[]")
    ConfidenceScore = Column(Float, default=0.92) # 0.0 - 1.0
    PrevalenceCount = Column(Integer, default=4) # Number of distinct anonymized contributors
    Severity = Column(String(20), default="High") # Critical, High, Medium, Low
    SourceQuality = Column(Float, default=0.95) # 0.0 - 1.0
    CompositeScore = Column(Float, default=88.5) # 0 - 100
    ValidationStatus = Column(String(50), default="VALIDATED", index=True) # CANDIDATE, VALIDATING, VALIDATED, DISTRIBUTED, REVOKED
    ProvenanceSignature = Column(String(128), nullable=False) # HMAC-SHA256 privacy-preserving attestation
    AnonymizedSector = Column(String(50), default="Technology") # Financial, Healthcare, Technology, Government, Energy, Retail
    FirstObserved = Column(DateTime, default=datetime.utcnow, index=True)
    LastObserved = Column(DateTime, default=datetime.utcnow)
    ExpiresAt = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=60), index=True)
    IsDistributed = Column(Boolean, default=True)
    DistributionTargetsJson = Column(Text, default='["DetectionEngine", "ThreatIntelFeed", "AiSoc", "SecurityGraph", "SOAR", "EndpointAgent"]')
    MetadataJson = Column(Text, default="{}")

class GlobalThreatCampaign(Base):
    """[v3.9.0] Phase 15: Cross-Tenant Coordinated Attack Campaign & Pattern Clustered Model"""
    __tablename__ = "GlobalThreatCampaigns"
    Id = Column(Integer, primary_key=True, index=True)
    CampaignId = Column(String(100), unique=True, index=True, nullable=False)
    Name = Column(String(255), nullable=False)
    ThreatActor = Column(String(100), default="UNC3821 / Advanced Adversary")
    TargetSectorsJson = Column(Text, default='["Financial", "Government", "Technology"]')
    AttackChainTechniquesJson = Column(Text, default='["T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1071.001"]')
    AssociatedInfrastructureJson = Column(Text, default="[]")
    EmergingTechnique = Column(String(255), default="T1055.012 - Process Hollowing into Explorer")
    CampaignConfidence = Column(Float, default=0.95)
    PrevalenceTenantsCount = Column(Integer, default=6)
    ActiveSince = Column(DateTime, default=datetime.utcnow)
    LastActivity = Column(DateTime, default=datetime.utcnow, index=True)
    RecommendedDetectionsCount = Column(Integer, default=3)
    Status = Column(String(50), default="ACTIVE", index=True) # ACTIVE, MONITORED, MITIGATED

class TenantIntelligencePrivacyProfile(Base):
    """[v3.9.0] Phase 15: Tenant Privacy Controls, Anonymization & Data Minimization Config"""
    __tablename__ = "TenantIntelligencePrivacyProfiles"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), unique=True, index=True, nullable=False)
    OptInSharing = Column(Boolean, default=True)
    ShareIocs = Column(Boolean, default=True)
    ShareTechniques = Column(Boolean, default=True)
    ShareMalwareSignatures = Column(Boolean, default=True)
    ShareProcessAnomalies = Column(Boolean, default=False) # Strict minimization
    RetentionDays = Column(Integer, default=60)
    MinimizationRulesEnforced = Column(Boolean, default=True)
    SaltSecret = Column(String(64), nullable=False)
    TotalSignalsContributed = Column(Integer, default=14)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class IntelligenceDistributionRecord(Base):
    """[v3.9.0] Phase 15: Safe Distribution of Validated Intelligence to Engines & Agents"""
    __tablename__ = "IntelligenceDistributionRecords"
    Id = Column(Integer, primary_key=True, index=True)
    DistributionId = Column(String(100), unique=True, index=True, nullable=False)
    SignalOrCampaignId = Column(String(100), index=True, nullable=False)
    DestinationTarget = Column(String(50), index=True, nullable=False) # DetectionEngine, ThreatIntelFeed, AiSoc, SecurityGraph, SOAR, EndpointAgent
    RuleOrPayloadContent = Column(Text, nullable=False)
    DistributedAt = Column(DateTime, default=datetime.utcnow, index=True)
    EnforcementStatus = Column(String(50), default="ACTIVE") # ACTIVE, TESTING, INACTIVE
    FalsePositiveRate = Column(Float, default=0.001)
    VerifiedSafe = Column(Boolean, default=True)

# ============================================================================
# [v3.10.0] PHASE 16: SECURITY RESEARCH & INNOVATION LAB MODELS
# ============================================================================

class ResearchExperiment(Base):
    """[v3.10.0] Phase 16: Isolated Security Research Experiment & Promotion Pipeline"""
    __tablename__ = "ResearchExperiments"
    Id = Column(Integer, primary_key=True, index=True)
    ExperimentId = Column(String(100), unique=True, index=True, nullable=False)
    Title = Column(String(255), nullable=False)
    Domain = Column(String(50), index=True, nullable=False) # ENDPOINT, NETWORK, IDENTITY, CLOUD, AI_SECURITY, DETECTION
    SubDomain = Column(String(100), nullable=False) # Kernel Telemetry, Memory Behavior, Adversarial AI, etc.
    Stage = Column(String(50), default="RESEARCH", index=True) # RESEARCH, PROTOTYPE, LAB_VALIDATION, REGRESSION_TESTING, SECURITY_REVIEW, CANARY, PRODUCTION
    Hypothesis = Column(Text, nullable=False)
    Methodology = Column(Text, nullable=False)
    DatasetId = Column(String(100), nullable=True)
    PrototypeId = Column(String(100), nullable=True)
    MetricsJson = Column(Text, default='{"detection_rate": 0.95, "false_positive_rate": 0.002, "latency_ms": 3.8, "cpu_overhead_pct": 1.2}')
    
    # Promotion Prerequisites & Production Safety Gates
    SecurityReviewCompleted = Column(Boolean, default=False)
    SecurityReviewDetailsJson = Column(Text, default='{}')
    PerformanceTestCompleted = Column(Boolean, default=False)
    PerformanceTestDetailsJson = Column(Text, default='{}')
    RegressionTestCompleted = Column(Boolean, default=False)
    RegressionTestDetailsJson = Column(Text, default='{}')
    RollbackStrategyDefined = Column(Boolean, default=False)
    RollbackStrategyDetailsJson = Column(Text, default='{}')
    
    ProductionPromoted = Column(Boolean, default=False)
    CanaryPercentage = Column(Float, default=0.0)
    LeadResearcher = Column(String(100), default="Monitorix Security Lab")
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ResearchDataset(Base):
    """[v3.10.0] Phase 16: Research Lab Synthetic & Anonymized Datasets"""
    __tablename__ = "ResearchDatasets"
    Id = Column(Integer, primary_key=True, index=True)
    DatasetId = Column(String(100), unique=True, index=True, nullable=False)
    Name = Column(String(255), nullable=False)
    Domain = Column(String(50), index=True, nullable=False)
    DataType = Column(String(50), nullable=False) # PCAP, MEMORY_DUMP, KERNEL_TRACE, ADVERSARIAL_PROMPTS, CLOUD_AUDIT, AUTH_EVENTS
    SampleCount = Column(Integer, default=10000)
    SizeBytes = Column(BigInteger, default=104857600) # 100MB
    Synthetic = Column(Boolean, default=True)
    Anonymized = Column(Boolean, default=True)
    Description = Column(Text, default="")
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class DetectionPrototype(Base):
    """[v3.10.0] Phase 16: Experimental Detection Prototypes in Isolated Sandbox"""
    __tablename__ = "DetectionPrototypes"
    Id = Column(Integer, primary_key=True, index=True)
    PrototypeId = Column(String(100), unique=True, index=True, nullable=False)
    Name = Column(String(255), nullable=False)
    Domain = Column(String(50), index=True, nullable=False)
    EngineTarget = Column(String(100), nullable=False) # EBPF_KERNEL, MEMORY_SCANNER, NETWORK_BEHAVIORAL, IDENTITY_GRAPH, CLOUD_DRIFT, AI_GUARDRAIL
    CodeOrRulePayload = Column(Text, nullable=False)
    LanguageOrFormat = Column(String(50), default="SIGMA") # SIGMA, EBPF_C, PYTHON_DETECTOR, YARA, GRAPH_QUERY, PROMPT_GUARD
    DetectionRate = Column(Float, default=0.96)
    FalsePositiveRate = Column(Float, default=0.003)
    ValidationStatus = Column(String(50), default="LAB_VALIDATED") # DRAFT, SANDBOX_PASSED, LAB_VALIDATED, CANARY_TESTING, PRODUCTION_READY
    IsIsolated = Column(Boolean, default=True) # Strict isolation from production
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class ResearchNote(Base):
    """[v3.10.0] Phase 16: Lab Research Notes, Hypotheses & Academic Findings"""
    __tablename__ = "ResearchNotes"
    Id = Column(Integer, primary_key=True, index=True)
    NoteId = Column(String(100), unique=True, index=True, nullable=False)
    ExperimentId = Column(String(100), index=True, nullable=True)
    Author = Column(String(100), default="Principal Security Researcher")
    Title = Column(String(255), nullable=False)
    Domain = Column(String(50), default="ENDPOINT")
    ContentMarkdown = Column(Text, nullable=False)
    TagsJson = Column(Text, default='["zero-day", "kernel", "mitre"]')
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)

# ============================================================================
# [v3.11.0] PHASE 17: GLOBAL MDR & MSSP PARTNER MODELS
# ============================================================================

class MsspPartnerOrganization(Base):
    """[v3.11.0] Phase 17: MSSP Master Partner Organization & Hierarchical Tenant Config"""
    __tablename__ = "MsspPartnerOrganizations"
    Id = Column(Integer, primary_key=True, index=True)
    PartnerId = Column(String(100), unique=True, index=True, nullable=False)
    Name = Column(String(255), nullable=False)
    PrimaryDomain = Column(String(255), nullable=False)
    PartnerTier = Column(String(50), default="PLATINUM") # PLATINUM, GOLD, SILVER, ELITE
    TotalCustomers = Column(Integer, default=0)
    TotalEndpointsManaged = Column(Integer, default=0)
    RevenueSharePct = Column(Float, default=25.0)
    DelegatedAdminRole = Column(String(50), default="MSSP_SUPER_ADMIN")
    SlaCommitmentP1Min = Column(Integer, default=15) # 15 min P1 response
    SlaCommitmentP2Min = Column(Integer, default=30) # 30 min P2 response
    SlaCommitmentP3Min = Column(Integer, default=120) # 2 hr P3 response
    SlaCommitmentP4Min = Column(Integer, default=480) # 8 hr P4 response
    Status = Column(String(50), default="ACTIVE") # ACTIVE, SUSPENDED, ONBOARDING
    BillingPlan = Column(String(50), default="WHOLESALE_AGGREGATED")
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class MsspDelegatedAdmin(Base):
    """[v3.11.0] Phase 17: MSSP Delegated Partner Administrator Role & Tenant Mapping"""
    __tablename__ = "MsspDelegatedAdmins"
    Id = Column(Integer, primary_key=True, index=True)
    PartnerId = Column(String(100), ForeignKey("MsspPartnerOrganizations.PartnerId"), index=True, nullable=False)
    UserId = Column(Integer, ForeignKey("Users.Id"), nullable=True)
    Email = Column(String(255), nullable=False)
    FullName = Column(String(255), nullable=False)
    Role = Column(String(50), default="MSSP_LEAD_COMMANDER") # MSSP_LEAD_COMMANDER, MSSP_SOC_ANALYST, MSSP_BILLING_ADMIN, MSSP_CUSTOMER_SUCCESS
    AssignedCustomerIdsJson = Column(Text, default='["*"]') # List of tenant IDs or '*' for all
    CanManageWhiteLabel = Column(Boolean, default=True)
    CanEscalateToMonitorixGlobal = Column(Boolean, default=True)
    LastActive = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class MsspCustomerAccount(Base):
    """[v3.11.0] Phase 17: MSSP Managed Customer Account & SLA Operations State"""
    __tablename__ = "MsspCustomerAccounts"
    Id = Column(Integer, primary_key=True, index=True)
    CustomerAccountId = Column(String(100), unique=True, index=True, nullable=False)
    PartnerId = Column(String(100), ForeignKey("MsspPartnerOrganizations.PartnerId"), index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), unique=True, nullable=False)
    CustomerName = Column(String(255), nullable=False)
    Industry = Column(String(100), default="Financial Services")
    MdrTier = Column(String(50), default="MANAGED_RESPONSE") # MANAGED_DETECTION, MANAGED_RESPONSE, PREMIUM_HUNTING, ENTERPRISE_SOC
    OnboardingStatus = Column(String(50), default="ACTIVE") # ACTIVE, PROVISIONING, HEALTH_CHECK
    HealthScore = Column(Float, default=98.0) # 0 - 100
    RiskScore = Column(Float, default=18.5) # 0 - 100
    SlaComplianceRate = Column(Float, default=99.6) # %
    ActiveIncidentsCount = Column(Integer, default=0)
    EndpointsCount = Column(Integer, default=250)
    ServiceAvailabilityPct = Column(Float, default=99.99)
    ContractRenewalDate = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=365))
    CreatedAt = Column(DateTime, default=datetime.utcnow)

class WhiteLabelConfig(Base):
    """[v3.11.0] Phase 17: MSSP White-Label Branding & Sovereign Audit Integrity"""
    __tablename__ = "WhiteLabelConfigs"
    Id = Column(Integer, primary_key=True, index=True)
    PartnerId = Column(String(100), unique=True, index=True, nullable=False)
    Enabled = Column(Boolean, default=True)
    BrandName = Column(String(255), default="Monitorix")
    LogoUrl = Column(String(512), default="https://cdn.monitorix.internal/logos/whitelabel-default.svg")
    FaviconUrl = Column(String(512), default="https://cdn.monitorix.internal/icons/whitelabel-favicon.ico")
    CustomDomain = Column(String(255), nullable=True) # e.g. soc.apexcyber.com
    PrimaryBrandColor = Column(String(50), default="#6366f1")
    AccentBrandColor = Column(String(50), default="#8b5cf6")
    CustomCssJson = Column(Text, default='{"portal_theme": "cyber_dark", "border_radius": "12px"}')
    EmailHeaderHtml = Column(Text, default="<div style='background:#0f172a;color:#fff;padding:16px;'><h3>Security Incident Alert</h3></div>")
    EmailFooterHtml = Column(Text, default="<div style='color:#64748b;font-size:12px;padding:8px;'>Protected by 24/7 MDR Operations</div>")
    SupportPortalUrl = Column(String(512), default="https://support.monitorix.internal")
    PrivacyPolicyUrl = Column(String(512), default="https://monitorix.internal/privacy")
    AuditControlsLocked = Column(Boolean, default=True) # Mandatory: Security and audit controls must remain Monitorix-controlled!
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class GlobalSocShiftHandover(Base):
    """[v3.11.0] Phase 17: Follow-the-Sun Global SOC Regional Shift Handover & Routing"""
    __tablename__ = "GlobalSocShiftHandovers"
    Id = Column(Integer, primary_key=True, index=True)
    HandoverId = Column(String(100), unique=True, index=True, nullable=False)
    FromRegion = Column(String(50), nullable=False) # APAC, EMEA, AMER
    ToRegion = Column(String(50), nullable=False) # EMEA, AMER, APAC
    OutgoingLead = Column(String(100), nullable=False)
    IncomingLead = Column(String(100), nullable=False)
    ShiftStartTime = Column(DateTime, default=lambda: datetime.utcnow() - timedelta(hours=8))
    ShiftEndTime = Column(DateTime, default=datetime.utcnow)
    HandoverTimestamp = Column(DateTime, default=datetime.utcnow)
    ActiveIncidentsCount = Column(Integer, default=3)
    EscalatedP1Count = Column(Integer, default=1)
    OpenWatchItemsJson = Column(Text, default='["UNC3821 C2 sweep in APAC", "Healthcare customer ransomware containment", "Kerberos ticket downgrade monitoring"]')
    BriefingNotes = Column(Text, default="All P1 incidents contained. Ongoing triage on financial sector customer.")
    ThreatAdvisoryBrief = Column(Text, default="Global threat intelligence indicates increased spearphishing with hollowed explorer payloads.")
    Status = Column(String(50), default="COMPLETED") # COMPLETED, IN_PROGRESS, ACKNOWLEDGED

class GlobalSocEscalationRecord(Base):
    """[v3.11.0] Phase 17: Incident Escalation Chain & Global SLA Performance Tracking"""
    __tablename__ = "GlobalSocEscalationRecords"
    Id = Column(Integer, primary_key=True, index=True)
    EscalationId = Column(String(100), unique=True, index=True, nullable=False)
    IncidentId = Column(Integer, nullable=False, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=False, index=True)
    PartnerId = Column(String(100), nullable=True, index=True)
    Severity = Column(String(50), default="P1_CRITICAL") # P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW
    EscalationTier = Column(String(50), default="L2_INVESTIGATION") # L1_TRIAGE, L2_INVESTIGATION, L3_THREAT_HUNTER, PRINCIPAL_COMMANDER
    OriginatingRegion = Column(String(50), default="APAC")
    TargetRegion = Column(String(50), default="EMEA")
    TriggerReason = Column(Text, nullable=False)
    SlaTargetMinutes = Column(Integer, default=15)
    ResponseTimeMinutes = Column(Float, default=4.2)
    SlaBreached = Column(Boolean, default=False)
    Status = Column(String(50), default="IN_PROGRESS") # OPEN, IN_PROGRESS, CONTAINED, RESOLVED
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    ResolvedAt = Column(DateTime, nullable=True)


class EvolutionReleaseStream(Base):
    """[v18.0.0] Phase 18: Continuous Evolution Release Streams Governance"""
    __tablename__ = "EvolutionReleaseStreams"
    Id = Column(Integer, primary_key=True, index=True)
    StreamKey = Column(String(50), unique=True, index=True, nullable=False) # MAJOR, MINOR, SECURITY, AGENT, DETECTION_PACK, INTELLIGENCE, CONNECTOR
    StreamName = Column(String(100), nullable=False)
    Cadence = Column(String(50), default="BI_WEEKLY") # QUARTERLY, BI_WEEKLY, CONTINUOUS_EMERGENCY, MONTHLY, WEEKLY, HOURLY_STREAM, ON_DEMAND
    CurrentVersion = Column(String(50), nullable=False)
    TargetChannels = Column(Text, default='["CANARY", "STAGING", "PRODUCTION"]')
    AutomatedGateCheckEnabled = Column(Boolean, default=True)
    ActiveReleasesCount = Column(Integer, default=1)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class EvolutionReleaseVersion(Base):
    """[v18.0.0] Phase 18: Versioned Product Releases (Monitorix v18.x+, Never Phase 19)"""
    __tablename__ = "EvolutionReleaseVersions"
    Id = Column(Integer, primary_key=True, index=True)
    ReleaseId = Column(String(100), unique=True, index=True, nullable=False)
    VersionString = Column(String(50), nullable=False, index=True) # e.g. v18.0.0, v18.1.0-canary
    StreamKey = Column(String(50), nullable=False, index=True)
    ReleaseType = Column(String(50), nullable=False) # MAJOR, MINOR, SECURITY, AGENT, DETECTION_PACK, INTELLIGENCE, CONNECTOR
    LifecycleStage = Column(String(50), default="PRODUCTION") # RESEARCH, PRODUCT_DEV, INTEGRATION, TESTING, SECURITY_VALIDATION, CANARY, PRODUCTION, MONITORING, FEEDBACK
    CanaryPercent = Column(Float, default=100.0)
    AllGatesPassed = Column(Boolean, default=True)
    SignedChecksum = Column(String(128), default="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    ChangelogSummary = Column(Text, nullable=False)
    RollbackTargetVersion = Column(String(50), nullable=True)
    RollbackReady = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    PromotedAt = Column(DateTime, default=datetime.utcnow)


class EvolutionReleaseGateEvaluation(Base):
    """[v18.0.0] Phase 18: The 13 Mandatory Production Release Gates Audit Ledgers"""
    __tablename__ = "EvolutionReleaseGateEvaluations"
    Id = Column(Integer, primary_key=True, index=True)
    EvaluationId = Column(String(100), unique=True, index=True, nullable=False)
    ReleaseId = Column(String(100), nullable=False, index=True)
    GateIndex = Column(Integer, nullable=False) # 1 to 13
    GateName = Column(String(100), nullable=False)
    Status = Column(String(50), default="PASSED") # PASSED, FAILED, RUNNING, SKIPPED
    ScorePercent = Column(Float, default=100.0)
    ExecutionDurationSeconds = Column(Float, default=8.5)
    DetailsJson = Column(Text, default='{"verified": true, "failures": 0}')
    EvaluatedAt = Column(DateTime, default=datetime.utcnow)


class ContinuousQualityMetric(Base):
    """[v18.0.0] Phase 18: Continuous Telemetry for Security, Detection, Agent, AI, Platform, and Compliance"""
    __tablename__ = "ContinuousQualityMetrics"
    Id = Column(Integer, primary_key=True, index=True)
    Domain = Column(String(50), nullable=False, index=True) # SECURITY, DETECTION, AGENT, AI, PLATFORM, COMPLIANCE
    MetricKey = Column(String(100), nullable=False, index=True)
    MetricValue = Column(Float, nullable=False)
    Unit = Column(String(30), default="")
    Threshold = Column(Float, nullable=True)
    ThresholdOperator = Column(String(10), default=">=") # >=, <=, ==
    Status = Column(String(50), default="OPTIMAL") # OPTIMAL, WARNING, CRITICAL
    ContextDataJson = Column(Text, default="{}")
    RecordedAt = Column(DateTime, default=datetime.utcnow)


# ==============================================================================
# IDENTITY THREAT DETECTION & RESPONSE (ITDR) MODELS
# ==============================================================================

class IdentityAccount(Base):
    """Directory and cloud identity account inventory with privilege tiers & posture flags"""
    __tablename__ = "IdentityAccounts"
    Id = Column(Integer, primary_key=True, index=True)
    AccountId = Column(String(100), unique=True, index=True, nullable=False)
    DisplayName = Column(String(255), nullable=False)
    AccountType = Column(String(50), default="USER") # USER, SERVICE_ACCOUNT, ADMIN, OAUTH_APP, GUEST
    IdentityProvider = Column(String(50), default="ACTIVE_DIRECTORY") # ACTIVE_DIRECTORY, ENTRA_ID, OKTA, LOCAL
    PrivilegeTier = Column(String(50), default="TIER_2_USER") # TIER_0_DOMAIN_ADMIN, TIER_1_SERVER_ADMIN, TIER_2_USER, TIER_CRITICAL_SERVICE
    RiskScore = Column(Float, default=0.0) # 0.0 to 100.0
    IsKerberoastable = Column(Boolean, default=False)
    HasUnconstrainedDelegation = Column(Boolean, default=False)
    IsShadowAdmin = Column(Boolean, default=False)
    MfaEnabled = Column(Boolean, default=True)
    Status = Column(String(50), default="ACTIVE") # ACTIVE, SUSPENDED, CONTAINED, PASSWORD_RESET_REQUIRED
    LastActivity = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    MetadataJson = Column(Text, default="{}")


class IdentityThreatEvent(Base):
    """Active identity threat detections: Kerberoasting, Pass-the-Hash, DCSync, Token Abuse"""
    __tablename__ = "IdentityThreatEvents"
    Id = Column(Integer, primary_key=True, index=True)
    ThreatId = Column(String(100), unique=True, index=True, nullable=False)
    ThreatType = Column(String(100), nullable=False, index=True) # KERBEROASTING, PASS_THE_HASH, DCSYNC, GOLDEN_TICKET, OAUTH_CONSENT_ABUSE, SHADOW_ADMIN_ESCALATION
    MitreTactic = Column(String(100), default="Credential Access")
    MitreTechnique = Column(String(50), default="T1558.003")
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    SourceHost = Column(String(100), nullable=True)
    SourceAccount = Column(String(100), nullable=True)
    TargetAccount = Column(String(100), nullable=True)
    TargetDomain = Column(String(100), default="corp.enterprise.com")
    Status = Column(String(50), default="ACTIVE") # ACTIVE, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    ContainmentActionTaken = Column(String(255), nullable=True)
    DetectedAt = Column(DateTime, default=datetime.utcnow)
    DetailsJson = Column(Text, default="{}")


class IdentityAttackPathNode(Base):
    """Identity graph relationships mapping potential attack paths to Tier-0 assets"""
    __tablename__ = "IdentityAttackPathNodes"
    Id = Column(Integer, primary_key=True, index=True)
    PathId = Column(String(100), index=True, nullable=False)
    SourceNodeId = Column(String(100), nullable=False)
    SourceNodeType = Column(String(50), default="ACCOUNT") # ACCOUNT, GROUP, HOST
    TargetNodeId = Column(String(100), nullable=False)
    TargetNodeType = Column(String(50), default="ACCOUNT") # ACCOUNT, GROUP, HOST, DOMAIN_CONTROLLER
    RelationType = Column(String(50), nullable=False) # MEMBER_OF, ADMIN_TO, CAN_DCSYNC, GENERIC_ALL, WRITE_OWNER, HAS_SESSION
    IsActiveExploitPath = Column(Boolean, default=False)
    HopsCount = Column(Integer, default=1)
    RiskLevel = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ==============================================================================
# CLOUD SECURITY / CNAPP & CSPM MODELS (AWS, AZURE, GCP, CWPP, CIEM)
# ==============================================================================

class CnappCloudAccount(Base):
    """Multi-cloud account / subscription / project inventory with compliance rating"""
    __tablename__ = "CnappCloudAccounts"
    Id = Column(Integer, primary_key=True, index=True)
    AccountId = Column(String(100), unique=True, index=True, nullable=False)
    Provider = Column(String(50), nullable=False, default="AWS") # AWS, AZURE, GCP
    AccountName = Column(String(255), nullable=False)
    Environment = Column(String(50), default="PRODUCTION") # PRODUCTION, STAGING, DEVELOPMENT
    PrimaryRegion = Column(String(50), default="us-east-1")
    ComplianceScore = Column(Float, default=75.0) # 0.0 to 100.0
    TotalResources = Column(Integer, default=0)
    Status = Column(String(50), default="CONNECTED") # CONNECTED, WARNING, ERROR, SCANNING
    LastScanAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    MetadataJson = Column(Text, default="{}")


class CnappCloudResource(Base):
    """Discovered cloud workloads & storage assets across multi-cloud (CWPP & CIEM)"""
    __tablename__ = "CnappCloudResources"
    Id = Column(Integer, primary_key=True, index=True)
    ResourceId = Column(String(255), unique=True, index=True, nullable=False)
    AccountId = Column(String(100), index=True, nullable=False)
    Provider = Column(String(50), nullable=False) # AWS, AZURE, GCP
    ResourceType = Column(String(100), nullable=False, index=True) # S3_BUCKET, EC2_INSTANCE, K8S_CLUSTER, IAM_ROLE, SECURITY_GROUP, AZURE_BLOB, GCS_BUCKET, LAMBDA_FUNCTION
    ResourceName = Column(String(255), nullable=False)
    Region = Column(String(50), default="us-east-1")
    IsPubliclyExposed = Column(Boolean, default=False)
    HasCriticalMisconfig = Column(Boolean, default=False)
    RiskScore = Column(Float, default=20.0) # 0.0 to 100.0
    TagsJson = Column(Text, default="{}")
    LastSeenAt = Column(DateTime, default=datetime.utcnow)


class CnappMisconfiguration(Base):
    """CSPM compliance findings & audit results against CIS / SOC2 / PCI-DSS"""
    __tablename__ = "CnappMisconfigurations"
    Id = Column(Integer, primary_key=True, index=True)
    FindingId = Column(String(100), unique=True, index=True, nullable=False)
    ResourceId = Column(String(255), index=True, nullable=False)
    AccountId = Column(String(100), index=True, nullable=False)
    Provider = Column(String(50), nullable=False) # AWS, AZURE, GCP
    Benchmark = Column(String(100), default="CIS_AWS_FOUNDATIONS_1.4") # CIS_AWS, CIS_AZURE, CIS_GCP, SOC2, PCI_DSS
    RuleId = Column(String(100), nullable=False)
    Title = Column(String(255), nullable=False)
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    Description = Column(Text, nullable=False)
    RemediationStep = Column(Text, nullable=True)
    Status = Column(String(50), default="OPEN") # OPEN, REMEDIATED, SUPPRESSED
    DetectedAt = Column(DateTime, default=datetime.utcnow)
    RemediatedAt = Column(DateTime, nullable=True)


class CnappCloudThreat(Base):
    """Real-time cloud threat detections from CloudTrail, Activity Logs, and Cloud Audit"""
    __tablename__ = "CnappCloudThreats"
    Id = Column(Integer, primary_key=True, index=True)
    ThreatId = Column(String(100), unique=True, index=True, nullable=False)
    AccountId = Column(String(100), index=True, nullable=False)
    Provider = Column(String(50), nullable=False) # AWS, AZURE, GCP
    ThreatType = Column(String(100), nullable=False, index=True) # EXPOSED_STORAGE, IAM_BACKDOOR, AUDIT_LOG_TAMPERING, CRYPTO_MINING, ANOMALOUS_ACCESS
    MitreTactic = Column(String(100), default="Impact")
    MitreTechnique = Column(String(50), default="T1530")
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    EventSource = Column(String(100), default="cloudtrail.amazonaws.com")
    PrincipalArn = Column(String(255), nullable=True)
    SourceIP = Column(String(100), nullable=True)
    Status = Column(String(50), default="ACTIVE") # ACTIVE, INVESTIGATING, CONTAINED, RESOLVED
    DetailsJson = Column(Text, default="{}")
    DetectedAt = Column(DateTime, default=datetime.utcnow)


class CnappAttackPath(Base):
    """Multi-cloud attack paths from internet ingress to crown-jewel assets"""
    __tablename__ = "CnappAttackPaths"
    Id = Column(Integer, primary_key=True, index=True)
    PathId = Column(String(100), index=True, nullable=False)
    AccountId = Column(String(100), index=True, nullable=False)
    Provider = Column(String(50), default="AWS")
    StartNode = Column(String(255), nullable=False) # e.g. "Internet: 0.0.0.0/0"
    StartType = Column(String(50), default="INTERNET")
    EndNode = Column(String(255), nullable=False) # e.g. "s3://corp-crown-jewels-customer-db"
    EndType = Column(String(50), default="STORAGE_BUCKET")
    HopsCount = Column(Integer, default=3)
    RiskScore = Column(Float, default=95.0)
    RiskDescription = Column(Text, nullable=False)
    IsCrownJewelAtRisk = Column(Boolean, default=True)
    StepsJson = Column(Text, default="[]")
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ==============================================================================
# EXTERNAL ATTACK SURFACE MANAGEMENT (EASM) MODELS
# ==============================================================================

class EasmAsset(Base):
    """External perimeter assets: Root domains, subdomains, public IPs, and cloud edges"""
    __tablename__ = "EasmAssets"
    Id = Column(Integer, primary_key=True, index=True)
    AssetId = Column(String(100), unique=True, index=True, nullable=False)
    AssetType = Column(String(50), nullable=False) # DOMAIN, SUBDOMAIN, IP_ADDRESS, CLOUD_EDGE
    Value = Column(String(255), nullable=False, index=True) # e.g. api.monitorix.co.in, 198.51.100.25
    RootDomain = Column(String(255), default="monitorix.co.in", index=True)
    HostingProvider = Column(String(100), default="CLOUDFLARE") # AWS, CLOUDFLARE, DIGITALOCEAN, AZURE, GCP
    IpAddress = Column(String(100), nullable=True)
    RiskScore = Column(Float, default=15.0) # 0.0 to 100.0
    IsShadowAsset = Column(Boolean, default=False)
    IsMonitored = Column(Boolean, default=True)
    Status = Column(String(50), default="ACTIVE") # ACTIVE, INACTIVE, INVESTIGATING
    LastSeenAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    MetadataJson = Column(Text, default="{}")


class EasmPortService(Base):
    """Discovered open ports, listening network services, and banners on external assets"""
    __tablename__ = "EasmPortServices"
    Id = Column(Integer, primary_key=True, index=True)
    PortId = Column(String(100), unique=True, index=True, nullable=False)
    AssetId = Column(String(100), index=True, nullable=False)
    IpAddress = Column(String(100), nullable=False)
    PortNumber = Column(Integer, nullable=False) # 22, 80, 443, 3389, 8080, 9200
    Protocol = Column(String(20), default="TCP") # TCP, UDP
    ServiceName = Column(String(100), default="HTTP") # SSH, HTTPS, RDP, ELASTICSEARCH, REDIS
    BannerText = Column(String(255), nullable=True)
    IsVulnerableOrExposed = Column(Boolean, default=False)
    TlsVersion = Column(String(50), nullable=True) # TLSv1.3, TLSv1.2, None
    DetectedAt = Column(DateTime, default=datetime.utcnow)


class EasmCertificate(Base):
    """SSL/TLS certificates, expiry tracking, key lengths, and cryptographic grades"""
    __tablename__ = "EasmCertificates"
    Id = Column(Integer, primary_key=True, index=True)
    CertId = Column(String(100), unique=True, index=True, nullable=False)
    DomainName = Column(String(255), nullable=False, index=True)
    Issuer = Column(String(255), default="Let's Encrypt")
    ValidFrom = Column(DateTime, default=datetime.utcnow)
    ValidTo = Column(DateTime, nullable=False)
    DaysUntilExpiration = Column(Integer, default=90)
    TlsGrade = Column(String(10), default="A+") # A+, A, B, C, F
    IsExpired = Column(Boolean, default=False)
    KeyLength = Column(Integer, default=2048)
    HasWeakCipher = Column(Boolean, default=False)
    DetectedAt = Column(DateTime, default=datetime.utcnow)


class EasmExposureFinding(Base):
    """Perimeter security findings: Subdomain takeover, exposed admin panels, open dangerous ports"""
    __tablename__ = "EasmExposureFindings"
    Id = Column(Integer, primary_key=True, index=True)
    FindingId = Column(String(100), unique=True, index=True, nullable=False)
    AssetId = Column(String(100), index=True, nullable=False)
    FindingType = Column(String(100), nullable=False, index=True) # SUBDOMAIN_TAKEOVER, EXPOSED_ADMIN_PANEL, DANGEROUS_PORT_OPEN, EXPIRED_TLS_CERT, MISSING_EMAIL_SECURITY
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    Title = Column(String(255), nullable=False)
    Description = Column(Text, nullable=False)
    RemediationStep = Column(Text, nullable=True)
    Status = Column(String(50), default="OPEN") # OPEN, REMEDIATED, SUPPRESSED
    DetectedAt = Column(DateTime, default=datetime.utcnow)
    RemediatedAt = Column(DateTime, nullable=True)


# ==============================================================================
# WEB APPLICATION & API SECURITY (WAAP / WAF) MODELS
# ==============================================================================

class WaapRule(Base):
    """WAF inspection rules: OWASP Top 10, CRS, Rate Limiting, and Custom Protections"""
    __tablename__ = "WaapRules"
    Id = Column(Integer, primary_key=True, index=True)
    RuleId = Column(String(100), unique=True, index=True, nullable=False)
    Name = Column(String(255), nullable=False)
    Category = Column(String(50), nullable=False, index=True) # SQLI, XSS, RCE_COMMAND_INJECTION, SSRF, PATH_TRAVERSAL, API_BOLA, BOT_RATE_LIMIT
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM
    Action = Column(String(50), default="BLOCK") # BLOCK, CHALLENGE, LOG
    PatternRegex = Column(Text, nullable=False)
    IsEnabled = Column(Boolean, default=True)
    MatchCount = Column(Integer, default=0)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class WaapSecurityEvent(Base):
    """Real-time HTTP/API attack detections & blocked payloads"""
    __tablename__ = "WaapSecurityEvents"
    Id = Column(Integer, primary_key=True, index=True)
    EventId = Column(String(100), unique=True, index=True, nullable=False)
    RuleId = Column(String(100), index=True, nullable=False)
    AttackType = Column(String(100), nullable=False, index=True) # SQLI, XSS, RCE, SSRF, PATH_TRAVERSAL, API_BOLA, BRUTE_FORCE
    ClientIp = Column(String(100), index=True, nullable=False)
    RequestMethod = Column(String(20), default="GET") # GET, POST, PUT, DELETE, PATCH
    RequestUri = Column(Text, nullable=False)
    UserAgent = Column(String(500), nullable=True)
    PayloadSample = Column(Text, nullable=True)
    ActionTaken = Column(String(50), default="BLOCKED") # BLOCKED, LOGGED, CHALLENGED
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    MetadataJson = Column(Text, default="{}")


class WaapApiEndpoint(Base):
    """API endpoint catalog with OWASP API Security posture & BOLA/IDOR monitoring"""
    __tablename__ = "WaapApiEndpoints"
    Id = Column(Integer, primary_key=True, index=True)
    EndpointId = Column(String(100), unique=True, index=True, nullable=False)
    Path = Column(String(255), nullable=False, index=True) # e.g. /api/v1/users/{id}
    Method = Column(String(20), default="GET")
    AuthType = Column(String(50), default="BEARER_JWT") # BEARER_JWT, API_KEY, MUTUAL_TLS, NONE
    IsPublic = Column(Boolean, default=False)
    HasSchemaValidation = Column(Boolean, default=True)
    RiskScore = Column(Float, default=20.0) # 0.0 to 100.0
    RateLimitPerMin = Column(Integer, default=120)
    TotalRequests = Column(Integer, default=0)
    BlockedRequests = Column(Integer, default=0)
    LastSeenAt = Column(DateTime, default=datetime.utcnow)


class WaapIpReputation(Base):
    """Client IP reputation, automated ban list, and threat actor tracking"""
    __tablename__ = "WaapIpReputations"
    Id = Column(Integer, primary_key=True, index=True)
    IpAddress = Column(String(100), unique=True, index=True, nullable=False)
    ReputationScore = Column(Float, default=90.0) # 0.0 to 100.0 (high = dangerous)
    IsBlocked = Column(Boolean, default=True)
    Reason = Column(String(255), nullable=False) # e.g. Repeated SQLi attempts, Tor Exit Node
    CountryCode = Column(String(10), default="XX")
    ThreatCategory = Column(String(50), default="EXPLOIT_SCANNER") # TOR_EXIT_NODE, KNOWN_BOTNET, EXPLOIT_SCANNER, MANUAL_BLOCK
    ExpiresAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# DATA SECURITY POSTURE MANAGEMENT (DSPM) MODELS (WAVE 1.5)
# ---------------------------------------------------------------------------

class DspmDataStore(Base):
    """Discovered managed and unmanaged (shadow) structured & unstructured data repositories"""
    __tablename__ = "DspmDataStores"
    Id = Column(Integer, primary_key=True, index=True)
    StoreId = Column(String(100), unique=True, index=True, nullable=False) # e.g. STORE-AWS-S3-FINANCE
    Name = Column(String(200), nullable=False)
    StoreType = Column(String(50), nullable=False) # S3_BUCKET, AZURE_BLOB, GCS_BUCKET, POSTGRES_DB, SMB_FILESHARE, LOCAL_DIR
    CloudProvider = Column(String(50), default="ON_PREMISE") # AWS, AZURE, GCP, ON_PREMISE, HYBRID
    Region = Column(String(50), default="global")
    IsPubliclyAccessible = Column(Boolean, default=False)
    IsEncryptedAtRest = Column(Boolean, default=True)
    IsShadowData = Column(Boolean, default=False) # True if unmanaged/rogue data store
    DataClassification = Column(String(50), default="INTERNAL") # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    TotalSizeMb = Column(Float, default=0.0)
    TotalRecordsCount = Column(Integer, default=0)
    SensitiveRecordsCount = Column(Integer, default=0)
    RiskScore = Column(Float, default=20.0) # 0-100 (high = high exposure/vulnerability)
    LastScannedAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class DspmDataAsset(Base):
    """Specific tables, files, or objects containing data in data stores"""
    __tablename__ = "DspmDataAssets"
    Id = Column(Integer, primary_key=True, index=True)
    AssetId = Column(String(100), unique=True, index=True, nullable=False) # e.g. ASSET-S3-FIN-001
    StoreId = Column(String(100), index=True, nullable=False)
    AssetPath = Column(String(500), nullable=False) # s3://fin-reports/2026/customers.parquet
    AssetType = Column(String(50), nullable=False) # PARQUET, CSV, JSON, DATABASE_TABLE, PDF, TXT, ENV_FILE
    SensitiveTypesFound = Column(Text, default="[]") # JSON list: ["PCI_CREDIT_CARD", "PII_SSN"]
    SensitivityScore = Column(Float, default=10.0) # 0-100
    RecordCount = Column(Integer, default=0)
    HasDirectAccess = Column(Boolean, default=False)
    IsShadowData = Column(Boolean, default=False)
    LastScannedAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class DspmClassificationFinding(Base):
    """Detected sensitive data exposures and compliance policy violations"""
    __tablename__ = "DspmClassificationFindings"
    Id = Column(Integer, primary_key=True, index=True)
    FindingId = Column(String(100), unique=True, index=True, nullable=False) # e.g. DSPM-FIND-001
    StoreId = Column(String(100), index=True, nullable=False)
    AssetId = Column(String(100), index=True, nullable=False)
    Category = Column(String(50), nullable=False) # PCI_DSS, PII_PERSONAL, PHI_HEALTH, CREDENTIALS_KEYS, SOURCE_CODE
    DataType = Column(String(100), nullable=False) # CREDIT_CARD_NUMBER, SSN, PASSPORT, MEDICAL_RECORD_ID, AWS_SECRET_KEY
    MatchedCount = Column(Integer, default=1)
    SampleMaskedSnippet = Column(String(255), nullable=True) # e.g. 4532-XXXX-XXXX-8921
    Severity = Column(String(20), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    Status = Column(String(50), default="OPEN") # OPEN, REMEDIATED, SUPPRESSED, ACCEPTED_RISK
    RemediationAction = Column(String(100), default="RESTRICT_PERMISSIONS") # ENCRYPT_STORE, REVOKE_PUBLIC_ACCESS, PURGE_SHADOW_COPY
    RemediatedAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class DspmCompliancePosture(Base):
    """Data residency, regulatory frameworks, and privacy posture scores"""
    __tablename__ = "DspmCompliancePostures"
    Id = Column(Integer, primary_key=True, index=True)
    Framework = Column(String(50), unique=True, index=True, nullable=False) # GDPR, HIPAA, PCI_DSS, SOC2_PRIVACY, DPDP_INDIA
    ComplianceScore = Column(Float, default=85.0) # 0-100
    ViolationsCount = Column(Integer, default=0)
    ControlledStoresCount = Column(Integer, default=0)
    Status = Column(String(50), default="COMPLIANT") # COMPLIANT, WARNING, NON_COMPLIANT
    LastEvaluatedAt = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# SECRETS SECURITY & VAULT GOVERNANCE MODELS (WAVE 1.6)
# ---------------------------------------------------------------------------

class SecretScanTarget(Base):
    """Scanned repositories, host file systems, container images, and CI/CD pipelines"""
    __tablename__ = "SecretScanTargets"
    Id = Column(Integer, primary_key=True, index=True)
    TargetId = Column(String(100), unique=True, index=True, nullable=False) # e.g. TGT-REPO-PAYMENT-SVC
    Name = Column(String(200), nullable=False)
    TargetType = Column(String(50), nullable=False) # GIT_REPO, HOST_FILESYSTEM, DOCKER_IMAGE, CI_CD_PIPELINE, ENV_VARS
    LocationPath = Column(String(500), nullable=False) # github.com/monitorix/payment-service, /opt/app/.env
    Environment = Column(String(50), default="PRODUCTION") # PRODUCTION, STAGING, DEVELOPMENT
    SecretsFoundCount = Column(Integer, default=0)
    RiskScore = Column(Float, default=15.0) # 0-100 (high = dangerous secrets exposed)
    LastScannedAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class SecretExposureIncident(Base):
    """Detected exposed credentials, API keys, tokens, and private certificates"""
    __tablename__ = "SecretExposureIncidents"
    Id = Column(Integer, primary_key=True, index=True)
    IncidentId = Column(String(100), unique=True, index=True, nullable=False) # e.g. SEC-INC-001
    TargetId = Column(String(100), index=True, nullable=False)
    SecretType = Column(String(100), nullable=False) # AWS_ACCESS_KEY, GITHUB_PAT, OPENAI_API_KEY, SSH_PRIVATE_KEY, STRIPE_SECRET_KEY, SLACK_WEBHOOK, JWT_SECRET, DATABASE_PASSWORD
    MaskedSecret = Column(String(255), nullable=False) # AKIA****EXAMPLE
    LocationFile = Column(String(500), nullable=False) # src/config/database.py, .env.prod
    LineNumber = Column(Integer, default=1)
    EntropyScore = Column(Float, default=4.5) # Shannon entropy (e.g. 3.5 - 6.0)
    Severity = Column(String(20), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    Status = Column(String(50), default="OPEN") # OPEN, REVOKED, ROTATED, FALSE_POSITIVE
    IsVaultManaged = Column(Boolean, default=False)
    RemediationPlaybook = Column(String(100), default="AUTOMATED_VAULT_ROTATION")
    ResolvedAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class SecretVaultIntegration(Base):
    """Enterprise vault synchronization and secret lifecycle automation status"""
    __tablename__ = "SecretVaultIntegrations"
    Id = Column(Integer, primary_key=True, index=True)
    VaultId = Column(String(100), unique=True, index=True, nullable=False) # e.g. VAULT-HASHICORP-CORE
    Name = Column(String(200), nullable=False)
    Provider = Column(String(50), nullable=False) # HASHICORP_VAULT, AWS_SECRETS_MANAGER, AZURE_KEY_VAULT, GCP_SECRET_MANAGER
    EndpointUrl = Column(String(300), nullable=False)
    Status = Column(String(50), default="CONNECTED") # CONNECTED, SYNCING, ERROR, DISCONNECTED
    SyncedSecretsCount = Column(Integer, default=0)
    LastSyncAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# DATABASE SECURITY & ACTIVITY MONITORING (DAM) MODELS (WAVE 1.7)
# ---------------------------------------------------------------------------

class DatabaseInstance(Base):
    """Monitored database engines, clusters, and data warehouses"""
    __tablename__ = "DatabaseInstances"
    Id = Column(Integer, primary_key=True, index=True)
    InstanceId = Column(String(100), unique=True, index=True, nullable=False) # e.g. DB-PG-PROD-PRIMARY
    Name = Column(String(200), nullable=False)
    Engine = Column(String(50), nullable=False) # POSTGRESQL, MYSQL, MONGODB, REDIS, ORACLE, CLICKHOUSE
    Host = Column(String(200), nullable=False)
    Port = Column(Integer, default=5432)
    Environment = Column(String(50), default="PRODUCTION") # PRODUCTION, STAGING, DEVELOPMENT
    IsTlsEnforced = Column(Boolean, default=True)
    SensitiveTablesCount = Column(Integer, default=0)
    TotalQueries24h = Column(Integer, default=0)
    RiskScore = Column(Float, default=25.0) # 0-100 (high = abnormal activity/vulnerabilities)
    Status = Column(String(50), default="ACTIVE") # ACTIVE, MAINTENANCE, ALERTING
    LastAuditedAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class DatabaseAuditLog(Base):
    """Query telemetry and real-time execution audit stream"""
    __tablename__ = "DatabaseAuditLogs"
    Id = Column(Integer, primary_key=True, index=True)
    LogId = Column(String(100), unique=True, index=True, nullable=False) # e.g. DBLOG-001
    InstanceId = Column(String(100), index=True, nullable=False)
    DbUser = Column(String(100), nullable=False) # e.g. app_backend, postgres, analyst_read
    ClientIp = Column(String(100), nullable=False)
    QueryText = Column(Text, nullable=False)
    QueryType = Column(String(50), nullable=False) # SELECT, INSERT, UPDATE, DELETE, DROP, ALTER, GRANT, COPY
    RowsReturned = Column(Integer, default=0)
    ExecutionTimeMs = Column(Float, default=1.5)
    IsPrivilegedUser = Column(Boolean, default=False)
    Timestamp = Column(DateTime, default=datetime.utcnow)


class DatabaseSecurityAlert(Base):
    """Detected anomalous queries, mass exfiltration, and privilege abuse"""
    __tablename__ = "DatabaseSecurityAlerts"
    Id = Column(Integer, primary_key=True, index=True)
    AlertId = Column(String(100), unique=True, index=True, nullable=False) # e.g. DB-ALERT-001
    InstanceId = Column(String(100), index=True, nullable=False)
    DbUser = Column(String(100), nullable=False)
    ClientIp = Column(String(100), nullable=False)
    AlertType = Column(String(100), nullable=False) # MASS_EXFILTRATION, SUSPICIOUS_DROP_TABLE, PRIVILEGE_ESCALATION, SENSITIVE_TABLE_BULK_DUMP, UNAUTHORIZED_IP_ACCESS
    QuerySnippet = Column(Text, nullable=False)
    Severity = Column(String(20), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    Status = Column(String(50), default="OPEN") # OPEN, CONTAINED, DISMISSED
    ActionTaken = Column(String(100), default="ALERT_SOC") # KILL_SESSION, BLOCK_IP, ALERT_SOC
    ResolvedAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class DatabaseAccessRule(Base):
    """Security guardrails and threshold enforcement policies"""
    __tablename__ = "DatabaseAccessRules"
    Id = Column(Integer, primary_key=True, index=True)
    RuleId = Column(String(100), unique=True, index=True, nullable=False) # e.g. DBRULE-001
    Name = Column(String(200), nullable=False)
    RuleType = Column(String(50), nullable=False) # EXFILTRATION_LIMIT, DDL_PROTECTION, PRIVILEGE_GUARD
    MaxRowsAllowed = Column(Integer, default=10000)
    EnforceTls = Column(Boolean, default=True)
    IsEnabled = Column(Boolean, default=True)
    Action = Column(String(50), default="BLOCK") # BLOCK, ALERT, LOG
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Wave 1.8: Kubernetes & Container Workload Security (KSPM / CWPP)
# ---------------------------------------------------------------------------

class K8sCluster(Base):
    """Monitored Kubernetes cluster inventory and benchmark posture"""
    __tablename__ = "K8sClusters"
    Id = Column(Integer, primary_key=True, index=True)
    ClusterId = Column(String(100), unique=True, index=True, nullable=False) # e.g. K8S-EKS-PROD-01
    Name = Column(String(200), nullable=False)
    Provider = Column(String(50), nullable=False) # EKS, GKE, AKS, SELF_HOSTED
    Region = Column(String(50), default="us-east-1")
    K8sVersion = Column(String(50), default="v1.28.7")
    NodeCount = Column(Integer, default=12)
    PodCount = Column(Integer, default=184)
    PostureScore = Column(Float, default=82.5) # 0 - 100
    CisBenchmarkScore = Column(Float, default=79.0) # 0 - 100
    Status = Column(String(50), default="HEALTHY") # HEALTHY, DEGRADED, CRITICAL
    LastAuditedAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class K8sWorkload(Base):
    """Container workloads, pods, and securityContext telemetry"""
    __tablename__ = "K8sWorkloads"
    Id = Column(Integer, primary_key=True, index=True)
    WorkloadId = Column(String(100), unique=True, index=True, nullable=False) # e.g. WKLD-PAYMENT-API
    ClusterId = Column(String(100), index=True, nullable=False)
    Namespace = Column(String(100), index=True, nullable=False) # prod, kube-system, staging
    Name = Column(String(200), nullable=False)
    WorkloadType = Column(String(50), default="Deployment") # Deployment, DaemonSet, StatefulSet, Pod
    Image = Column(String(255), nullable=False)
    IsPrivileged = Column(Boolean, default=False)
    RunsAsRoot = Column(Boolean, default=False)
    HasHostPathMount = Column(Boolean, default=False)
    HasHostPid = Column(Boolean, default=False)
    Capabilities = Column(Text, default="[]") # JSON list of capabilities like CAP_SYS_ADMIN
    RiskScore = Column(Float, default=15.0)
    Status = Column(String(50), default="RUNNING") # RUNNING, QUARANTINED, TERMINATED
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class K8sSecurityFinding(Base):
    """Runtime alerts, posture misconfigurations, and admission violations"""
    __tablename__ = "K8sSecurityFindings"
    Id = Column(Integer, primary_key=True, index=True)
    FindingId = Column(String(100), unique=True, index=True, nullable=False) # e.g. K8S-FIND-001
    ClusterId = Column(String(100), index=True, nullable=False)
    WorkloadId = Column(String(100), index=True, nullable=True)
    Namespace = Column(String(100), index=True, nullable=False)
    FindingType = Column(String(100), nullable=False) # PRIVILEGED_CONTAINER, DOCKER_SOCKET_MOUNT, CONTAINER_ESCAPE, EXCESSIVE_RBAC
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    Title = Column(String(255), nullable=False)
    Description = Column(Text, nullable=False)
    Remediation = Column(Text, nullable=True)
    Status = Column(String(50), default="OPEN") # OPEN, QUARANTINED, RESOLVED
    DetectedAt = Column(DateTime, default=datetime.utcnow)
    ResolvedAt = Column(DateTime, nullable=True)


class K8sAdmissionPolicy(Base):
    """Admission control policies and Pod Security Standards guardrails"""
    __tablename__ = "K8sAdmissionPolicies"
    Id = Column(Integer, primary_key=True, index=True)
    PolicyId = Column(String(100), unique=True, index=True, nullable=False) # e.g. POL-K8S-PSS-001
    Name = Column(String(200), nullable=False)
    Category = Column(String(100), default="POD_SECURITY_STANDARDS") # POD_SECURITY_STANDARDS, RBAC_GUARDRAIL, IMAGE_ASSURANCE
    EnforceMode = Column(String(50), default="ENFORCE") # ENFORCE, AUDIT
    Description = Column(Text, nullable=False)
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Wave 1.9: Software Supply-Chain Security & SBOM Governance
# ---------------------------------------------------------------------------

class SupplyChainProject(Base):
    """Monitored application repos, build targets, and CI/CD pipelines"""
    __tablename__ = "SupplyChainProjects"
    Id = Column(Integer, primary_key=True, index=True)
    ProjectId = Column(String(100), unique=True, index=True, nullable=False) # e.g. PROJ-PAYMENT-SVC
    Name = Column(String(200), nullable=False)
    RepoUrl = Column(String(255), nullable=False)
    Branch = Column(String(100), default="main")
    Ecosystem = Column(String(50), nullable=False) # NPM, PYPI, GO, CARGO, MAVEN
    DependencyCount = Column(Integer, default=0)
    CriticalCveCount = Column(Integer, default=0)
    SlsaLevel = Column(String(50), default="SLSA_LEVEL_2") # SLSA_LEVEL_1, SLSA_LEVEL_2, SLSA_LEVEL_3
    PostureScore = Column(Float, default=85.0) # 0 - 100
    Status = Column(String(50), default="ACTIVE") # ACTIVE, BLOCKED, COMPLIANT
    LastScannedAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class SupplyChainComponent(Base):
    """Software dependencies, packages, and library inventory"""
    __tablename__ = "SupplyChainComponents"
    Id = Column(Integer, primary_key=True, index=True)
    ComponentId = Column(String(100), unique=True, index=True, nullable=False) # e.g. COMP-AXIOS-1.6.0
    ProjectId = Column(String(100), index=True, nullable=False)
    Name = Column(String(200), index=True, nullable=False) # e.g. requests, axios, lodash
    Version = Column(String(100), nullable=False)
    Ecosystem = Column(String(50), nullable=False) # NPM, PYPI, GO, CARGO
    License = Column(String(100), default="MIT")
    IsDirect = Column(Boolean, default=True)
    IsVulnerable = Column(Boolean, default=False)
    CveCount = Column(Integer, default=0)
    HighestCvss = Column(Float, default=0.0)
    IsMalicious = Column(Boolean, default=False) # Typosquat, dependency confusion, malware
    PackageHash = Column(String(128), nullable=True) # sha256 checksum
    Status = Column(String(50), default="ALLOWED") # ALLOWED, QUARANTINED, BLOCKED
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class SupplyChainFinding(Base):
    """Supply chain threats, typosquats, and build gate violations"""
    __tablename__ = "SupplyChainFindings"
    Id = Column(Integer, primary_key=True, index=True)
    FindingId = Column(String(100), unique=True, index=True, nullable=False) # e.g. SC-FIND-001
    ProjectId = Column(String(100), index=True, nullable=False)
    ComponentName = Column(String(200), index=True, nullable=False)
    FindingType = Column(String(100), nullable=False) # TYPOSQUATTING, DEPENDENCY_CONFUSION, MALICIOUS_POSTINSTALL, CRITICAL_CVE
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    Title = Column(String(255), nullable=False)
    Description = Column(Text, nullable=False)
    Remediation = Column(Text, nullable=True)
    Status = Column(String(50), default="OPEN") # OPEN, QUARANTINED, RESOLVED
    DetectedAt = Column(DateTime, default=datetime.utcnow)
    ResolvedAt = Column(DateTime, nullable=True)


class SupplyChainPolicy(Base):
    """CI/CD build gates and SBOM security verification guardrails"""
    __tablename__ = "SupplyChainPolicies"
    Id = Column(Integer, primary_key=True, index=True)
    PolicyId = Column(String(100), unique=True, index=True, nullable=False) # e.g. POL-SC-001
    Name = Column(String(200), nullable=False)
    RuleType = Column(String(100), nullable=False) # BLOCK_TYPOSQUAT, REJECT_POSTINSTALL, ENFORCE_SLSA, FAIL_ON_CRITICAL_CVE
    EnforceMode = Column(String(50), default="BLOCK") # BLOCK, WARN
    Description = Column(Text, nullable=False)
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Wave 1.10: Advanced Network Detection & Response (NDR)
# ---------------------------------------------------------------------------

class NdrSensor(Base):
    """Network capture sensors, probe interfaces, and tap collectors"""
    __tablename__ = "NdrSensors"
    Id = Column(Integer, primary_key=True, index=True)
    SensorId = Column(String(100), unique=True, index=True, nullable=False) # e.g. SENSOR-EDGE-DC1
    Name = Column(String(200), nullable=False)
    Interface = Column(String(50), default="eth0") # eth0, bond0, mirror0
    Location = Column(String(100), default="Primary Datacenter") # Edge, Cloud DMZ, Branch
    Status = Column(String(50), default="ONLINE") # ONLINE, DEGRADED, OFFLINE
    PacketsPerSec = Column(Integer, default=45000)
    BandwidthMbps = Column(Float, default=850.5)
    CaptureBufferMb = Column(Float, default=2048.0) # PCAP ring buffer size
    LastSeenAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class NdrFlowRecord(Base):
    """High-fidelity NetFlow / IPFIX and connection session telemetry"""
    __tablename__ = "NdrFlowRecords"
    Id = Column(Integer, primary_key=True, index=True)
    FlowId = Column(String(100), unique=True, index=True, nullable=False) # e.g. FLOW-A9812C44
    SensorId = Column(String(100), index=True, nullable=False)
    SourceIp = Column(String(50), index=True, nullable=False)
    DestinationIp = Column(String(50), index=True, nullable=False)
    SourcePort = Column(Integer, nullable=False)
    DestinationPort = Column(Integer, nullable=False)
    Protocol = Column(String(20), default="TCP") # TCP, UDP, ICMP
    BytesTransferred = Column(Integer, default=0)
    Packets = Column(Integer, default=1)
    Flags = Column(String(50), default="SYN,ACK") # SYN, ACK, PSH, FIN, RST
    IsSuspicious = Column(Boolean, default=False)
    ThreatType = Column(String(50), default="BENIGN") # BENIGN, C2_BEACONING, DNS_EXFIL, PORT_SWEEP
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class NdrThreatDetection(Base):
    """Behavioral network security threats, beacon radar alerts, and exfiltration"""
    __tablename__ = "NdrThreatDetections"
    Id = Column(Integer, primary_key=True, index=True)
    AlertId = Column(String(100), unique=True, index=True, nullable=False) # e.g. NDR-ALERT-001
    SensorId = Column(String(100), index=True, nullable=False)
    ThreatType = Column(String(100), nullable=False) # C2_BEACONING, DNS_TUNNELING, DGA_LOOKUP, PORT_SWEEP, LATERAL_MOVEMENT
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    SourceIp = Column(String(50), index=True, nullable=False)
    DestinationIp = Column(String(50), index=True, nullable=False)
    Title = Column(String(255), nullable=False)
    Description = Column(Text, nullable=False)
    Mitigation = Column(Text, nullable=True)
    Status = Column(String(50), default="OPEN") # OPEN, CONTAINED, DISMISSED
    DetectedAt = Column(DateTime, default=datetime.utcnow)
    ResolvedAt = Column(DateTime, nullable=True)


class NdrRulePolicy(Base):
    """Behavioral detection thresholds and automated traffic mitigation rules"""
    __tablename__ = "NdrRulePolicies"
    Id = Column(Integer, primary_key=True, index=True)
    RuleId = Column(String(100), unique=True, index=True, nullable=False) # e.g. RULE-NDR-C2-001
    Name = Column(String(200), nullable=False)
    RuleType = Column(String(100), nullable=False) # BEACON_DETECTION, DNS_TUNNEL_THRESHOLD, SWEEP_RATE, LATERAL_SMB
    Threshold = Column(String(100), default="Jitter < 5%, Periodicity > 0.85")
    EnforceAction = Column(String(50), default="BLOCK_IP") # BLOCK_IP, KILL_SESSION, SINKHOLE, ALERT
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Wave 1.11: Monitorix Platform Self-Protection & Tamper Defense
# ---------------------------------------------------------------------------

class PlatformTamperEvent(Base):
    """Real-time platform and agent tampering, process injection, and integrity violations"""
    __tablename__ = "PlatformTamperEvents"
    Id = Column(Integer, primary_key=True, index=True)
    EventId = Column(String(100), unique=True, index=True, nullable=False) # e.g. TMP-EVT-001
    ComponentType = Column(String(50), nullable=False) # AGENT, API_GATEWAY, DATABASE, KAFKA, REDIS, MINIO_STORAGE, QDRANT_VECTOR, SOAR_ENGINE
    TargetIdentifier = Column(String(255), nullable=False) # e.g. srv-prod-agent-01, postgres:5432/ledger
    TamperType = Column(String(100), nullable=False) # SERVICE_TERMINATION_ATTEMPT, PROCESS_INJECTION, DLL_HIJACK, FILE_INTEGRITY_VIOLATION, UNHOOKING_ATTEMPT, DATABASE_HASH_CHAIN_MISMATCH, REDIS_CACHE_POISONING, RULE_SIGNATURE_TAMPER, KAFKA_TOPIC_ALTERATION
    Severity = Column(String(50), default="CRITICAL") # CRITICAL, HIGH, MEDIUM, LOW
    MitreTechnique = Column(String(50), default="T1562.001") # T1562.001, T1055, T1014, T1574
    SourceProcessOrIp = Column(String(255), nullable=True) # e.g. kill -9 (PID 8941), 10.0.4.12
    Description = Column(Text, nullable=False)
    ActionTaken = Column(String(100), default="BLOCKED_AND_LOCKED") # BLOCKED_AND_LOCKED, PROCESS_TERMINATED, INTEGRITY_RESTORED, ALERT_DISPATCHED
    Status = Column(String(50), default="DETECTED") # DETECTED, CONTAINED, INVESTIGATING, RESOLVED
    DetectedAt = Column(DateTime, default=datetime.utcnow, index=True)


class PlatformIntegrityNode(Base):
    """Attested platform components, agent self-defense posture, and subsystem hashes"""
    __tablename__ = "PlatformIntegrityNodes"
    Id = Column(Integer, primary_key=True, index=True)
    NodeId = Column(String(100), unique=True, index=True, nullable=False) # e.g. NODE-CORE-API, NODE-AGENT-FLT-WIN
    ComponentName = Column(String(100), nullable=False)
    Subsystem = Column(String(50), nullable=False) # AGENT_FLEET, CONTROL_PLANE, DATA_PLANE, STORAGE_LAYER, DETECTION_ENGINE
    Status = Column(String(50), default="VERIFIED_SECURE") # VERIFIED_SECURE, TAMPER_WARNING, COMPROMISED, LOCKDOWN
    IntegrityScore = Column(Float, default=100.0) # 0.0 to 100.0
    ExpectedHash = Column(String(128), nullable=False)
    CurrentHash = Column(String(128), nullable=False)
    SelfProtectionLevel = Column(String(50), default="HARDENED_ENFORCING") # HARDENED_ENFORCING, MONITOR_ONLY, KERNEL_LOCK
    LastAttestedAt = Column(DateTime, default=datetime.utcnow)


class PlatformTamperPolicy(Base):
    """Enforcement rules and auto-lockdown policies protecting Monitorix components"""
    __tablename__ = "PlatformTamperPolicies"
    Id = Column(Integer, primary_key=True, index=True)
    PolicyId = Column(String(100), unique=True, index=True, nullable=False) # e.g. POL-TAMPER-001
    Name = Column(String(200), nullable=False)
    ProtectionScope = Column(String(100), nullable=False) # AGENT_TERMINATION_GUARD, PROCESS_INJECTION_DEFENSE, DB_HASH_CHAIN_INTEGRITY, RULE_SIGNATURE_VERIFICATION, REDIS_CACHE_VALIDATION
    EnforcementMode = Column(String(50), default="ACTIVE_BLOCK") # ACTIVE_BLOCK, ALERT_ONLY, EMERGENCY_LOCKDOWN
    AutoLockdownThreshold = Column(Integer, default=3)
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class PlatformCryptographicProof(Base):
    """Merkle proofs and cryptographic hash chain verification ledgers"""
    __tablename__ = "PlatformCryptographicProofs"
    Id = Column(Integer, primary_key=True, index=True)
    ProofId = Column(String(100), unique=True, index=True, nullable=False) # e.g. PROOF-HASHCHAIN-001
    LedgerType = Column(String(50), nullable=False) # DATABASE_STATE_LEDGER, AGENT_BINARY_ATTESTATION, DETECTION_RULE_PACK, KAFKA_LOG_STREAM
    MerkleRoot = Column(String(128), nullable=False)
    PreviousProofHash = Column(String(128), nullable=False)
    VerifiedStatus = Column(String(50), default="CRYPTOGRAPHICALLY_VALID") # CRYPTOGRAPHICALLY_VALID, ANOMALY_DETECTED, REVOKED
    Timestamp = Column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# Wave 1.12: Advanced Malware Analysis & Detonation Sandbox
# ---------------------------------------------------------------------------

class MalwareSample(Base):
    """Static binary telemetry, hash signatures, and threat classification"""
    __tablename__ = "MalwareSamples"
    Id = Column(Integer, primary_key=True, index=True)
    SampleId = Column(String(100), unique=True, index=True, nullable=False) # e.g. MAL-SAMP-001
    Filename = Column(String(255), nullable=False)
    Sha256 = Column(String(64), index=True, nullable=False)
    Md5 = Column(String(32), nullable=True)
    Sha1 = Column(String(40), nullable=True)
    FileSize = Column(Integer, default=0)
    FileType = Column(String(50), default="PE32") # PE32, PE64, ELF64, MACHO, SCRIPT, PDF, DOCX
    Imphash = Column(String(64), nullable=True)
    Entropy = Column(Float, default=0.0)
    IsPacked = Column(Boolean, default=False)
    PackerType = Column(String(100), nullable=True) # UPX, Themida, VMProtect, None
    Verdict = Column(String(50), default="ANALYZING") # MALICIOUS, SUSPICIOUS, BENIGN, ANALYZING
    ThreatScore = Column(Float, default=0.0) # 0.0 to 100.0
    ThreatFamily = Column(String(100), default="Unknown") # Ransomware.LockBit, Trojan.CobaltStrike, Infostealer.RedLine
    SubmissionSource = Column(String(100), default="ANALYST_PORTAL") # ANALYST_PORTAL, EDR_AGENT_SUBMISSION, EMAIL_GATEWAY, API
    SubmittingAgentId = Column(String(100), nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)


class MalwareDetonationRun(Base):
    """Dynamic behavioral detonation traces, process spawn trees, and network beacons"""
    __tablename__ = "MalwareDetonationRuns"
    Id = Column(Integer, primary_key=True, index=True)
    RunId = Column(String(100), unique=True, index=True, nullable=False) # e.g. DET-RUN-001
    SampleId = Column(String(100), index=True, nullable=False)
    Environment = Column(String(100), default="Windows 11 x64 (Isolated MicroVM)")
    DetonationDurationSec = Column(Float, default=45.0)
    Status = Column(String(50), default="COMPLETED") # COMPLETED, RUNNING, FAILED, TIMED_OUT
    ProcessTreeJson = Column(Text, default="[]")
    FileMutationsJson = Column(Text, default="[]")
    RegistryMutationsJson = Column(Text, default="[]")
    NetworkBeaconsJson = Column(Text, default="[]")
    MemoryInjectionsJson = Column(Text, default="[]")
    MitreTacticsJson = Column(Text, default="[]")
    YaraMatchesJson = Column(Text, default="[]")
    DetonatedAt = Column(DateTime, default=datetime.utcnow)


class MalwareThreatRule(Base):
    """Detection heuristics, YARA rulesets, and behavioral signatures"""
    __tablename__ = "MalwareThreatRules"
    Id = Column(Integer, primary_key=True, index=True)
    RuleId = Column(String(100), unique=True, index=True, nullable=False) # e.g. RULE-MAL-001
    Name = Column(String(200), nullable=False)
    RuleType = Column(String(100), default="YARA") # YARA, HEURISTIC, BEHAVIORAL_SIGNATURE
    Category = Column(String(100), default="Ransomware") # Ransomware, Infostealer, Rootkit, C2_Beacon
    Severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    PatternOrExpression = Column(Text, nullable=False)
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class MalwareQuarantineAction(Base):
    """Automated fleet quarantine, hash ban, and containment records"""
    __tablename__ = "MalwareQuarantineActions"
    Id = Column(Integer, primary_key=True, index=True)
    ActionId = Column(String(100), unique=True, index=True, nullable=False) # e.g. QRN-ACT-001
    SampleId = Column(String(100), index=True, nullable=False)
    Sha256 = Column(String(64), index=True, nullable=False)
    FleetAction = Column(String(100), default="FLEET_HASH_BLOCK") # FLEET_HASH_BLOCK, HOST_ISOLATION, PROCESS_KILL, SAMPLE_DELETED
    AffectedAgentsCount = Column(Integer, default=0)
    EnforcedAt = Column(DateTime, default=datetime.utcnow)
    EnforcedBy = Column(String(100), default="SOC_AUTONOMOUS_POLICY")


# ---------------------------------------------------------------------------
# Wave 1.13: Attack-Path Validation & Automated Breach Emulation
# ---------------------------------------------------------------------------

class AttackValidationScenario(Base):
    """End-to-end multi-stage adversary attack path emulation blueprints"""
    __tablename__ = "AttackValidationScenarios"
    Id = Column(Integer, primary_key=True, index=True)
    ScenarioId = Column(String(100), unique=True, index=True, nullable=False) # e.g. VAL-SCEN-001
    Name = Column(String(200), nullable=False)
    Category = Column(String(100), default="Ransomware Blast") # Ransomware, Identity Kill-Chain, Cloud Crown Jewel, Supply-Chain Compromise, Container Escape
    Severity = Column(String(50), default="CRITICAL") # CRITICAL, HIGH, MEDIUM
    Description = Column(Text, nullable=False)
    MitreTacticsJson = Column(Text, default="[]")
    TotalStages = Column(Integer, default=5)
    TargetScope = Column(String(100), default="HYBRID_ENTERPRISE") # HYBRID_ENTERPRISE, ENDPOINT_FLEET, MULTI_CLOUD, K8S_CLUSTER
    RecommendedPlaybook = Column(String(100), default="SOAR-AUTO-ISOLATE-001")
    IsEnabled = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class AttackValidationExecution(Base):
    """Live validation runs measuring MTTD, MTTC, correlation completeness, and defense efficacy"""
    __tablename__ = "AttackValidationExecutions"
    Id = Column(Integer, primary_key=True, index=True)
    ExecutionId = Column(String(100), unique=True, index=True, nullable=False) # e.g. VAL-EXEC-001
    ScenarioId = Column(String(100), index=True, nullable=False)
    TargetAgentOrAsset = Column(String(255), nullable=False) # e.g. ELSEA-DESKTOP, AWS:Account-98124, K8s:prod-cluster-1
    Status = Column(String(50), default="COMPLETED") # COMPLETED, RUNNING, CONTAINED, FAILED
    DefenseEfficacyScore = Column(Float, default=100.0) # 0.0 to 100.0
    MeanTimeToDetectMs = Column(Integer, default=85) # Milliseconds
    MeanTimeToContainMs = Column(Integer, default=240) # Milliseconds
    StagesCompleted = Column(Integer, default=5)
    TotalStages = Column(Integer, default=5)
    TelemetryStreamsVerified = Column(Text, default="[]")
    ContainmentActionTaken = Column(String(200), default="HOST_ISOLATION_AND_PROCESS_TERMINATION")
    ForensicProofHash = Column(String(128), nullable=False) # Cryptographic SHA-256 seal
    StageExecutionLogJson = Column(Text, default="[]")
    StartedAt = Column(DateTime, default=datetime.utcnow)
    CompletedAt = Column(DateTime, default=datetime.utcnow)


class AttackValidationStageLog(Base):
    """Granular stage-by-stage telemetry, detection rules triggered, and containment events"""
    __tablename__ = "AttackValidationStageLogs"
    Id = Column(Integer, primary_key=True, index=True)
    LogId = Column(String(100), unique=True, index=True, nullable=False) # e.g. VAL-LOG-001
    ExecutionId = Column(String(100), index=True, nullable=False)
    StageIndex = Column(Integer, default=1)
    StageName = Column(String(200), nullable=False)
    Tactic = Column(String(100), default="Initial Access")
    Technique = Column(String(100), default="T1566.001")
    TelemetryObserved = Column(Text, nullable=False)
    DetectionRuleTriggered = Column(String(200), nullable=False)
    CorrelationStatus = Column(String(50), default="CORRELATED") # CORRELATED, ISOLATED, UNMATCHED
    ContainmentTriggered = Column(Boolean, default=True)
    Timestamp = Column(DateTime, default=datetime.utcnow)


class AttackValidationPostureCert(Base):
    """Cryptographically signed enterprise breach defense posture certification"""
    __tablename__ = "AttackValidationPostureCerts"
    Id = Column(Integer, primary_key=True, index=True)
    CertId = Column(String(100), unique=True, index=True, nullable=False) # e.g. CERT-POSTURE-20261023
    TenantId = Column(Integer, default=1)
    PostureGrade = Column(String(10), default="A+") # A+, A, B, C, F
    ValidationScore = Column(Float, default=98.6)
    TotalScenariosTested = Column(Integer, default=6)
    PreventedKillChains = Column(Integer, default=6)
    CryptographicAttestation = Column(String(128), nullable=False)
    IssuedAt = Column(DateTime, default=datetime.utcnow)
    ExpiresAt = Column(DateTime, default=datetime.utcnow)


# ============================================================================
# [v4.2.0] PHASE 19: COMMERCIAL LIFECYCLE, RESELLER & DEPLOYMENT ARCHITECTURE
# ============================================================================

class Partner(Base):
    """[v4.2.0] Reseller, Distributor, or MSSP Commercial Partner"""
    __tablename__ = "Partners"
    Id = Column(Integer, primary_key=True, index=True)
    PartnerCode = Column(String(50), unique=True, index=True, nullable=False) # e.g. PRT-ABC-SEC
    PartnerName = Column(String(150), nullable=False) # e.g. ABC Security Partners
    PartnerType = Column(String(50), default="Reseller") # Reseller, Distributor, MSSP, OEM
    ContactEmail = Column(String(150), nullable=False)
    ContactPhone = Column(String(50), nullable=True)
    Country = Column(String(100), default="US")
    CommissionRatePercent = Column(Float, default=20.0) # Standard 20% reseller commission
    Status = Column(String(50), default="ACTIVE") # ACTIVE, PENDING, SUSPENDED, TERMINATED
    MetadataJson = Column(Text, default="{}")
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Customer(Base):
    """[v4.2.0] Commercial Customer Organization linked to Tenant and Partner"""
    __tablename__ = "Customers"
    Id = Column(Integer, primary_key=True, index=True)
    CustomerCode = Column(String(50), unique=True, index=True, nullable=False) # e.g. CUST-ACME-CORP
    CustomerName = Column(String(200), nullable=False) # e.g. Acme Corporation
    PartnerId = Column(Integer, ForeignKey("Partners.Id"), nullable=True, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=True, index=True)
    PrimaryContactEmail = Column(String(150), nullable=False)
    Industry = Column(String(100), default="Technology")
    DeploymentModel = Column(String(50), default="OnPremises") # Cloud, OnPremises, Hybrid
    Status = Column(String(50), default="ACTIVE") # LEAD, TRIAL, ACTIVE, EXPIRING, CHURNED
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ProductCatalog(Base):
    """[v4.2.0] Commercial Cybersecurity Product Catalog"""
    __tablename__ = "ProductCatalogs"
    Id = Column(Integer, primary_key=True, index=True)
    ProductCode = Column(String(50), unique=True, index=True, nullable=False) # MTX-ENTERPRISE-XDR
    ProductName = Column(String(150), nullable=False) # Monitorix Enterprise XDR
    Category = Column(String(100), default="XDR")
    Description = Column(Text, nullable=True)
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class ProductPlan(Base):
    """[v4.2.0] Quantifiable Product Plans & Entitlement Definitions"""
    __tablename__ = "ProductPlans"
    Id = Column(Integer, primary_key=True, index=True)
    PlanCode = Column(String(50), unique=True, index=True, nullable=False) # XDR-500, XDR-1000, etc.
    PlanName = Column(String(150), nullable=False) # Monitorix Enterprise XDR (500 Endpoints)
    Edition = Column(String(50), default="Enterprise XDR")
    EndpointLimit = Column(Integer, default=500)
    ServerLimit = Column(Integer, default=50)
    VmLimit = Column(Integer, default=100)
    CloudAccountLimit = Column(Integer, default=20)
    UserLimit = Column(Integer, default=50)
    DatabaseLimit = Column(Integer, default=10)
    KubernetesLimit = Column(Integer, default=5)
    NetworkSensorLimit = Column(Integer, default=10)
    StorageLimitGB = Column(Integer, default=5000)
    EventsPerSecondLimit = Column(Integer, default=15000)
    EnabledFeaturesJson = Column(Text, default="{}")
    AnnualPriceUsd = Column(Float, default=48000.0)
    MonthlyPriceUsd = Column(Float, default=4500.0)
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)


class CommercialQuote(Base):
    """[v4.2.0] Partner / Customer Commercial Quotes"""
    __tablename__ = "CommercialQuotes"
    Id = Column(Integer, primary_key=True, index=True)
    QuoteNumber = Column(String(50), unique=True, index=True, nullable=False) # QUO-2026-XXXX
    PartnerId = Column(Integer, ForeignKey("Partners.Id"), nullable=True, index=True)
    CustomerId = Column(Integer, ForeignKey("Customers.Id"), nullable=False, index=True)
    PlanCode = Column(String(50), nullable=False)
    BillingCycle = Column(String(20), default="annual") # annual, monthly
    GrossAmountUsd = Column(Float, nullable=False)
    DiscountPercent = Column(Float, default=0.0)
    NetAmountUsd = Column(Float, nullable=False)
    ValidUntil = Column(DateTime, nullable=False)
    Status = Column(String(50), default="DRAFT") # DRAFT, SENT, ACCEPTED, REJECTED, EXPIRED
    Notes = Column(Text, nullable=True)
    CreatedBy = Column(String(100), default="partner_admin")
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CommercialOrder(Base):
    """[v4.2.0] Formal Purchase Orders & Provisioning Trigger"""
    __tablename__ = "CommercialOrders"
    Id = Column(Integer, primary_key=True, index=True)
    OrderNumber = Column(String(50), unique=True, index=True, nullable=False) # ORD-2026-XXXX
    QuoteId = Column(Integer, ForeignKey("CommercialQuotes.Id"), nullable=True, index=True)
    CustomerId = Column(Integer, ForeignKey("Customers.Id"), nullable=False, index=True)
    PartnerId = Column(Integer, ForeignKey("Partners.Id"), nullable=True, index=True)
    PlanCode = Column(String(50), nullable=False)
    TotalAmountUsd = Column(Float, nullable=False)
    Status = Column(String(50), default="PENDING") # PENDING, PROCESSING, COMPLETED, CANCELLED
    PaymentStatus = Column(String(50), default="PAYMENT_PENDING") # PAYMENT_PENDING, PAYMENT_PROCESSING, PAYMENT_SUCCESS, PAYMENT_FAILED, REFUNDED
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CommercialPayment(Base):
    """[v4.2.0] Payment Transactions & Auditing"""
    __tablename__ = "CommercialPayments"
    Id = Column(Integer, primary_key=True, index=True)
    TransactionId = Column(String(100), unique=True, index=True, nullable=False) # TXN-2026-XXXX
    OrderId = Column(Integer, ForeignKey("CommercialOrders.Id"), nullable=False, index=True)
    CustomerId = Column(Integer, ForeignKey("Customers.Id"), nullable=False, index=True)
    AmountUsd = Column(Float, nullable=False)
    PaymentMethod = Column(String(50), default="WireTransfer") # CreditCard, WireTransfer, ACH, PartnerCredit
    Status = Column(String(50), default="PAYMENT_PENDING") # PAYMENT_PENDING, PAYMENT_PROCESSING, PAYMENT_SUCCESS, PAYMENT_FAILED, REFUNDED
    ReceiptUrl = Column(String(255), nullable=True)
    ProcessedAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)


class PartnerCommissionRecord(Base):
    """[v4.2.0] Reseller Commission Tracking & Payouts"""
    __tablename__ = "PartnerCommissionRecords"
    Id = Column(Integer, primary_key=True, index=True)
    PartnerId = Column(Integer, ForeignKey("Partners.Id"), nullable=False, index=True)
    OrderId = Column(Integer, ForeignKey("CommercialOrders.Id"), nullable=False, index=True)
    CustomerId = Column(Integer, ForeignKey("Customers.Id"), nullable=False, index=True)
    GrossAmountUsd = Column(Float, nullable=False)
    DiscountAmountUsd = Column(Float, default=0.0)
    TaxAmountUsd = Column(Float, default=0.0)
    NetAmountUsd = Column(Float, nullable=False)
    CommissionRatePercent = Column(Float, default=20.0)
    CommissionAmountUsd = Column(Float, nullable=False)
    PayoutStatus = Column(String(50), default="PENDING") # PENDING, APPROVED, PAYABLE, PAID, REVERSED
    PaidAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)


class CustomerDeployment(Base):
    """[v4.2.0] On-Premises & Hybrid Customer Deployment Registry & Live Health"""
    __tablename__ = "CustomerDeployments"
    Id = Column(Integer, primary_key=True, index=True)
    DeploymentId = Column(String(100), unique=True, index=True, nullable=False) # dep-mtx-xxxx
    CustomerId = Column(Integer, ForeignKey("Customers.Id"), nullable=False, index=True)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=False, index=True)
    Environment = Column(String(50), default="Production") # Production, Staging, DR, AirGapped
    DeploymentType = Column(String(50), default="OnPremises") # OnPremises, Cloud, Hybrid
    Version = Column(String(50), default="v4.2.0")
    ServerIdentity = Column(String(255), nullable=True)
    CertificateIdentity = Column(String(255), nullable=True)
    LicenseId = Column(String(100), nullable=True, index=True)
    LicenseStatus = Column(String(50), default="ACTIVE") # ACTIVE, EXPIRING, GRACE_PERIOD, RESTRICTED, SUSPENDED, EXPIRED, REVOKED
    ControlPlaneConnection = Column(String(50), default="CONNECTED") # CONNECTED, OFFLINE, DEGRADED
    LocalHealth = Column(String(50), default="HEALTHY") # HEALTHY, WARNING, CRITICAL
    LastHealth = Column(String(50), default="HEALTHY") # Synced alias for health state
    AgentGatewayHealth = Column(String(50), default="HEALTHY")
    LocalEntitlementHealth = Column(String(50), default="HEALTHY")
    ActiveAgentCount = Column(Integer, default=0)
    AgentLimit = Column(Integer, default=500)
    SubscriptionId = Column(String(100), nullable=True, index=True)
    Region = Column(String(50), default="default")
    EnabledModules = Column(Text, nullable=True) # JSON array or comma-separated modules
    Status = Column(String(50), default="ACTIVE") # ACTIVE, SUSPENDED, DECOMMISSIONED
    LastVersion = Column(String(50), nullable=True)
    ServerCount = Column(Integer, default=0)
    CloudAccountCount = Column(Integer, default=0)
    DatabaseCount = Column(Integer, default=0)
    KubernetesClusterCount = Column(Integer, default=0)
    SecurityEventsDaily = Column(Integer, default=0)
    StorageUsageGB = Column(Float, default=0.0)
    CpuUsagePercent = Column(Float, default=12.5)
    MemoryUsagePercent = Column(Float, default=34.2)
    LastHeartbeatAt = Column(DateTime, default=datetime.utcnow, index=True)
    LastCloudSyncAt = Column(DateTime, default=datetime.utcnow)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DeploymentPackage(Base):
    """[v4.3.0] Customer Distribution Release Packages (Self-Contained On-Premise Bundles)"""
    __tablename__ = "DeploymentPackages"
    Id = Column(Integer, primary_key=True, index=True)
    PackageId = Column(String(100), unique=True, index=True, nullable=False) # PKG-DEP-XXXX
    DeploymentId = Column(String(100), ForeignKey("CustomerDeployments.DeploymentId"), nullable=False, index=True)
    CustomerId = Column(Integer, ForeignKey("Customers.Id"), nullable=False, index=True)
    Version = Column(String(50), default="19.1.0")
    DeploymentType = Column(String(50), default="ON_PREMISE") # ON_PREMISE, PRIVATE_CLOUD, AIR_GAPPED
    PackageFileName = Column(String(255), nullable=False) # monitorix-enterprise-19.1.0-dep-xxx.tar.gz
    PackagePath = Column(String(500), nullable=False)
    FileSizeBytes = Column(BigInteger, default=0)
    Sha256Checksum = Column(String(64), nullable=False)
    SignatureHex = Column(Text, nullable=False) # Ed25519 signature of checksum
    Status = Column(String(50), default="READY") # BUILDING, READY, FAILED, REVOKED
    DownloadUrl = Column(String(255), nullable=True)
    ExpiresAt = Column(DateTime, nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)


class SoftwareRelease(Base):
    """[v4.3.0] Official Enterprise Software Releases & Release Manifests"""
    __tablename__ = "SoftwareReleases"
    Id = Column(Integer, primary_key=True, index=True)
    ReleaseVersion = Column(String(50), unique=True, index=True, nullable=False) # e.g. 19.1.0
    Channel = Column(String(50), default="LTS") # LTS, STABLE, SECURITY_PATCH
    GitCommitSha = Column(String(64), nullable=True)
    ReleaseNotes = Column(Text, nullable=True)
    MinUpgradeVersion = Column(String(50), default="18.0.0")
    ManifestJson = Column(Text, default="{}")
    IsAirGappedSupported = Column(Boolean, default=True)
    IsActive = Column(Boolean, default=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)


class UpdatePackage(Base):
    """[v4.3.0] Differential Update Bundles for Online and Air-Gapped Cluster Upgrades"""
    __tablename__ = "UpdatePackages"
    Id = Column(Integer, primary_key=True, index=True)
    UpdateId = Column(String(100), unique=True, index=True, nullable=False) # UPD-19.1.1
    ReleaseVersion = Column(String(50), nullable=False, index=True)
    TargetChannel = Column(String(50), default="LTS")
    PackageFileName = Column(String(255), nullable=False) # monitorix-update-19.1.1.tar.gz
    PackagePath = Column(String(500), nullable=False)
    Sha256Checksum = Column(String(64), nullable=False)
    SignatureHex = Column(Text, nullable=False)
    FileSizeBytes = Column(BigInteger, default=0)
    Status = Column(String(50), default="ACTIVE") # ACTIVE, DEPRECATED
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)


class UpdateHistory(Base):
    """[v4.3.0] Cluster Upgrade Audit Trail & Rollback Tracking"""
    __tablename__ = "UpdateHistories"
    Id = Column(Integer, primary_key=True, index=True)
    DeploymentId = Column(String(100), nullable=False, index=True)
    FromVersion = Column(String(50), nullable=False)
    ToVersion = Column(String(50), nullable=False)
    PreUpdateBackupPath = Column(String(500), nullable=True)
    Status = Column(String(50), default="STARTED") # STARTED, MIGRATING, SUCCESS, FAILED, ROLLED_BACK
    ErrorMessage = Column(Text, nullable=True)
    StartedAt = Column(DateTime, default=datetime.utcnow)
    CompletedAt = Column(DateTime, nullable=True)


class AgentEnrollmentToken(Base):
    """[v4.3.0] Ephemeral, Expiring, and Revokable Agent Enrollment Tokens"""
    __tablename__ = "AgentEnrollmentTokens"
    Id = Column(Integer, primary_key=True, index=True)
    Token = Column(String(128), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, ForeignKey("Tenants.Id"), nullable=False, index=True)
    DeploymentId = Column(String(100), nullable=True, index=True)
    CreatedBy = Column(String(100), default="system")
    MaxUses = Column(Integer, default=1) # 1 = single-use, >1 = batch enrollment
    UsesCount = Column(Integer, default=0)
    ExpiresAt = Column(DateTime, nullable=False, index=True)
    IsRevoked = Column(Boolean, default=False)
    RevokedReason = Column(String(255), nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)


# ============================================================================
# [v4.4.0] GLOBAL COMPLIANCE & REGULATORY GOVERNANCE PERSISTENCE MODELS
# ============================================================================

class ComplianceAssessmentRecord(Base):
    """Persistent tenant-scoped compliance assessment snapshot per framework."""
    __tablename__ = "ComplianceAssessmentRecords"
    Id = Column(Integer, primary_key=True, index=True)
    AssessmentId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=False, default=1)
    FrameworkId = Column(String(64), index=True, nullable=False)
    FrameworkName = Column(String(255), nullable=False)
    FrameworkVersion = Column(String(100), nullable=True)
    Jurisdiction = Column(String(100), nullable=True)
    Score = Column(Float, default=0.0)
    Status = Column(String(64), default="MANUAL_REVIEW_REQUIRED")
    TotalControls = Column(Integer, default=0)
    ApplicableControls = Column(Integer, default=0)
    PassedControls = Column(Integer, default=0)
    PartialControls = Column(Integer, default=0)
    FailedControls = Column(Integer, default=0)
    ManualReviewControls = Column(Integer, default=0)
    NotApplicableControls = Column(Integer, default=0)
    ResultsJson = Column(Text, default="[]")
    EvaluatedBy = Column(String(100), default="system")
    EvaluatedAt = Column(DateTime, default=datetime.utcnow, index=True)


class ComplianceFindingRecord(Base):
    """Persistent compliance control gap / finding record."""
    __tablename__ = "ComplianceFindingRecords"
    Id = Column(Integer, primary_key=True, index=True)
    FindingId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=False, default=1)
    FrameworkId = Column(String(64), index=True, nullable=False)
    ControlId = Column(String(100), index=True, nullable=False)
    Title = Column(String(255), nullable=False)
    Description = Column(Text, nullable=False)
    Severity = Column(String(32), default="HIGH", index=True)
    Category = Column(String(64), default="SECURITY")
    AffectedAsset = Column(String(255), nullable=True)
    Department = Column(String(100), nullable=True)
    Status = Column(String(50), default="OPEN", index=True)
    RemediationJson = Column(Text, default="{}")
    DetectedAt = Column(DateTime, default=datetime.utcnow, index=True)
    ResolvedAt = Column(DateTime, nullable=True)


class ComplianceEvidenceRecord(Base):
    """Cryptographically hashed, immutable compliance evidence artifact."""
    __tablename__ = "ComplianceEvidenceRecords"
    Id = Column(Integer, primary_key=True, index=True)
    EvidenceId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=False, default=1)
    FrameworkId = Column(String(64), index=True, nullable=False)
    ControlId = Column(String(100), index=True, nullable=False)
    ArtifactType = Column(String(64), nullable=False)
    SourceModule = Column(String(100), nullable=False)
    Summary = Column(Text, nullable=False)
    RawPayloadSummaryJson = Column(Text, default="{}")
    Sha256Hash = Column(String(64), nullable=False, index=True)
    RetentionDays = Column(Integer, default=2555)
    CollectedAt = Column(DateTime, default=datetime.utcnow, index=True)


class ComplianceScanJobRecord(Base):
    """Asynchronous compliance assessment job tracking."""
    __tablename__ = "ComplianceScanJobRecords"
    Id = Column(Integer, primary_key=True, index=True)
    JobId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=False, default=1)
    FrameworkIdsJson = Column(Text, default="[]")
    Status = Column(String(32), default="PENDING", index=True)
    ProgressPct = Column(Float, default=0.0)
    SummaryJson = Column(Text, default="{}")
    TriggeredBy = Column(String(100), default="system")
    ErrorMessage = Column(Text, nullable=True)
    StartedAt = Column(DateTime, default=datetime.utcnow, index=True)
    CompletedAt = Column(DateTime, nullable=True)


class PrivacyRequestRecord(Base):
    """Persistent Data Subject / Principal Privacy Request (DSR) workflow record."""
    __tablename__ = "PrivacyRequestRecords"
    Id = Column(Integer, primary_key=True, index=True)
    RequestId = Column(String(100), unique=True, index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=False, default=1)
    FrameworkId = Column(String(64), index=True, nullable=False)
    Jurisdiction = Column(String(64), nullable=False)
    RightType = Column(String(64), nullable=False, index=True)
    SubjectIdentifierHash = Column(String(128), nullable=False)
    Status = Column(String(50), default="PENDING_VERIFICATION", index=True)
    VerificationMethod = Column(String(100), default="CRYPTOGRAPHIC_TOKEN")
    Notes = Column(Text, nullable=True)
    AuditTrailJson = Column(Text, default="[]")
    SubmittedAt = Column(DateTime, default=datetime.utcnow, index=True)
    DueAt = Column(DateTime, nullable=False)
    CompletedAt = Column(DateTime, nullable=True)


class TenantPrivacyPreferenceRecord(Base):
    """Tenant-level privacy governance, CCPA/CPRA preferences, and applicability config."""
    __tablename__ = "TenantPrivacyPreferenceRecords"
    Id = Column(Integer, primary_key=True, index=True)
    TenantId = Column(Integer, unique=True, index=True, nullable=False)
    DoNotSellShare = Column(Boolean, default=True)
    LimitSensitivePersonalInfo = Column(Boolean, default=True)
    GlobalPrivacyControlHonored = Column(Boolean, default=True)
    DefaultRetentionDays = Column(Integer, default=90)
    PreferredResidencyRegion = Column(String(64), default="eu-central-1")
    ApplicableJurisdictionsJson = Column(Text, default="[]")
    ApplicableIndustriesJson = Column(Text, default="[]")
    CiiOperatorDesignated = Column(Boolean, default=False)
    NistBaseline = Column(String(32), default="MODERATE")
    UpdatedBy = Column(String(100), default="system")
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DslDataAssetClassificationRecord(Base):
    """Configurable China Data Security Law (DSL) 3-tier asset classification registry."""
    __tablename__ = "DslDataAssetClassificationRecords"
    Id = Column(Integer, primary_key=True, index=True)
    AssetCode = Column(String(100), index=True, nullable=False)
    TenantId = Column(Integer, index=True, nullable=False, default=1)
    AssetName = Column(String(255), nullable=False)
    DslCategory = Column(String(50), default="GENERAL_DATA", index=True) # GENERAL_DATA, IMPORTANT_DATA, CORE_DATA
    Owner = Column(String(150), default="Data Governance Office")
    Department = Column(String(100), default="Security Operations")
    BusinessPurpose = Column(Text, nullable=True)
    RiskLevel = Column(String(50), default="MEDIUM")
    CrossBorderAllowed = Column(Boolean, default=False)
    EvidenceRef = Column(String(255), nullable=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================================================
# CONTROL PLANE ENTITY ALIASES (Requirement 2)
# ============================================================================
Deployment = CustomerDeployment
Subscription = SaaSPlanSubscription
License = CommercialLicense
Plan = ProductPlan
Product = ProductCatalog
Quote = CommercialQuote
Order = CommercialOrder
SupportCase = SupportTicket
AuditEvent = AuditLog
Release = SoftwareRelease
Update = UpdatePackage
Organization = Tenant




