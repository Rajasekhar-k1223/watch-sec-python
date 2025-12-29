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
    # TrustedDomainsJson = Column(Text, default="[]") 
    # TrustedIPsJson = Column(Text, default="[]")

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
    LastSeen = Column(DateTime, default=datetime.utcnow)
    Hostname = Column(String(255), default="Unknown")
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
