# Feature Matrix Definition
# 1=Starter, 2=Pro, 3=Enterprise
import os # type: ignore
from typing import Optional

# Feature Matrix Definition
# 1=Starter, 2=Pro, 3=Enterprise

# [v1.7.0] UX & Reliability Hardening
# The exact version string to match. When agents check in, if they report a lower version
LATEST_AGENT_VERSION = "v4.2.5"

FEATURE_TIERS = {
    "ActivityMonitorEnabled": 1,
    "ScreenshotsEnabled": 1,
    "BrowserEnforcerEnabled": 1,
    "KeyloggerEnabled": 2,
    "ClipboardMonitorEnabled": 2,
    "AppBlockerEnabled": 2,
    "PrinterMonitorEnabled": 2,
    "LocationTrackingEnabled": 2,
    "UsbBlockingEnabled": 2,
    "ShadowMonitorEnabled": 3,
    "LiveStreamEnabled": 3,
    "RemoteShellEnabled": 3,
    "MailMonitorEnabled": 3,
    "NetworkMonitoringEnabled": 3,
    "FileDlpEnabled": 3,
    "SpeechMonitorEnabled": 3,
    "VulnerabilityIntelligenceEnabled": 3,
    "RedRainbowEnabled": 3
}

PLAN_LEVELS = {
    "Starter": 1,
    "Professional": 2,
    "Pro": 2, # Alias for backward compatibility
    "Enterprise": 3,
    "Unlimited": 100,
    "Sovereign": 100,
    "MDR-Premier": 3,
    "ENTERPRISE_SOC": 3,
    "Enterprise XDR": 3,
}

def resolve_plan_level(plan: Optional[str]) -> int:
    if not plan:
        return 1
    if plan in PLAN_LEVELS:
        return PLAN_LEVELS[plan]
    p_lower = plan.lower()
    for k, v in PLAN_LEVELS.items():
        if k.lower() == p_lower:
            return v
    if "sovereign" in p_lower or "unlimited" in p_lower:
        return 100
    if "enterprise" in p_lower or "mdr" in p_lower or "premier" in p_lower or "xdr" in p_lower or "soc" in p_lower:
        return 3
    if "pro" in p_lower:
        return 2
    return 1
