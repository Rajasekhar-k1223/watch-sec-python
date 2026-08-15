# Feature Matrix Definition
# 1=Starter, 2=Pro, 3=Enterprise
import os # type: ignore

# Feature Matrix Definition
# 1=Starter, 2=Pro, 3=Enterprise

# [v1.7.0] UX & Reliability Hardening
# The exact version string to match. When agents check in, if they report a lower version
# and auto_patch is enabled, they will be given an update package.
LATEST_AGENT_VERSION = "v2.2.10"

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
    "VulnerabilityIntelligenceEnabled": 3
}

PLAN_LEVELS = {
    "Starter": 1,
    "Professional": 2,
    "Pro": 2, # Alias for backward compatibility
    "Enterprise": 3,
    "Unlimited": 100
}
