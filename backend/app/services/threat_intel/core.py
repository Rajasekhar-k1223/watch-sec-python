"""
Monitorix Enterprise Threat Intelligence Platform — Core Engine
==============================================================
Provides structured Indicator of Compromise (IOC) management, normalization,
strict validation, duplicate detection, decay/expiry evaluation, Admiralty reliability
classification, and MITRE ATT&CK mapping.
"""

import ipaddress
import re
import urllib.parse
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple


class IndicatorType(str, Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    EMAIL = "Email"
    FILENAME = "FileName"
    NETWORK = "Network"


class ThreatSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ThreatClassification(str, Enum):
    C2 = "C2"
    MALWARE = "Malware"
    RANSOMWARE = "Ransomware"
    PHISHING = "Phishing"
    EXPLOIT = "Exploit"
    BOTNET = "Botnet"
    APT = "APT"
    SCANNER = "Scanner"
    SUSPICIOUS = "Suspicious"
    UNKNOWN = "Unknown"


# Admiralty Code / Source Reliability Rating (NATO standard)
ADMIRALTY_RELIABILITY = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Reliability cannot be judged"
}

ADMIRALTY_CREDIBILITY = {
    "1": "Confirmed by other sources",
    "2": "Probably true",
    "3": "Possibly true",
    "4": "Doubtful",
    "5": "Improbable",
    "6": "Truth cannot be judged"
}

# Compiled regex patterns
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.\s\(\)]+\.[a-zA-Z0-9]{1,10}$")


def normalize_indicator(indicator_type: str, value: str) -> Tuple[str, str]:
    """
    Normalizes an indicator value into its canonical form.
    Returns: (canonical_type, canonical_value)
    Raises: ValueError if the value is structurally invalid for the given type.
    """
    if not value or not isinstance(value, str):
        raise ValueError("Indicator value must be a non-empty string.")

    raw_val = value.strip()
    raw_type = indicator_type.strip()

    # Determine canonical type
    norm_type = None
    for member in IndicatorType:
        if member.value.lower() == raw_type.lower():
            norm_type = member.value
            break
    
    if not norm_type:
        # Auto-detect if type is unknown or general
        norm_type = detect_indicator_type(raw_val)

    # Perform type-specific canonical normalization
    if norm_type == IndicatorType.IPV4.value:
        try:
            # Handle host:port syntax (e.g. 1.2.3.4:8080)
            if ":" in raw_val:
                host, port = raw_val.split(":", 1)
                ip_obj = ipaddress.IPv4Address(host.strip())
                return IndicatorType.IPV4.value, str(ip_obj)
            ip_obj = ipaddress.IPv4Address(raw_val)
            return IndicatorType.IPV4.value, str(ip_obj)
        except ValueError as err:
            raise ValueError(f"Invalid IPv4 address: '{raw_val}' - {err}")

    elif norm_type == IndicatorType.IPV6.value:
        try:
            # Handle [ipv6]:port or raw ipv6
            clean_ip = raw_val.strip("[]")
            if ":" in clean_ip and not clean_ip.startswith("http"):
                # Check for bracketed port
                if "]:" in raw_val:
                    clean_ip = raw_val.split("]:")[0].lstrip("[")
            ip_obj = ipaddress.IPv6Address(clean_ip)
            return IndicatorType.IPV6.value, ip_obj.compressed
        except ValueError as err:
            raise ValueError(f"Invalid IPv6 address: '{raw_val}' - {err}")

    elif norm_type == IndicatorType.NETWORK.value:
        try:
            net_obj = ipaddress.ip_network(raw_val, strict=False)
            return IndicatorType.NETWORK.value, str(net_obj)
        except ValueError as err:
            raise ValueError(f"Invalid network CIDR: '{raw_val}' - {err}")

    elif norm_type in (IndicatorType.DOMAIN.value, IndicatorType.SUBDOMAIN.value):
        clean_domain = raw_val.lower().rstrip(".")
        # Strip protocol if accidentally included
        if clean_domain.startswith("http://") or clean_domain.startswith("https://"):
            parsed = urllib.parse.urlparse(clean_domain)
            clean_domain = parsed.hostname or clean_domain
        # Strip port
        if ":" in clean_domain:
            clean_domain = clean_domain.split(":")[0]

        if not _DOMAIN_RE.match(clean_domain):
            raise ValueError(f"Invalid domain syntax: '{raw_val}'")

        parts = clean_domain.split(".")
        actual_type = IndicatorType.SUBDOMAIN.value if len(parts) > 2 else IndicatorType.DOMAIN.value
        return actual_type, clean_domain

    elif norm_type == IndicatorType.URL.value:
        # Prepend https:// if bare URL scheme missing
        target_url = raw_val
        if not target_url.lower().startswith(("http://", "https://")):
            target_url = "http://" + target_url
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.netloc:
            raise ValueError(f"Invalid URL structure: '{raw_val}'")
        # Canonicalize scheme and netloc to lowercase, strip trailing slash from path if empty
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        canonical_url = urllib.parse.urlunparse((
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.params,
            parsed.query,
            ""  # Strip fragment for IOC matching
        ))
        return IndicatorType.URL.value, canonical_url

    elif norm_type == IndicatorType.MD5.value:
        clean_hash = raw_val.lower()
        if not _MD5_RE.match(clean_hash):
            raise ValueError(f"Invalid MD5 hash (must be 32 hex characters): '{raw_val}'")
        return IndicatorType.MD5.value, clean_hash

    elif norm_type == IndicatorType.SHA1.value:
        clean_hash = raw_val.lower()
        if not _SHA1_RE.match(clean_hash):
            raise ValueError(f"Invalid SHA1 hash (must be 40 hex characters): '{raw_val}'")
        return IndicatorType.SHA1.value, clean_hash

    elif norm_type == IndicatorType.SHA256.value:
        clean_hash = raw_val.lower()
        if not _SHA256_RE.match(clean_hash):
            raise ValueError(f"Invalid SHA256 hash (must be 64 hex characters): '{raw_val}'")
        return IndicatorType.SHA256.value, clean_hash

    elif norm_type == IndicatorType.EMAIL.value:
        clean_email = raw_val.lower()
        if not _EMAIL_RE.match(clean_email):
            raise ValueError(f"Invalid email address: '{raw_val}'")
        return IndicatorType.EMAIL.value, clean_email

    elif norm_type == IndicatorType.FILENAME.value:
        clean_name = raw_val.lower()
        # Strip path prefixes if present
        clean_name = clean_name.replace("\\", "/").split("/")[-1]
        if not clean_name:
            raise ValueError(f"Invalid filename: '{raw_val}'")
        return IndicatorType.FILENAME.value, clean_name

    return norm_type, raw_val


def detect_indicator_type(value: str) -> str:
    """
    Auto-detects the indicator type of an arbitrary raw string.
    """
    v = value.strip()
    if _SHA256_RE.match(v):
        return IndicatorType.SHA256.value
    if _MD5_RE.match(v):
        return IndicatorType.MD5.value
    if _SHA1_RE.match(v):
        return IndicatorType.SHA1.value
    if "/" in v and not v.startswith("http"):
        try:
            ipaddress.ip_network(v, strict=False)
            return IndicatorType.NETWORK.value
        except ValueError:
            pass
    try:
        ipaddress.IPv4Address(v.split(":")[0] if ":" in v and not v.startswith("http") else v)
        return IndicatorType.IPV4.value
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(v.strip("[]").split("]:")[0] if "]:" in v else v.strip("[]"))
        return IndicatorType.IPV6.value
    except ValueError:
        pass
    if v.startswith("http://") or v.startswith("https://"):
        return IndicatorType.URL.value
    if _EMAIL_RE.match(v):
        return IndicatorType.EMAIL.value
    if _DOMAIN_RE.match(v.lower().rstrip(".")):
        parts = v.lower().rstrip(".").split(".")
        return IndicatorType.SUBDOMAIN.value if len(parts) > 2 else IndicatorType.DOMAIN.value
    if _FILENAME_RE.match(v):
        return IndicatorType.FILENAME.value

    return IndicatorType.FILENAME.value


class IocRecord:
    """
    In-memory validated IOC representation.
    """
    __slots__ = (
        "value", "type", "threat_classification", "confidence", "severity",
        "source", "source_reliability", "tenant_id", "first_seen", "last_seen",
        "valid_until", "is_active", "tags", "mitre_technique", "mitre_tactic"
    )

    def __init__(
        self,
        value: str,
        indicator_type: str,
        threat_classification: str = ThreatClassification.UNKNOWN.value,
        confidence: int = 50,
        severity: str = ThreatSeverity.HIGH.value,
        source: str = "Manual",
        source_reliability: str = "B2",
        tenant_id: Optional[int] = None,
        valid_days: int = 30,
        tags: Optional[List[str]] = None,
        mitre_technique: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None
    ):
        canon_type, canon_val = normalize_indicator(indicator_type, value)
        self.value: str = canon_val
        self.type: str = canon_type
        self.threat_classification: str = threat_classification
        self.confidence: int = max(0, min(100, int(confidence)))
        self.severity: str = severity
        self.source: str = source
        self.source_reliability: str = source_reliability
        self.tenant_id: Optional[int] = int(tenant_id) if tenant_id is not None else None
        
        now = datetime.utcnow()
        self.first_seen: datetime = first_seen or now
        self.last_seen: datetime = last_seen or now
        self.valid_until: datetime = now + timedelta(days=valid_days)
        self.is_active: bool = True
        self.tags: Set[str] = set(tags or [])
        self.mitre_technique: Optional[str] = mitre_technique
        self.mitre_tactic: Optional[str] = mitre_tactic

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.valid_until

    def merge_duplicate(self, other: "IocRecord") -> None:
        """
        Merges duplicate indicator observation, preserving authoritative attributes.
        """
        self.last_seen = max(self.last_seen, other.last_seen)
        self.valid_until = max(self.valid_until, other.valid_until)
        # Update confidence to highest observed
        if other.confidence > self.confidence:
            self.confidence = other.confidence
            self.severity = other.severity
        # Union tags
        self.tags.update(other.tags)
        # If new MITRE technique supplied, enrich
        if not self.mitre_technique and other.mitre_technique:
            self.mitre_technique = other.mitre_technique
            self.mitre_tactic = other.mitre_tactic

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type,
            "threat_classification": self.threat_classification,
            "confidence": self.confidence,
            "severity": self.severity,
            "source": self.source,
            "source_reliability": self.source_reliability,
            "tenant_id": self.tenant_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "is_active": self.is_active and not self.is_expired,
            "tags": list(self.tags),
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic
        }

