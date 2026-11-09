"""
[v2.8.0] Compliance Evidence Collection & Chain of Custody
Produces cryptographically hashed, immutable evidence items respecting tenant isolation.
"""
import hashlib
import json
from typing import Dict, Any, List
from datetime import datetime
from .models import ComplianceEvidence


def create_evidence(
    tenant_id: int,
    framework: str,
    control_id: str,
    source: str,
    collector: str,
    details: Dict[str, Any],
    status: str = "VERIFIED"
) -> ComplianceEvidence:
    """
    Constructs an evidence item with an immutable SHA-256 hash
    anchored to the tenant, framework, control, and state payload.
    """
    ts = datetime.utcnow().isoformat()
    raw_payload = json.dumps(details, sort_keys=True)
    hash_seed = f"{tenant_id}|{framework}|{control_id}|{source}|{ts}|{raw_payload}"
    evidence_hash = hashlib.sha256(hash_seed.encode("utf-8")).hexdigest()

    return ComplianceEvidence(
        tenant_id=tenant_id,
        framework=framework,
        control_id=control_id,
        source=source,
        timestamp=ts,
        evidence_hash=evidence_hash,
        collector=collector,
        details=details,
        status=status
    )
