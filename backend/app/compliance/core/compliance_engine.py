"""
[v2.8.0] Compliance Engine Core Module
Re-exports ComplianceEngine and compliance_engine singleton.
"""
from .engine import ComplianceEngine, compliance_engine

__all__ = ["ComplianceEngine", "compliance_engine"]
