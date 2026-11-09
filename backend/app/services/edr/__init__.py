"""
Monitorix Advanced EDR Service Package.
Provides dynamic process lineage, explainable risk scoring, and containment orchestration.
"""

from .process_tree import ProcessTreeBuilder, ProcessNode
from .risk_scoring import calculate_endpoint_risk

__all__ = ["ProcessTreeBuilder", "ProcessNode", "calculate_endpoint_risk"]

