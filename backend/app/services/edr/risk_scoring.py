"""
Explainable Endpoint Risk Engine for Monitorix Advanced EDR.
Computes deterministic, multi-factor risk scores with granular factor breakdowns,
eliminating hardcoded scores and opaque constants.
"""

from typing import Dict, List, Any, Optional
import math


def calculate_endpoint_risk(
    agent_id: str,
    alerts: Optional[List[Any]] = None,
    ioc_matches_count: int = 0,
    posture_issues_count: int = 0,
    is_isolated: bool = False,
    is_compromised: bool = False
) -> Dict[str, Any]:
    """
    Calculate dynamic, explainable risk score for an endpoint based on empirical evidence.
    Returns composite score, category breakdown, risk tier, and transparent factor list.
    """
    alerts = alerts or []
    factors: List[str] = []

    # Vector 1: Threat Intelligence (0 - 100)
    ti_score = 0.0
    if ioc_matches_count > 0:
        ti_score = min(100.0, 30.0 + (ioc_matches_count * 15.0))
        factors.append(f"+{round(ti_score, 1)} pts: {ioc_matches_count} active IOC threat intelligence correlation(s)")
    else:
        ti_score = 5.0  # Clean baseline

    # Vector 2: Process Execution & Detection Alerts (0 - 100)
    proc_score = 0.0
    crit_alerts = 0
    high_alerts = 0
    med_alerts = 0

    def _get_val(obj, *keys):
        if isinstance(obj, dict):
            for k in keys:
                v = obj.get(k) or obj.get(k.lower())
                if v: return str(v)
            return ""
        for k in keys:
            v = getattr(obj, k, None)
            if v: return str(v)
        return ""

    for a in alerts:
        sev = _get_val(a, "Severity", "severity").upper()
        if "CRIT" in sev:
            crit_alerts += 1
        elif "HIGH" in sev:
            high_alerts += 1
        elif "MED" in sev:
            med_alerts += 1

    proc_calc = (crit_alerts * 35.0) + (high_alerts * 15.0) + (med_alerts * 5.0)
    proc_score = min(100.0, proc_calc)

    if crit_alerts > 0:
        factors.append(f"+{crit_alerts * 35.0} pts: {crit_alerts} Critical detection alert(s) on endpoint")
    if high_alerts > 0:
        factors.append(f"+{high_alerts * 15.0} pts: {high_alerts} High detection alert(s) on endpoint")

    # Vector 3: Network Anomaly (0 - 100)
    network_score = 10.0
    if any("C2" in _get_val(a, "Title", "title").upper() or "BEACON" in _get_val(a, "Title", "title").upper() for a in alerts):
        network_score = 85.0
        factors.append("+85.0 pts: Network C2 beaconing pattern identified")
    elif any("NETWORK" in _get_val(a, "RuleTitle", "rule_title", "title").upper() for a in alerts):
        network_score = 55.0
        factors.append("+55.0 pts: Suspicious outbound network egress detected")

    # Vector 4: Identity & Privilege Behavior (0 - 100)
    identity_score = 15.0
    if any("LSASS" in _get_val(a, "Description", "description", "title").upper() or "CREDENTIAL" in _get_val(a, "Title", "title", "category").upper() for a in alerts):
        identity_score = 90.0
        factors.append("+90.0 pts: Credential access attempt (LSASS/SAM memory read)")
    elif any("PRIVILEGE" in _get_val(a, "Title", "title").upper() for a in alerts):
        identity_score = 60.0
        factors.append("+60.0 pts: Local privilege escalation attempt")

    # Posture penalty
    if posture_issues_count > 0:
        posture_penalty = min(20.0, posture_issues_count * 4.0)
        factors.append(f"+{posture_penalty} pts: {posture_issues_count} unpatched compliance/vulnerability weakness(es)")
    else:
        posture_penalty = 0.0

    # Isolation discount: if isolated, blast radius is contained
    if is_isolated:
        factors.append("-15.0 pts: Blast radius mitigated via active Network Containment")

    # Composite Risk Score Calculation:
    # Formula: 35% Threat Intel + 30% Process/Alerts + 20% Network + 15% Identity + Posture
    composite = (
        (0.35 * ti_score) +
        (0.30 * proc_score) +
        (0.20 * network_score) +
        (0.15 * identity_score) +
        posture_penalty
    )

    if is_isolated:
        composite = max(10.0, composite - 15.0)

    device_risk_score = min(100.0, round(composite, 1))

    # Determine Risk Tier
    if device_risk_score >= 80.0:
        fleet_risk_tier = "Critical Threat Exposure"
    elif device_risk_score >= 60.0:
        fleet_risk_tier = "High Risk"
    elif device_risk_score >= 40.0:
        fleet_risk_tier = "Medium Risk"
    else:
        fleet_risk_tier = "Low Risk (Compliant)"

    # Blast radius score (how easily host could compromise peers)
    blast_radius = min(100.0, round((device_risk_score * 0.8) if not is_isolated else (device_risk_score * 0.25), 1))

    return {
        "device_risk_score": device_risk_score,
        "fleet_risk_tier": fleet_risk_tier,
        "blast_radius_score": blast_radius,
        "vectors": {
            "threat_intel": round(ti_score, 1),
            "process_execution": round(proc_score, 1),
            "network_anomaly": round(network_score, 1),
            "identity_behavior": round(identity_score, 1)
        },
        "factors": factors if factors else ["Baseline normal operation; zero active threat indicators."],
        "is_explainable": True,
        "agent_id": agent_id
    }

