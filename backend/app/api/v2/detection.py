from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from app.db.session import get_db
from app.db.models import DetectionRule, DetectionAlert, User, AuditLog, Agent
from app.services.detection_engine import detection_engine
from app.api.deps import get_current_user, verify_agent_signature
from pydantic import BaseModel

router = APIRouter()

RULE_ADMIN_ROLES = ["SuperAdmin", "Admin", "TenantAdmin"]
ALERT_TRIAGE_ROLES = ["SuperAdmin", "Admin", "TenantAdmin", "Analyst"]
RESERVED_SYSTEM_RULE_IDS = set(range(9001, 9009))

class RuleRequest(BaseModel):
    name: str
    rule_type: str = "Sigma"
    category: str
    mitre_tactic: str
    mitre_technique: str
    severity: str = "High"
    content: str

class TelemetryPayload(BaseModel):
    agent_id: str
    process_name: str
    cmdline: str
    log_id: int = 0

class AlertStatusUpdate(BaseModel):
    status: str

@router.get("/rules")
async def list_rules(tactic: str = None, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    query = select(DetectionRule)
    if current_user.Role != "SuperAdmin" and current_user.TenantId is not None:
        query = query.where(
            (DetectionRule.TenantId == current_user.TenantId) | (DetectionRule.TenantId == None)
        )
    if tactic:
        query = query.where(DetectionRule.MitreTactic == tactic)
    return (await db.execute(query)).scalars().all()

@router.post("/rules")
async def create_rule(request: RuleRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.Role not in RULE_ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Insufficient permissions to create detection rules")
    target_tenant_id = None if current_user.Role == "SuperAdmin" else current_user.TenantId
    rule = DetectionRule(
        TenantId=target_tenant_id,
        Name=request.name,
        Type=request.rule_type,
        Category=request.category,
        MitreTactic=request.mitre_tactic,
        MitreTechnique=request.mitre_technique,
        Severity=request.severity,
        RuleContent=request.content
    )
    db.add(rule)
    
    # Security Audit Log
    audit = AuditLog(
        TenantId=target_tenant_id,
        Actor=current_user.Username or str(current_user.Id),
        Action="DetectionRuleCreated",
        Target=f"Rule '{request.name}'",
        Details=f"Created detection rule '{request.name}' ({request.severity}, Tactic: {request.mitre_tactic})",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()

    await detection_engine.load_rules(db)
    return {"status": "success", "rule_id": rule.Id}

@router.get("/rules/{rule_id}")
async def get_rule_detail(rule_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = (await db.execute(select(DetectionRule).where(DetectionRule.Id == rule_id))).scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    if current_user.Role != "SuperAdmin" and current_user.TenantId is not None:
        if rule.TenantId is not None and rule.TenantId != current_user.TenantId:
            raise HTTPException(status_code=404, detail="Detection rule not found or access denied")
    return rule

@router.put("/rules/{rule_id}")
async def update_rule(rule_id: int, request: RuleRequest, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = (await db.execute(select(DetectionRule).where(DetectionRule.Id == rule_id))).scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    
    # Guard: System rules cannot be updated by tenant users
    if rule.Id in RESERVED_SYSTEM_RULE_IDS or rule.TenantId is None:
        if current_user.Role != "SuperAdmin" or current_user.TenantId is not None:
            audit = AuditLog(
                TenantId=current_user.TenantId,
                Actor=current_user.Username or str(current_user.Id),
                Action="SYSTEM_RULE_MODIFICATION_BLOCKED",
                Target=f"Rule #{rule_id}",
                Details=f"Unauthorized modification attempt on protected system rule #{rule_id} by {current_user.Username} (Role: {current_user.Role})",
                Timestamp=datetime.utcnow()
            )
            db.add(audit)
            await db.commit()
            raise HTTPException(status_code=403, detail="System rules are managed globally and cannot be modified by tenant users")
    else:
        if current_user.Role not in RULE_ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Insufficient permissions to modify detection rules")
        if current_user.Role != "SuperAdmin" and rule.TenantId != current_user.TenantId:
            raise HTTPException(status_code=404, detail="Detection rule not found or access denied")

    rule.Name = request.name
    rule.Type = request.rule_type
    rule.Category = request.category
    rule.MitreTactic = request.mitre_tactic
    rule.MitreTechnique = request.mitre_technique
    rule.Severity = request.severity
    rule.RuleContent = request.content
    
    audit = AuditLog(
        TenantId=rule.TenantId,
        Actor=current_user.Username or str(current_user.Id),
        Action="DetectionRuleUpdated",
        Target=f"Rule #{rule.Id}",
        Details=f"Updated detection rule #{rule.Id} ('{rule.Name}')",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    return {"status": "success", "rule_id": rule.Id}

@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    rule = (await db.execute(select(DetectionRule).where(DetectionRule.Id == rule_id))).scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
        
    # Guard: System rules cannot be deleted by tenant users
    if rule.Id in RESERVED_SYSTEM_RULE_IDS or rule.TenantId is None:
        if current_user.Role != "SuperAdmin" or current_user.TenantId is not None:
            audit = AuditLog(
                TenantId=current_user.TenantId,
                Actor=current_user.Username or str(current_user.Id),
                Action="SYSTEM_RULE_DELETION_BLOCKED",
                Target=f"Rule #{rule_id}",
                Details=f"Unauthorized deletion attempt on protected system rule #{rule_id} by {current_user.Username} (Role: {current_user.Role})",
                Timestamp=datetime.utcnow()
            )
            db.add(audit)
            await db.commit()
            raise HTTPException(status_code=403, detail="System rules are managed globally and cannot be deleted by tenant users")
    else:
        if current_user.Role not in RULE_ADMIN_ROLES:
            raise HTTPException(status_code=403, detail="Insufficient permissions to delete detection rules")
        if current_user.Role != "SuperAdmin" and rule.TenantId != current_user.TenantId:
            raise HTTPException(status_code=404, detail="Detection rule not found or access denied")

    await db.delete(rule)
    audit = AuditLog(
        TenantId=rule.TenantId,
        Actor=current_user.Username or str(current_user.Id),
        Action="DetectionRuleDeleted",
        Target=f"Rule #{rule.Id}",
        Details=f"Deleted detection rule #{rule.Id} ('{rule.Name}')",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    return {"status": "success", "deleted_rule_id": rule_id}

@router.get("/alerts")
async def get_alerts(status: str = "New", db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    stmt = (
        select(DetectionAlert, DetectionRule)
        .outerjoin(DetectionRule, DetectionAlert.RuleId == DetectionRule.Id)
    )
    if current_user.Role != "SuperAdmin" and current_user.TenantId is not None:
        stmt = stmt.where(
            (DetectionAlert.TenantId == current_user.TenantId) |
            ((DetectionAlert.TenantId == None) & (DetectionAlert.AgentId.in_(select(Agent.AgentId).where(Agent.TenantId == current_user.TenantId))))
        )
    if status and status != "All":
        stmt = stmt.where(DetectionAlert.Status == status)
    stmt = stmt.order_by(desc(DetectionAlert.Timestamp)).limit(100)
    
    rows = (await db.execute(stmt)).all()
    results = []
    for alert, rule in rows:
        results.append({
            "Id": alert.Id,
            "TenantId": getattr(alert, "TenantId", None),
            "AgentId": alert.AgentId,
            "RuleId": alert.RuleId,
            "MatchedContent": alert.MatchedContent,
            "Status": alert.Status,
            "Timestamp": alert.Timestamp.isoformat() if alert.Timestamp else "",
            "HitCount": getattr(alert, "HitCount", 1) or 1,
            "LastSeenAt": alert.LastSeenAt.isoformat() if getattr(alert, "LastSeenAt", None) else (alert.Timestamp.isoformat() if alert.Timestamp else ""),
            "RuleName": rule.Name if rule else f"Detection Rule #{alert.RuleId}",
            "MitreTactic": rule.MitreTactic if rule else "Defense Evasion",
            "MitreTechnique": rule.MitreTechnique if rule else "T1059",
            "Severity": rule.Severity if rule else "Critical",
            "Category": rule.Category if rule else "Threat Detection"
        })
    return results

@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    stmt = (
        select(DetectionAlert, DetectionRule)
        .outerjoin(DetectionRule, DetectionAlert.RuleId == DetectionRule.Id)
        .where(DetectionAlert.Id == alert_id)
    )
    row = (await db.execute(stmt)).first()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert, rule = row
    if current_user.Role != "SuperAdmin" and current_user.TenantId is not None:
        alert_tenant = getattr(alert, "TenantId", None)
        if alert_tenant is not None:
            if alert_tenant != current_user.TenantId:
                raise HTTPException(status_code=404, detail="Alert not found or access denied")
        else:
            from app.db.models import Agent
            agent = (await db.execute(select(Agent).where(Agent.AgentId == alert.AgentId))).scalars().first()
            if not agent or agent.TenantId != current_user.TenantId:
                raise HTTPException(status_code=404, detail="Alert not found or access denied")
    return {
        "Id": alert.Id,
        "TenantId": getattr(alert, "TenantId", None),
        "AgentId": alert.AgentId,
        "RuleId": alert.RuleId,
        "MatchedContent": alert.MatchedContent,
        "Status": alert.Status,
        "Timestamp": alert.Timestamp.isoformat() if alert.Timestamp else "",
        "HitCount": getattr(alert, "HitCount", 1) or 1,
        "LastSeenAt": alert.LastSeenAt.isoformat() if getattr(alert, "LastSeenAt", None) else (alert.Timestamp.isoformat() if alert.Timestamp else ""),
        "RuleName": rule.Name if rule else f"Detection Rule #{alert.RuleId}",
        "MitreTactic": rule.MitreTactic if rule else "Defense Evasion",
        "MitreTechnique": rule.MitreTechnique if rule else "T1059",
        "Severity": rule.Severity if rule else "Critical",
        "Category": rule.Category if rule else "Threat Detection"
    }

@router.patch("/alerts/{alert_id}")
@router.put("/alerts/{alert_id}")
async def update_alert_status(alert_id: int, request: AlertStatusUpdate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.Role not in ALERT_TRIAGE_ROLES:
        raise HTTPException(status_code=403, detail="Insufficient permissions to modify alert status")
    alert = (await db.execute(select(DetectionAlert).where(DetectionAlert.Id == alert_id))).scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if current_user.Role != "SuperAdmin" and current_user.TenantId is not None:
        alert_tenant = getattr(alert, "TenantId", None)
        if alert_tenant is not None:
            if alert_tenant != current_user.TenantId:
                raise HTTPException(status_code=404, detail="Alert not found or access denied")
        else:
            from app.db.models import Agent
            agent = (await db.execute(select(Agent).where(Agent.AgentId == alert.AgentId))).scalars().first()
            if not agent or agent.TenantId != current_user.TenantId:
                raise HTTPException(status_code=404, detail="Alert not found or access denied")
    prev_status = alert.Status
    alert.Status = request.status
    
    # Security Audit Log
    audit = AuditLog(
        TenantId=current_user.TenantId,
        Actor=current_user.Username or str(current_user.Id),
        Action="DetectionAlertStatusChanged",
        Target=f"Alert #{alert.Id}",
        Details=f"Alert #{alert.Id} status transitioned from '{prev_status}' to '{request.status}'",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    return {"status": "success", "alert_id": alert.Id, "new_status": alert.Status}

@router.get("/mitre-matrix")
async def get_mitre_matrix(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Returns MITRE ATT&CK Matrix coverage with rule counts and alert triggers per tactic."""
    TACTICS = [
        {"id": "TA0043", "name": "Reconnaissance"},
        {"id": "TA0042", "name": "Resource Development"},
        {"id": "TA0001", "name": "Initial Access"},
        {"id": "TA0002", "name": "Execution"},
        {"id": "TA0003", "name": "Persistence"},
        {"id": "TA0004", "name": "Privilege Escalation"},
        {"id": "TA0005", "name": "Defense Evasion"},
        {"id": "TA0006", "name": "Credential Access"},
        {"id": "TA0007", "name": "Discovery"},
        {"id": "TA0008", "name": "Lateral Movement"},
        {"id": "TA0009", "name": "Collection"},
        {"id": "TA0011", "name": "Command and Control"},
        {"id": "TA0010", "name": "Exfiltration"},
        {"id": "TA0040", "name": "Impact"},
    ]

    rules = (await db.execute(select(DetectionRule))).scalars().all()
    alerts = (await db.execute(select(DetectionAlert))).scalars().all()

    # Build lookup of rule id to tactic
    rule_tactic_map = {r.Id: r.MitreTactic for r in rules if r.MitreTactic}

    matrix = []
    total_covered = 0
    for tac in TACTICS:
        tac_rules = [r for r in rules if r.MitreTactic and (tac["name"].lower() in r.MitreTactic.lower() or tac["id"].lower() in r.MitreTactic.lower())]
        tac_rule_ids = {r.Id for r in tac_rules}
        tac_alerts = [a for a in alerts if a.RuleId in tac_rule_ids]

        is_covered = len(tac_rules) > 0
        if is_covered:
            total_covered += 1

        techniques = list({r.MitreTechnique for r in tac_rules if r.MitreTechnique})

        matrix.append({
            "tacticId": tac["id"],
            "tacticName": tac["name"],
            "ruleCount": len(tac_rules),
            "alertCount": len(tac_alerts),
            "isCovered": is_covered,
            "techniques": techniques
        })

    coverage_percent = round((total_covered / len(TACTICS)) * 100, 1)

    return {
        "totalTactics": len(TACTICS),
        "coveredTactics": total_covered,
        "coveragePercent": coverage_percent,
        "matrix": matrix
    }

@router.post("/evaluate")
async def evaluate_payload(payload: TelemetryPayload, db: AsyncSession = Depends(get_db), agent_sig: str = Depends(verify_agent_signature)):
    alerts = await detection_engine.evaluate_telemetry(db, payload.dict(), payload.agent_id)
    return {
        "status": "evaluated",
        "alerts_triggered": len(alerts),
        "alert_ids": [a.Id for a in alerts]
    }

# ---------------------------------------------------------------------------
# [v3.0.0] Feature 52: Golden Detection & Regression Suite
# ---------------------------------------------------------------------------
from app.services.golden_detection_suite import golden_suite

@router.post("/regression/run")
async def run_golden_regression_suite(
    target_agent: str = "GOLDEN-TEST-HOST",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Executes the full Golden Detection & Regression test suite against baseline vectors."""
    result = await golden_suite.run_regression_suite(db=db, target_agent=target_agent)
    return result

@router.get("/regression/test-cases")
async def get_golden_test_cases(
    current_user: User = Depends(get_current_user)
):
    """Returns all cataloged golden test vectors and assertion mappings."""
    return {"test_cases": golden_suite.GOLDEN_TEST_CASES}

# ---------------------------------------------------------------------------
# [v3.0.0] Feature 53: Detection Accuracy & Quality Engine
# ---------------------------------------------------------------------------
@router.get("/quality")
async def get_detection_quality_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Calculates precision, recall, false positive rates, duplicate rates, and latency per detection rule.
    """
    return await golden_suite.get_detection_quality_metrics(db=db)
