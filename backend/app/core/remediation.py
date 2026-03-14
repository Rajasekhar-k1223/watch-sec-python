import json # type: ignore
import logging # type: ignore
from sqlalchemy.orm import Session # type: ignore
from ..db.models import Policy # type: ignore
from ..socket_instance import sio_sync # type: ignore

logger = logging.getLogger("RemediationEngine")

def evaluate_remediation(session: Session, tenant_id: int, agent_id: str, trigger_context: dict):
    """
    Evaluates active policies for a tenant and triggers remediation actions if criteria met.
    
    trigger_context format example: 
    {
        "event_type": "DLP_FINDING", 
        "risk_level": "Critical", 
        "category": "PII",
        "process_name": "chrome.exe"
    }
    """
    if not tenant_id:
        return

    try:
        # 1. Fetch Active Policies for Tenant
        policies = session.query(Policy).filter(
            Policy.TenantId == tenant_id,
            Policy.IsActive == True
        ).all()

        for policy in policies:
            try:
                # Basic check for non-empty RemediationJson
                if not policy.RemediationJson or policy.RemediationJson == "[]":
                    continue
                    
                remediation_rules = json.loads(policy.RemediationJson)
                if not isinstance(remediation_rules, list):
                    continue

                for rule in remediation_rules:
                    # rule format: {"if": {"risk_level": "Critical"}, "then": {"action": "KillProcess", "params": {}}}
                    if_logic = rule.get("if", {})
                    then_logic = rule.get("then", {})
                    
                    if not if_logic or not then_logic:
                        continue

                    # Evaluate "IF" conditions (ALL must match)
                    trigger_match = True
                    for key, val in if_logic.items():
                        if trigger_context.get(key) != val:
                            trigger_match = False
                            break
                    
                    if trigger_match:
                        action = then_logic.get("action")
                        params = then_logic.get("params", {})
                        
                        # Special handling: if action is KillProcess and no process name in params,
                        # try to inherit from trigger context
                        if action == "KillProcess" and not params.get("process_name"):
                            params["process_name"] = trigger_context.get("process_name")

                        logger.warning(f"Remediation TRIGGERED for Agent {agent_id}: Policy '{policy.Name}' -> Action: {action}")
                        
                        # 2. Dispatch Action via Socket.IO (Sync manager for Celery/FastAPI)
                        sio_sync.emit('SecurityRemediation', {
                            "action": action,
                            "params": params,
                            "policy_name": policy.Name,
                            "trigger_context": trigger_context
                        }, room=f"agent_{agent_id}")
                        
                        # Also broadcast to tenant room for dashboard feedback
                        sio_sync.emit('RemediationFeedback', {
                            "agent_id": agent_id,
                            "action": action,
                            "status": "Triggered",
                            "policy_name": policy.Name
                        }, room=f"tenant_{tenant_id}")

            except json.JSONDecodeError:
                logger.error(f"Invalid RemediationJson in Policy {policy.Id}")
            except Exception as pe:
                logger.error(f"Error evaluating policy {policy.Id} for remediation: {pe}")

    except Exception as e:
        logger.error(f"Remediation evaluation failed: {e}")
