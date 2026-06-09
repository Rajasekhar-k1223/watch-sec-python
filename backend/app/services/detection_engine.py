import json
import re
from sqlalchemy.orm import Session
from app.db.models import DetectionRule, DetectionAlert

class SigmaEvaluator:
    def __init__(self):
        # Cache of compiled regex rules
        self.rules_cache = []
        
    def load_rules(self, db: Session):
        active_rules = db.query(DetectionRule).filter(DetectionRule.IsActive == True).all()
        self.rules_cache.clear()
        
        for rule in active_rules:
            # Stub: convert Sigma YAML logic into a basic python regex
            # e.g., if ruleContent has 'powershell.exe -enc', compile to regex
            # In a real implementation, we would use a true AST parser
            try:
                # Extract basic patterns from YAML string
                if "selection:" in rule.RuleContent:
                    pattern = r"(?i)powershell.*-enc" # Mock pattern extraction
                    self.rules_cache.append({
                        "id": rule.Id,
                        "pattern": re.compile(pattern),
                        "tactic": rule.MitreTactic,
                        "technique": rule.MitreTechnique
                    })
            except Exception as e:
                pass

    def evaluate_telemetry(self, db: Session, telemetry_payload: dict, agent_id: str):
        """
        Evaluate an incoming telemetry event (ActivityLog/Process Create) against loaded rules.
        """
        if not self.rules_cache:
            self.load_rules(db)
            
        # Example payload: {"process_name": "powershell.exe", "cmdline": "-enc JABz..."}
        process_name = telemetry_payload.get("process_name", "")
        cmdline = telemetry_payload.get("cmdline", "")
        search_target = f"{process_name} {cmdline}"
        
        alerts_generated = []
        
        for rule in self.rules_cache:
            if rule["pattern"].search(search_target):
                # Trigger!
                alert = DetectionAlert(
                    AgentId=agent_id,
                    RuleId=rule["id"],
                    TelemetryId=telemetry_payload.get("log_id", 0),
                    MatchedContent=search_target
                )
                db.add(alert)
                alerts_generated.append(alert)
                
                # In Layer 2, we would also push a risk increment to the DeviceRiskProfile here
                
        if alerts_generated:
            db.commit()
            
        return alerts_generated

detection_engine = SigmaEvaluator()
