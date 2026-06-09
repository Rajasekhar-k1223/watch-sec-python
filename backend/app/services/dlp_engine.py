import re
import json
from sqlalchemy.orm import Session
from app.db.models import DlpRule, DlpPolicy, DlpPolicyRuleLink, DlpViolation

class DlpEngine:
    def __init__(self):
        self.rules_cache = {} # Map rule Id -> compiled regex
        self.policies_cache = []

    def load_policies(self, db: Session):
        """Loads active DLP rules and policies into fast memory cache."""
        rules = db.query(DlpRule).filter(DlpRule.IsActive == True).all()
        self.rules_cache.clear()
        
        for r in rules:
            try:
                self.rules_cache[r.Id] = re.compile(r.Pattern)
            except Exception:
                pass
                
        self.policies_cache = db.query(DlpPolicy).filter(DlpPolicy.IsActive == True).all()

    def obfuscate_match(self, match_str: str, category: str) -> str:
        """Masks sensitive data before writing to database."""
        if category == "PII" and len(match_str) > 4:
            # Mask middle characters
            return match_str[:2] + ("*" * (len(match_str) - 4)) + match_str[-2:]
        elif category == "Secrets":
            return "[REDACTED SECRET]"
        return "****"

    def evaluate_payload(self, db: Session, agent_id: str, channel: str, text_payload: str):
        """
        Scans a text payload (e.g. from Clipboard) against active rules and policies.
        Returns the strictest enforcement action to take (e.g., Block).
        """
        if not self.rules_cache:
            self.load_policies(db)
            
        action_to_take = "Allow"
        violations_logged = []
        
        # Determine which policies apply to this channel
        applicable_policies = []
        for policy in self.policies_cache:
            channels = json.loads(policy.TargetChannelsJson)
            if channel in channels:
                applicable_policies.append(policy)
                
        if not applicable_policies:
            return action_to_take, violations_logged
            
        # Get rules for these policies
        for policy in applicable_policies:
            links = db.query(DlpPolicyRuleLink).filter(DlpPolicyRuleLink.PolicyId == policy.Id).all()
            rule_ids = [link.RuleId for link in links]
            
            for rid in rule_ids:
                if rid in self.rules_cache:
                    pattern = self.rules_cache[rid]
                    matches = pattern.findall(text_payload)
                    
                    if matches:
                        # Found a violation
                        rule_meta = db.query(DlpRule).filter(DlpRule.Id == rid).first()
                        
                        # Upgrade strictness if necessary
                        if policy.Action == "Block":
                            action_to_take = "Block"
                        elif policy.Action == "Alert" and action_to_take != "Block":
                            action_to_take = "Alert"
                            
                        # Obfuscate first match for the audit log
                        sample = str(matches[0])
                        obfuscated = self.obfuscate_match(sample, rule_meta.Category)
                        
                        violation = DlpViolation(
                            AgentId=agent_id,
                            PolicyId=policy.Id,
                            RuleId=rid,
                            Channel=channel,
                            MatchedContentObfuscated=obfuscated,
                            ActionTaken=policy.Action
                        )
                        db.add(violation)
                        violations_logged.append(violation)
                        
        if violations_logged:
            db.commit()
            
        return action_to_take, [v.Id for v in violations_logged]

dlp_engine = DlpEngine()
