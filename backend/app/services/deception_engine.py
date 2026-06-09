from sqlalchemy.orm import Session
from app.db.models import DeceptionCampaign, HoneyToken, DeceptionAlert
import random
import string

class DeceptionEngine:
    
    def get_tokens_for_agent(self, db: Session, agent_id: str):
        """
        Called when an agent registers. The engine calculates which
        honey tokens should be deployed to this specific agent.
        """
        active_campaigns = db.query(DeceptionCampaign).filter(DeceptionCampaign.IsActive == True).all()
        tokens = []
        
        for camp in active_campaigns:
            # Check if token already deployed
            existing = db.query(HoneyToken).filter(
                HoneyToken.CampaignId == camp.Id,
                HoneyToken.AgentId == agent_id
            ).first()
            
            if existing:
                tokens.append({
                    "id": existing.Id,
                    "type": camp.Type,
                    "path": existing.TokenPath,
                    "payload": camp.PayloadTemplate
                })
            else:
                # Generate new token
                random_suffix = ''.join(random.choices(string.digits, k=4))
                if camp.Type == "File":
                    path = f"C:\\Users\\Public\\Documents\\financial_Q3_{random_suffix}.xlsx"
                elif camp.Type == "Credential":
                    path = f"svc_backup_{random_suffix}"
                else:
                    path = f"\\\\WIN-DC-01\\HiddenShare_{random_suffix}"
                    
                new_token = HoneyToken(
                    CampaignId=camp.Id,
                    AgentId=agent_id,
                    TokenPath=path
                )
                db.add(new_token)
                db.commit()
                
                tokens.append({
                    "id": new_token.Id,
                    "type": camp.Type,
                    "path": path,
                    "payload": camp.PayloadTemplate
                })
                
        return tokens

    def process_trigger(self, db: Session, payload: dict):
        """
        When an agent detects interaction with a Honey Token, it hits this engine.
        This generates a high-fidelity alert (zero false positives).
        """
        agent_id = payload.get("agent_id")
        token_path = payload.get("token_path")
        process_id = payload.get("process_id")
        action = payload.get("action")
        
        # Verify the token exists for this agent
        token = db.query(HoneyToken).filter(
            HoneyToken.AgentId == agent_id,
            HoneyToken.TokenPath == token_path
        ).first()
        
        if not token:
            return False, "Unrecognized token"
            
        # Log the Deception Alert
        alert = DeceptionAlert(
            TokenId=token.Id,
            AgentId=agent_id,
            ProcessId=process_id,
            Action=action
        )
        db.add(alert)
        db.commit()
        
        # In a full integration, we would emit to the Zero Trust Engine here
        # to immediately escalate the host's RiskScore to Critical.
        print(f"[DECEPTION ENGINE] HIGH FIDELITY ALERT! Agent {agent_id} interacted with Honey Token {token_path} via PID {process_id}")
        
        return True, alert.Id

deception_engine = DeceptionEngine()
