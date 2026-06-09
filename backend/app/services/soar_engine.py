import json
import datetime
from sqlalchemy.orm import Session
from app.db.models import SoarPlaybook, SoarActionExecution, SoarApprovalQueue

class SoarEngine:
    
    def trigger_playbook(self, db: Session, playbook_id: int, target_agent_id: str):
        """
        Manually or automatically trigger a playbook against a target agent.
        """
        playbook = db.query(SoarPlaybook).filter(SoarPlaybook.Id == playbook_id).first()
        if not playbook:
            return False, "Playbook not found."
            
        actions = json.loads(playbook.ActionsJson)
        execution_records = []
        
        for action_def in actions:
            action_type = action_def.get("action")
            
            # Create execution audit record
            execution = SoarActionExecution(
                PlaybookId=playbook.Id,
                TargetAgentId=target_agent_id,
                ActionType=action_type,
                Status="Pending",
                ExecutedBy="System"
            )
            db.add(execution)
            db.commit() # Commit to get ID
            
            if playbook.RequiresApproval:
                # Add to approval queue and halt
                approval = SoarApprovalQueue(ExecutionId=execution.Id)
                db.add(approval)
            else:
                # Execute immediately
                self._execute_action(db, execution)
                
            execution_records.append(execution)
            
        db.commit()
        return True, "Playbook triggered successfully."
        
    def _execute_action(self, db: Session, execution: SoarActionExecution):
        """
        Internal method to execute the specific SOAR action.
        """
        execution.Status = "Executing"
        db.commit()
        
        # Stub: Push command to Socket.IO.
        # In a real implementation:
        # socket_manager.emit_to_agent(execution.TargetAgentId, "soar_command", {"action": execution.ActionType})
        print(f"[SOAR MOCK] Sending {execution.ActionType} to Agent {execution.TargetAgentId}")
        
        # Mark as success (in reality, we wait for an agent ACK)
        execution.Status = "Success"
        db.commit()

    def approve_action(self, db: Session, approval_id: int, admin_id: str):
        """
        Approve a pending action in the queue.
        """
        approval = db.query(SoarApprovalQueue).filter(SoarApprovalQueue.Id == approval_id).first()
        if not approval or approval.Status != "Pending":
            return False, "Invalid or already resolved approval."
            
        approval.Status = "Approved"
        approval.ApproverId = admin_id
        approval.ResolvedAt = datetime.datetime.utcnow()
        
        execution = db.query(SoarActionExecution).filter(SoarActionExecution.Id == approval.ExecutionId).first()
        if execution:
            execution.ExecutedBy = admin_id
            self._execute_action(db, execution)
            
        db.commit()
        return True, "Action approved and executed."

soar_engine = SoarEngine()
