import json
import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.db.models import SoarPlaybook, SoarActionExecution, SoarApprovalQueue

class SoarEngine:

    async def trigger_playbook(self, db: AsyncSession, playbook_id: int, target_agent_id: str, action_params: dict = None):
        playbook = (await db.execute(select(SoarPlaybook).where(SoarPlaybook.Id == playbook_id))).scalars().first()
        if not playbook:
            return False, "Playbook not found."

        actions = json.loads(playbook.ActionsJson)
        execution_records = []

        for action_def in actions:
            action_type = action_def.get("action")

            execution = SoarActionExecution(
                PlaybookId=playbook.Id,
                TargetAgentId=target_agent_id,
                ActionType=action_type,
                Status="Pending",
                ExecutedBy="System"
            )
            db.add(execution)
            await db.commit()

            if playbook.RequiresApproval:
                approval = SoarApprovalQueue(ExecutionId=execution.Id)
                db.add(approval)
            else:
                await self._execute_action(db, execution, action_params)

            execution_records.append(execution)

        await db.commit()
        return True, "Playbook triggered successfully."

    async def _execute_action(self, db: AsyncSession, execution: SoarActionExecution, action_params: dict = None):
        execution.Status = "Executing"
        await db.commit()

        print(f"[SOAR] Executing {execution.ActionType} on Target {execution.TargetAgentId}")
        try:
            from app.db.models import Agent, Tenant, AgentlessEndpoint
            from app.core.security import generate_agent_command_signature
            from app.socket_instance import sio
            from app.services.agentless_engine import agentless_engine
            
            # Check if target is an IP (Agentless)
            is_ip = False
            import re
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", execution.TargetAgentId):
                is_ip = True
                
            if is_ip:
                agentless = (await db.execute(select(AgentlessEndpoint).where(AgentlessEndpoint.IpAddress == execution.TargetAgentId))).scalars().first()
                if agentless:
                    # Universal Execution - Call Agentless Engine directly
                    action_param_value = action_params.get("TargetPID", "malicious_target") if action_params else "malicious_target"
                    res = await agentless_engine.remediate_threat(agentless.IpAddress, agentless.OsType, "kill_process" if "kill" in execution.ActionType.lower() else "delete_file", action_param_value)
                    if res.get("status") == "remediated":
                        execution.Status = "Success"
                    else:
                        execution.Status = f"Failed: {res.get('error', 'Agentless Error')}"
                else:
                    execution.Status = "Failed: Agentless Endpoint Not Found"
            else:
                agent = (await db.execute(select(Agent).where(Agent.AgentId == execution.TargetAgentId))).scalars().first()
                if agent:
                    tenant = (await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))).scalars().first()
                    if tenant:
                        timestamp = datetime.datetime.utcnow().isoformat()
                        full_params = {"Action": execution.ActionType}
                        if action_params:
                            full_params.update(action_params)
                        
                        signature = generate_agent_command_signature(
                            api_key=tenant.ApiKey, 
                            machine_id=agent.MachineId or "",
                            action="Remediation", 
                            params=full_params, 
                            timestamp=timestamp
                        )

                        payload = full_params.copy()
                        payload["timestamp"] = timestamp
                        payload["signature"] = signature

                        await sio.emit('Remediation', payload, room=agent.AgentId)
                        execution.Status = "Success"
                    else:
                        execution.Status = "Failed: Tenant Not Found"
                else:
                    execution.Status = "Failed: Agent Not Found"
        except Exception as e:
            print(f"[SOAR] Error executing action: {e}")
            execution.Status = f"Failed: {str(e)}"

        await db.commit()

    async def approve_action(self, db: AsyncSession, approval_id: int, admin_id: str):
        approval = (await db.execute(select(SoarApprovalQueue).where(SoarApprovalQueue.Id == approval_id))).scalars().first()
        if not approval or approval.Status != "Pending":
            return False, "Invalid or already resolved approval."

        approval.Status = "Approved"
        approval.ApproverId = admin_id
        approval.ResolvedAt = datetime.datetime.utcnow()

        execution = (await db.execute(select(SoarActionExecution).where(SoarActionExecution.Id == approval.ExecutionId))).scalars().first()
        if execution:
            execution.ExecutedBy = admin_id
            await self._execute_action(db, execution)

        await db.commit()
        return True, "Action approved and executed."

soar_engine = SoarEngine()
