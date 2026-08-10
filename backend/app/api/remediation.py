import hashlib
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional

from ..db.session import get_db
from ..db.models import Agent, User, Tenant, EventLog
from .deps import get_current_user as get_current_active_user
from ..socket_instance import sio
from datetime import datetime
import json
import hmac

router = APIRouter()

async def dispatch_lockdown(agent: Agent, tenant: Tenant, unlock_key: str, db: AsyncSession, actor: str):
    """Internal helper to sign and dispatch a lockdown command to an agent."""
    
    # 1. Generate Unlock Hash (SHA256)
    unlock_hash = hashlib.sha256(unlock_key.encode()).hexdigest()
    
    # 2. Construct Payload
    action = "SOVEREIGN_LOCKDOWN"
    params = {"unlock_hash": unlock_hash}
    timestamp = datetime.utcnow().isoformat()
    
    # 3. Sign the Command
    msg_parts = [
        str(action),
        json.dumps(params, sort_keys=True),
        str(timestamp)
    ]
    message = "|".join(msg_parts).encode('utf-8')
    
    # Derive Key (ApiKey + MachineId)
    machine_id = agent.MachineId or agent.AgentId
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    payload = {
        "action": action,
        "params": params,
        "timestamp": timestamp,
        "signature": signature,
        "policy_name": "Sovereign Lockdown (Manual)"
    }
    
    # 4. Dispatch via WebSocket
    await sio.emit('Remediation', payload, room=agent.AgentId)
    
    # 5. Log the forensic event
    log = EventLog(
        AgentId=agent.AgentId,
        Type="SOVEREIGN_LOCKDOWN",
        Details=f"System locked by {actor}. Requires sovereign unlock key.",
        Timestamp=datetime.utcnow()
    )
    db.add(log)

@router.post("/lock-agent/{agent_id}")
async def lock_single_agent(
    agent_id: str,
    unlock_key: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Tenant Action: Locks a single agent with a sovereign key."""
    # Verify Agent
    res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
    agent = res_a.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Access denied")
        
    # Get Tenant Key
    res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
    tenant = res_t.scalars().first()
    
    await dispatch_lockdown(agent, tenant, unlock_key, db, current_user.Username)
    await db.commit()
    
    return {"status": "dispatched", "agentId": agent_id}

@router.post("/lock-multiple")
async def lock_multiple_agents(
    payload: dict, # { "agent_ids": [...], "unlock_key": "...", "reason": "..." }
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """[v2.6.0] Bulk Action: Locks a specific set of agents across the fleet."""
    agent_ids = payload.get("agent_ids", [])
    unlock_key = payload.get("unlock_key")
    reason = payload.get("reason", "No reason provided")
    
    if not unlock_key or not agent_ids:
        raise HTTPException(status_code=400, detail="Agent IDs and Unlock Key are required")
        
    affected = 0
    for agent_id in agent_ids:
        res_a = await db.execute(select(Agent).where(Agent.AgentId == agent_id))
        agent = res_a.scalars().first()
        if not agent: continue
        
        if current_user.Role != "SuperAdmin" and agent.TenantId != current_user.TenantId:
            continue
            
        res_t = await db.execute(select(Tenant).where(Tenant.Id == agent.TenantId))
        tenant = res_t.scalars().first()
        
        # Log Audit per agent or per batch? Per batch is better for performance.
        await dispatch_lockdown(agent, tenant, unlock_key, db, f"BATCH:{current_user.Username}")
        affected += 1
    
    # Global Audit Log for the batch
    if affected > 0:
        new_event = EventLog(
            AgentId="BULK",
            TenantId=current_user.TenantId if current_user.Role != "SuperAdmin" else 0,
            EventType="SOVEREIGN_GOVERNANCE",
            Severity="CRITICAL",
            Description=f"BULK LOCKDOWN: {affected} nodes neutralized by {current_user.Username}. Reason: {reason}",
            Timestamp=datetime.utcnow()
        )
        db.add(new_event)
        
    await db.commit()
    return {"status": "bulk_dispatched", "nodesAffected": affected}

@router.post("/lock-tenant/{tenant_id}")
async def lock_entire_tenant(
    tenant_id: int,
    payload: dict, # { "unlock_key": "...", "reason": "..." }
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """[v2.6.0] SuperAdmin Action: Locks all agents belonging to a tenant."""
    if current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="SuperAdmin authority required")
        
    # Get Tenant
    res_t = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = res_t.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    unlock_key = payload.get("unlock_key")
    if not unlock_key:
        raise HTTPException(status_code=400, detail="Unlock key is required")

    # Get All Agents
    res_a = await db.execute(select(Agent).where(Agent.TenantId == tenant_id))
    agents = res_a.scalars().all()
    
    # Set Persistent Tenant-Wide Lock
    tenant.IsLocked = True
    tenant.UnlockKeyHash = hashlib.sha256(unlock_key.encode()).hexdigest()
    
    # [v2.6.8] Sovereign Governance Audit
    reason = payload.get("reason", "No reason provided")
    tenant.LockdownReason = reason # Store for Dashboard Banner
    
    new_event = EventLog(
        AgentId="GLOBAL",
        TenantId=tenant_id,
        EventType="SOVEREIGN_GOVERNANCE",
        Severity="CRITICAL",
        Description=f"TENANT-WIDE LOCKDOWN: {tenant.Name} neutralized by {current_user.Username}. Reason: {reason}",
        Timestamp=datetime.utcnow()
    )
    db.add(new_event)
    
    for agent in agents:
        await dispatch_lockdown(agent, tenant, unlock_key, db, f"SUPERADMIN:{current_user.Username}")
        
    await db.commit()
    
    return {"status": "bulk_dispatched", "nodesAffected": len(agents), "tenant": tenant.Name}

async def dispatch_unlock(agent: Agent, tenant: Tenant, db: AsyncSession, actor: str):
    """[v2.6.5] Signs and dispatches an immediate unlock command."""
    action = "SOVEREIGN_UNLOCK"
    params = {}
    timestamp = datetime.utcnow().isoformat()
    
    # Sign the Command (SHA256(ApiKey + MachineId))
    machine_id = agent.MachineId or agent.AgentId
    key = hashlib.sha256(tenant.ApiKey.encode() + machine_id.encode()).digest()
    msg_parts = [str(action), json.dumps(params, sort_keys=True), str(timestamp)]
    message = "|".join(msg_parts).encode('utf-8')
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    
    payload = {
        "action": action,
        "params": params,
        "timestamp": timestamp,
        "signature": signature,
        "policy_name": f"Sovereign Release (By {actor})"
    }
    
    # Emit real-time remediation event
    await sio.emit("Remediation", payload, room=f"agent_{agent.AgentId}")
    return True

@router.post("/unlock-tenant/{tenant_id}")
async def unlock_entire_tenant(
    tenant_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """[v2.6.0] SuperAdmin Action: Releases a tenant-wide lock."""
    if current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="SuperAdmin authority required")
        
    res_t = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = res_t.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    tenant.IsLocked = False
    tenant.UnlockKeyHash = None
    tenant.LockdownReason = None
    
    # [v2.6.5] Instant Governance Broadcast
    # We must sign the unlock for each agent
    res_a = await db.execute(select(Agent).where(Agent.TenantId == tenant_id))
    agents = res_a.scalars().all()
    
    for agent in agents:
        await dispatch_unlock(agent, tenant, db, f"SUPERADMIN:{current_user.Username}")
    
    await db.commit()
    return {"status": "unlocked", "nodesAffected": len(agents), "tenant": tenant.Name}
