from fastapi import APIRouter, Depends, HTTPException # type: ignore
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from ...db.session import get_db # type: ignore
from ..deps import get_current_user # type: ignore
from ...db.models import User, AgentlessEndpoint # type: ignore
from sqlalchemy.future import select # type: ignore
from ...services.agentless_engine import agentless_engine

async def verify_tenant_access(target_ip: str, db: AsyncSession, current_user: User):
    if current_user.Role == 'SuperAdmin':
        return
        
    result = await db.execute(select(AgentlessEndpoint).where(AgentlessEndpoint.IpAddress == target_ip))
    endpoint = result.scalars().first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    if endpoint.TenantId != current_user.TenantId:
        raise HTTPException(status_code=403, detail="Tenant Isolation Violation: Access Denied")


from pydantic import BaseModel # type: ignore

router = APIRouter()

@router.get("/endpoints")
async def list_endpoints(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="No Tenant assigned")
        
    query = select(AgentlessEndpoint)
    if current_user.Role != 'SuperAdmin':
        query = query.where(AgentlessEndpoint.TenantId == current_user.TenantId)
        
    res = await db.execute(query)
    endpoints = res.scalars().all()
    
    return [
        {
            "ip": ep.IpAddress,
            "os": ep.OsType,
            "hostname": ep.Hostname or f"Manual-{ep.IpAddress}",
            "status": "Active (Bound)",
            "logs": []
        }
        for ep in endpoints
    ]

class ManualEndpointDto(BaseModel):
    ip: str
    os_type: str
    username: str = "root"
    password: str = ""

@router.post("/manual")
async def add_manual_endpoint(
    dto: ManualEndpointDto,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not current_user.TenantId:
        raise HTTPException(status_code=400, detail="No Tenant assigned")
        
    # Check if already exists
    res = await db.execute(select(AgentlessEndpoint).where(AgentlessEndpoint.IpAddress == dto.ip))
    if res.scalars().first():
        raise HTTPException(status_code=400, detail="Endpoint IP already registered")
        
    new_ep = AgentlessEndpoint(
        TenantId=current_user.TenantId,
        IpAddress=dto.ip,
        OsType=dto.os_type,
        Hostname=f"Manual-{dto.ip}"
    )
    db.add(new_ep)
    await db.commit()
    await db.refresh(new_ep)
    
    # Store credentials in the vault
    if dto.password:
        from ...db.models import AgentlessCredential
        from ...services.credential_vault import credential_vault
        encrypted_pw = credential_vault.encrypt_credential(dto.password)
        new_cred = AgentlessCredential(
            TenantId=current_user.TenantId,
            EndpointId=new_ep.Id,
            AuthType="PASSWORD",
            Username=dto.username,
            EncryptedPassword=encrypted_pw
        )
        db.add(new_cred)
        await db.commit()
    
    return {"status": "success"}

@router.post("/scan")
async def scan_subnet(
    subnet: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.2.0] Active Network Discovery for Agentless Endpoints
    """
    results = await agentless_engine.run_discovery_scan(subnet)
    return {"status": "success", "found_devices": results}

@router.post("/poll/{target_ip}")
async def force_poll_endpoint(
    target_ip: str,
    os_type: str,
    credentials_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.2.0] Forces an immediate polling sequence to a remote machine.
    """
    await verify_tenant_access(target_ip, db, current_user)
    
    if os_type.lower() == "linux":
        data = await agentless_engine.poll_linux_ssh(target_ip, credentials_id)
    elif os_type.lower() == "windows":
        data = await agentless_engine.poll_windows_wmi(target_ip, credentials_id)
    else:
        raise HTTPException(status_code=400, detail="Unsupported OS type for agentless polling.")
        
    return data

@router.post("/enforce/{target_ip}")
async def enforce_policy_on_endpoint(
    target_ip: str,
    os_type: str,
    policy_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.2.0] Forces a policy enforcement on a remote machine.
    """
    await verify_tenant_access(target_ip, db, current_user)
    
    if os_type.lower() not in ["linux", "windows"]:
        raise HTTPException(status_code=400, detail="Unsupported OS type.")
        
    data = await agentless_engine.enforce_policy(target_ip, os_type, policy_data)
    return data

@router.post("/remediate/{target_ip}")
async def remediate_threat_on_endpoint(
    target_ip: str,
    os_type: str,
    action: str,
    target: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.2.0] Automated SOAR Response: Kills processes or deletes files remotely.
    """
    await verify_tenant_access(target_ip, db, current_user)
    
    if os_type.lower() not in ["linux", "windows"]:
        raise HTTPException(status_code=400, detail="Unsupported OS type.")
        
    data = await agentless_engine.remediate_threat(target_ip, os_type, action, target)
    return data
        
@router.post("/sensors/deploy/{target_ip}")
async def deploy_native_sensors(
    target_ip: str,
    os_type: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    [v2.3.0] Remotely bootstraps Sysmon/auditd and configures WEF/rsyslog.
    """
    await verify_tenant_access(target_ip, db, current_user)
    
    if os_type.lower() not in ["linux", "windows"]:
        raise HTTPException(status_code=400, detail="Unsupported OS type.")
        
    # Deploy deep hooks
    if os_type.lower() == "linux":
        await agentless_engine.configure_auditd(target_ip)
    else:
        await agentless_engine.configure_sysmon(target_ip)
        
    # Configure zero data loss event forwarding
    res = await agentless_engine.setup_event_forwarding(target_ip, os_type, receiver_url="monitorix-receiver.local")
    
    return {"status": "success", "deployment": res}
