from fastapi import APIRouter, Depends, HTTPException # type: ignore
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from ..db.session import get_db # type: ignore
from .deps import get_current_user # type: ignore
from ..db.models import User # type: ignore
from ...services.agentless_engine import agentless_engine

router = APIRouter()

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
    if os_type.lower() not in ["linux", "windows"]:
        raise HTTPException(status_code=400, detail="Unsupported OS type.")
        
    data = await agentless_engine.remediate_threat(target_ip, os_type, action, target)
    return data
