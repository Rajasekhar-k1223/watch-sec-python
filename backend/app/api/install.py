from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional, List
import json

from ..db.session import get_db
from ..db.models import Tenant, User
from ..services.email_service import email_service

router = APIRouter()

class ValidateRequest(BaseModel):
    MachineName: str
    Domain: str
    IP: str
    TenantApiKey: Optional[str] = None

@router.post("/validate")
async def validate_device(req: ValidateRequest, db: AsyncSession = Depends(get_db)):
    print(f"[Install] Validating Device: {req.MachineName} | Domain: {req.Domain} | IP: {req.IP}")

    tenant_name = "Unknown"
    trusted_domains = []
    trusted_ips = []
    tenant = None

    # 1. Resolve Tenant
    if req.TenantApiKey:
        result = await db.execute(select(Tenant).where(Tenant.ApiKey == req.TenantApiKey))
        tenant = result.scalars().first()
        
        if tenant:
            tenant_name = tenant.Name
            try:
                trusted_domains = json.loads(tenant.TrustedDomainsJson)
            except:
                trusted_domains = []
            try:
                trusted_ips = json.loads(tenant.TrustedIPsJson)
            except:
                trusted_ips = []
    
    # 2. Check Match
    # Simple substring check for domains, exact match for IPs
    is_domain_trusted = any(d.upper() in req.Domain.upper() for d in trusted_domains)
    is_ip_trusted = req.IP in trusted_ips

    if is_domain_trusted or is_ip_trusted:
        return {"Status": "Trusted", "Message": f"Device Authorized for {tenant_name} via Policy."}

    # --- UNTRUSTED DEVICE LOGIC ---
    
    # 3. Notify Tenant Admin if known Tenant
    if tenant:
        # Find Tenant Admin
        # Logic: Find User with Role='TenantAdmin' and TenantId=tenant.Id
        user_result = await db.execute(
            select(User).where(User.TenantId == tenant.Id).where(User.Role == "TenantAdmin")
        )
        admin = user_result.scalars().first()
        
        if admin:
             email_target = admin.Username if "@" in admin.Username else f"{admin.Username}@example.com"
             
             # Fire and forget email (async)
             await email_service.send_email(
                 email_target,
                 "Installation Blocked: Authorization Required",
                 f"""
                    <h2>New Device Installation Attempt</h2>
                    <p>A device outside your trusted network attempted to install the agent.</p>
                    <ul>
                        <li><b>Machine:</b> {req.MachineName}</li>
                        <li><b>Domain:</b> {req.Domain}</li>
                        <li><b>IP Address:</b> {req.IP}</li>
                    </ul>
                 """
             )

    return {"Status": "Authorization Required", "Message": "This device is not in the trusted network. Admin has been notified."}
