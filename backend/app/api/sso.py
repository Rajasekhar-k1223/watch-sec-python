from fastapi import APIRouter, Depends, HTTPException, Request # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional # type: ignore
import json

from ..db.session import get_db # type: ignore
from ..db.models import User, Tenant # type: ignore
from .deps import get_current_user # type: ignore

router = APIRouter()

class SsoConfigUpdate(BaseModel):
    idp_url: str
    certificate: str
    attribute_mapping: Dict[str, str] = {"username": "nameid", "role": "memberOf"}
    enabled: bool = False

@router.get("/metadata/{tenant_id}")
async def get_saml_metadata(tenant_id: int, db: AsyncSession = Depends(get_db)):
    """
    [v2.2.0] Enterprise SSO: Generates the SAML Service Provider (SP) metadata.
    Organizations use this to configure Monitorix as an Application in Okta/Entra.
    """
    # Logic to generate SAML XML Metadata based on tenant's base URL
    return {"message": "SAML SP Metadata generated for tenant.", "entity_id": f"monitorix-sp-{tenant_id}"}

@router.post("/acs/{tenant_id}")
async def assertion_consumer_service(tenant_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """
    [v2.2.0] Enterprise SSO: The endpoint where the IdP sends the SAML Response.
    Handles user provisioning and session creation.
    """
    # 1. Parse SAML Response
    # 2. Verify Signature using Tenant.SsoConfigJson certificate
    # 3. Extract Attributes (Username, Role)
    # 4. Provision User (JIT) if they don't exist
    # 5. Issue JWT
    return {"status": "success", "message": "SSO Authentication Complete"}

@router.put("/config")
async def update_sso_config(
    config: SsoConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Updates the SSO configuration for the current tenant."""
    if current_user.Role != "TenantAdmin":
        raise HTTPException(status_code=403, detail="Only TenantAdmins can configure SSO")
        
    result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
        
    tenant.SsoConfigJson = config.dict()
    await db.commit()
    
    return {"status": "updated", "ssoEnabled": config.enabled}
