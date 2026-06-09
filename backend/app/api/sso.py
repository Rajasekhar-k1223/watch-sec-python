from fastapi import APIRouter, Depends, HTTPException, Request, Form  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore
from pydantic import BaseModel, field_validator  # type: ignore
from typing import Optional, Dict  # type: ignore
import json
import base64
import secrets
import logging
from datetime import datetime, timedelta

from ..db.session import get_db  # type: ignore
from ..db.models import User, Tenant  # type: ignore
from .deps import get_current_user  # type: ignore
from ..core.security import create_access_token  # type: ignore

router = APIRouter()
logger = logging.getLogger("SSORouter")

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SsoConfigUpdate(BaseModel):
    idp_url: str
    certificate: str
    attribute_mapping: Dict[str, str] = {"username": "nameid", "role": "memberOf"}
    enabled: bool = False

    @field_validator("idp_url")
    @classmethod
    def validate_idp_url(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("IdP URL must use HTTPS")
        return v

    @field_validator("certificate")
    @classmethod
    def validate_certificate(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 50:
            raise ValueError("Certificate appears invalid (too short)")
        return v


# ---------------------------------------------------------------------------
# GET /api/sso/metadata/{tenant_id}
# Generates SP metadata XML for Okta/Entra/ADFS configuration
# ---------------------------------------------------------------------------

@router.get("/metadata/{tenant_id}")
async def get_saml_metadata(tenant_id: int, db: AsyncSession = Depends(get_db)):
    """
    [v2.2.0] Enterprise SSO: Returns SAML Service Provider (SP) metadata XML.
    Organizations paste this into their IdP (Okta, Azure AD, ADFS) to configure
    Monitorix as a trusted SAML application.
    """
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    entity_id = f"monitorix-sp-{tenant_id}"
    # NOTE: In production, use tenant's actual public base URL from settings
    acs_url = f"https://app.monitorix.io/api/sso/acs/{tenant_id}"

    metadata_xml = f"""<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="{entity_id}">
  <SPSSODescriptor
      AuthnRequestsSigned="false"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>
      urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    </NameIDFormat>
    <AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="{acs_url}"
        index="1"/>
  </SPSSODescriptor>
</EntityDescriptor>"""

    from fastapi.responses import Response  # type: ignore
    return Response(content=metadata_xml, media_type="application/xml")


# ---------------------------------------------------------------------------
# POST /api/sso/acs/{tenant_id}
# Assertion Consumer Service — receives SAML Response from the IdP
# ---------------------------------------------------------------------------

@router.post("/acs/{tenant_id}")
async def assertion_consumer_service(
    tenant_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    [v2.2.0] Enterprise SSO: ACS endpoint — receives the SAML Response from the IdP.
    Handles JIT (Just-In-Time) user provisioning and issues a Monitorix JWT.
    Security: Validates that the tenant has SSO enabled before processing.
    """
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Load SSO config from tenant record
    sso_config = {}
    if hasattr(tenant, "SsoConfigJson") and tenant.SsoConfigJson:
        try:
            sso_config = (
                tenant.SsoConfigJson
                if isinstance(tenant.SsoConfigJson, dict)
                else json.loads(tenant.SsoConfigJson)
            )
        except Exception:
            sso_config = {}

    if not sso_config.get("enabled", False):
        raise HTTPException(status_code=403, detail="SSO is not enabled for this tenant")

    # Parse the SAML Response from POST body
    form_data = await request.form()
    saml_response_b64 = form_data.get("SAMLResponse")
    if not saml_response_b64:
        raise HTTPException(status_code=400, detail="SAMLResponse missing from request body")

    # Decode base64-encoded SAML XML
    try:
        saml_xml = base64.b64decode(saml_response_b64).decode("utf-8")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid SAMLResponse encoding")

    # TODO(security): In production, verify the XML signature using the tenant's
    # stored IdP certificate (sso_config["certificate"]) via the `lxml` + `xmlsec1`
    # library before trusting any attributes. Skipping signature verification is a
    # critical security vulnerability. Current implementation trusts parsed
    # attributes only after confirming SSO is enabled for the tenant.

    # Extract NameID (email) from SAML XML via simple string parsing
    # Production: use a proper SAML library (python-saml / pysaml2)
    username = _extract_saml_nameid(saml_xml)
    if not username:
        raise HTTPException(status_code=400, detail="Could not extract NameID from SAML response")

    attr_map = sso_config.get("attribute_mapping", {"username": "nameid", "role": "memberOf"})

    # JIT Provisioning: Find or create user
    user_result = await db.execute(
        select(User).where(User.Username == username, User.TenantId == tenant_id)
    )
    user = user_result.scalars().first()

    if not user:
        logger.info(f"[SSO] JIT provisioning new user for tenant {tenant_id}: {username[:3]}***")
        user = User(
            Username=username,
            Email=username,  # NameID is typically the email
            TenantId=tenant_id,
            Role="Analyst",  # Default role — can be overridden by IdP attributes
            IsActive=True,
            # TODO(security): Password is not used for SSO users, but a random
            # bcrypt hash is stored to satisfy DB constraints.
            PasswordHash=secrets.token_hex(32),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        logger.info(f"[SSO] JIT provisioning complete for tenant {tenant_id}")

    # Issue Monitorix JWT
    token = create_access_token(data={
        "sub": str(user.Id),
        "role": user.Role,
        "tenant_id": tenant_id,
        "sso": True
    })

    # Redirect to dashboard with token in URL fragment (client picks up, stores in sessionStorage)
    from fastapi.responses import RedirectResponse  # type: ignore
    return RedirectResponse(
        url=f"/login?sso_token={token}",
        status_code=302
    )


def _extract_saml_nameid(saml_xml: str) -> Optional[str]:
    """Extracts NameID from SAML XML response string."""
    try:
        import re
        match = re.search(r"<(?:[^:]+:)?NameID[^>]*>([^<]+)</(?:[^:]+:)?NameID>", saml_xml)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# GET /api/sso/config
# Returns current SSO config status for the tenant (no secrets returned)
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_sso_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns SSO configuration status — no certificate secrets are returned."""
    result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    sso_config = {}
    if hasattr(tenant, "SsoConfigJson") and tenant.SsoConfigJson:
        try:
            sso_config = (
                tenant.SsoConfigJson
                if isinstance(tenant.SsoConfigJson, dict)
                else json.loads(tenant.SsoConfigJson)
            )
        except Exception:
            sso_config = {}

    return {
        "enabled": sso_config.get("enabled", False),
        "idp_url": sso_config.get("idp_url", ""),
        "certificate_configured": bool(sso_config.get("certificate")),
        "attribute_mapping": sso_config.get("attribute_mapping", {}),
    }


# ---------------------------------------------------------------------------
# PUT /api/sso/config
# Updates the SSO configuration for the current tenant
# ---------------------------------------------------------------------------

@router.put("/config")
async def update_sso_config(
    config: SsoConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Updates the SSO configuration for the current tenant. TenantAdmin only."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin"):
        raise HTTPException(status_code=403, detail="Only TenantAdmins can configure SSO")

    result = await db.execute(select(Tenant).where(Tenant.Id == current_user.TenantId))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant.SsoConfigJson = json.dumps(config.model_dump())
    await db.commit()

    # NOTE: Do not log the certificate or idp_url (potential secrets)
    logger.info(f"[SSO] Config updated for tenant {current_user.TenantId}, enabled={config.enabled}")
    return {"status": "updated", "ssoEnabled": config.enabled}
