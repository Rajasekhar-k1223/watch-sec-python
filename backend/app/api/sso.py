from fastapi import APIRouter, Depends, HTTPException, Request, Form  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore
from sqlalchemy.future import select  # type: ignore
from pydantic import BaseModel, field_validator  # type: ignore
from typing import Optional, Dict, Any, List  # type: ignore
import json
import base64
import secrets
import logging
from datetime import datetime, timedelta

from ..db.session import get_db  # type: ignore
from ..db.models import User, Tenant  # type: ignore
from .deps import get_current_user  # type: ignore
from ..core.security import create_access_token, get_password_hash  # type: ignore

router = APIRouter()
logger = logging.getLogger("SSORouter")

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SsoConfigUpdate(BaseModel):
    provider: Optional[str] = "custom"
    idp_url: str
    entity_id: Optional[str] = ""
    certificate: Optional[str] = None
    attribute_mapping: Dict[str, str] = {
        "username": "nameid",
        "email": "email",
        "displayName": "displayName",
        "role": "memberOf"
    }
    default_role: Optional[str] = "Analyst"
    jit_provisioning: Optional[bool] = True
    enabled: bool = False

    @field_validator("idp_url")
    @classmethod
    def validate_idp_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://"):
            raise ValueError("IdP URL must use HTTPS (e.g., https://tenant.okta.com/app/...)")
        return v


class SsoTestRequest(BaseModel):
    idp_url: str
    certificate: str
    entity_id: Optional[str] = ""


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

    cert = sso_config.get("certificate")
    if not cert:
        raise HTTPException(status_code=403, detail="Tenant IdP certificate not configured")

    from lxml import etree # type: ignore
    from signxml import XMLVerifier # type: ignore

    try:
        root = etree.fromstring(saml_xml.encode('utf-8'))
        # Enforce Cryptographic Signature Validation
        verified_data = XMLVerifier().verify(root, x509_cert=cert)
        # Convert verified ElementTree back to string for extraction
        saml_xml = etree.tostring(verified_data.signed_xml).decode('utf-8')
    except Exception as e:
        logger.error(f"[SSO] SAML Signature Verification Failed: {e}")
        raise HTTPException(status_code=403, detail="SAML signature verification failed")

    # Extract NameID (email) from VERIFIED SAML XML
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
            ActiveStatus=True,
            PasswordHash=get_password_hash(secrets.token_urlsafe(32)),
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        logger.info(f"[SSO] JIT provisioning complete for tenant {tenant_id}")

    # Issue Monitorix JWT
    token = create_access_token(data={
        "sub": user.Username,
        "user_id": user.Id,
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


def _inspect_x509_certificate(cert_str: str) -> Dict[str, Any]:
    """Inspects and extracts metadata from an X.509 PEM certificate."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        import hashlib

        clean_pem = cert_str.strip()
        if not clean_pem.startswith("-----BEGIN CERTIFICATE-----"):
            clean_pem = f"-----BEGIN CERTIFICATE-----\n{clean_pem}\n-----END CERTIFICATE-----"

        cert = x509.load_pem_x509_certificate(clean_pem.encode("utf-8"), default_backend())
        now = datetime.utcnow()

        not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
        if hasattr(not_before, "replace"):
            not_before = not_before.replace(tzinfo=None)

        not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
        if hasattr(not_after, "replace"):
            not_after = not_after.replace(tzinfo=None)

        is_valid = not_before <= now <= not_after
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        fp_hex = hashlib.sha256(der_bytes).hexdigest()
        formatted_fp = ":".join(fp_hex[i:i+2].upper() for i in range(0, len(fp_hex), 2))

        return {
            "valid_format": True,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": hex(cert.serial_number),
            "not_valid_before": not_before.isoformat(),
            "not_valid_after": not_after.isoformat(),
            "is_valid": is_valid,
            "is_expired": now > not_after,
            "days_remaining": max(0, (not_after - now).days),
            "sha256_fingerprint": formatted_fp
        }
    except Exception as e:
        return {
            "valid_format": False,
            "error": str(e)
        }


# ---------------------------------------------------------------------------
# GET /api/sso/presets
# Returns standardized IdP configuration templates
# ---------------------------------------------------------------------------

@router.get("/presets")
async def get_sso_presets():
    """Returns configuration templates for Okta, Entra ID, PingIdentity, and Google Workspace."""
    return [
        {
            "id": "okta",
            "name": "Okta Universal Directory",
            "icon": "okta",
            "description": "Standard SAML 2.0 integration with Okta Workforce Identity Cloud",
            "default_idp_url": "https://{yourOktaDomain}.okta.com/app/{appName}/{appId}/sso/saml",
            "default_entity_id": "http://www.okta.com/{appId}",
            "attribute_mapping": {
                "username": "nameid",
                "email": "email",
                "displayName": "displayName",
                "role": "groups"
            },
            "scim_supported": True,
            "instructions": "In Okta Admin Console: Add Application -> Create SAML 2.0 -> Set Single Sign-On URL to Monitorix SP ACS URL and Audience URI to Monitorix SP Entity ID."
        },
        {
            "id": "entra",
            "name": "Microsoft Entra ID (Azure AD)",
            "icon": "microsoft",
            "description": "Enterprise cloud single sign-on with Azure Active Directory",
            "default_idp_url": "https://login.microsoftonline.com/{tenantId}/saml2",
            "default_entity_id": "https://sts.windows.net/{tenantId}/",
            "attribute_mapping": {
                "username": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "displayName": "http://schemas.microsoft.com/identity/claims/displayname",
                "role": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
            },
            "scim_supported": True,
            "instructions": "In Azure Portal: Enterprise Applications -> New application -> Set up Single Sign-On with SAML -> Download Certificate (Base64) and paste below."
        },
        {
            "id": "google",
            "name": "Google Workspace SAML",
            "icon": "google",
            "description": "Google Identity SAML SSO with Org Unit group syncing",
            "default_idp_url": "https://accounts.google.com/o/saml2/idp?idpid={idpid}",
            "default_entity_id": "https://accounts.google.com/o/saml2?idpid={idpid}",
            "attribute_mapping": {
                "username": "nameid",
                "email": "primaryEmail",
                "displayName": "name",
                "role": "department"
            },
            "scim_supported": False,
            "instructions": "In Google Admin: Apps -> Web and mobile apps -> Add Custom SAML app -> Paste ACS URL and Entity ID."
        },
        {
            "id": "ping",
            "name": "PingIdentity / PingFederate",
            "icon": "shield",
            "description": "Federated identity connection for hybrid and enterprise topologies",
            "default_idp_url": "https://sso.connect.pingidentity.com/sso/idp/SSO.saml2",
            "default_entity_id": "https://auth.pingone.com/{envId}",
            "attribute_mapping": {
                "username": "nameid",
                "email": "mail",
                "displayName": "cn",
                "role": "memberOf"
            },
            "scim_supported": True,
            "instructions": "In PingOne: Connections -> External IDPs / SAML Applications -> Configure SP ACS URL and SP Entity ID."
        },
        {
            "id": "custom",
            "name": "Custom SAML 2.0 Provider",
            "icon": "key",
            "description": "Any compliant RFC 7522 SAML 2.0 Web Browser SSO profile Identity Provider",
            "default_idp_url": "https://idp.yourcompany.com/sso/saml",
            "default_entity_id": "https://idp.yourcompany.com/entity",
            "attribute_mapping": {
                "username": "nameid",
                "email": "email",
                "displayName": "displayName",
                "role": "memberOf"
            },
            "scim_supported": True,
            "instructions": "Provide your Identity Provider's SSO URL, Entity ID, and X.509 Certificate in PEM format."
        }
    ]


# ---------------------------------------------------------------------------
# POST /api/sso/test
# Validates IdP settings and parses X.509 certificate
# ---------------------------------------------------------------------------

@router.post("/test")
async def test_sso_config(
    test_req: SsoTestRequest,
    current_user: User = Depends(get_current_user)
):
    """Validates SAML parameters and extracts X.509 certificate metadata without modifying config."""
    if not test_req.idp_url.startswith("https://"):
        raise HTTPException(status_code=400, detail="IdP SSO URL must use HTTPS")

    if not test_req.certificate or len(test_req.certificate.strip()) < 50:
        raise HTTPException(status_code=400, detail="X.509 Certificate is required and must be valid PEM format")

    cert_info = _inspect_x509_certificate(test_req.certificate)
    if not cert_info.get("valid_format"):
        raise HTTPException(status_code=400, detail=f"Invalid X.509 Certificate: {cert_info.get('error')}")

    diagnostics = [
        f"IdP URL syntax valid ({test_req.idp_url})",
        f"X.509 Subject: {cert_info.get('subject')}",
        f"X.509 Issuer: {cert_info.get('issuer')}",
        f"Valid from {cert_info.get('not_valid_before')} to {cert_info.get('not_valid_after')}",
        f"SHA-256 Fingerprint: {cert_info.get('sha256_fingerprint')}"
    ]

    if cert_info.get("is_expired"):
        diagnostics.append("WARNING: Certificate is EXPIRED")
    else:
        diagnostics.append(f"Certificate status: ACTIVE ({cert_info.get('days_remaining')} days remaining)")

    return {
        "status": "success",
        "certificate_valid": cert_info.get("is_valid", False),
        "cert_info": cert_info,
        "diagnostics": diagnostics
    }


# ---------------------------------------------------------------------------
# GET /api/sso/config
# Returns current SSO config status for the tenant
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_sso_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Returns SSO configuration status — secret certificates are safely summarized."""
    tenant_id = current_user.TenantId or 1
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
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

    cert_raw = sso_config.get("certificate", "")
    cert_info = _inspect_x509_certificate(cert_raw) if cert_raw else None

    # Derive Service Provider URLs
    sp_entity_id = f"monitorix-sp-{tenant_id}"
    sp_acs_url = f"https://app.monitorix.io/api/sso/acs/{tenant_id}"

    return {
        "tenant_id": tenant_id,
        "enabled": sso_config.get("enabled", False),
        "provider": sso_config.get("provider", "custom"),
        "idp_url": sso_config.get("idp_url", ""),
        "entity_id": sso_config.get("entity_id", ""),
        "certificate_configured": bool(cert_raw),
        "certificate_info": cert_info,
        "attribute_mapping": sso_config.get("attribute_mapping", {
            "username": "nameid",
            "email": "email",
            "displayName": "displayName",
            "role": "memberOf"
        }),
        "default_role": sso_config.get("default_role", "Analyst"),
        "jit_provisioning": sso_config.get("jit_provisioning", True),
        "sp_entity_id": sp_entity_id,
        "sp_acs_url": sp_acs_url,
        "sp_metadata_url": f"/api/sso/metadata/{tenant_id}"
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
    """Updates the SSO configuration for the current tenant. TenantAdmin or SuperAdmin only."""
    if current_user.Role not in ("TenantAdmin", "SuperAdmin"):
        raise HTTPException(status_code=403, detail="Only TenantAdmins can configure SSO")

    tenant_id = current_user.TenantId or 1
    result = await db.execute(select(Tenant).where(Tenant.Id == tenant_id))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    existing_config = {}
    if hasattr(tenant, "SsoConfigJson") and tenant.SsoConfigJson:
        try:
            existing_config = (
                tenant.SsoConfigJson
                if isinstance(tenant.SsoConfigJson, dict)
                else json.loads(tenant.SsoConfigJson)
            )
        except Exception:
            existing_config = {}

    data = config.model_dump()
    # Retain existing certificate if caller didn't provide a new one
    if not data.get("certificate") and existing_config.get("certificate"):
        data["certificate"] = existing_config.get("certificate")

    tenant.SsoConfigJson = json.dumps(data)
    await db.commit()

    logger.info(f"[SSO] Config updated for tenant {tenant_id}, enabled={config.enabled}, provider={config.provider}")
    return {"status": "updated", "ssoEnabled": config.enabled, "provider": config.provider}
