from fastapi import APIRouter, Depends, HTTPException, status, Request # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from datetime import timedelta # type: ignore
import os # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import User, Tenant, RefreshToken # type: ignore
from ..core.security import verify_password, create_access_token, get_password_hash, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS # type: ignore
from ..core.rate_limit import RateLimiter # [v1.7.0] # type: ignore
import secrets
import hashlib
from datetime import datetime, timedelta

router = APIRouter()

class LoginRequest(BaseModel):
    username: str 
    password: str

from typing import Optional # type: ignore

class UserDto(BaseModel):
    username: str
    role: str
    tenantId: Optional[int] = None
    plan: Optional[str] = "Starter"
    agentlessEnabled: Optional[bool] = False

class LoginResponse(BaseModel):
    token: str
    refresh_token: str # [v2.0.0]
    user: UserDto

@router.post("/login", response_model=LoginResponse)
async def login_for_access_token(
    form_data: LoginRequest, 
    request: Request,
    db: AsyncSession = Depends(get_db),
    _ = Depends(RateLimiter(times=5, seconds=60)) # [SEC] 5 attempts per minute
):
    # 1. Fetch User (Try to find in DB)
    result = await db.execute(select(User).where(User.Username == form_data.username))
    user = result.scalars().first()

    # 2. Validate
    auth_success = False
    
    if user and verify_password(form_data.password, user.PasswordHash):
        auth_success = True

    if not user or not auth_success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # [AUDIT] Log Login
    from ..db.models import AuditLog # type: ignore
    
    audit = AuditLog(
        TenantId=user.TenantId,
        Actor=user.Username,
        Action="User Login",
        Target="Auth System",
        Details="External Login via /api/auth/login",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()

    # 3. Create Access Token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.Username, "role": user.Role, "tenantId": user.TenantId},
        expires_delta=access_token_expires
    )
    
    # 4. Create Refresh Token [v2.0.0]
    refresh_token_raw = secrets.token_urlsafe(64)
    refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
    
    new_rt = RefreshToken(
        UserId=user.Id,
        TokenHash=refresh_token_hash,
        ExpiresAt=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        UserAgent=request.headers.get("User-Agent"),
        IpAddress=request.client.host if request.client else None
    )
    db.add(new_rt)
    await db.commit()

    # Fetch Plan if TenantId exists
    plan = "Starter"
    agentless_enabled = True
    if user.TenantId:
        t_res = await db.execute(select(Tenant).where(Tenant.Id == user.TenantId))
        tenant_obj = t_res.scalars().first()
        if tenant_obj:
            plan = tenant_obj.Plan
            agentless_enabled = getattr(tenant_obj, "AgentlessEnabled", True)

    return {
        "token": access_token, 
        "refresh_token": refresh_token_raw,
        "user": {
            "username": user.Username,
            "role": user.Role,
            "tenantId": user.TenantId,
            "plan": plan,
            "agentlessEnabled": agentless_enabled
        }
    }

class SdkHandshakeRequest(BaseModel):
    sdk_key: str

@router.post("/sdk-handshake", response_model=LoginResponse)
async def sdk_handshake(
    payload: SdkHandshakeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _ = Depends(RateLimiter(times=10, seconds=60)) # [SEC] rate limit
):
    """[SECURITY] Exchange a static SDK key for a short-lived Session JWT"""
    from ..db.models import ApiKey
    import json
    
    if not payload.sdk_key.startswith("mk_"):
        raise HTTPException(status_code=401, detail="Invalid SDK Key format")
        
    token_hash = hashlib.sha256(payload.sdk_key.encode()).hexdigest()
    result = await db.execute(select(ApiKey).where(ApiKey.KeyHash == token_hash))
    api_key = result.scalars().first()
    
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid SDK Key")
        
    if api_key.ExpiresAt and api_key.ExpiresAt < datetime.utcnow():
        raise HTTPException(status_code=401, detail="SDK Key expired")

    # [SECURITY] SDK IP Whitelist Validation
    forwarded_for = request.headers.get("X-Forwarded-For")
    real_ip = request.headers.get("X-Real-IP")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    elif real_ip:
        client_ip = real_ip
    else:
        client_ip = request.client.host if request.client else "Unknown"

    try:
        allowed_ips = json.loads(api_key.AllowedIpsJson) if api_key.AllowedIpsJson else []
    except Exception:
        allowed_ips = []
        
    if allowed_ips and client_ip not in allowed_ips:
        raise HTTPException(status_code=403, detail=f"Handshake Forbidden: IP address {client_ip} is not authorized for this SDK Key")
        
    # Update usage
    api_key.LastUsedAt = datetime.utcnow()
    await db.commit()
    
    # Generate short-lived JWT (15 mins)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": f"sdk_{api_key.Name}", 
            "role": "TenantAdmin", 
            "tenantId": api_key.TenantId
        },
        expires_delta=access_token_expires
    )
    
    # Generate standard refresh token
    refresh_token_raw = secrets.token_urlsafe(64)
    refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
    
    # We use a placeholder user ID (-1) for SDK tokens in the RefreshToken table
    # But wait, RefreshToken requires a valid UserId due to foreign keys. 
    # Let's find the tenant admin or skip DB insert for SDK refresh tokens.
    # Actually, let's just find the first TenantAdmin user for this tenant to bind the refresh token.
    user_res = await db.execute(select(User).where(User.TenantId == api_key.TenantId, User.Role == "TenantAdmin"))
    admin_user = user_res.scalars().first()
    
    if not admin_user:
        raise HTTPException(status_code=500, detail="Cannot issue SDK token: No TenantAdmin found for tenant")
        
    new_rt = RefreshToken(
        UserId=admin_user.Id,
        TokenHash=refresh_token_hash,
        ExpiresAt=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        UserAgent=request.headers.get("User-Agent", "SDK"),
        IpAddress=request.client.host if request.client else None
    )
    db.add(new_rt)
    
    # Log Audit
    from ..db.models import AuditLog
    audit = AuditLog(
        TenantId=api_key.TenantId,
        Actor=f"SDK ({api_key.Name})",
        Action="SDK Handshake",
        Target="Auth System",
        Details="Static SDK key exchanged for Session JWT",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()
    
    return {
        "token": access_token,
        "refresh_token": refresh_token_raw,
        "user": {
            "username": f"sdk_{api_key.Name}",
            "role": "TenantAdmin",
            "tenantId": api_key.TenantId,
            "plan": "API" # Placeholder
        }
    }

class RefreshRequest(BaseModel):
    refresh_token: str

@router.post("/refresh", response_model=LoginResponse)
async def refresh_access_token(
    payload: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Rotate tokens using a valid refresh token. [v2.0.0]"""
    token_hash = hashlib.sha256(payload.refresh_token.encode()).hexdigest()
    
    result = await db.execute(
        select(RefreshToken, User)
        .join(User, RefreshToken.UserId == User.Id)
        .where(RefreshToken.TokenHash == token_hash, RefreshToken.RevokedAt == None)
    )
    row = result.first()
    
    if not row or row.RefreshToken.ExpiresAt < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    rt, user = row
    
    # Rotate: Revoke old, issue new
    rt.RevokedAt = datetime.utcnow()
    
    # Create Access Token
    access_token = create_access_token(
        data={"sub": user.Username, "role": user.Role, "tenantId": user.TenantId}
    )
    
    # Create New Refresh Token
    new_raw = secrets.token_urlsafe(64)
    new_hash = hashlib.sha256(new_raw.encode()).hexdigest()
    
    new_rt = RefreshToken(
        UserId=user.Id,
        TokenHash=new_hash,
        ExpiresAt=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        UserAgent=request.headers.get("User-Agent"),
        IpAddress=request.client.host if request.client else None
    )
    db.add(new_rt)
    await db.commit()
    # Fetch Tenant info
    plan = "Starter"
    agentless_enabled = True
    if user.TenantId:
        t_res = await db.execute(select(Tenant).where(Tenant.Id == user.TenantId))
        tenant_obj = t_res.scalars().first()
        if tenant_obj:
            plan = tenant_obj.Plan
            agentless_enabled = getattr(tenant_obj, "AgentlessEnabled", True)
            
    return {
        "token": access_token,
        "refresh_token": new_raw,
        "user": {
            "username": user.Username,
            "role": user.Role,
            "tenantId": user.TenantId,
            "plan": plan,
            "agentlessEnabled": agentless_enabled
        }
    }

class RegisterTenantRequest(BaseModel):
    tenantName: str
    adminUsername: str
    password: str
    email: str # [v1.7.1] Mandatory
    plan: str = "Starter"

@router.post("/register-tenant", response_model=LoginResponse)
async def register_tenant(
    form_data: RegisterTenantRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _ = Depends(RateLimiter(times=3, seconds=60)) # [SEC] 3 attempts per minute for registration
):
    # 1. Check if user already exists (globally unique username enforcement)
    result = await db.execute(select(User).where(User.Username == form_data.adminUsername))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    # 2. Create Tenant
    import uuid # type: ignore
    
    # Determine Limit
    limit_map = {
        "Starter": 5,
        "Professional": 50,
        "Enterprise": 1000,
        "Unlimited": -1
    }
    agent_limit = limit_map.get(form_data.plan, 5) # Default to 5

    # Extract IP (Robust Proxy Support)
    forwarded_for = request.headers.get("X-Forwarded-For")
    real_ip = request.headers.get("X-Real-IP")
    
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    elif real_ip:
        client_ip = real_ip
    else:
        client_ip = request.client.host if request.client else "Unknown"

    # [MOD] Relaxing IP Uniqueness Check to allow multiple tenants/agents per IP for SuperAdmin testing
    # ip_check = await db.execute(select(Tenant).where(Tenant.RegistrationIp == client_ip))
    # if ip_check.scalars().first():
    #     print(f"[DEBUG] BLOCKED Tenant Registration: IP {client_ip} already exists in Tenants table.")
    #     raise HTTPException(
    #         status_code=400, 
    #         detail="Registration Limit Exceeded: A tenant is already registered from this IP address."
    #     )
    pass

    # [v1.7.1] Domain Validation
    import re # type: ignore
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, form_data.email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    email_domain = form_data.email.split("@")[-1].lower()
    
    # Block common freemail providers for organization registration
    freemail_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com"]
    if email_domain in freemail_providers:
        # [MOD] Optional: Only allow company domains. Let's keep it strict for production vibe.
        raise HTTPException(
            status_code=400, 
            detail=f"Registration requires a company email address. {email_domain} is not allowed."
        )

    import json # type: ignore
    new_tenant = Tenant(
        Name=form_data.tenantName,
        Plan=form_data.plan,
        AgentLimit=agent_limit,
        ApiKey=str(uuid.uuid4()),
        RegistrationIp=client_ip,
        AdminEmail=form_data.email,
        TrustedDomainsJson=json.dumps([email_domain]) # [v1.7.1] Auto-trust the registration domain
    )
    db.add(new_tenant)
    await db.flush() # flush to get ID

    # 3. Create Admin User
    new_user = User(
        Username=form_data.adminUsername,
        Email=form_data.email,
        PasswordHash=get_password_hash(form_data.password),
        Role="TenantAdmin",
        TenantId=new_tenant.Id
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # 4. Generate Token (Auto Login)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": new_user.Username, "role": new_user.Role, "tenantId": new_user.TenantId},
        expires_delta=access_token_expires
    )
    
    # 4b. Create Refresh Token [v2.0.0]
    refresh_token_raw = secrets.token_urlsafe(64)
    refresh_token_hash = hashlib.sha256(refresh_token_raw.encode()).hexdigest()
    
    new_rt = RefreshToken(
        UserId=new_user.Id,
        TokenHash=refresh_token_hash,
        ExpiresAt=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        UserAgent=request.headers.get("User-Agent"),
        IpAddress=request.client.host if request.client else None
    )
    db.add(new_rt)
    
    # [AUDIT] Log Registration
    from ..db.models import AuditLog # type: ignore
    
    audit = AuditLog(
        TenantId=new_tenant.Id,
        Actor=new_user.Username,
        Action="Tenant Registration",
        Target=new_tenant.Name,
        Details=f"New tenant registered from IP: {client_ip}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    await db.commit()

    return {
        "token": access_token, 
        "refresh_token": refresh_token_raw,
        "user": {
            "username": new_user.Username,
            "role": new_user.Role,
            "tenantId": new_user.TenantId
        }
    }
