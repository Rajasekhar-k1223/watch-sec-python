from fastapi import APIRouter, Depends, HTTPException, status, Request # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from datetime import timedelta # type: ignore
import os # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import User, Tenant # type: ignore
from ..core.security import verify_password, create_access_token, get_password_hash, ACCESS_TOKEN_EXPIRE_MINUTES # type: ignore
from ..core.rate_limit import RateLimiter # [v1.7.0] # type: ignore

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

class LoginResponse(BaseModel):
    token: str
    user: UserDto

@router.post("/login", response_model=LoginResponse)
async def login_for_access_token(
    form_data: LoginRequest, 
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
    from datetime import datetime # type: ignore
    
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

    # 3. Create Token
    # 3. Create Token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.Username, "role": user.Role, "tenantId": user.TenantId},
        expires_delta=access_token_expires
    )
    
    # Fetch Plan if TenantId exists
    plan = "Starter"
    if user.TenantId:
        t_res = await db.execute(select(Tenant).where(Tenant.Id == user.TenantId))
        tenant_obj = t_res.scalars().first()
        if tenant_obj:
            plan = tenant_obj.Plan

    return {
        "token": access_token, 
        "user": {
            "username": user.Username,
            "role": user.Role,
            "tenantId": user.TenantId,
            "plan": plan
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
    db: AsyncSession = Depends(get_db)
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
    
    # [AUDIT] Log Registration
    from ..db.models import AuditLog # type: ignore
    from datetime import datetime # type: ignore
    
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
        "user": {
            "username": new_user.Username,
            "role": new_user.Role,
            "tenantId": new_user.TenantId
        }
    }
