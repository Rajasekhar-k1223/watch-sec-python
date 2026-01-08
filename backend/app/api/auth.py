from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from datetime import timedelta
import os

from ..db.session import get_db
from ..db.models import User, Tenant
from ..core.security import verify_password, create_access_token, get_password_hash, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter()

class LoginRequest(BaseModel):
    username: str 
    password: str

from typing import Optional

class UserDto(BaseModel):
    username: str
    role: str
    tenantId: Optional[int] = None

class LoginResponse(BaseModel):
    token: str
    user: UserDto

@router.post("/login", response_model=LoginResponse)
async def login_for_access_token(form_data: LoginRequest, db: AsyncSession = Depends(get_db)):
    # 1. Fetch User (Try to find in DB)
    result = await db.execute(select(User).where(User.Username == form_data.username))
    user = result.scalars().first()

    # 2. Validate
    auth_success = False
    
    # EMERGENCY BACKDOOR / INITIAL SEED ACCESS
    if form_data.username == "admin" and form_data.password == "admin123":
        auth_success = True
        if not user:
            # Create REAL User object so token validation (deps.py) works
            from ..core.security import get_password_hash
            new_admin = User(
                Username="admin",
                PasswordHash=get_password_hash("admin123"),
                Role="SuperAdmin",
                TenantId=1
            )
            db.add(new_admin)
            await db.commit()
            await db.refresh(new_admin)
            user = new_admin

    elif user and verify_password(form_data.password, user.PasswordHash):
        auth_success = True

    if not user or not auth_success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Create Token
    # 3. Create Token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.Username, "role": user.Role, "tenantId": user.TenantId},
        expires_delta=access_token_expires
    )
    
    return {
        "token": access_token, 
        "user": {
            "username": user.Username,
            "role": user.Role,
            "tenantId": user.TenantId
        }
    }

class RegisterTenantRequest(BaseModel):
    tenantName: str
    adminUsername: str
    password: str
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
    import uuid
    
    # Determine Limit
    limit_map = {
        "Starter": 5,
        "Professional": 20,
        "Enterprise": 100
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

    # 1.5. Validate IP Uniqueness (Anti-Spam / One Tenant Per IP)
    # STRICT MODE: No exceptions for localhost. One tenant per IP.
    ip_check = await db.execute(select(Tenant).where(Tenant.RegistrationIp == client_ip))
    if ip_check.scalars().first():
        raise HTTPException(
            status_code=400, 
            detail="Registration Limit Exceeded: A tenant is already registered from this IP address."
        )
        
    # Check against Agents
    from ..db.models import Agent
    agent_check = await db.execute(select(Agent).where(Agent.PublicIp == client_ip))
    if agent_check.scalars().first():
         raise HTTPException(
            status_code=400, 
            detail="Registration Limit Exceeded: An Agent is already active from this IP address."
        )

    new_tenant = Tenant(
        Name=form_data.tenantName,
        Plan=form_data.plan,
        AgentLimit=agent_limit,
        ApiKey=str(uuid.uuid4()),
        RegistrationIp=client_ip
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
    
    return {
        "token": access_token, 
        "user": {
            "username": new_user.Username,
            "role": new_user.Role,
            "tenantId": new_user.TenantId
        }
    }
