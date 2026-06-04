from fastapi import APIRouter, Depends, HTTPException, status # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore
from pydantic import BaseModel # type: ignore
from typing import Optional, List # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import User, Tenant # type: ignore
from .deps import get_current_user # type: ignore
from ..core.security import verify_password, get_password_hash # type: ignore

router = APIRouter()

class UserDto(BaseModel):
    Id: int
    Username: str
    Role: str
    TenantId: Optional[int]
    TenantName: Optional[str]

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "Analyst"

@router.post("/", response_model=UserDto)
async def create_user(
    req: CreateUserRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # 1. Authorization
    if current_user.Role not in ["SuperAdmin", "TenantAdmin"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    # [SECURITY] Prevent TenantAdmin from creating SuperAdmin
    if current_user.Role != "SuperAdmin" and req.role == "SuperAdmin":
        raise HTTPException(status_code=403, detail="Insufficient privileges to create SuperAdmin")

    # 2. Determine TenantId
    target_tenant_id = current_user.TenantId
    if current_user.Role == "SuperAdmin":
        # In a real app, SuperAdmin might specify TenantId in request. 
        # For now, simplistic: Create in own tenant (if any) or error?
        # Let's assume SuperAdmin creates global admins or admins for their own tenant context.
        pass
    
    if not target_tenant_id:
        # If SuperAdmin has no tenant (unlikely), they can't create scoped users without specifying tenant.
        # Allowing creation for now, but strictly checking username.
        pass

    # 3. Check Username Uniqueness
    result = await db.execute(select(User).where(User.Username == req.username))
    if result.scalars().first():
         raise HTTPException(status_code=400, detail="Username already exists")

    # 4. Create
    new_user = User(
        Username=req.username,
        PasswordHash=get_password_hash(req.password),
        Role=req.role,
        TenantId=target_tenant_id
    )
    db.add(new_user)
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Create User",
        Target=new_user.Username,
        Details=f"Role: {new_user.Role}",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    await db.refresh(new_user)

    # 5. Return DTO
    # Fetch Tenant Name
    tenant_name = "N/A"
    if new_user.TenantId:
        t_result = await db.execute(select(Tenant).where(Tenant.Id == new_user.TenantId))
        t = t_result.scalars().first()
        if t: tenant_name = t.Name

    return UserDto(
        Id=new_user.Id,
        Username=new_user.Username,
        Role=new_user.Role,
        TenantId=new_user.TenantId,
        TenantName=tenant_name
    )

class ChangePasswordRequest(BaseModel):
    oldPassword: str
    newPassword: str

@router.get("/", response_model=List[UserDto])
async def get_users(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # 1. Logic: SuperAdmin sees all, TenantAdmin sees own
    query = select(User, Tenant.Name.label("TenantName")).outerjoin(Tenant, User.TenantId == Tenant.Id)
    
    if current_user.Role == "SuperAdmin":
        pass # No filter
    elif current_user.Role == "TenantAdmin":
        if not current_user.TenantId:
            return [] # Should not happen
        query = query.where(User.TenantId == current_user.TenantId)
    else:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    result = await db.execute(query)
    rows = result.all()
    
    users = []
    for user, tenant_name in rows:
        users.append(UserDto(
            Id=user.Id,
            Username=user.Username,
            Role=user.Role,
            TenantId=user.TenantId,
            TenantName=tenant_name or "N/A"
        ))
        
    return users

@router.post("/change-password")
async def change_password(
    req: ChangePasswordRequest, 
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    # 1. Fetch Fresh User (to be safe)
    result = await db.execute(select(User).where(User.Id == current_user.Id))
    user = result.scalars().first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # 2. Verify Old Password
    # In C# code, it was direct comparison `user.PasswordHash != req.OldPassword` because of seed data.
    # Here we should support both plain (for seed compatibility) and hashed.
    
    is_valid = False
    if user.PasswordHash == req.oldPassword: # Legacy/Seed compat
        is_valid = True
    elif verify_password(req.oldPassword, user.PasswordHash): # Prod compat
        is_valid = True
        
    if not is_valid:
         raise HTTPException(status_code=400, detail="Incorrect current password.")

    # 3. Update with Hashing
    user.PasswordHash = get_password_hash(req.newPassword)
    
    # [AUDIT]
    from datetime import datetime # type: ignore
    from ..db.models import AuditLog # type: ignore
    audit = AuditLog(
        TenantId=current_user.TenantId or 0,
        Actor=current_user.Username,
        Action="Change Password",
        Target=user.Username,
        Details="Password changed via User API",
        Timestamp=datetime.utcnow()
    )
    db.add(audit)
    
    await db.commit()
    
    return {"message": "Password updated successfully."}
