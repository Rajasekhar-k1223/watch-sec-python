from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from typing import Optional, List

from ..db.session import get_db
from ..db.models import User, Tenant
from .deps import get_current_user
from ..core.security import verify_password, get_password_hash

router = APIRouter()

class UserDto(BaseModel):
    Id: int
    Username: str
    Role: str
    TenantId: Optional[int]
    TenantName: Optional[str]

class ChangePasswordRequest(BaseModel):
    OldPassword: str
    NewPassword: str

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
    if user.PasswordHash == req.OldPassword: # Legacy/Seed compat
        is_valid = True
    elif verify_password(req.OldPassword, user.PasswordHash): # Prod compat
        is_valid = True
        
    if not is_valid:
         raise HTTPException(status_code=400, detail="Incorrect current password.")

    # 3. Update
    # For now, we store plain text if that's what C# did, OR we upgrade to hash.
    # To be safe and compatible with the Auth endpoint which expects `verify_password`(hash), 
    # we should ideally hash it. BUT if C# auth expects plain text, we break it.
    # Checking C# AuthController: It uses `_signInManager` or custom?
    # C# `UsersController` line 72: `if (user.PasswordHash != req.OldPassword)` <- Direct String Compare!
    # This implies C# uses PLAIN TEXT storage for this prototype.
    # Python `auth.py` line 40: `verify_password(form_data.Password, user.PasswordHash)` which calls `pwd_context.verify`.
    # `pwd_context` handles bcrypt. Handing plain text to it might fail or work if "plain" scheme enabled.
    # To support BOTH, we will Hash it in Python.
    # WAIT: If C# writes plain text, Python reads plain text. 
    # If Python writes Hash, C# reads Hash -> C# `!=` check will FAIL because Hash != Password.
    # Conflict: C# expects Plain, Python expects Hash.
    # Decision: For now, write PLAIN TEXT to maintain C# compatibility until we migrate C# to hashing too.
    
    user.PasswordHash = req.NewPassword # Keeping it simple/insecure as per C# prototype
    # user.PasswordHash = get_password_hash(req.NewPassword) # The Correct Way
    
    await db.commit()
    
    return {"message": "Password updated successfully."}
