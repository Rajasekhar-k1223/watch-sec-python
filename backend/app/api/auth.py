from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel
from datetime import timedelta
import os

from ..db.session import get_db
from ..db.models import User
from ..core.security import verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES

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
            # Create a Mock User object if DB is empty so token generation works
            class MockUser:
                Username = "admin"
                Role = "SuperAdmin"
                TenantId = 1 # Default ID
                PasswordHash = ""
            user = MockUser()

    elif user and verify_password(form_data.password, user.PasswordHash):
        auth_success = True

    if not user or not auth_success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Create Token
    access_token_expires = timedelta(minutes=float(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
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
