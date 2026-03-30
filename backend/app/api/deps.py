from typing import Optional # type: ignore
from fastapi import Depends, HTTPException, status, Header # type: ignore
from fastapi.security import OAuth2PasswordBearer # type: ignore
from jose import JWTError, jwt # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession # type: ignore
from sqlalchemy.future import select # type: ignore

from ..db.session import get_db # type: ignore
from ..db.models import User, Tenant # type: ignore
from ..core.security import SECRET_KEY, ALGORITHM # type: ignore

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    result = await db.execute(select(User).where(User.Username == username))
    user = result.scalars().first()
    
    if user is None:
        raise credentials_exception
        
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.TenantId and current_user.Role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="User not assigned to any tenant")
    return current_user

async def get_tenant_by_key(x_tenant_api_key: Optional[str] = Header(None, alias="X-Tenant-Api-Key"), db: AsyncSession = Depends(get_db)):
    if not x_tenant_api_key:
        return None
    result = await db.execute(select(Tenant).where(Tenant.ApiKey == x_tenant_api_key))
    tenant = result.scalars().first()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return tenant
