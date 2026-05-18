from typing import Optional, List # type: ignore
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

async def get_current_user_flexible(
    token: Optional[str] = None, 
    db: AsyncSession = Depends(get_db),
    header_token: str = Depends(oauth2_scheme)
):
    """
    Tries to get token from Query Param first (for <img> and window.open), 
    then falls back to standard oauth2_scheme (Authorization Header).
    """
    # Note: oauth2_scheme will RAISE 401 if header is missing.
    # To make it truly optional, we need a custom extractor or handle the fail.
    # Actually, we'll try a simpler approach: check header manually first.
    pass

# We redefine to handle the 'optional' header case for flexible usage
from fastapi.security import APIKeyHeader # type: ignore
header_scheme = APIKeyHeader(name="Authorization", auto_error=False)

async def get_current_user_flexible(
    token: Optional[str] = None, 
    auth_header: Optional[str] = Depends(header_scheme),
    db: AsyncSession = Depends(get_db)
):
    actual_token = token
    if not actual_token and auth_header:
        if auth_header.startswith("Bearer "):
            actual_token = auth_header.split(" ")[1]
        else:
            actual_token = auth_header

    if not actual_token:
        raise HTTPException(status_code=401, detail="Authentication required (Token or Header missing)")

    try:
        payload = jwt.decode(actual_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    result = await db.execute(select(User).where(User.Username == username))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
        
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

# --- RBAC Helper ---
def check_role(required_roles: List[str]):
    """
    Dependency that ensures the current user has one of the required roles.
    Example: Depends(check_role(["SuperAdmin", "TenantAdmin"]))
    """
    from typing import List as ListType # type: ignore
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.Role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: This operation requires one of the following roles: {', '.join(required_roles)}"
            )
        return current_user
    return role_checker
