from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

load_dotenv()

# Config
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    # In a migration scenario, you might need to handle different hashing algos 
    # if C# used something else (like IdentityServer default PBKDF2).
    # For now, we assume bcrypt or transparent handling.
    # Note: ASP.NET Core Identity uses PBKDF2-HMAC-SHA256 by default. 
    # Passlib can verify this format if configured, but often it's easier to reset passwords 
    # or handle legacy verification logic if strictly needed.
    # For 'Total Project' parity, we'll try standard verify.
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except:
        # Fallback for Legacy/Plaintext passwords found in imported DBs
        return plain_password == hashed_password

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
