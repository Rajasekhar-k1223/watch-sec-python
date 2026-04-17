from datetime import datetime, timedelta # type: ignore
from typing import Optional # type: ignore
from jose import JWTError, jwt # type: ignore
from passlib.context import CryptContext # type: ignore
import os # type: ignore
import hmac
import hashlib
import json
from dotenv import load_dotenv # type: ignore

load_dotenv()

def _get_or_create_secret():
    """Self-provisioning root-of-trust: Ensures a high-entropy key is committed to the environment."""
    key = os.getenv("SECRET_KEY")
    if key and key != "default-secret-key":
        return key
    
    # [SECURITY v1.8.41] Root Entropy Generation
    import secrets # type: ignore
    new_secret = secrets.token_urlsafe(64)
    
    # Persist to .env if possible
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "a") as f:
                f.write(f"\n# Auto-Generated Root of Trust [v1.8.41]\nSECRET_KEY=\"{new_secret}\"\n")
            print(f"[SECURITY] Self-Provisioned High-Entropy Secret committed to {env_path}")
        except: pass
    
    # Update current process environment
    os.environ["SECRET_KEY"] = new_secret
    return new_secret

# Config
SECRET_KEY = _get_or_create_secret()
ALGORITHM = "HS256"
# [SECURITY v1.8.41] Reduced Longevity: 120 minutes (2 hours) instead of 24h
ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    """Secure Bcrypt-only verification. Legacy plaintext fallbacks are strictly purged."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except:
        # [SECURITY v1.8.41] PURGED plaintext fallback.
        # Unauthorized access via unhashed passwords is now strictly impossible.
        return False

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

def generate_agent_command_signature(api_key: str, machine_id: str, action: str, params: dict, timestamp: str) -> str:
    """
    Generates an HMAC-SHA256 signature matching the agent's verification logic.
    Ref: agent_core/remediation_handler.py: _verify_signature
    """
    if not api_key or not machine_id:
        return ""
    
    # Reconstruct the message base for signing
    msg_parts = [
        str(action),
        json.dumps(params, sort_keys=True),
        str(timestamp)
    ]
    message = "|".join(msg_parts).encode('utf-8')
    
    # Derive HMAC Key (Sha256(ApiKey + MachineId))
    key = hashlib.sha256(api_key.encode() + machine_id.encode()).digest()
    
    # Calculate signature
    return hmac.new(key, message, hashlib.sha256).hexdigest()
