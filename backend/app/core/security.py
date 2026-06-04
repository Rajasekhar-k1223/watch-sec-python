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
REFRESH_TOKEN_EXPIRE_DAYS = 30 # [v2.0.0]

def _get_or_create_signing_keys():
    """Self-provisioning: Ensures an Ed25519 key pair exists for update signing."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    priv_path = os.getenv("UPDATE_PRIVATE_KEY_PATH", "update_signing.key")
    pub_path = os.getenv("UPDATE_PUBLIC_KEY_PATH", "update_signing.pub")
    
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
            
    # Generate new pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Save
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))
    print(f"[SECURITY] Generated new Ed25519 Update Signing Key Pair: {priv_path}")
    return private_key

UPDATE_PRIVATE_KEY = _get_or_create_signing_keys()

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

def sign_payload_asymmetric(payload_bytes: bytes) -> str:
    """Signs a payload using the Ed25519 private key. [v2.0.0]"""
    signature = UPDATE_PRIVATE_KEY.sign(payload_bytes)
    return signature.hex()

def decrypt_e2e_payload(payload_bytes: bytes, machine_secret: str) -> bytes:
    """Decrypts E2EE payload from the agent using AES-256-GCM."""
    try:
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        data = json.loads(payload_bytes)
        if "e2e_payload" not in data or "nonce" not in data:
            return payload_bytes # Not encrypted
            
        key = hashlib.sha256(machine_secret.encode()).digest()
        aesgcm = AESGCM(key)
        
        ct = base64.b64decode(data["e2e_payload"])
        nonce = base64.b64decode(data["nonce"])
        
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt
    except Exception as e:
        print(f"[SECURITY] E2EE Decryption Failed: {e}")
        return payload_bytes
