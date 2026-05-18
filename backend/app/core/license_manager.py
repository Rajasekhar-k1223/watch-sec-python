import json
import base64
import logging
from datetime import datetime
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding, rsa # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore

logger = logging.getLogger("LicenseManager")

class LicenseManager:
    """[v2.5.0] Enterprise RSA Licensing System (Offline/On-Premise Support)."""
    
    def __init__(self, public_key_pem: str = None):
        # Default Public Key for verification
        self.public_key_pem = public_key_pem or os.getenv("MONITORIX_LICENSE_PUB_KEY")

    def verify_license(self, license_data_b64: str) -> dict:
        """Verifies a signed license file and returns its entitlements."""
        try:
            # 1. Decode Payload
            payload_json = base64.b64decode(license_data_b64).decode('utf-8')
            license_obj = json.loads(payload_json)
            
            data = license_obj.get("data")
            signature = base64.b64decode(license_obj.get("signature"))
            
            # 2. Verify Signature
            if not self.public_key_pem:
                return {"valid": False, "error": "Public key not configured"}
                
            public_key = serialization.load_pem_public_key(self.public_key_pem.encode())
            
            public_key.verify(
                signature,
                json.dumps(data, sort_keys=True).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # 3. Check Expiration
            exp_date = datetime.fromisoformat(data.get("expires_at"))
            if exp_date < datetime.utcnow():
                return {"valid": False, "error": "License expired"}
                
            return {"valid": True, "entitlements": data}
            
        except Exception as e:
            logger.error(f"License Verification Failed: {e}")
            return {"valid": False, "error": str(e)}

    @staticmethod
    def generate_dummy_license(tenant_id: int, plan: str = "Enterprise") -> str:
        """Helper for development: generates a signed-looking base64 string."""
        data = {
            "tenant_id": tenant_id,
            "plan": plan,
            "agent_limit": 5000,
            "features": ["AI", "DLP", "Forensics", "SSO"],
            "expires_at": "2030-01-01T00:00:00"
        }
        # In prod, this would be signed by a private key held by Monitorix
        payload = {
            "data": data,
            "signature": "MOCK_SIGNATURE_BASE64"
        }
        return base64.b64encode(json.dumps(payload).encode()).decode()

# Global singleton
license_manager = LicenseManager()
