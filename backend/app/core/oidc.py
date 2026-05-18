import httpx
import logging
import jwt # type: ignore
from typing import Optional, Dict, Any
from fastapi import HTTPException, status # type: ignore

logger = logging.getLogger("OidcService")

class OidcProvider:
    """[v2.5.0] Zero Trust Identity Provider (Azure Entra ID / Okta / Auth0)."""

    def __init__(self, tenant_id: str, client_id: str, discovery_url: Optional[str] = None):
        self.tenant_id = tenant_id
        self.client_id = client_id
        # Azure Entra ID Default Discovery URL
        self.discovery_url = discovery_url or f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        self.jwks_uri: Optional[str] = None
        self._keys: list = []

    async def _fetch_metadata(self):
        """Fetches OIDC discovery metadata and JWKS keys."""
        if self.jwks_uri:
            return

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(self.discovery_url)
                resp.raise_for_status()
                metadata = resp.json()
                self.jwks_uri = metadata.get("jwks_uri")
                
                # Fetch Public Keys
                key_resp = await client.get(self.jwks_uri)
                key_resp.raise_for_status()
                self._keys = key_resp.json().get("keys", [])
                logger.info(f"OIDC Metadata initialized for tenant {self.tenant_id}")
            except Exception as e:
                logger.error(f"OIDC Metadata Fetch Failed: {e}")
                raise HTTPException(status_code=500, detail="Identity provider unavailable")

    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Verifies an OIDC Access/Identity token and returns claims."""
        await self._fetch_metadata()

        try:
            # Decode header to find 'kid' (Key ID)
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            # Find matching public key
            key = next((k for k in self._keys if k.get("kid") == kid), None)
            if not key:
                raise HTTPException(status_code=401, detail="Invalid token signature key")

            # Decode and Validate
            payload = jwt.decode(
                token,
                key, # In a real app, convert JWK to PEM
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"
            )
            
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"OIDC Token Validation Failed: {e}")
            raise HTTPException(status_code=401, detail="Invalid identity token")
        except Exception as e:
            logger.error(f"OIDC Verification Error: {e}")
            raise HTTPException(status_code=500, detail="Identity verification internal error")

# Example Global Manager for Multi-tenant OIDC
class ZeroTrustManager:
    _providers: Dict[str, OidcProvider] = {}

    @classmethod
    def get_provider(cls, tenant_id: str, client_id: str):
        key = f"{tenant_id}:{client_id}"
        if key not in cls._providers:
            cls._providers[key] = OidcProvider(tenant_id, client_id)
        return cls._providers[key]

zero_trust_manager = ZeroTrustManager()
