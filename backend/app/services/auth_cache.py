"""
Monitorix Enterprise — Redis Fast-Path Authentication Cache Service
Provides:
  - Sub-millisecond user identity and permission caching in Redis
  - Maximum 60-second TTL
  - Strict tenant-prefixed namespace isolation to prevent collisions
  - Secure eviction on user update, password change, and logout
  - Fail-closed error handling with automatic fallback to PostgreSQL
  - Zero storage of passwords, hashes, or raw credentials
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from app.core.rate_limit import get_redis_client
from app.db.models import User

logger = logging.getLogger("AuthCache")

class AuthCacheService:
    CACHE_TTL_SECONDS = 60  # Maximum 60 seconds TTL

    def _get_cache_key(self, username: str, tenant_id: Optional[int] = None) -> str:
        t_id = str(tenant_id) if tenant_id is not None else "global"
        return f"auth:user:tenant_{t_id}:{username}"

    async def get_cached_user(self, username: str, tenant_id: Optional[int] = None) -> Optional[User]:
        """
        Retrieves cached validated user permissions from Redis.
        Returns a detached User instance if valid, or None on cache miss.
        """
        try:
            client = get_redis_client()
            key = self._get_cache_key(username, tenant_id)
            cached_raw = await client.get(key)
            if not cached_raw:
                return None

            data = json.loads(cached_raw)
            # Fail closed if invalid structure or missing mandatory role/identity
            if not data.get("Username") or not data.get("Role"):
                return None

            # Reconstruct detached User instance
            user = User(
                Id=data.get("Id"),
                Username=data.get("Username"),
                Role=data.get("Role"),
                TenantId=data.get("TenantId"),
                Email=data.get("Email"),
                ActiveStatus=data.get("ActiveStatus", True)
            )
            return user
        except Exception as e:
            logger.warning(f"[AuthCache] Redis get error: {e}. Falling back to DB.")
            return None

    async def cache_user(self, user: User, tenant_id: Optional[int] = None):
        """
        Caches validated user identity and permissions with 60-second TTL.
        Never stores passwords, password hashes, or sensitive credentials.
        """
        try:
            client = get_redis_client()
            t_id = tenant_id if tenant_id is not None else user.TenantId
            key = self._get_cache_key(user.Username, t_id)
            payload = {
                "Id": user.Id,
                "Username": user.Username,
                "Role": user.Role,
                "TenantId": user.TenantId,
                "Email": getattr(user, "Email", None),
                "ActiveStatus": getattr(user, "ActiveStatus", True)
            }
            await client.set(key, json.dumps(payload), ex=self.CACHE_TTL_SECONDS)
        except Exception as e:
            logger.warning(f"[AuthCache] Redis set error: {e}")

    async def invalidate_user(self, username: str, tenant_id: Optional[int] = None):
        """
        Evicts cached user permissions across all matching tenant scopes.
        """
        try:
            client = get_redis_client()
            # Explicit key
            t_id = tenant_id if tenant_id is not None else "global"
            direct_key = self._get_cache_key(username, tenant_id)
            await client.delete(direct_key)

            # Invalidate any wildcard matches for this username across all tenants
            wildcard_pattern = f"auth:user:tenant_*:{username}"
            keys = await client.keys(wildcard_pattern)
            if keys:
                await client.delete(*keys)
            logger.info(f"[AuthCache] Invalidated cache keys for user '{username}'")
        except Exception as e:
            logger.warning(f"[AuthCache] Redis invalidation error: {e}")

auth_cache = AuthCacheService()

