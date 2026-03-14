import os # type: ignore
import time # type: ignore
import redis.asyncio as redis # type: ignore
from fastapi import HTTPException, Request, Depends # type: ignore
from functools import wraps # type: ignore

# Reuse Celery's Redis URL or fallback to localhost
REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

class RateLimiter:
    def __init__(self, times: int, seconds: int):
        self.times = times
        self.seconds = seconds
        self.redis = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)

    async def __call__(self, request: Request):
        if not self.redis:
            return # Fail open if Redis is down
            
        # Identifier: IP or TenantID (if available)
        # We try to get TenantId from user/agent if possible, defaulting to IP
        client_ip = request.client.host
        # specific for agent update - try to limit by tenant if possible, or just IP for now
        # Ideally, we'd inspect the token, but for now IP-based is a good start for DDoS protection
        
        key = f"rate_limit:{client_ip}:{request.url.path}"
        
        try:
            # Simple Fixed Window Counter
            current = await self.redis.get(key)
            
            if current and int(current) >= self.times:
                raise HTTPException(
                    status_code=429, 
                    detail="Too many update requests. Please try again later."
                )
            
            # Atomic Increment & Expire
            pipe = self.redis.pipeline()
            pipe.incr(key)
            if not current:
                pipe.expire(key, self.seconds)
            await pipe.execute()
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"Rate Limiter Error: {e}")
            # Fail open to avoid blocking legit traffic on redis error
            pass
