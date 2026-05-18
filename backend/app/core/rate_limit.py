import os # type: ignore
import time # type: ignore
import redis.asyncio as redis # type: ignore
from fastapi import HTTPException, Request, Depends # type: ignore
from functools import wraps # type: ignore

# Reuse Celery's Redis URL or fallback to localhost
REDIS_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

# [NEW] Share a single connection pool across all instances
_shared_redis_client = None

def get_redis_client():
    global _shared_redis_client
    if _shared_redis_client is None:
        # Use single client with pooling
        _shared_redis_client = redis.from_url(
            REDIS_URL, 
            encoding="utf-8", 
            decode_responses=True,
            socket_timeout=5,     # [NEW] Don't wait 20s if redis is down
            socket_connect_timeout=5,
            retry_on_timeout=True
        )
    return _shared_redis_client

class RateLimiter:
    def __init__(self, times: int, seconds: int):
        self.times = times
        self.seconds = seconds

    async def __call__(self, request: Request):
        client = get_redis_client()
        
        # Identifier: IP (Robust detection for WAF/Proxy compatibility)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = request.headers.get("X-Real-IP", request.client.host if request.client else "Unknown")
            
        key = f"rate_limit:{client_ip}:{request.url.path}"
        
        try:
            # Simple Fixed Window Counter
            current = await client.get(key)
            
            if current and int(current) >= self.times:
                raise HTTPException(
                    status_code=429, 
                    detail="Too many requests. Please try again later."
                )
            
            # Atomic Increment & Expire
            pipe = client.pipeline()
            pipe.incr(key)
            if not current:
                pipe.expire(key, self.seconds)
            await pipe.execute()
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"Rate Limiter Warning: {e}")
            # Fail open to avoid blocking legit traffic on redis error
            pass
