# app/auth/redis.py
from redis.asyncio import Redis
from app.core.config import get_settings
import time

settings = get_settings()

# Create a global Redis client (async)
redis_client = Redis.from_url(settings.REDIS_URL or "redis://localhost")

async def add_to_blacklist(jti: str, exp: int):
    """
    Add a token's JTI to the blacklist until expiration time.
    `exp` is a timestamp (epoch seconds).
    """
    ttl = exp - int(time.time())
    if ttl > 0:
        await redis_client.setex(f"blacklist:{jti}", ttl, "1")


async def is_blacklisted(jti: str) -> bool:
    """
    Check if a token's JTI is blacklisted.
    """
    result = await redis_client.exists(f"blacklist:{jti}")
    return result == 1