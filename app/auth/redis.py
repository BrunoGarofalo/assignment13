# app/auth/redis.py
from redis.asyncio import Redis
from app.core.config import get_settings
import time

settings = get_settings()

redis_client = Redis.from_url(settings.REDIS_URL or "redis://localhost")

async def get_redis_client():
    return redis_client

async def add_to_blacklist(jti: str, exp: int):
    ttl = exp - int(time.time())
    if ttl > 0:
        redis = await get_redis_client()
        await redis.setex(f"blacklist:{jti}", ttl, "1")

async def is_blacklisted(jti: str) -> bool:
    redis = await get_redis_client()
    result = await redis.exists(f"blacklist:{jti}")
    return result == 1
