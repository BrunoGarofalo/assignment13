import pytest
from unittest.mock import AsyncMock, patch

from app.auth.redis import add_to_blacklist, is_blacklisted


@pytest.mark.asyncio
async def test_add_to_blacklist_sets_key_with_ttl():
    fake_redis = AsyncMock()

    with patch("app.auth.redis.redis_client", fake_redis):
        await add_to_blacklist("abc123", exp=9999999999)

    fake_redis.setex.assert_awaited()
    args, kwargs = fake_redis.setex.call_args
    assert args[0] == "blacklist:abc123"
    assert args[2] == "1"


@pytest.mark.asyncio
async def test_is_blacklisted_true():
    fake_redis = AsyncMock()
    fake_redis.exists.return_value = 1

    with patch("app.auth.redis.redis_client", fake_redis):
        result = await is_blacklisted("xyz999")

    assert result is True


@pytest.mark.asyncio
async def test_is_blacklisted_false(monkeypatch):
    fake_redis = AsyncMock()
    fake_redis.exists.return_value = 0

    async def fake_get_redis_client():
        return fake_redis

    monkeypatch.setattr("app.auth.redis.get_redis_client", fake_get_redis_client)

    result = await is_blacklisted("abc123")
    assert result is False

