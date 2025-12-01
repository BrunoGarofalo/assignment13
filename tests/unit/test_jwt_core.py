import pytest
import asyncio
from datetime import timedelta
from uuid import uuid4
from fastapi import HTTPException, status

from app.auth.jwt import (
    create_token,
    decode_token,
    get_current_user,
    get_password_hash
)
from app.schemas.token import TokenType
from app.models.user import User


# --------------------------------------------------------------------
#                 decode_token() MISSING TESTS
# --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_decode_valid_access_token(monkeypatch):
    """Ensure decode_token() correctly decodes a valid ACCESS token."""
    user_id = str(uuid4())
    token = create_token(user_id, TokenType.ACCESS)

    # mock blacklist to always return False
    monkeypatch.setattr(
        "app.auth.jwt.is_blacklisted",
        lambda jti: asyncio.sleep(0, result=False)
    )

    payload = await decode_token(token, TokenType.ACCESS)

    assert payload["sub"] == user_id
    assert payload["type"] == "access"


@pytest.mark.asyncio
async def test_decode_token_wrong_type(monkeypatch):
    """Using an ACCESS token where REFRESH is expected should raise."""
    user_id = str(uuid4())
    token = create_token(user_id, TokenType.ACCESS)

    monkeypatch.setattr(
        "app.auth.jwt.is_blacklisted",
        lambda jti: asyncio.sleep(0, result=False)
    )

    with pytest.raises(Exception):
        await decode_token(token, TokenType.REFRESH)


@pytest.mark.asyncio
async def test_decode_expired_access_token(monkeypatch):
    """Expired token must raise an Unauthorized error."""
    user_id = str(uuid4())

    # token expired 5 seconds ago
    token = create_token(
        user_id,
        TokenType.ACCESS,
        expires_delta=timedelta(seconds=-5)
    )

    monkeypatch.setattr(
        "app.auth.jwt.is_blacklisted",
        lambda jti: asyncio.sleep(0, result=False)
    )

    with pytest.raises(Exception):
        await decode_token(token, TokenType.ACCESS)


@pytest.mark.asyncio
async def test_decode_blacklisted_token(monkeypatch):
    """If token's jti is blacklisted, decoding should fail."""
    user_id = str(uuid4())
    token = create_token(user_id, TokenType.ACCESS)

    # Force blacklist check to return TRUE
    monkeypatch.setattr(
        "app.auth.jwt.is_blacklisted",
        lambda jti: asyncio.sleep(0, result=True)
    )

    with pytest.raises(Exception):
        await decode_token(token, TokenType.ACCESS)


# --------------------------------------------------------------------
#               get_current_user() MISSING TESTS
# --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_current_user_success(monkeypatch, db_session):
    """Valid ACCESS token should return user instance."""
    user = User(
        first_name="John",
        last_name="Doe",
        email="john@example.com",
        username="johndoe",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_token(str(user.id), TokenType.ACCESS)

    monkeypatch.setattr(
        "app.auth.jwt.is_blacklisted",
        lambda jti: asyncio.sleep(0, result=False)
    )

    returned_user = await get_current_user(token=token, db=db_session)

    assert returned_user.id == user.id
    assert returned_user.username == "johndoe"


@pytest.mark.asyncio
async def test_get_current_user_user_not_found(monkeypatch, db_session):
    """Token valid but no user in DB → must raise 404."""
    fake_id = str(uuid4())
    token = create_token(fake_id, TokenType.ACCESS)

    monkeypatch.setattr(
        "app.auth.jwt.is_blacklisted",
        lambda jti: asyncio.sleep(0, result=False)
    )

    with pytest.raises(Exception):
        await get_current_user(token=token, db=db_session)


@pytest.mark.asyncio
async def test_get_current_user_inactive_user(monkeypatch, db_session):
    """Inactive users must be rejected."""
    user = User(
        first_name="Inactive",
        last_name="User",
        email="inactive@example.com",
        username="inactiveuser",
        hashed_password=get_password_hash("Password123!"),
        is_active=False,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_token(str(user.id), TokenType.ACCESS)

    monkeypatch.setattr(
        "app.auth.jwt.is_blacklisted",
        lambda jti: asyncio.sleep(0, result=False)
    )

    with pytest.raises(Exception):
        await get_current_user(token=token, db=db_session)


@pytest.mark.asyncio
async def test_decode_token_wrong_type():
    token = create_token("user123", TokenType.ACCESS)

    with pytest.raises(HTTPException) as exc:
        await decode_token(token, TokenType.REFRESH)

    assert exc.value.status_code == 401
    assert "Invalid token type" in exc.value.detail or "Could not validate credentials" in exc.value.detail




