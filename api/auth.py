"""
Authentication Module

JWT-based authentication for the API.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from core.config import get_config

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


class TokenData(BaseModel):
    """Token payload data."""
    username: str
    exp: datetime


class Token(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(
    username: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token."""
    config = get_config()

    if expires_delta is None:
        expires_delta = timedelta(minutes=config.api.access_token_expire_minutes)

    expire = datetime.utcnow() + expires_delta
    payload = {"sub": username, "exp": expire}

    return jwt.encode(payload, config.api.secret_key, algorithm="HS256")


def decode_token(token: str) -> TokenData:
    """Decode and validate a JWT token."""
    config = get_config()

    try:
        payload = jwt.decode(token, config.api.secret_key, algorithms=["HS256"])
        username = payload.get("sub")
        exp = payload.get("exp")

        if username is None:
            raise JWTError("Invalid token payload")

        return TokenData(username=username, exp=datetime.fromtimestamp(exp))

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """Get the current authenticated user from the token."""
    token_data = decode_token(credentials.credentials)

    if token_data.exp < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data.username


def create_token_response(username: str) -> Token:
    """Create a token response for a user."""
    config = get_config()
    expires_in = config.api.access_token_expire_minutes * 60

    return Token(
        access_token=create_access_token(username),
        expires_in=expires_in,
    )
