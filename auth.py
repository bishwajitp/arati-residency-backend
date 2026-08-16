import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

import jwt
from bson import ObjectId
from fastapi import Depends, Header, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient

from database import get_db

SECRET_KEY = os.getenv("SECRET_KEY", "arati-residency-change-me")
ALGORITHM = "HS256"
TOKEN_EXPIRY_DAYS = 7

_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return (
        base64.b64encode(salt).decode()
        + "$"
        + base64.b64encode(dk).decode()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, dk_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
        return hmac.compare_digest(base64.b64encode(dk).decode(), dk_b64)
    except Exception:
        return False


def create_token(user_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRY_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, ALGORITHM)


async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    token = authorization[len("Bearer "):]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")

    user_id = payload.get("sub")
    db = get_db()
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(401, "User no longer exists")
    return user


def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin access required")
    return user