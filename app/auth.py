import secrets

import bcrypt
from fastapi import Request, HTTPException, status
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlmodel import Session, select

from app.config import (
    SECRET_KEY,
    SESSION_COOKIE_NAME,
    SESSION_MAX_AGE_SECONDS,
    ADMIN_USERNAME,
    ADMIN_PASSWORD,
)
from app.models import User

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="netguard-session")


def hash_password(password: str) -> str:
    # bcrypt has a hard 72-byte input limit; truncate defensively rather
    # than erroring on unusually long passphrases.
    pw_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    pw_bytes = password.encode("utf-8")[:72]
    try:
        return bcrypt.checkpw(pw_bytes, password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_session_cookie_value(username: str) -> str:
    return _serializer.dumps({"u": username})


def read_session_cookie_value(value: str) -> str | None:
    try:
        data = _serializer.loads(value, max_age=SESSION_MAX_AGE_SECONDS)
        return data.get("u")
    except (BadSignature, SignatureExpired):
        return None


def get_current_username(request: Request) -> str | None:
    raw = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw:
        return None
    return read_session_cookie_value(raw)


def require_login(request: Request) -> str:
    username = get_current_username(request)
    if not username:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return username


def bootstrap_admin_if_needed(session: Session) -> str | None:
    """
    Create the first admin user if the users table is empty.
    Returns the generated password if one had to be auto-generated, else None.
    Idempotent: safe to call on every startup.
    """
    existing = session.exec(select(User)).first()
    if existing:
        return None

    password = ADMIN_PASSWORD or secrets.token_urlsafe(12)
    user = User(
        username=ADMIN_USERNAME,
        password_hash=hash_password(password),
        is_admin=True,
    )
    session.add(user)
    session.commit()
    return None if ADMIN_PASSWORD else password
