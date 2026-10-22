
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from pwdlib import PasswordHash


SECRET_KEY = os.getenv("JWT_SECRET")

if not SECRET_KEY:
    raise RuntimeError("Please set the JWT_SECRET environment variable")

ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30

app = FastAPI(
    title="Security REST API",
    description="REST API with password hashing and JWT authentication",
    version="1.0.0",
)

DB_PATH = Path(__file__).with_name("users.db")
password_hash = PasswordHash.recommended()
bearer_scheme = HTTPBearer()

def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with closing(get_db()) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        db.commit()


init_db()

class RegisterRequest(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=50,
        pattern=r"^[a-zA-Z0-9_]+$",
    )
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)


def escape_html(value: str) -> str:
    """Escape HTML-sensitive characters for HTML output contexts."""
    return escape(value, quote=True)


def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "iat", "exp"]},
        )

        user_id = int(payload["sub"])

    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    with closing(get_db()) as db:
        user = db.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return dict(user)

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    hashed_password = password_hash.hash(data.password)

    try:
        with closing(get_db()) as db:
            cursor = db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                """,
                (data.username, hashed_password),
            )
            db.commit()

            return {
                "id": cursor.lastrowid,
                "username": data.username,
            }

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )


@app.post("/auth/login")
def login(data: LoginRequest):
    with closing(get_db()) as db:
        user = db.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (data.username,),
        ).fetchone()

    if user is None or not password_hash.verify(
        data.password,
        user["password_hash"],
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user["id"], user["username"])

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@app.get("/api/data")
def get_data(user: dict = Depends(get_current_user)):
    return {
        "message": "Authenticated access granted",
        "requested_by": user["username"],
        "items": [
            {"id": 1, "title": "Security basics"},
            {"id": 2, "title": "REST API protection"},
        ],
    }

@app.get("/me")
def get_me(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
    }

