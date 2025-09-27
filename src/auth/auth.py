"""Authentication module for the application."""
from datetime import datetime, timedelta
from typing import Optional
import json
from pathlib import Path
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Security constants
SECRET_KEY = "your-secret-key-keep-it-secret"  # In production, use proper secret management
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Path to users file
USERS_FILE = Path(__file__).parent / "users.json"

class Token(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Token data model."""
    email: Optional[str] = None

class User(BaseModel):
    """User model."""
    email: str
    full_name: Optional[str] = None
    role: str = "student"

class UserInDB(User):
    """User model with hashed password."""
    password: str

def get_user(email: str) -> Optional[UserInDB]:
    """Get user from the JSON file."""
    try:
        with open(USERS_FILE, "r") as f:
            data = json.load(f)
            teachers = data.get("teachers", [])
            for teacher in teachers:
                if teacher["email"] == email:
                    return UserInDB(**teacher)
    except (json.JSONDecodeError, FileNotFoundError):
        return None
    return None

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str) -> Optional[UserInDB]:
    """Authenticate a user."""
    user = get_user(email)
    if not user:
        return None
    if not verify_password(password, user.password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get current user from token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_teacher(current_user: User = Depends(get_current_user)) -> User:
    """Check if current user is a teacher."""
    if current_user.role != "teacher":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only teachers can perform this action"
        )
    return current_user