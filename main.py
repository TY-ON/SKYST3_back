# uvicorn main:app --reload
# http://127.0.0.1:8000/docs

from fastapi import FastAPI, HTTPException, Depends, Body
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.hash import bcrypt
import os
from dotenv import load_dotenv
from jose import JWTError, jwt
from datetime import datetime, timedelta

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# Database setup
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    instrument = Column(String, nullable=False)
    zip_code = Column(Integer, nullable=False)

Base.metadata.create_all(bind=engine)

# Schemas
class RegisterRequest(BaseModel):
    username: str
    password: str
    name: str
    email: EmailStr
    instrument: str
    zip_code: int

class LoginRequest(BaseModel):
    username: str
    password: str

class FindPasswordRequest(BaseModel):
    username: str
    email: EmailStr

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# OAuth2 scheme
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")


# jwt token creation
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = verify_access_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# FastAPI app
app = FastAPI()

@app.post("/api/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
    """
    [Register API]
    POST /api/register
    Registers a new user.

    Allowed instruments:
    - keyboard
    - vocal
    - bass
    - drum
    - guitar
    - etc

    Request Body Example (JSON):
    {
        "username": "amugae_kim",
        "password": "securepassword123",
        "name": "nickname",
        "email": "kim@example.com",
        "instrument": "guitar",
        "zip_code": 90210
    }

    Responses:
    - 200 OK: User registered successfully
    - 400 Bad Request: Username or email already exists
    """
    
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = bcrypt.hash(data.password)
    user = User(
        username=data.username,
        password=hashed_password,
        name=data.name,
        email=data.email,
        instrument=data.instrument,
        zip_code=data.zip_code
    )
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/api/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    """
    [Login API]
    POST /api/login
    Authenticates an existing user with username and password.

    Request Body Example (JSON):
    {
        "username": "amugae_kim",
        "password": "securepassword123"
    }

    Responses:
    - 200 OK: Returns a welcome message
    - 401 Unauthorized: Invalid username or password
    - Sets a jwt token in the session cookie
    """
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not bcrypt.verify(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # JWT 토큰 생성 
    token_data = {
        "sub": user.username
    }
    access_token = create_access_token(token_data)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "name": user.name,
            "instrument": user.instrument,
            "zip_code": user.zip_code
        }
    }

@app.get("/api/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "name": current_user.name,
        "instrument": current_user.instrument,
        "zip_code": current_user.zip_code
    }

@app.post("/api/find-password")
def find_password(data: FindPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username, User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # add if needed (currently just skeleton)
    return {"message": "Password reset link sent to your email (simulation)"}
