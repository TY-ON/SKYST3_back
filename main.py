# uvicorn main:app --reload
# http://127.0.0.1:8000/docs

from fastapi import FastAPI, HTTPException, Depends, Body
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.hash import bcrypt

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

Base.metadata.create_all(bind=engine)

# Schemas
class RegisterRequest(BaseModel):
    username: str
    password: str
    name: str
    email: EmailStr
    instrument: str

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

# FastAPI app
app = FastAPI()

@app.post("/api/register")
def register(data: RegisterRequest, db: Session = Depends(get_db)):
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
        instrument=data.instrument
    )
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/api/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not bcrypt.verify(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": f"Welcome {user.name}"}

@app.post("/api/find-password")
def find_password(data: FindPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == data.username, User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # In a real application, you'd send a password reset email or similar secure process.
    return {"message": "Password reset link sent to your email (simulation)"}
