# uvicorn main:app --reload
# http://127.0.0.1:8000/docs

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi import Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.hash import bcrypt
import os
from dotenv import load_dotenv
from jose import JWTError, jwt
from datetime import datetime, timedelta
from kozip import KoZIP

from typing import Optional, Literal
from pydantic import Field
import random
import string
from datetime import datetime

AREA_MAP = {
    "area1": ["종로구", "중구", "용산구"],
    "area2": ["서대문구", "은평구", "마포구"],
    "area3": ["서초구", "강남구", "송파구", "강동구"],
    "area4": ["성북구", "광진구", "동대문구", "중랑구", "성동구"],
    "area5": ["양천구", "강서구", "구로구", "금천구", "영등포구", "동작구", "관악구"],
    "area6": ["강북구", "도봉구", "노원구", "은평구"],
}

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
    zip_code = Column(String, nullable=False)


class Room(Base):
    __tablename__ = "room"
    id = Column(Integer, primary_key=True, index=True)
    room_code = Column(String(8), unique=True, index=True, nullable=False)
    start_date = Column(String, nullable=False)  # YYYY-MM-DD
    end_date = Column(String, nullable=False)    # YYYY-MM-DD
    time_slot = Column(String, nullable=False)  # morning/afternoon/evening
    genre = Column(String, nullable=False)
    part_random = Column(Integer, default=1)  # 1 if true, 0 otherwise
    member_count = Column(Integer, default=0)
    instruments = Column(String, nullable=True)  # comma-separated assigned instruments

class RoomJoin(Base):
    __tablename__ = "room_join"
    id = Column(Integer, primary_key=True, index=True)
    room_code = Column(String, nullable=False)
    user_id = Column(Integer, nullable=False)
    instrument = Column(String, nullable=True)
    start_date = Column(String, nullable=False)
    end_date = Column(String, nullable=False)

class JoinRoomRequest(BaseModel):
    room_code: str
    instrument: Optional[str] = None

Base.metadata.create_all(bind=engine)

# Schemas
class RegisterRequest(BaseModel):
    username: str
    password: str
    name: str
    email: EmailStr
    instrument: str
    zip_code: str

class LoginRequest(BaseModel):
    username: str
    password: str

class FindPasswordRequest(BaseModel):
    username: str
    email: EmailStr

class QueueRequest(BaseModel):
    start_date: str  # YYYY-MM-DD
    end_date: str    # YYYY-MM-DD
    time_slot: Literal["morning", "afternoon", "evening"]
    genre: str
    instrument: Optional[str] = None  # only for part_random

def generate_room_code():
    return ''.join(random.choices(string.ascii_uppercase, k=8))

def room_instruments_to_list(instr: str) -> list:
    return instr.split(",") if instr else []

def list_to_room_instruments(instr_list: list) -> str:
    return ",".join(instr_list)

def date_overlap(a_start, a_end, b_start, b_end):
    return a_start <= b_end and b_start <= a_end

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
    user = db.query(User).filter(User.username == payload.get("username")).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def get_area_by_gu(gu_name: str):
    for area, gu_list in AREA_MAP.items():
        if gu_name in gu_list:
            return area
    return None



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
def login(data: LoginRequest, db: Session = Depends(get_db), response: Response = None):
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
    - access_token should be set in Authorization: Bearer
    """
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not bcrypt.verify(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # JWT 토큰 생성 
    token_data = {
        "username": user.username
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

@app.get("/api/get_user_area")
def get_user_area(zip_code: str):

    try:
        k = KoZIP()
        addr = k.ZIPtoAddr(zip_code, depth=2, format="list")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid zipcode")

    gu_name = addr[0][1]

    area = get_area_by_gu(gu_name)
    if not area:
        raise HTTPException(status_code=404, detail="Area not found for this zipcode")

    return {"area": area, "gu": gu_name}

@app.post("/api/queue/part_random")
def part_random_queue(req: QueueRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_start = datetime.strptime(req.start_date, "%Y-%m-%d").date()
    user_end = datetime.strptime(req.end_date, "%Y-%m-%d").date()

    for room in db.query(Room).filter(Room.time_slot == req.time_slot,
                                      Room.genre == req.genre,
                                      Room.part_random == 1).all():

        joins = db.query(RoomJoin).filter(RoomJoin.room_code == room.room_code).all()
        valid = True
        for j in joins:
            member_start = datetime.strptime(j.start_date, "%Y-%m-%d").date()
            member_end = datetime.strptime(j.end_date, "%Y-%m-%d").date()
            if not date_overlap(user_start, user_end, member_start, member_end):
                valid = False
                break

        assigned = room_instruments_to_list(room.instruments)
        if valid and room.member_count < 5 and req.instrument not in assigned:
            assigned.append(req.instrument)
            room.member_count += 1
            room.instruments = list_to_room_instruments(assigned)

            db.add(RoomJoin(room_code=room.room_code, user_id=current_user.id, instrument=req.instrument,
                            start_date=req.start_date, end_date=req.end_date))
            db.commit()
            return {"message": "Joined existing room", "room_code": room.room_code}

    # Create room
    new_code = generate_room_code()
    new_room = Room(
        room_code=new_code,
        start_date=req.start_date,
        end_date=req.end_date,
        time_slot=req.time_slot,
        genre=req.genre,
        part_random=1,
        member_count=1,
        instruments=req.instrument
    )
    db.add(new_room)
    db.commit()
    db.add(RoomJoin(room_code=new_code, user_id=current_user.id, instrument=req.instrument,
                    start_date=req.start_date, end_date=req.end_date))
    db.commit()
    return {"message": "Created and joined new room", "room_code": new_code}

@app.post("/api/queue/true_random")
def true_random_queue(req: QueueRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_start = datetime.strptime(req.start_date, "%Y-%m-%d").date()
    user_end = datetime.strptime(req.end_date, "%Y-%m-%d").date()

    for room in db.query(Room).filter(Room.time_slot == req.time_slot,
                                      Room.genre == req.genre,
                                      Room.part_random == 0).all():

        joins = db.query(RoomJoin).filter(RoomJoin.room_code == room.room_code).all()
        valid = True
        for j in joins:
            member_start = datetime.strptime(j.start_date, "%Y-%m-%d").date()
            member_end = datetime.strptime(j.end_date, "%Y-%m-%d").date()
            if not date_overlap(user_start, user_end, member_start, member_end):
                valid = False
                break

        if valid and room.member_count < 5:
            room.member_count += 1
            db.add(RoomJoin(room_code=room.room_code, user_id=current_user.id,
                            start_date=req.start_date, end_date=req.end_date))
            db.commit()
            return {"message": "Joined existing room", "room_code": room.room_code}

    # Create room
    new_code = generate_room_code()
    new_room = Room(
        room_code=new_code,
        start_date=req.start_date,
        end_date=req.end_date,
        time_slot=req.time_slot,
        genre=req.genre,
        part_random=0,
        member_count=1
    )
    db.add(new_room)
    db.commit()
    db.add(RoomJoin(room_code=new_code, user_id=current_user.id,
                    start_date=req.start_date, end_date=req.end_date))
    db.commit()
    return {"message": "Created and joined new room", "room_code": new_code}

@app.post("/api/room/join")
def join_room_direct(req: JoinRoomRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    room = db.query(Room).filter(Room.room_code == req.room_code).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    if room.member_count >= 5:
        raise HTTPException(status_code=400, detail="Room is full")

    if room.part_random:
        if not req.instrument:
            raise HTTPException(status_code=400, detail="Instrument is required for part_random room")
        assigned = room_instruments_to_list(room.instruments)
        if req.instrument in assigned:
            raise HTTPException(status_code=400, detail="Instrument already taken")
        assigned.append(req.instrument)
        room.instruments = list_to_room_instruments(assigned)

    room.member_count += 1
    db.add(RoomJoin(room_code=req.room_code, user_id=current_user.id,
                    instrument=req.instrument, start_date=room.start_date, end_date=room.end_date))
    db.commit()
    return {"message": "Successfully joined room", "room_code": req.room_code}

@app.get("/api/room/people_count")
def get_room_people_count(room_code: str, db: Session = Depends(get_db)):
    room = db.query(Room).filter(Room.room_code == room_code).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    return {"room_code": room_code, "people_count": room.member_count}