import time
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, IPvAnyAddress
import threading
from collections import defaultdict
import asyncio
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SECRET_KEY = "your-secret-key-keep-it-safe"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    role: str

class UserInDB(User):
    hashed_password: str

fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("adminpass"),
        "role": "admin"
    },
    "user": {
        "username": "user",
        "hashed_password": pwd_context.hash("userpass"),
        "role": "user"
    }
}

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db: dict, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db: dict, username: str, password: str):
    user = get_user(fake_db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=username)
    if user is None:
        raise credentials_exception
    return user

async def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# --- Anomaly Detection and Login Abuse Tracker ---
REQUEST_THRESHOLD = 3
TIME_WINDOW = 60
HEALING_INTERVAL = 3600
BAN_DURATION = 300

class AnomalyDetector:
    def __init__(self):
        self.request_logs = defaultdict(list)
        self.suspicious_ips = {}   # General anomaly suspicious IPs
        self.blocked_ips = {}      # General anomaly blocked IPs
        self.failed_login_attempts = {}       # For wrong credentials
        self.last_failed_attempt = {}         # Timestamp for last failed attempt
        self.successful_login_logs = defaultdict(list)  # Timestamps for successful logins
        self.successful_login_block = {}      # IP : block expiration timestamp for too many successes
        self.lock = threading.RLock()

    def log_request(self, ip: str):
        with self.lock:
            now = time.time()
            self.request_logs[ip].append(now)
            self.request_logs[ip] = [t for t in self.request_logs[ip] if now - t < TIME_WINDOW]

    def is_blocked(self, ip: str) -> bool:
        with self.lock:
            if ip in self.blocked_ips and time.time() - self.blocked_ips[ip] < BAN_DURATION:
                return True
            elif ip in self.blocked_ips:
                del self.blocked_ips[ip]
            return False

    def check_threshold(self, ip: str) -> bool:
        with self.lock:
            recent_requests = len([t for t in self.request_logs[ip] if time.time() - t < TIME_WINDOW])
            if recent_requests > REQUEST_THRESHOLD:
                self.blocked_ips[ip] = time.time()
                return True
            if recent_requests > REQUEST_THRESHOLD * 0.7:
                self.suspicious_ips[ip] = time.time()
            elif ip in self.suspicious_ips:
                del self.suspicious_ips[ip]
            return False

    def self_heal(self):
        with self.lock:
            now = time.time()
            self.blocked_ips = {ip: ts for ip, ts in self.blocked_ips.items() if now - ts < BAN_DURATION}
            self.suspicious_ips = {ip: ts for ip, ts in self.suspicious_ips.items() if now - ts < TIME_WINDOW}
            cleanup_threshold = 3600  # 1 hour cleanup
            for ip in list(self.last_failed_attempt.keys()):
                if now - self.last_failed_attempt[ip] > cleanup_threshold:
                    del self.failed_login_attempts[ip]
                    del self.last_failed_attempt[ip]
            for ip in list(self.successful_login_logs.keys()):
                self.successful_login_logs[ip] = [t for t in self.successful_login_logs[ip] if now - t < TIME_WINDOW]
                if not self.successful_login_logs[ip]:
                    self.successful_login_block.pop(ip, None)

detector = AnomalyDetector()

class RequestData(BaseModel):
    ip_address: IPvAnyAddress
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None

async def self_healing_task():
    while True:
        detector.self_heal()
        await asyncio.sleep(HEALING_INTERVAL)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(self_healing_task())

# --- /token Endpoint ---
@app.post("/token", response_model=Token)
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    ip = request.client.host
    current_time = time.time()

    with detector.lock:
        # Check if IP is blocked due to too many successful logins.
        if ip in detector.successful_login_block and current_time < detector.successful_login_block[ip]:
            remaining = int(detector.successful_login_block[ip] - current_time)
            raise HTTPException(
                status_code=429,
                detail=f"Too many successful logins. Please try again in {remaining} seconds."
            )
        # Check brute-force (failed login) lockout.
        attempts = detector.failed_login_attempts.get(ip, 0)
        if attempts >= 5:
            buffer_time = 60 * (attempts - 4)  # 60 seconds per extra failed attempt.
            remaining = int(buffer_time - (current_time - detector.last_failed_attempt[ip]))
            if remaining > 0:
                # Add IP to both blocked and suspicious lists.
                detector.blocked_ips[ip] = current_time
                detector.suspicious_ips[ip] = current_time
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many unsuccessful attempts. Please try again in {remaining} seconds."
                )
        # Optionally, check general anomaly detection.
        if detector.is_blocked(ip):
            raise HTTPException(
                status_code=403,
                detail="IP blocked: Too many login attempts"
            )

    # Log the login attempt.
    detector.log_request(ip)

    # Authenticate the user.
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        with detector.lock:
            detector.failed_login_attempts[ip] = detector.failed_login_attempts.get(ip, 0) + 1
            detector.last_failed_attempt[ip] = current_time
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        with detector.lock:
            # Successful login: reset failed attempts.
            detector.failed_login_attempts[ip] = 0
            detector.successful_login_logs[ip].append(current_time)
            detector.successful_login_logs[ip] = [t for t in detector.successful_login_logs[ip] if current_time - t < TIME_WINDOW]
            count = len(detector.successful_login_logs[ip])
            # If exactly 4 successful logins within TIME_WINDOW, mark as suspicious.
            if count == 4:
                detector.suspicious_ips[ip] = current_time
                # Ensure the IP is not in blocked_ips yet.
                if ip in detector.blocked_ips:
                    del detector.blocked_ips[ip]
            # If 5 or more successful logins within TIME_WINDOW, block the IP.
            elif count >= 5:
                extra = count - 4
                block_duration = 60 * extra
                detector.successful_login_block[ip] = current_time + block_duration
                detector.blocked_ips[ip] = current_time  # Add to blocked list.
                # Remove from suspicious list if present.
                if ip in detector.suspicious_ips:
                    del detector.suspicious_ips[ip]
                remaining = int(detector.successful_login_block[ip] - current_time)
                raise HTTPException(
                    status_code=429,
                    detail=f"Suspicious login activity detected. Please try again in {remaining} seconds."
                )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/validate-token")
async def validate_token(current_user: User = Depends(get_current_user)):
    return {"valid": True, "role": current_user.role}

# --- /dashboard-data Endpoint ---
@app.get("/dashboard-data")
async def dashboard_data(current_user: User = Depends(get_current_user)):
    with detector.lock:
        current_time = time.time()
        brute_force_ips = [
            {
                "ip": ip,
                "remaining": int(60 * (attempts - 4) - (current_time - detector.last_failed_attempt[ip]))
            }
            for ip, attempts in detector.failed_login_attempts.items()
            if attempts >= 5 and current_time - detector.last_failed_attempt[ip] < 60 * (attempts - 4)
        ]
        successful_block_ips = [
            {
                "ip": ip,
                "remaining": int(exp - current_time)
            }
            for ip, exp in detector.successful_login_block.items()
            if current_time < exp
        ]
        stats = {
            "total_ips": len(detector.request_logs),
            "blocked_ips": list(detector.blocked_ips.keys()),
            "suspicious_ips": list(detector.suspicious_ips.keys()),
            "request_counts": {ip: len(times) for ip, times in detector.request_logs.items()},
            "brute_force_ips": brute_force_ips,
            "successful_block_ips": successful_block_ips
        }
    return stats

# --- HTML Template Endpoints ---
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/admin/stats")
async def admin_stats(admin: User = Depends(require_admin)):
    with detector.lock:
        return {
            "total_ips": len(detector.request_logs),
            "blocked_ips": list(detector.blocked_ips.keys()),
            "system_health": "OK",
            "active_threshold": REQUEST_THRESHOLD
        }

@app.get("/user-home", response_class=HTMLResponse)
async def user_home(request: Request):
    return templates.TemplateResponse("user.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem"
    )
