"""
Camera Monitor Backend - FastAPI Application
Provides RTSP camera status monitoring with encrypted configuration storage.
"""

import json
import asyncio
import logging
import subprocess
import sys
import os
import secrets
import time
import threading
import bcrypt
import io
import pandas as pd


from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from contextlib import asynccontextmanager

from database import generate_report_data
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, Response
from cryptography.fernet import Fernet
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from notifier import EmailNotifier
from database import (
    init_db,
    log_status_change,
    get_camera_history,
    get_camera_uptime,
    get_all_cameras_summary,
)


# =============================================================================
# PLATFORM COMPATIBILITY
# =============================================================================
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================
KEY_FILE = "secret.key"
CAMERAS_ENC = "cameras.enc"
CHECK_INTERVAL_SECONDS = 300
FFPROBE_TIMEOUT_SECONDS = 10

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", encoding="utf-8", mode="a"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Security logger
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
if not security_logger.handlers:
    security_handler = logging.FileHandler("security.log", encoding="utf-8")
    security_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    security_logger.addHandler(security_handler)

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in .env file!")

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD not set in .env file!")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")
SESSION_EXPIRY = int(os.getenv("SESSION_EXPIRY", "86400"))
COOKIE_NAME = "cam_session"

HASHED_PASSWORD = bcrypt.hashpw(
    ADMIN_PASSWORD.encode("utf-8"), bcrypt.gensalt()
).decode("utf-8")
logger.info("✅ Admin password hashed with bcrypt")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    except Exception as e:
        logger.debug(f"Password verification error: {e}")
        return False


cookie_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cam-monitor-session")
SESSIONS: Dict[str, dict] = {}

LOGIN_ATTEMPTS: Dict[str, list] = {}
MAX_LOGIN_ATTEMPTS = 5
RATE_WINDOW_SECONDS = 60

active_streams = 0
streams_lock = threading.Lock()
MAX_CONCURRENT_STREAMS = 5


def check_rate_limit(ip: str) -> bool:
    now = time.time()
    if ip in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = [
            t for t in LOGIN_ATTEMPTS[ip] if now - t < RATE_WINDOW_SECONDS
        ]
    else:
        LOGIN_ATTEMPTS[ip] = []

    if len(LOGIN_ATTEMPTS[ip]) >= MAX_LOGIN_ATTEMPTS:
        return False

    LOGIN_ATTEMPTS[ip].append(now)
    return True


def sign_session_token(token: str) -> str:
    return cookie_serializer.dumps(token, salt="session")


def verify_signed_token(signed: str) -> Optional[str]:
    try:
        return cookie_serializer.loads(signed, salt="session", max_age=SESSION_EXPIRY)
    except (BadSignature, SignatureExpired):
        return None


async def get_current_session(request: Request) -> dict:
    signed_token = request.cookies.get(COOKIE_NAME)
    if not signed_token:
        raise HTTPException(status_code=401, detail="No session")

    token = verify_signed_token(signed_token)
    if not token or token not in SESSIONS:
        raise HTTPException(status_code=401, detail="Invalid session")

    session = SESSIONS[token]

    if time.time() - session["created_at"] > SESSION_EXPIRY:
        SESSIONS.pop(token, None)
        raise HTTPException(status_code=401, detail="Session expired")

    return session


async def require_auth(session: dict = Depends(get_current_session)):
    return True


# =============================================================================
# DATA STORE
# =============================================================================
class CameraStore:
    def __init__(self):
        self.cameras: List[Dict] = []
        self.statuses: Dict[int, str] = {}
        self._lock = asyncio.Lock()

    def load_from_file(self) -> bool:
        try:
            cipher = Fernet(Path(KEY_FILE).read_bytes())
            encrypted_data = Path(CAMERAS_ENC).read_bytes()
            decrypted = cipher.decrypt(encrypted_data)

            self.cameras = json.loads(decrypted.decode("utf-8"))
            self.statuses = {cam["id"]: "offline" for cam in self.cameras}

            logger.info(f"Loaded {len(self.cameras)} cameras from configuration")
            return True

        except FileNotFoundError as e:
            logger.error(f"Configuration file not found: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to load camera configuration: {e}")
            return False

    def update_status(self, camera_id: int, status: str) -> None:
        self.statuses[camera_id] = status

    def get_all_for_api(self) -> List[Dict]:
        result = []
        for cam in self.cameras:
            camera_id = cam.get("id")
            current_status = self.statuses.get(camera_id, "offline")

            safe_camera = {
                "id": camera_id,
                "name": cam.get("location", f"Camera {camera_id}"),
                "object": cam.get("object", "Unassigned"),
                "location": cam.get("type", ""),
                "ip": self._extract_safe_address(cam.get("url", "")),
                "status": current_status,
                "enabled": cam.get("enabled", True),
            }
            result.append(safe_camera)
        return result

    def _extract_safe_address(self, url: str) -> str:
        if not url:
            return "unknown"
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            host = parsed.hostname or "unknown"
            port = parsed.port
            return f"{host}:{port}" if port else host
        except Exception:
            return "invalid_url"

    def get_camera_url(self, camera_id: int) -> str:
        for cam in self.cameras:
            if cam.get("id") == camera_id:
                return cam.get("url", "")
        return ""


camera_store = CameraStore()
# Initialize SQLite database
init_db()
for cam in camera_store.cameras:
    status = camera_store.statuses.get(cam["id"], "offline")
    log_status_change(cam["id"], status)

# =============================================================================
# EMAIL NOTIFICATIONS
# =============================================================================
email_notifier = EmailNotifier()
EMAIL_COOLDOWN = int(os.getenv("EMAIL_COOLDOWN_SECONDS", 300))  # 5 minutes default
last_email_time: Dict[int, float] = {}


# =============================================================================
# CAMERA STATUS CHECKING
# =============================================================================
def _check_camera_sync(url: str, timeout: int) -> bool:
    cmd = [
        "ffprobe",
        "-v",
        "error",
        "-show_entries",
        "stream=codec_name",
        "-of",
        "json",
        "-timeout",
        str(timeout * 1_000_000),
        "-rtsp_transport",
        "tcp",
        url,
    ]

    try:
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 1, creationflags=creation_flags
        )

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout.decode())
            return bool(data.get("streams"))
        return False

    except subprocess.TimeoutExpired:
        logger.debug(f"Timeout checking camera: {url[:60]}...")
        return False
    except FileNotFoundError:
        logger.error("ffprobe executable not found. Ensure ffmpeg is installed.")
        return False
    except Exception as e:
        logger.debug(f"Error during camera check: {type(e).__name__}: {e}")
        return False


async def check_camera_async(url: str, timeout: int) -> bool:
    return await asyncio.to_thread(_check_camera_sync, url, timeout)


async def monitoring_loop():
    """
    Background task: periodically checks all enabled cameras,
    updates statuses, logs history, and sends notifications.
    """
    while True:
        try:
            # Get list of enabled cameras (thread-safe copy)
            async with camera_store._lock:
                active_cameras = [
                    c for c in camera_store.cameras if c.get("enabled", True)
                ]

            if not active_cameras:
                logger.info("No active cameras to check, waiting...")
                await asyncio.sleep(CHECK_INTERVAL_SECONDS)
                continue

            logger.info(f"Starting status check for {len(active_cameras)} cameras...")
            start_time = datetime.now()

            # Check cameras sequentially (reliable, predictable resource usage)
            for idx, camera in enumerate(active_cameras, 1):
                cam_id = camera["id"]
                url = camera["url"]

                logger.debug(
                    f"[{idx}/{len(active_cameras)}] Checking camera {cam_id}..."
                )

                # Check camera availability
                is_online = await check_camera_async(
                    url, timeout=FFPROBE_TIMEOUT_SECONDS
                )
                new_status = "online" if is_online else "offline"

                # Update status in store (thread-safe) and get old status
                async with camera_store._lock:
                    old_status = camera_store.statuses.get(cam_id, "offline")
                    camera_store.update_status(cam_id, new_status)

                # Log status change to history if it changed
                if new_status != old_status:
                    log_status_change(cam_id, new_status)
                    logger.info(
                        f"📝 Status change logged: Camera {cam_id} {old_status} → {new_status}"
                    )

                # Log to console
                status_symbol = "✓" if is_online else "✗"
                logger.info(
                    f"  [{status_symbol}] Camera {cam_id}: {new_status.upper()}"
                )

                # === EMAIL NOTIFICATION LOGIC ===
                if new_status != old_status:
                    # Build detailed camera label for email
                    cam_obj = camera.get("object", "Неизвестный объект")
                    cam_loc = camera.get("location", f"Камера {cam_id}")
                    cam_type = camera.get("type", "Обзорная камера")
                    cam_ip = camera.get("ip", "нет IP")
                    camera_label = f"{cam_obj}, {cam_loc} {cam_type} {cam_ip}"

                    now = time.time()

                    # Check cooldown (don't spam emails)
                    if now - last_email_time.get(cam_id, 0) < EMAIL_COOLDOWN:
                        logger.debug(f"📧 Email cooldown active for {camera_label}")
                    else:
                        error_detail = "Камера недоступна" if not is_online else ""
                        asyncio.create_task(
                            email_notifier.send_camera_alert(
                                camera_label, new_status, error_detail
                            )
                        )
                        last_email_time[cam_id] = now
                        logger.info(
                            f"📧 Email alert queued: {camera_label} → {new_status}"
                        )

            # Summary statistics for this cycle
            elapsed = (datetime.now() - start_time).total_seconds()
            online_count = sum(
                1 for s in camera_store.statuses.values() if s == "online"
            )
            total_count = len(camera_store.cameras)

            logger.info(
                f"✅ Check complete: {online_count}/{total_count} online "
                f"({elapsed:.1f}s elapsed, next in {CHECK_INTERVAL_SECONDS}s)"
            )

            # Wait before next check cycle
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)

        except asyncio.CancelledError:
            logger.info("🛑 Monitoring loop cancelled (application shutdown)")
            break
        except Exception as e:
            logger.error(
                f"❌ Unexpected error in monitoring loop: {type(e).__name__}: {e}"
            )
            # Avoid tight error loop - wait before retry
            await asyncio.sleep(60)


async def session_cleanup_loop():
    """Background task: removes expired sessions every 10 minutes."""
    while True:
        await asyncio.sleep(600)
        now = time.time()
        expired = [
            token
            for token, data in SESSIONS.items()
            if now - data["created_at"] > SESSION_EXPIRY
        ]
        for token in expired:
            SESSIONS.pop(token, None)
        if expired:
            logger.info(f"🧹 Cleaned {len(expired)} expired sessions")


# =============================================================================
# FASTAPI APPLICATION
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Application starting...")
    if camera_store.load_from_file():
        asyncio.create_task(monitoring_loop())
        asyncio.create_task(session_cleanup_loop())
        logger.info("Background monitoring and session cleanup started")
    else:
        logger.warning("Camera configuration not loaded")
    yield
    logger.info("Application shutting down...")


app = FastAPI(
    title="Camera Monitor API",
    description="RTSP camera status monitoring with encrypted configuration",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# =============================================================================
# MIDDLEWARE
# =============================================================================
@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return await call_next(request)

    if request.url.path == "/api/login":
        return await call_next(request)

    if request.headers.get("x-requested-with") != "XMLHttpRequest":
        logger.warning(f"CSRF check failed: {request.method} {request.url.path}")
        raise HTTPException(
            status_code=403, detail="CSRF protection: Missing X-Requested-With header"
        )

    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'"
    )
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


# =============================================================================
# AUTH ENDPOINTS
# =============================================================================
@app.post("/api/login")
async def login(request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"

    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for login from {client_ip}")
        raise HTTPException(
            status_code=429, detail="Too many attempts. Wait 60 seconds."
        )

    try:
        body = await request.json()
        username = body.get("username", "").strip()
        password = body.get("password", "")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request format")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    if username == ADMIN_USER and verify_password(password, HASHED_PASSWORD):
        new_token = secrets.token_urlsafe(32)
        signed_token = sign_session_token(new_token)

        SESSIONS[new_token] = {
            "username": username,
            "created_at": time.time(),
            "ip": client_ip,
            "user_agent": request.headers.get("user-agent", "")[:100],
        }

        response.set_cookie(
            key=COOKIE_NAME,
            value=signed_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite=COOKIE_SAMESITE,
            max_age=SESSION_EXPIRY,
            path="/",
        )

        security_logger.info(f"✅ LOGIN: {username} from {client_ip}")
        logger.info(f"✅ Successful login: {username} from {client_ip}")
        return {"status": "success", "username": username}

    security_logger.warning(f"⚠️ FAILED LOGIN: '{username}' from {client_ip}")
    logger.warning(f"⚠️ Failed login attempt: '{username}' from {client_ip}")
    raise HTTPException(status_code=401, detail="Invalid username or password")


@app.get("/api/logout")
async def logout(
    request: Request, response: Response, session: dict = Depends(get_current_session)
):
    signed_token = request.cookies.get(COOKIE_NAME)
    token = verify_signed_token(signed_token) if signed_token else None

    if token and token in SESSIONS:
        security_logger.info(f"🚪 LOGOUT: {session['username']}")
        logger.info(f"🚪 Logout: {session['username']}")
        del SESSIONS[token]

    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"status": "logged_out"}


# =============================================================================
# API ENDPOINTS
# =============================================================================
@app.get("/", response_class=FileResponse)
async def root():
    return "static/index.html"


@app.get("/api/cameras")
async def get_cameras(auth: bool = Depends(require_auth)):
    return camera_store.get_all_for_api()


@app.get("/api/debug")
async def debug_status(auth: bool = Depends(require_auth)):
    return {
        "total_cameras": len(camera_store.cameras),
        "status_mapping": camera_store.statuses,
        "online_count": sum(1 for s in camera_store.statuses.values() if s == "online"),
        "last_check": datetime.now().isoformat(),
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "camera-monitor"}


# =============================================================================
# SNAPSHOT ENDPOINT
# =============================================================================
def _get_snapshot_sync(rtsp_url: str, timeout: int = 8) -> bytes:
    """
    Snapshot extraction with maximum FFmpeg compatibility.
    Uses only universally supported flags.
    """
    cmd = [
        "ffmpeg",
        "-loglevel",
        "error",
        "-timeout",
        str(timeout * 1000000),
        "-rtsp_transport",
        "tcp",
        "-i",
        rtsp_url,
        "-frames:v",
        "1",
        "-q:v",
        "2",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "-an",
        "-y",
        "pipe:1",
    ]

    try:
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2,
            creationflags=creation_flags,
        )

        if (
            result.returncode == 0
            and result.stdout
            and result.stdout.startswith(b"\xff\xd8")
        ):
            logger.debug(f"✅ Snapshot captured: {len(result.stdout)} bytes")
            return result.stdout

        error_stdout = result.stdout[:200] if result.stdout else b"(empty)"
        error_stderr = result.stderr.decode("utf-8", errors="ignore").strip()

        logger.warning(
            f"⚠️ FFmpeg snapshot FAILED for {rtsp_url[:50]}...\n"
            f"   returncode: {result.returncode}\n"
            f"   stdout (first 200): {error_stdout}\n"
            f"   stderr: {error_stderr or '(empty)'}"
        )
        return b""

    except subprocess.TimeoutExpired:
        logger.warning(f"⏱️ Timeout getting snapshot from {rtsp_url[:50]}...")
        return b""
    except Exception as e:
        logger.error(f"❌ Snapshot error: {type(e).__name__}: {e}")
        return b""


@app.get("/api/snapshot/{camera_id}")
async def get_snapshot(camera_id: int, auth: bool = Depends(require_auth)):
    camera_data = next((c for c in camera_store.cameras if c["id"] == camera_id), None)

    if not camera_data:
        raise HTTPException(status_code=404, detail="Camera not found")

    rtsp_url = camera_data.get("url")
    if not rtsp_url:
        raise HTTPException(status_code=404, detail="Stream URL not configured")

    if not camera_data.get("enabled", True):
        raise HTTPException(status_code=403, detail="Camera is disabled")

    snapshot_data = await asyncio.to_thread(_get_snapshot_sync, rtsp_url, 8)

    if not snapshot_data:
        raise HTTPException(
            status_code=503, detail="Unable to get snapshot from camera"
        )

    return StreamingResponse(
        iter([snapshot_data]),
        media_type="image/jpeg",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# =============================================================================
# VIDEO STREAMING ENDPOINT
# =============================================================================
@app.get("/api/stream/{camera_id}")
def stream_camera(camera_id: int, request: Request):
    global active_streams

    signed_token = request.cookies.get(COOKIE_NAME)
    if not signed_token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = verify_signed_token(signed_token)
    if not token or token not in SESSIONS:
        raise HTTPException(status_code=401, detail="Invalid session")

    camera_data = next((c for c in camera_store.cameras if c["id"] == camera_id), None)

    if not camera_data:
        raise HTTPException(status_code=404, detail="Camera not found")

    rtsp_url = camera_data.get("url")
    if not rtsp_url:
        raise HTTPException(status_code=404, detail="Stream URL not configured")

    if not camera_data.get("enabled", True):
        raise HTTPException(status_code=403, detail="Camera is disabled")

    with streams_lock:
        if active_streams >= MAX_CONCURRENT_STREAMS:
            logger.warning(
                f"⚠️ Stream limit reached ({MAX_CONCURRENT_STREAMS}), rejecting camera {camera_id}"
            )
            raise HTTPException(
                status_code=503,
                detail=f"Too many concurrent streams. Max: {MAX_CONCURRENT_STREAMS}",
            )
        active_streams += 1

    cam_name = camera_data.get("location", f"Camera {camera_id}")
    logger.info(
        f"🎬 Stream STARTED for '{cam_name}' (ID: {camera_id}), active: {active_streams}/{MAX_CONCURRENT_STREAMS}"
    )

    cmd = [
        "ffmpeg",
        "-rtsp_transport",
        "tcp",
        "-rtsp_flags",
        "prefer_tcp",
        "-i",
        rtsp_url,
        "-c:v",
        "mjpeg",
        "-q:v",
        "10",
        "-f",
        "mpjpeg",
        "-boundary",
        "ffserver",
        "-an",
        "pipe:1",
    ]

    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

    def generate_frames():
        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags,
                bufsize=65536,
            )

            if not process.stdout:
                yield b""
                return

            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                yield chunk

        except Exception as e:
            logger.error(f"Stream error camera {camera_id}: {e}")
        finally:
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        process.kill()
                    except:
                        pass
            global active_streams
            with streams_lock:
                active_streams -= 1
            logger.info(
                f"🎬 Stream ENDED for '{cam_name}' (ID: {camera_id}), active: {active_streams}/{MAX_CONCURRENT_STREAMS}"
            )

    return StreamingResponse(
        generate_frames(),
        media_type="multipart/x-mixed-replace; boundary=ffserver",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            "Connection": "keep-alive",
        },
    )


# =============================================================================
# ADMIN PANEL ENDPOINTS (только для pepethefrog)
# =============================================================================
async def require_admin(session: dict = Depends(get_current_session)):
    """Проверка, что текущий пользователь - админ pepethefrog"""
    if session.get("username") != "pepethefrog":
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


@app.get("/api/admin/cameras", tags=["Admin"])
async def admin_get_cameras(admin: dict = Depends(require_admin)):
    """Получить все камеры с полными данными (включая URL)"""
    result = []
    for cam in camera_store.cameras:
        result.append(
            {
                "id": cam.get("id"),
                "name": cam.get("name", ""),
                "object": cam.get("object", ""),
                "location": cam.get("location", ""),
                "type": cam.get("type", ""),
                "url": cam.get("url", ""),
                "enabled": cam.get("enabled", True),
            }
        )
    return result


@app.post("/api/admin/cameras", tags=["Admin"])
async def admin_add_camera(camera: dict, admin: dict = Depends(require_admin)):
    """Добавить новую камеру"""
    # Валидация
    required_fields = ["id", "name", "url"]
    for field in required_fields:
        if field not in camera:
            raise HTTPException(status_code=400, detail=f"Missing field: {field}")

    # Проверка на дубликат ID
    for cam in camera_store.cameras:
        if cam.get("id") == camera["id"]:
            raise HTTPException(
                status_code=400, detail="Camera with this ID already exists"
            )

    # Добавление
    new_camera = {
        "id": camera["id"],
        "name": camera.get("name", f"Camera {camera['id']}"),
        "object": camera.get("object", "Unassigned"),
        "location": camera.get("location", ""),
        "type": camera.get("type", ""),
        "url": camera["url"],
        "enabled": camera.get("enabled", True),
    }

    camera_store.cameras.append(new_camera)

    # Сохранение в зашифрованный файл
    await save_cameras_to_file()

    logger.info(f"✅ Admin {admin['username']} added camera {new_camera['id']}")
    return {"status": "success", "camera": new_camera}


@app.put("/api/admin/cameras/{camera_id}", tags=["Admin"])
async def admin_update_camera(
    camera_id: int, camera: dict, admin: dict = Depends(require_admin)
):
    """Обновить существующую камеру"""
    # Поиск камеры
    cam_index = None
    for i, cam in enumerate(camera_store.cameras):
        if cam.get("id") == camera_id:
            cam_index = i
            break

    if cam_index is None:
        raise HTTPException(status_code=404, detail="Camera not found")

    # Обновление полей
    updated_camera = camera_store.cameras[cam_index].copy()
    update_fields = ["name", "object", "location", "type", "url", "enabled"]

    for field in update_fields:
        if field in camera:
            updated_camera[field] = camera[field]

    camera_store.cameras[cam_index] = updated_camera

    # Сохранение
    await save_cameras_to_file()

    logger.info(f"✅ Admin {admin['username']} updated camera {camera_id}")
    return {"status": "success", "camera": updated_camera}


@app.delete("/api/admin/cameras/{camera_id}", tags=["Admin"])
async def admin_delete_camera(camera_id: int, admin: dict = Depends(require_admin)):
    """Удалить камеру"""
    # Поиск и удаление
    cam_index = None
    for i, cam in enumerate(camera_store.cameras):
        if cam.get("id") == camera_id:
            cam_index = i
            break

    if cam_index is None:
        raise HTTPException(status_code=404, detail="Camera not found")

    deleted_cam = camera_store.cameras.pop(cam_index)

    # Сохранение
    await save_cameras_to_file()

    logger.info(f"✅ Admin {admin['username']} deleted camera {camera_id}")
    return {"status": "success", "deleted": deleted_cam}


@app.post("/api/admin/cameras/{camera_id}/toggle", tags=["Admin"])
async def admin_toggle_camera(camera_id: int, admin: dict = Depends(require_admin)):
    """Включить/выключить камеру"""
    for cam in camera_store.cameras:
        if cam.get("id") == camera_id:
            cam["enabled"] = not cam.get("enabled", True)
            await save_cameras_to_file()

            status = "enabled" if cam["enabled"] else "disabled"
            logger.info(f"✅ Admin {admin['username']} {status} camera {camera_id}")
            return {
                "status": "success",
                "camera_id": camera_id,
                "enabled": cam["enabled"],
            }

    raise HTTPException(status_code=404, detail="Camera not found")


@app.post("/api/admin/reload", tags=["Admin"])
async def admin_reload_config(admin: dict = Depends(require_admin)):
    """Перезагрузить конфигурацию камер из файла"""
    if camera_store.load_from_file():
        logger.info(f"✅ Admin {admin['username']} reloaded camera configuration")
        return {"status": "success", "message": "Configuration reloaded"}
    else:
        raise HTTPException(status_code=500, detail="Failed to reload configuration")


async def save_cameras_to_file():
    """Сохранить камеры в зашифрованный файл"""
    try:
        cipher = Fernet(Path(KEY_FILE).read_bytes())
        cameras_json = json.dumps(camera_store.cameras, ensure_ascii=False)
        encrypted = cipher.encrypt(cameras_json.encode("utf-8"))
        Path(CAMERAS_ENC).write_bytes(encrypted)
        logger.info("💾 Cameras configuration saved")
    except Exception as e:
        logger.error(f"❌ Failed to save cameras: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save: {e}")


# =============================================================================
# HISTORY & STATS ENDPOINTS
# =============================================================================
@app.get("/api/admin/history/{camera_id}", tags=["History"])
async def get_history(
    camera_id: int, days: int = 7, auth: bool = Depends(require_admin)
):
    """Get status history for a camera."""
    history = get_camera_history(camera_id, days)
    return {"camera_id": camera_id, "days": days, "history": history}


@app.get("/api/admin/uptime/{camera_id}", tags=["History"])
async def get_uptime(
    camera_id: int, days: int = 7, auth: bool = Depends(require_admin)
):
    """Get uptime statistics for a camera."""
    return get_camera_uptime(camera_id, days)

# =============================================================================
# STATS EXPORT ENDPOINTS
# =============================================================================

@app.get("/api/admin/stats/summary", tags=["History"])
async def get_stats_summary(days: int = 7, auth: bool = Depends(require_admin)):
    """Get uptime summary for all cameras."""
    return get_all_cameras_summary(days)

@app.get("/api/admin/export/stats", tags=["Export"])
async def export_stats(days: int = 7, auth: bool = Depends(require_admin)):
    """
    Export camera uptime statistics to an Excel file.
    """
    try:
        # 1. Generate data
        # We need the full camera list to get names/locations
        df = generate_report_data(camera_store.cameras, days)
        
        # Sort by Uptime (lowest first - problem cameras at top)
        df = df.sort_values(by="Uptime (%)", ascending=True)
        
        # 2. Write to memory buffer
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name="Uptime Report")
        
        output.seek(0)
        
        # 3. Return file
        filename = f"camera_report_{days}days.xlsx"
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
