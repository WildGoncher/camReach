"""
Camera Monitor Backend - FastAPI Application
Multi-user support with Role-Based Access Control (RBAC).
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
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse, Response
from cryptography.fernet import Fernet
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from users import USERS, verify_password, get_user_permissions
from database import (
    init_db,
    log_status_change,
    get_camera_history,
    get_camera_uptime,
    get_all_cameras_summary,
    generate_report_data,
    aggregate_and_cleanup,
)
from notifier import EmailNotifier


# =============================================================================
# Вспомогательная функция для получения реального IP за nginx
# =============================================================================
def get_client_ip(request: Request) -> str:
    """Возвращает реальный IP-адрес клиента, учитывая проксирование nginx."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# =============================================================================
# LOGGING CONFIGURATION WITH ROTATION
# =============================================================================
Path("logs").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)

log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

main_handler = RotatingFileHandler(
    "logs/monitor.log", maxBytes=10_485_760, backupCount=5, encoding="utf-8"
)
main_handler.setFormatter(log_formatter)

security_handler = RotatingFileHandler(
    "logs/security.log", maxBytes=10_485_760, backupCount=5, encoding="utf-8"
)
security_handler.setFormatter(log_formatter)

logging.basicConfig(
    level=logging.INFO, handlers=[main_handler, logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
security_logger.addHandler(security_handler)
security_logger.addHandler(logging.StreamHandler())

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

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in .env file!")

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")
SESSION_EXPIRY = int(os.getenv("SESSION_EXPIRY", "86400"))
COOKIE_NAME = "cam_session"

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
        if not LOGIN_ATTEMPTS[ip]:
            del LOGIN_ATTEMPTS[ip]
    if LOGIN_ATTEMPTS.get(ip) and len(LOGIN_ATTEMPTS[ip]) >= MAX_LOGIN_ATTEMPTS:
        return False
    LOGIN_ATTEMPTS.setdefault(ip, []).append(now)
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
            key_path = Path(KEY_FILE)
            cam_path = Path(CAMERAS_ENC)
            if not key_path.exists():
                key_path = Path("data") / KEY_FILE
            if not cam_path.exists():
                cam_path = Path("data") / CAMERAS_ENC
            cipher = Fernet(key_path.read_bytes())
            encrypted_data = cam_path.read_bytes()
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

# =============================================================================
# SNAPSHOT CACHE & DEDUPLICATION (NEW)
# =============================================================================
_snapshot_cache: dict[int, tuple[bytes, float]] = {}
_snapshot_events: dict[int, asyncio.Event] = {}
_snapshot_lock = asyncio.Lock()
SNAPSHOT_TTL = 5.0

init_db()
email_notifier = EmailNotifier()
EMAIL_COOLDOWN = int(os.getenv("EMAIL_COOLDOWN_SECONDS", 300))
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
        return False
    except FileNotFoundError:
        logger.error("ffprobe executable not found.")
        return False
    except Exception:
        return False


async def check_camera_async(url: str, timeout: int) -> bool:
    return await asyncio.to_thread(_check_camera_sync, url, timeout)


async def monitoring_loop():
    while True:
        try:
            async with camera_store._lock:
                active_cameras = [
                    c for c in camera_store.cameras if c.get("enabled", True)
                ]

            if not active_cameras:
                await asyncio.sleep(CHECK_INTERVAL_SECONDS)
                continue

            logger.info(f"Starting status check for {len(active_cameras)} cameras...")
            start_time = datetime.now()

            # Параллельная проверка всех камер
            async def check_one(camera):
                cam_id = camera["id"]
                is_online = await check_camera_async(
                    camera["url"], timeout=FFPROBE_TIMEOUT_SECONDS
                )
                new_status = "online" if is_online else "offline"
                async with camera_store._lock:
                    old_status = camera_store.statuses.get(cam_id, "offline")
                    camera_store.update_status(cam_id, new_status)
                if new_status != old_status:
                    log_status_change(cam_id, new_status)
                    logger.info(
                        f"📝 Status change: Camera {cam_id} {old_status} → {new_status}"
                    )
                    # email уведомление
                    now = time.time()
                    if now - last_email_time.get(cam_id, 0) >= EMAIL_COOLDOWN:
                        cam_obj = camera.get("object", "Неизвестный объект")
                        cam_loc = camera.get("location", f"Камера {cam_id}")
                        cam_type = camera.get("type", "Обзорная камера")
                        cam_ip = camera.get("ip", "нет IP")
                        camera_label = f"{cam_obj}, {cam_loc} {cam_type} {cam_ip}"
                        error_detail = "Камера недоступна" if not is_online else ""
                        asyncio.create_task(
                            email_notifier.send_camera_alert(
                                camera_label, new_status, error_detail
                            )
                        )
                        last_email_time[cam_id] = now
                logger.info(
                    f"  [{'✓' if is_online else '✗'}] Camera {cam_id}: {new_status.upper()}"
                )

            await asyncio.gather(*[check_one(cam) for cam in active_cameras])

            elapsed = (datetime.now() - start_time).total_seconds()
            online_count = sum(
                1 for s in camera_store.statuses.values() if s == "online"
            )
            logger.info(
                f"✅ Check complete: {online_count}/{len(active_cameras)} online ({elapsed:.1f}s elapsed)"
            )
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"❌ Loop error: {e}")
            await asyncio.sleep(60)


_last_aggregation_day: int = -1


async def session_cleanup_loop():
    global _last_aggregation_day
    while True:
        await asyncio.sleep(600)  # каждые 10 минут
        now = time.time()

        # Очистка просроченных сессий
        expired = [
            t for t, d in SESSIONS.items() if now - d["created_at"] > SESSION_EXPIRY
        ]
        for token in expired:
            SESSIONS.pop(token, None)

        # Очистка устаревшего кэша скриншотов
        for cid in list(_snapshot_cache.keys()):
            if now - _snapshot_cache[cid][1] > SNAPSHOT_TTL * 2:
                _snapshot_cache.pop(cid, None)

        # Агрегация и очистка БД — раз в сутки
        today = datetime.now().day
        if today != _last_aggregation_day:
            _last_aggregation_day = today
            logger.info("⏳ Running daily DB aggregation...")
            await asyncio.to_thread(aggregate_and_cleanup)


async def run_initial_check():
    await asyncio.sleep(5)
    logger.info("Running initial camera check...")
    async with camera_store._lock:
        for camera in camera_store.cameras:
            if camera.get("enabled", True):
                try:
                    is_online = await check_camera_async(
                        camera["url"], timeout=FFPROBE_TIMEOUT_SECONDS
                    )
                    new_status = "online" if is_online else "offline"
                    camera_store.update_status(camera["id"], new_status)
                    logger.info(f"Initial check: Camera {camera['id']} = {new_status}")
                except Exception as e:
                    logger.error(f"Initial check failed for camera {camera['id']}: {e}")


# =============================================================================
# LIFESPAN (WITH THREAD POOL CONFIGURATION)
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Настройка пула потоков для asyncio.to_thread()
    # По умолчанию пул маленький, из-за чего запросы к ffmpeg встают в очередь
    loop = asyncio.get_event_loop()
    executor = ThreadPoolExecutor(max_workers=20)  # 20 параллельных ffmpeg-вызовов
    loop.set_default_executor(executor)

    logger.info("Application starting with ThreadPoolExecutor(max_workers=20)...")
    if camera_store.load_from_file():
        asyncio.create_task(monitoring_loop())
        asyncio.create_task(session_cleanup_loop())
        asyncio.create_task(run_initial_check())
    else:
        logger.warning("Camera configuration not loaded")
    yield
    # Корректное завершение пула при выключении
    executor.shutdown(wait=False)
    logger.info("Application shutting down...")


app = FastAPI(title="Camera Monitor API", version="2.0.0", lifespan=lifespan)
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
        raise HTTPException(status_code=403, detail="CSRF failed")
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' blob:; connect-src 'self'"
    )
    return response


# =============================================================================
# API ENDPOINTS
# =============================================================================
@app.get("/", response_class=FileResponse)
async def root():
    return "static/index.html"


@app.get("/api/cameras")
async def get_cameras(session: dict = Depends(get_current_session)):
    cameras = camera_store.get_all_for_api()
    role = session.get("role")
    allowed_objects = session.get("allowed_objects")
    if role == "restricted" and allowed_objects:
        cameras = [c for c in cameras if c.get("object") in allowed_objects]
    return cameras


@app.get("/api/debug")
async def debug_status(session: dict = Depends(get_current_session)):
    return {
        "total": len(camera_store.cameras),
        "online": sum(1 for s in camera_store.statuses.values() if s == "online"),
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.post("/api/login")
async def login(request: Request, response: Response):
    client_ip = get_client_ip(request)
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
    if verify_password(username, password):
        new_token = secrets.token_urlsafe(32)
        signed_token = sign_session_token(new_token)
        permissions = get_user_permissions(username)
        SESSIONS[new_token] = {
            "username": username,
            "role": permissions["role"],
            "allowed_objects": permissions["allowed_objects"],
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
        security_logger.info(
            f"✅ LOGIN: {username} ({permissions['role']}) from {client_ip}"
        )
        logger.info(f"✅ Successful login: {username} from {client_ip}")
        return {"status": "success", "username": username, "role": permissions["role"]}
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
# SNAPSHOT FUNCTIONS (OPTIMIZED)
# =============================================================================
def _capture_snapshot_sync(url: str, timeout: int = 5) -> bytes | None:
    """FFmpeg-вызов с оптимизированными флагами для быстрого захвата кадра."""
    cmd = [
        "ffmpeg",
        "-y",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-timeout",
        str(timeout * 1_000_000),
        "-fflags",
        "nobuffer",
        "-flags",
        "low_delay",
        "-probesize",
        "32",
        "-analyzeduration",
        "0",
        "-i",
        url,
        "-frames:v",
        "1",
        "-q:v",
        "3",
        "-f",
        "image2pipe",
        "-vcodec",
        "mjpeg",
        "-an",
        "pipe:1",
    ]
    try:
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 2, creationflags=creation_flags
        )
        # Проверяем, что вернулся валидный JPEG (начинается с FF D8)
        if (
            result.returncode == 0
            and result.stdout
            and result.stdout.startswith(b"\xff\xd8")
        ):
            return result.stdout
    except Exception as e:
        logger.debug(f"Snapshot capture failed for {url}: {e}")
    return None


async def get_snapshot_dedup(camera_id: int, url: str) -> bytes | None:
    """TTL-кэш + дедупликация запросов к камере через asyncio.Event."""
    now = time.time()

    # 1. Проверяем кэш — если есть валидный снимок, отдаём сразу
    if camera_id in _snapshot_cache:
        data, ts = _snapshot_cache[camera_id]
        if now - ts < SNAPSHOT_TTL:
            return data

    # 2. Получаем или создаём Event для этой камеры
    async with _snapshot_lock:
        event = _snapshot_events.setdefault(camera_id, asyncio.Event())

    # 3. Если событие ещё не выполнено → мы первые, делаем запрос к камере
    if not event.is_set():
        try:
            data = await asyncio.to_thread(_capture_snapshot_sync, url, 5)
            if data:
                _snapshot_cache[camera_id] = (data, time.time())
            return data
        finally:
            # Сообщаем всем ожидающим, что результат готов
            event.set()
            async with _snapshot_lock:
                _snapshot_events.pop(camera_id, None)
    else:
        # Мы не первые → ждём, пока первый запрос завершится
        await asyncio.wait_for(event.wait(), timeout=15)
        cached = _snapshot_cache.get(camera_id)
        return cached[0] if cached else None

    # Fallback на случай непредвиденного
    return None


@app.get("/api/snapshot/{camera_id}")
async def get_snapshot(camera_id: int, session: dict = Depends(get_current_session)):
    # Проверка прав доступа
    if session.get("role") == "restricted":
        cam_data = next((c for c in camera_store.cameras if c["id"] == camera_id), None)
        if cam_data and cam_data.get("object") not in session.get(
            "allowed_objects", []
        ):
            raise HTTPException(status_code=403, detail="Access denied")

    camera_data = next((c for c in camera_store.cameras if c["id"] == camera_id), None)
    if not camera_data or not camera_data.get("enabled", True):
        raise HTTPException(status_code=404, detail="Camera not found")

    # Если камера офлайн → сразу возвращаем 204, не вызывая ffmpeg
    if camera_store.statuses.get(camera_id) == "offline":
        return Response(
            content=b"", status_code=204, headers={"X-Camera-Status": "offline"}
        )

    # Новая логика: кэш + дедупликация
    snapshot_data = await get_snapshot_dedup(camera_id, camera_data.get("url"))
    if not snapshot_data:
        raise HTTPException(status_code=503, detail="Unable to get snapshot")

    return StreamingResponse(iter([snapshot_data]), media_type="image/jpeg")


@app.get("/api/stream/{camera_id}")
def stream_camera(camera_id: int, request: Request):
    session_token = request.cookies.get(COOKIE_NAME)
    token = verify_signed_token(session_token)
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if session.get("role") == "restricted":
        cam_data = next((c for c in camera_store.cameras if c["id"] == camera_id), None)
        if cam_data and cam_data.get("object") not in session.get(
            "allowed_objects", []
        ):
            raise HTTPException(status_code=403, detail="Access denied")
    camera_data = next((c for c in camera_store.cameras if c["id"] == camera_id), None)
    if not camera_data:
        raise HTTPException(status_code=404, detail="Camera not found")
    if not camera_data.get("enabled", True):
        raise HTTPException(status_code=403, detail="Camera disabled")
    global active_streams
    with streams_lock:
        if active_streams >= MAX_CONCURRENT_STREAMS:
            raise HTTPException(status_code=503, detail="Stream limit reached")
        active_streams += 1
    cmd = [
        "ffmpeg",
        "-rtsp_transport",
        "tcp",
        "-i",
        camera_data["url"],
        "-c:v",
        "mjpeg",
        "-q:v",
        "10",
        "-f",
        "mpjpeg",
        "-an",
        "pipe:1",
    ]

    def generate():
        global active_streams
        process = None
        try:
            creation_flags = (
                subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags,
            )
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            if process:
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except:
                    process.kill()
            with streams_lock:
                active_streams -= 1

    return StreamingResponse(
        generate(),
        media_type="multipart/x-mixed-replace; boundary=ffmpeg",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def require_admin(session: dict = Depends(get_current_session)):
    if session.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return session


@app.get("/api/admin/cameras")
async def admin_get_cameras(admin: dict = Depends(require_admin)):
    return [
        {
            "id": c.get("id"),
            "name": c.get("name"),
            "object": c.get("object"),
            "location": c.get("location"),
            "type": c.get("type"),
            "url": c.get("url"),
            "enabled": c.get("enabled", True),
        }
        for c in camera_store.cameras
    ]


@app.post("/api/admin/cameras")
async def admin_add_camera(camera: dict, admin: dict = Depends(require_admin)):
    required = ["id", "name", "url"]
    if not all(k in camera for k in required):
        raise HTTPException(status_code=400, detail="Missing fields")
    if any(c.get("id") == camera["id"] for c in camera_store.cameras):
        raise HTTPException(status_code=400, detail="ID exists")
    new_cam = {
        "id": camera["id"],
        "name": camera.get("name"),
        "object": camera.get("object", "Unassigned"),
        "location": camera.get("location", ""),
        "type": camera.get("type", ""),
        "url": camera["url"],
        "enabled": True,
    }
    camera_store.cameras.append(new_cam)
    await save_cameras()
    return {"status": "success"}


@app.put("/api/admin/cameras/{camera_id}")
async def admin_update_camera(
    camera_id: int, data: dict, admin: dict = Depends(require_admin)
):
    idx = next(
        (i for i, c in enumerate(camera_store.cameras) if c.get("id") == camera_id),
        None,
    )
    if idx is None:
        raise HTTPException(status_code=404, detail="Not found")
    camera_store.cameras[idx].update(data)
    await save_cameras()
    return {"status": "success"}


@app.post("/api/admin/cameras/{camera_id}/toggle")
async def admin_toggle_camera(camera_id: int, admin: dict = Depends(require_admin)):
    idx = next(
        (i for i, c in enumerate(camera_store.cameras) if c.get("id") == camera_id),
        None,
    )
    if idx is None:
        raise HTTPException(status_code=404, detail="Not found")

    current = camera_store.cameras[idx].get("enabled", True)
    camera_store.cameras[idx]["enabled"] = not current
    await save_cameras()

    return {"status": "success", "enabled": camera_store.cameras[idx]["enabled"]}


@app.delete("/api/admin/cameras/{camera_id}")
async def admin_delete_camera(camera_id: int, admin: dict = Depends(require_admin)):
    camera_store.cameras = [c for c in camera_store.cameras if c.get("id") != camera_id]
    await save_cameras()
    return {"status": "success"}


@app.post("/api/admin/reload")
async def admin_reload(admin: dict = Depends(require_admin)):
    if camera_store.load_from_file():
        return {"status": "success"}
    raise HTTPException(status_code=500, detail="Reload failed")


async def save_cameras():
    try:
        key_path = Path(KEY_FILE)
        cam_path = Path(CAMERAS_ENC)
        if not key_path.exists():
            key_path = Path("data") / KEY_FILE
            cam_path = Path("data") / CAMERAS_ENC
        cipher = Fernet(key_path.read_bytes())
        cam_path.write_bytes(
            cipher.encrypt(
                json.dumps(camera_store.cameras, ensure_ascii=False).encode()
            )
        )
        logger.info(f"Saved {len(camera_store.cameras)} cameras to configuration")
    except Exception as e:
        logger.error(f"Save failed: {e}")


@app.get("/api/admin/stats/summary")
async def get_stats(days: int = 7, admin: dict = Depends(require_admin)):
    if days not in (1, 7, 30, 90, 180, 365):
        raise HTTPException(
            status_code=400, detail="days must be 1, 7, 30, 90, 180 or 365"
        )
    return get_all_cameras_summary(days)


@app.get("/api/admin/export/stats")
async def export_stats(days: int = 7, admin: dict = Depends(require_admin)):
    if days not in (1, 7, 30, 90, 180, 365):
        raise HTTPException(
            status_code=400, detail="days must be 1, 7, 30, 90, 180 or 365"
        )
    df = generate_report_data(camera_store.cameras, days)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False)
    output.seek(0)
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=report_{days}d.xlsx"},
    )
