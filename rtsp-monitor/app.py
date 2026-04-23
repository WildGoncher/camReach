"""
Camera Monitor Backend - FastAPI Application
Provides RTSP camera status monitoring with encrypted configuration storage.
"""

import json
import asyncio
import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from cryptography.fernet import Fernet

# =============================================================================
# PLATFORM COMPATIBILITY
# =============================================================================
# Windows requires ProactorEventLoop for proper subprocess handling in asyncio
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================
KEY_FILE = "secret.key"
CAMERAS_ENC = "cameras.enc"
CHECK_INTERVAL_SECONDS = 300  # Time between status checks (5 minutes)
FFPROBE_TIMEOUT_SECONDS = 10  # Timeout for individual camera probe

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


# =============================================================================
# DATA STORE: Camera configuration and status management
# =============================================================================
class CameraStore:
    """
    Manages camera configuration loading, status tracking, and API response formatting.
    Thread-safe for concurrent access from background tasks and HTTP handlers.
    """

    def __init__(self):
        self.cameras: List[Dict] = []
        self.statuses: Dict[int, str] = {}
        self._lock = asyncio.Lock()

    def load_from_file(self) -> bool:
        """
        Loads and decrypts camera configuration from encrypted file.

        Returns:
            bool: True if loading successful, False otherwise.
        """
        try:
            cipher = Fernet(Path(KEY_FILE).read_bytes())
            encrypted_data = Path(CAMERAS_ENC).read_bytes()
            decrypted = cipher.decrypt(encrypted_data)

            self.cameras = json.loads(decrypted.decode("utf-8"))
            # Initialize all cameras as offline until first check completes
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
        """Updates the online/offline status for a specific camera."""
        self.statuses[camera_id] = status

    def get_all_for_api(self) -> List[Dict]:
        """
        Returns a sanitized list of cameras for frontend consumption.
        Sensitive data (URLs, credentials) is excluded; only safe fields included.
        """
        result = []
        for cam in self.cameras:
            camera_id = cam.get("id")
            current_status = self.statuses.get(camera_id, "offline")

            # Build safe response object
            safe_camera = {
                "id": camera_id,
                "name": cam.get(
                    "location", f"Camera {camera_id}"
                ),  # Display name = location
                "object": cam.get("object", "Unassigned"),  # Grouping key = site name
                "location": cam.get("type", ""),  # Secondary info = camera type
                "ip": self._extract_safe_address(
                    cam.get("url", "")
                ),  # Host:port only, no credentials
                "status": current_status,  # Current online/offline state
                "enabled": cam.get("enabled", True),  # Whether camera is active
            }
            result.append(safe_camera)
        return result

    def _extract_safe_address(self, url: str) -> str:
        """
        Extracts host:port from RTSP/HTTP URL, removing credentials for safe display.

        Args:
            url: Full camera URL (may contain username:password)

        Returns:
            str: Safe address string (e.g., "192.168.1.10:554") or "unknown" on error.
        """
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
        """Returns full RTSP URL for a camera by ID."""
        for cam in self.cameras:
            if cam.get("id") == camera_id:
                return cam.get("url", "")
        return ""


# Global store instance
camera_store = CameraStore()


# =============================================================================
# CAMERA STATUS CHECKING LOGIC
# =============================================================================
def _check_camera_sync(url: str, timeout: int) -> bool:
    """
    Synchronous camera availability check using ffprobe.
    Designed to be run in a thread pool to avoid blocking the event loop.

    Args:
        url: Full RTSP URL with credentials
        timeout: Maximum wait time in seconds

    Returns:
        bool: True if camera stream is accessible, False otherwise.
    """
    cmd = [
        "ffprobe",
        "-v",
        "error",
        "-show_entries",
        "stream=codec_name",
        "-of",
        "json",
        "-timeout",
        str(timeout * 1_000_000),  # ffprobe uses microseconds
        "-rtsp_transport",
        "tcp",
        url,
    ]

    try:
        # CREATE_NO_WINDOW prevents console popup on Windows
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 1, creationflags=creation_flags
        )

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout.decode())
            # Stream exists if codec_name is present
            return bool(data.get("streams"))
        return False

    except subprocess.TimeoutExpired:
        logger.debug(f"Timeout checking camera: {url[:60]}...")
        return False
    except FileNotFoundError:
        logger.error(
            "ffprobe executable not found. Ensure ffmpeg is installed and in PATH."
        )
        return False
    except Exception as e:
        logger.debug(f"Error during camera check: {type(e).__name__}: {e}")
        return False


async def check_camera_async(url: str, timeout: int) -> bool:
    """
    Async wrapper for camera checking - delegates to thread pool.

    Args:
        url: Camera RTSP URL
        timeout: Check timeout in seconds

    Returns:
        bool: Camera availability status
    """
    return await asyncio.to_thread(_check_camera_sync, url, timeout)


async def monitoring_loop():
    """
    Background task: periodically checks all enabled cameras and updates statuses.
    Runs indefinitely until application shutdown.
    """
    while True:
        try:
            # Get list of enabled cameras (thread-safe copy)
            async with camera_store._lock:
                active_cameras = [
                    c for c in camera_store.cameras if c.get("enabled", True)
                ]

            if not active_cameras:
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

                is_online = await check_camera_async(
                    url, timeout=FFPROBE_TIMEOUT_SECONDS
                )

                # Update status in store (thread-safe)
                async with camera_store._lock:
                    camera_store.update_status(
                        cam_id, "online" if is_online else "offline"
                    )

                status_symbol = "✓" if is_online else "✗"
                status_text = "ONLINE" if is_online else "OFFLINE"
                logger.info(f"  [{status_symbol}] Camera {cam_id}: {status_text}")

            # Summary statistics
            elapsed = (datetime.now() - start_time).total_seconds()
            online_count = sum(
                1 for s in camera_store.statuses.values() if s == "online"
            )
            total_count = len(camera_store.cameras)

            logger.info(
                f"Check complete: {online_count}/{total_count} online ({elapsed:.1f}s elapsed)"
            )

            # Wait before next check cycle
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)

        except asyncio.CancelledError:
            logger.info("Monitoring loop cancelled (application shutdown)")
            break
        except Exception as e:
            logger.error(f"Unexpected error in monitoring loop: {e}")
            # Avoid tight error loop - wait before retry
            await asyncio.sleep(60)


# =============================================================================
# FASTAPI APPLICATION SETUP
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler: manages startup/shutdown lifecycle.
    """
    # Startup: load configuration and start background monitoring
    logger.info("Application starting...")
    if camera_store.load_from_file():
        asyncio.create_task(monitoring_loop())
        logger.info("Background monitoring started")
    else:
        logger.warning("Camera configuration not loaded - API will return empty list")

    yield  # Application runs here

    # Shutdown: cleanup (asyncio tasks auto-cancel on exit)
    logger.info("Application shutting down...")


# Initialize FastAPI app with lifespan handler
app = FastAPI(
    title="Camera Monitor API",
    description="RTSP camera status monitoring service with encrypted configuration",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount static files directory for frontend assets
app.mount("/static", StaticFiles(directory="static"), name="static")


# =============================================================================
# API ENDPOINTS
# =============================================================================
@app.get("/", response_class=FileResponse)
async def root():
    """Serves the frontend application."""
    return "static/index.html"


@app.get("/api/cameras")
async def get_cameras():
    """
    Returns list of cameras with current status information.

    Response format:
    [
        {
            "id": int,
            "name": str,        # Display name (location)
            "object": str,      # Grouping key (site name)
            "location": str,    # Secondary info (camera type)
            "ip": str,          # Safe address (host:port)
            "status": "online" | "offline",
            "enabled": bool
        },
        ...
    ]
    """
    return camera_store.get_all_for_api()


@app.get("/api/debug")
async def debug_status():
    """
    Debug endpoint: returns raw internal state.
    For development/troubleshooting only - not for production frontend.
    """
    return {
        "total_cameras": len(camera_store.cameras),
        "status_mapping": camera_store.statuses,
        "online_count": sum(1 for s in camera_store.statuses.values() if s == "online"),
        "last_check": datetime.now().isoformat(),
    }


@app.get("/health")
async def health_check():
    """Simple health check endpoint for load balancers / monitoring."""
    return {"status": "healthy", "service": "camera-monitor"}


# =============================================================================
# SNAPSHOT ENDPOINT (NEW!)
# =============================================================================
def _get_snapshot_sync(rtsp_url: str, timeout: int) -> bytes:
    """
    Synchronous function to extract a single frame (JPEG) from RTSP stream.
    Uses ffmpeg to grab one frame.
    """
    cmd = [
        'ffmpeg',
        '-rtsp_transport', 'tcp',
        '-i', rtsp_url,
        '-frames:v', '1',
        '-f', 'image2',
        '-vcodec', 'mjpeg',
        '-q:v', '8',
        '-an',  # No audio
        '-y',
        'pipe:1'
    ]
    
    try:
        creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            creationflags=creation_flags
        )
        
        if result.returncode == 0 and result.stdout:
            return result.stdout
        else:
            logger.debug(f"ffmpeg error for {rtsp_url[:60]}: {result.stderr[:100]}")
            return b""
            
    except subprocess.TimeoutExpired:
        logger.debug(f"Timeout getting snapshot from {rtsp_url[:60]}")
        return b""
    except Exception as e:
        logger.debug(f"Snapshot error: {e}")
        return b""


@app.get("/api/snapshot/{camera_id}")
async def get_snapshot(camera_id: int):
    """
    Returns a single JPEG snapshot from the specified camera.
    Used by frontend for periodic updates in the modal dialog.
    """
    # Find camera
    camera_data = next((c for c in camera_store.cameras if c['id'] == camera_id), None)
    
    if not camera_data:
        raise HTTPException(status_code=404, detail="Camera not found")
    
    rtsp_url = camera_data.get("url")
    if not rtsp_url:
        raise HTTPException(status_code=404, detail="Stream URL not configured")
    
    # Check if camera is enabled
    if not camera_data.get("enabled", True):
        raise HTTPException(status_code=403, detail="Camera is disabled")
    
    # Get snapshot (run in thread pool to avoid blocking)
    snapshot_data = await asyncio.to_thread(_get_snapshot_sync, rtsp_url, 5)
    
    if not snapshot_data:
        raise HTTPException(status_code=503, detail="Unable to get snapshot from camera")
    
    return StreamingResponse(
        iter([snapshot_data]),
        media_type="image/jpeg",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


# =============================================================================
# VIDEO STREAMING ENDPOINT (Stable Sync Generator)
# =============================================================================
@app.get("/api/stream/{camera_id}")
def stream_camera(camera_id: int):
    """
    Proxies RTSP to MJPEG stream for the browser.
    Uses a synchronous generator to avoid Windows async subprocess issues.
    """
    # Find camera in the list
    camera_data = next((c for c in camera_store.cameras if c['id'] == camera_id), None)
    
    if not camera_data:
        raise HTTPException(status_code=404, detail="Camera not found")
    
    rtsp_url = camera_data.get("url")
    if not rtsp_url:
        raise HTTPException(status_code=404, detail="Stream URL not configured")

    # FFmpeg command configuration
    cmd = [
        'ffmpeg',
        '-rtsp_transport', 'tcp',
        '-i', rtsp_url,
        '-c:v', 'mjpeg',
        '-q:v', '10',
        '-f', 'mpjpeg',
        '-boundary', 'ffserver',
        'pipe:1'
    ]
    
    # Hide console window on Windows
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0

    def generate_frames():
        process = None
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags,
                bufsize=65536
            )
            
            # Check that stdout is available
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

    return StreamingResponse(
        generate_frames(),
        media_type="multipart/x-mixed-replace; boundary=ffserver",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Connection": "keep-alive"
        }
    )
