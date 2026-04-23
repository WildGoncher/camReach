"""
Безопасный RTSP Monitor с уведомлениями
- Шифрование камер и SMTP-пароля (Fernet)
- Сохранение состояния между перезапусками
- Дебаунс уведомлений (15 мин на камеру)
- Email-уведомления при смене статуса
- Вывод IP:Port при ошибках (без паролей)
"""

import asyncio
import json
import logging
import smtplib
import os
import sys
import re
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# === КОНФИГУРАЦИЯ ===
load_dotenv()

KEY_FILE = "secret.key"
CAMERAS_ENC = "cameras.enc"
RESULTS_FILE = "results.json"
DEBOUNCE_MINUTES = 15

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", encoding="utf-8", mode="a"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# === УТИЛИТЫ ===


def load_or_create_key() -> Fernet:
    p = Path(KEY_FILE)
    if p.exists():
        return Fernet(p.read_bytes())
    key = Fernet.generate_key()
    p.write_bytes(key)
    logger.warning(f"🔑 Создан ключ: {KEY_FILE}. Сохраните его!")
    return Fernet(key)


def decrypt_value(enc_value: str, cipher: Fernet) -> str:
    if not enc_value or not enc_value.startswith("enc:"):
        return enc_value or ""
    return cipher.decrypt(enc_value[4:].encode()).decode()


def get_safe_address(url: str) -> str:
    """
    Безопасно извлекает IP:Port из URL.
    Пример: rtsp://user:pass@192.168.1.10:554/stream -> 192.168.1.10:554
    """
    try:
        # Если нет протокола, добавляем для парсинга
        if not url.startswith(("rtsp://", "http://", "https://")):
            url = "rtsp://" + url

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port

        if not host:
            return "unknown_host"

        # Если порт стандартный для RTSP (554), можно его не писать,
        # но для явной идентификации лучше оставить.
        return f"{host}:{port}" if port else host
    except Exception:
        return "invalid_url"


# === УПРАВЛЕНИЕ СОСТОЯНИЕМ ===
def load_state() -> dict:
    p = Path(RESULTS_FILE)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"prev_status": {}, "cooldowns": {}, "results": []}


def save_state(state: dict):
    Path(RESULTS_FILE).write_text(
        json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# === ОТПРАВКА EMAIL ===
def send_email_notification(changes: list, smtp_cfg: dict, cipher: Fernet):
    if not changes:
        return
    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_cfg["from"]
        msg["To"] = smtp_cfg["to"]
        msg["Subject"] = f"📹 Камеры: {len(changes)} изменений"

        body = "📊 Изменения статуса:\n\n"
        for ch in changes:
            icon = "🔴" if ch["type"] == "DOWN" else "🟢"
            status_text = "ОФФЛАЙН" if ch["type"] == "DOWN" else "ОНЛАЙН"

            # Добавляем IP в письмо, если камера упала
            address_info = ""
            if ch.get("safe_address"):
                address_info = f" ({ch['safe_address']})"

            body += f"{icon} {ch['name']}{address_info} → {status_text}\n"
            body += f"   Время: {ch['timestamp']}\n"
            if ch.get("error"):
                body += f"   Детали: {ch['error'][:80]}\n"
            body += "\n"

        msg.attach(MIMEText(body, "plain", "utf-8"))

        pwd = decrypt_value(smtp_cfg["password_enc"], cipher)
        if smtp_cfg["port"] == 465:
            server = smtplib.SMTP_SSL(smtp_cfg["host"], smtp_cfg["port"])
        else:
            server = smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"])
            server.starttls()

        server.login(smtp_cfg["user"], pwd)
        server.send_message(msg)
        server.quit()
        logger.info(f"📧 Email отправлен: {len(changes)} событий")

    except Exception as e:
        logger.error(f"❌ Ошибка отправки Email: {e}")


# === ПРОВЕРКА КАМЕР ===
async def check_camera(url: str, timeout: int = 5) -> dict:
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
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        if proc.returncode == 0 and stdout:
            data = json.loads(stdout.decode())
            if data.get("streams"):
                return {
                    "status": True,
                    "codec": data["streams"][0].get("codec_name", "ok"),
                }
        error = stderr.decode("utf-8", errors="ignore").strip()
        return {"status": False, "error": error[:150] or "Unknown"}
    except asyncio.TimeoutError:
        return {"status": False, "error": "Timeout"}
    except FileNotFoundError:
        return {"status": False, "error": "ffprobe not found"}
    except Exception as e:
        return {"status": False, "error": f"{type(e).__name__}: {str(e)[:100]}"}


async def check_all_cameras(
    cameras: list, max_concurrent: int = 20, timeout: int = 5
) -> list:
    active = [c for c in cameras if c.get("enabled", True)]
    sem = asyncio.Semaphore(max_concurrent)

    async def check_safe(cam):
        async with sem:
            res = await check_camera(cam["url"], timeout)
            return {
                "id": cam["id"],
                "name": cam["name"],
                "type": cam.get("type", ""),
                "safe_address": get_safe_address(cam["url"]),  # <--- Безопасный адрес
                **res,
            }

    logger.info(f"🔍 Проверка {len(active)} камер (параллельно: {max_concurrent})")
    return await asyncio.gather(*[check_safe(c) for c in active])


# === ОСНОВНОЙ ЦИКЛ ===
async def monitoring_loop(interval: int = 300):
    cipher = load_or_create_key()

    try:
        enc_data = Path(CAMERAS_ENC).read_bytes()
        cameras = json.loads(cipher.decrypt(enc_data).decode())
    except Exception as e:
        logger.error(f"❌ Не удалось загрузить камеры: {e}")
        return

    logger.info(
        f"📹 Загружено {len(cameras)} камер. Цикл: {interval}с, Дебаунс: {DEBOUNCE_MINUTES}мин"
    )

    while True:
        try:
            state = load_state()
            prev_status = state.get("prev_status", {})
            cooldowns = state.get("cooldowns", {})
            now = datetime.now()

            results = await check_all_cameras(cameras)

            changes = []
            for res in results:
                cid = str(res["id"])
                curr = res["status"]
                prev = prev_status.get(cid)
                last_notify = cooldowns.get(cid)

                if prev is None:
                    prev_status[cid] = curr
                    continue

                if curr != prev:
                    if last_notify:
                        last_dt = datetime.fromisoformat(last_notify)
                        if now < last_dt + timedelta(minutes=DEBOUNCE_MINUTES):
                            continue

                    changes.append(
                        {
                            "id": cid,
                            "name": res["name"],
                            "safe_address": res.get(
                                "safe_address", ""
                            ),  # Передаем адрес в изменение
                            "type": "DOWN" if not curr else "UP",
                            "timestamp": now.strftime("%H:%M %d.%m"),
                            "error": res.get("error", ""),
                        }
                    )
                    cooldowns[cid] = now.isoformat()

                prev_status[cid] = curr

            if changes:
                smtp_cfg = {
                    "host": os.getenv("SMTP_HOST", "smtp.yandex.ru"),
                    "port": int(os.getenv("SMTP_PORT", 465)),
                    "user": os.getenv("SMTP_USER", ""),
                    "password_enc": os.getenv("SMTP_PASS", ""),
                    "from": os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "")),
                    "to": os.getenv("NOTIFY_TO", os.getenv("SMTP_FROM", "")),
                }
                await asyncio.to_thread(
                    send_email_notification, changes, smtp_cfg, cipher
                )

            save_state(
                {
                    "checked_at": now.isoformat(),
                    "prev_status": prev_status,
                    "cooldowns": cooldowns,
                    "results": results,
                }
            )

            online = sum(1 for r in results if r["status"])
            logger.info(f"✅ Проверка: {online}/{len(results)} онлайн")

            # Вывод в лог только проблемных камер с IP
            for r in results:
                if not r["status"]:
                    addr = r.get("safe_address", "?")
                    logger.warning(f"🔴 {r['name']} ({addr}) -> {r.get('error', '')}")

            await asyncio.sleep(interval)

        except Exception as e:
            logger.error(f"❌ Сбой цикла: {e}")
            await asyncio.sleep(60)


# === CLI ===
async def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "test"
    cipher = load_or_create_key()

    try:
        enc_data = Path(CAMERAS_ENC).read_bytes()
        cameras = json.loads(cipher.decrypt(enc_data).decode())
    except Exception as e:
        logger.error(f"❌ Ошибка загрузки камер: {e}")
        return

    if mode == "test":
        results = await check_all_cameras(cameras, max_concurrent=10)
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Результаты:")
        for r in results:
            icon = "🟢" if r["status"] else "🔴"
            type_suffix = f" - {r['type']}" if r.get("type") else ""

            # Логика вывода:
            # Если ОК -> только Имя и Тип
            # Если ОШИБКА -> Имя, Тип и (IP:Порт)
            if r["status"]:
                print(f"{icon} {r['name']}{type_suffix}")
            else:
                addr = r.get("safe_address", "unknown")
                print(f"{icon} {r['name']}{type_suffix} ({addr})")

    elif mode == "monitor":
        await monitoring_loop(interval=300)
    else:
        print("Использование: python camera_monitor.py [test|monitor]")


if __name__ == "__main__":
    asyncio.run(main())
