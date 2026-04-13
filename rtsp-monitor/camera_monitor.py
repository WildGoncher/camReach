#!/usr/bin/env python3
"""
Безопасный RTSP Monitor
- Читает зашифрованный cameras.enc
- Проверяет камеры через ffprobe
- Выводит результаты БЕЗ паролей в логах/терминале
"""
import asyncio
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet

# === НАСТРОЙКИ ===
KEY_FILE = "secret.key"
CAMERAS_ENC = "cameras.enc"
RESULTS_FILE = "results.json"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('monitor.log', encoding='utf-8', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def load_cameras_encrypted() -> list:
    """Расшифровывает и возвращает список камер из cameras.enc"""
    key_path = Path(KEY_FILE)
    enc_path = Path(CAMERAS_ENC)
    
    if not key_path.exists():
        raise RuntimeError(f"❌ Ключ не найден: {KEY_FILE}\nЗапустите сначала excelToJSON.py")
    if not enc_path.exists():
        raise RuntimeError(f"❌ Файл камер не найден: {CAMERAS_ENC}\nЗапустите сначала excelToJSON.py")
    
    cipher = Fernet(key_path.read_bytes())
    decrypted = cipher.decrypt(enc_path.read_bytes())
    return json.loads(decrypted.decode())


def strip_auth_for_display(url: str) -> str:
    """Заменяет логин:пароль на *** для безопасного вывода"""
    return re.sub(r'://[^@/]+@', '://***@', url)


async def check_camera(url: str, timeout: int = 5) -> dict:
    """Проверка одной камеры через ffprobe"""
    cmd = [
        'ffprobe', '-v', 'error',
        '-show_entries', 'stream=codec_name',
        '-of', 'json',
        '-timeout', str(timeout * 1_000_000),
        '-rtsp_transport', 'tcp',
        url
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        
        if proc.returncode == 0 and stdout:
            data = json.loads(stdout.decode())
            if data.get('streams'):
                return {'status': True, 'detail': data['streams'][0].get('codec_name', 'ok')}
        
        error = stderr.decode('utf-8', errors='ignore').strip()
        return {'status': False, 'detail': error[:150] if error else 'Unknown'}
        
    except asyncio.TimeoutError:
        return {'status': False, 'detail': 'Timeout'}
    except FileNotFoundError:
        return {'status': False, 'detail': 'ffprobe not found. Install ffmpeg.'}
    except Exception as e:
        return {'status': False, 'detail': f'{type(e).__name__}: {str(e)[:100]}'}


async def check_all_cameras(cameras: list, max_concurrent: int = 20, timeout: int = 5) -> list:
    """Параллельная проверка с ограничением одновременных запросов"""
    active = [c for c in cameras if c.get('enabled', True)]
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def check_with_limit(cam):
        async with semaphore:
            result = await check_camera(cam['url'], timeout)
            return {
                'id': cam['id'],
                'name': cam['name'],
                'url_display': strip_auth_for_display(cam['url']),
                **result
            }
    
    logger.info(f"🔍 Проверка {len(active)} камер (параллельно: {max_concurrent})")
    tasks = [check_with_limit(c) for c in active]
    return await asyncio.gather(*tasks)


def save_results(results: list):
    """Сохраняет результаты БЕЗ конфиденциальных данных"""
    output = {
        'checked_at': datetime.now().isoformat(),
        'summary': {
            'total': len(results),
            'online': sum(1 for r in results if r['status']),
            'offline': sum(1 for r in results if not r['status'])
        },
        'results': [
            {k: v for k, v in r.items() if k != 'url'}
            for r in results
        ]
    }
    Path(RESULTS_FILE).write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding='utf-8'
    )


def print_summary(results: list):
    """Вывод в терминале с итоговой строкой"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Результаты:")
    for i, r in enumerate(results, 1):
        icon = "🟢" if r['status'] else "🔴"
        print(f"{icon} {i}. {r['name']}: {r['detail']}")
    
    total = len(results)
    online = sum(1 for r in results if r['status'])
    offline = total - online
    off_str = f"\033[91m{offline}\033[0m" if offline else str(offline)
    print(f"Количество камер: {total}, в сети: {online}, отключены: {off_str}")


async def main():
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else 'test'
    
    cameras = load_cameras_encrypted()
    
    if mode == 'test':
        results = await check_all_cameras(cameras, max_concurrent=10)
        save_results(results)
        print_summary(results)
        
    elif mode == 'monitor':
        while True:
            try:
                start = datetime.now()
                results = await check_all_cameras(cameras)
                save_results(results)
                online = sum(1 for r in results if r['status'])
                elapsed = (datetime.now() - start).total_seconds()
                logger.info(f"✅ Проверка: {online}/{len(results)} онлайн, {elapsed:.1f}с")
                for r in results:
                    if not r['status']:
                        logger.warning(f"🔴 {r['name']}: {r['detail']}")
                await asyncio.sleep(300)
            except Exception as e:
                logger.error(f"❌ Ошибка цикла: {e}")
                await asyncio.sleep(60)
    else:
        print("Использование: python camera_monitor.py [test|monitor]")


if __name__ == "__main__":
    asyncio.run(main())
