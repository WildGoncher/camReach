#!/usr/bin/env python3
import asyncio
import subprocess
import json
import logging
from datetime import datetime
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('monitor.log', encoding='utf-8', mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

async def check_camera(url: str, timeout: int = 5) -> dict:
    cmd = [
        'ffprobe',
        '-v', 'error',
        '-show_entries', 'stream=codec_name',
        '-of', 'json',
        '-timeout', str(timeout * 1000000),
        '-rtsp_transport', 'tcp',
        url
    ]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout + 1
        )
        
        if process.returncode == 0 and stdout:
            data = json.loads(stdout.decode())
            if data.get('streams'):
                return {'status': True, 'codec': data['streams'][0].get('codec_name', 'unknown')}
        
        error = stderr.decode('utf-8', errors='ignore').strip()
        return {'status': False, 'error': error[:200] if error else 'Unknown'}
        
    except asyncio.TimeoutError:
        if 'process' in locals() and process.returncode is None:
            process.kill()
            await process.wait()
        return {'status': False, 'error': 'Timeout'}
    except FileNotFoundError:
        return {'status': False, 'error': 'ffprobe not found'}
    except Exception as e:
        return {'status': False, 'error': f'{type(e).__name__}: {str(e)[:100]}'}

def load_cameras(path='cameras.json') -> list:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_results(results: list, path='results.json'):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({
            'checked_at': datetime.now().isoformat(),
            'results': results
        }, f, indent=2, ensure_ascii=False)

async def check_all_cameras(cameras: list, max_concurrent: int = 30, timeout: int = 5) -> list:
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def check_with_sem(cam):
        async with semaphore:
            result = await check_camera(cam['url'], timeout)
            return {'id': cam['id'], 'name': cam['name'], 'url': cam['url'], **result}
    
    active = [c for c in cameras if c.get('enabled')]
    logger.info(f"Запуск проверки {len(active)} камер (параллельно: {max_concurrent})")
    
    tasks = [check_with_sem(c) for c in active]
    return await asyncio.gather(*tasks)

async def monitoring_loop(interval: int = 300, max_concurrent: int = 30):
    """Бесконечный цикл проверки"""
    while True:
        try:
            start = datetime.now()
            cameras = load_cameras()
            results = await check_all_cameras(cameras, max_concurrent)
            
            # Сохраняем результаты
            save_results(results)
            
            # Статистика
            online = sum(1 for r in results if r['status'])
            elapsed = (datetime.now() - start).total_seconds()
            
            logger.info(f"✅ Проверка завершена: {online}/{len(results)} онлайн, время: {elapsed:.1f}с")
            
            # Вывод изменений (только оффлайн-камеры для наглядности)
            for r in results:
                if not r['status']:
                    logger.warning(f"🔴 {r['name']}: {r.get('error', 'No info')}")
            
            await asyncio.sleep(interval)
            
        except Exception as e:
            logger.error(f"❌ Ошибка в цикле: {e}")
            await asyncio.sleep(60)

async def main():
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else 'test'
    
    if mode == 'test':
        # Однократная проверка
        cameras = load_cameras()
        results = await check_all_cameras(cameras, max_concurrent=10)
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Результаты:")
        for r in results:
            icon = "🟢" if r['status'] else "🔴"
            info = r.get('codec') or r.get('error', '')
            print(f"{icon} {r['name']}: {info}")
            
    elif mode == 'monitor':
        # Непрерывный мониторинг
        await monitoring_loop(interval=300, max_concurrent=30)

if __name__ == "__main__":
    asyncio.run(main())
