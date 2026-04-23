"""
Конвертер Excel → зашифрованный cameras.enc
Новая структура: ConstSite, Type, CamLocation
"""

import pandas as pd
import json
import sys
from pathlib import Path
from cryptography.fernet import Fernet

# === НАСТРОЙКИ ===
INPUT_FILE = "../data/dbRaw.xlsx"
OUTPUT_ENC = "cameras.enc"
KEY_FILE = "secret.key"

# Номера колонок (0 = первая)
COL_ID = 0
COL_CONST_SITE = 1  # ConstSite - название объекта (для группировки)
COL_TYPE = 2  # Type - тип камеры
COL_CAM_LOCATION = 3  # CamLocation - описание расположения
COL_URL = 4  # Link - RTSP URL
COL_LOGIN = 5  # login
COL_PASSWORD = 6  # password
COL_ENABLED = 7  # enabled (опционально)


def load_or_create_key(path: str) -> Fernet:
    p = Path(path)
    if p.exists():
        return Fernet(p.read_bytes())
    key = Fernet.generate_key()
    p.write_bytes(key)
    print(f"🔑 Создан новый ключ: {path} — СОХРАНИТЕ ЕГО!")
    return Fernet(key)


def is_enabled(value) -> bool:
    if pd.isna(value):
        return True
    return str(value).strip().lower() not in [
        "0",
        "false",
        "no",
        "нет",
        "-",
        "off",
        "disabled",
    ]


def main():
    if not Path(INPUT_FILE).exists():
        print(f"❌ Файл не найден: {INPUT_FILE}")
        sys.exit(1)

    cipher = load_or_create_key(KEY_FILE)
    df = pd.read_excel(INPUT_FILE)
    cameras = []
    stats = {"total": 0, "online": 0, "disabled": 0}

    print(f"\n📋 Обработка: {INPUT_FILE}\n" + "─" * 70)

    for idx, row in df.iterrows():
        # Извлекаем данные с проверкой границ
        cam_id = row.iloc[COL_ID] if COL_ID < len(row) else idx + 1
        const_site = row.iloc[COL_CONST_SITE] if COL_CONST_SITE < len(row) else None
        cam_type = row.iloc[COL_TYPE] if COL_TYPE < len(row) else ""
        cam_location = row.iloc[COL_CAM_LOCATION] if COL_CAM_LOCATION < len(row) else ""
        url = row.iloc[COL_URL] if COL_URL < len(row) else None
        login = row.iloc[COL_LOGIN] if COL_LOGIN < len(row) else ""
        password = row.iloc[COL_PASSWORD] if COL_PASSWORD < len(row) else ""
        enabled_val = row.iloc[COL_ENABLED] if COL_ENABLED < len(row) else True

        # Пропуск пустых строк
        if pd.isna(const_site) or pd.isna(url):
            continue

        const_site = str(const_site).strip()
        cam_type = str(cam_type).strip() if not pd.isna(cam_type) else ""
        cam_location = str(cam_location).strip() if not pd.isna(cam_location) else ""
        url = str(url).strip()
        login = str(login).strip() if not pd.isna(login) else ""
        password = str(password).strip() if not pd.isna(password) else ""
        enabled = is_enabled(enabled_val)

        # Формируем структуру камеры
        camera = {
            "id": int(cam_id) if not pd.isna(cam_id) else idx + 1,
            "object": const_site,  # Для группировки
            "name": const_site,  # Название камеры (пока как объект)
            "type": cam_type,  # Тип камеры
            "location": cam_location,  # Описание расположения
            "url": url,
            "login": login,
            "password": password,
            "enabled": enabled,
        }
        cameras.append(camera)

        # Статистика
        stats["total"] += 1
        if enabled:
            stats["online"] += 1
        else:
            stats["disabled"] += 1

        # Вывод строки
        status = "🟢" if enabled else "🔴"
        print(f"{status} {const_site} | {cam_type} | {cam_location}")

    # Шифруем и сохраняем
    encrypted = cipher.encrypt(json.dumps(cameras, ensure_ascii=False).encode())
    Path(OUTPUT_ENC).write_bytes(encrypted)

    print("─" * 70)
    disabled_str = (
        f"\033[91m{stats['disabled']}\033[0m"
        if stats["disabled"]
        else str(stats["disabled"])
    )
    print(
        f"Количество камер: {stats['total']}, в сети: {stats['online']}, отключены: {disabled_str}"
    )
    print(f"💾 Зашифровано и сохранено: {OUTPUT_ENC}")


if __name__ == "__main__":
    main()
