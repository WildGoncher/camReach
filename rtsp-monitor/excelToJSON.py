#!/usr/bin/env python3
"""
Однократный инструмент: Excel → зашифрованный cameras.enc
URL в таблице уже содержат авторизацию — не добавляем повторно.
"""
import pandas as pd
import json
import re
import sys
from pathlib import Path
from cryptography.fernet import Fernet

# === НАСТРОЙКИ ===
INPUT_FILE = "../data/dbRaw.xlsx"   # Ваш Excel-файл
OUTPUT_ENC = "cameras.enc"           # Зашифрованный результат
KEY_FILE = "secret.key"              # Ключ шифрования

# Номера колонок (0 = первая колонка)
COL_ID = 0          # ID (не используется, генерируется автоматически)
COL_NAME = 1        # Название объекта
COL_TYPE = 2        # Тип (не используется, можно добавить позже)
COL_URL = 3         # RTSP/HTTP ссылка (УЖЕ содержит логин:пароль)
COL_LOGIN = 4       # Логин (отдельно, не добавляем в URL)
COL_PASSWORD = 5    # Пароль (отдельно)
COL_ENABLED = 6     # Активна? (пустое/0/нет = отключена)


def load_or_create_key(path: str) -> Fernet:
    """Загружает или создаёт ключ шифрования"""
    p = Path(path)
    if p.exists():
        return Fernet(p.read_bytes())
    key = Fernet.generate_key()
    p.write_bytes(key)
    print(f"🔑 Создан новый ключ: {path} — СОХРАНИТЕ ЕГО В БЕЗОПАСНОМ МЕСТЕ!")
    return Fernet(key)


def is_enabled(value) -> bool:
    """Определяет, активна ли камера"""
    if pd.isna(value):
        return True
    return str(value).strip().lower() not in ["0", "false", "no", "нет", "-", "off", "disabled"]


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
        name = row.iloc[COL_NAME] if COL_NAME < len(row) else None
        url = row.iloc[COL_URL] if COL_URL < len(row) else None
        login = row.iloc[COL_LOGIN] if COL_LOGIN < len(row) else ""
        password = row.iloc[COL_PASSWORD] if COL_PASSWORD < len(row) else ""
        enabled_val = row.iloc[COL_ENABLED] if COL_ENABLED < len(row) else True

        # Пропуск пустых строк
        if pd.isna(name) or pd.isna(url):
            continue

        name = str(name).strip()
        url = str(url).strip()
        login = str(login).strip() if not pd.isna(login) else ""
        password = str(password).strip() if not pd.isna(password) else ""
        enabled = is_enabled(enabled_val)

        # ⚠️ URL в таблице уже содержит авторизацию — используем как есть
        final_url = url

        camera = {
            "id": idx + 1,
            "name": name,
            "url": final_url,
            "enabled": enabled
        }
        cameras.append(camera)

        # Статистика
        stats["total"] += 1
        if enabled:
            stats["online"] += 1
        else:
            stats["disabled"] += 1

        # Вывод строки с индикатором
        status = "🟢" if enabled else "🔴"
        print(f"{status} {idx + 1}. {name}")

    # Шифруем и сохраняем
    encrypted = cipher.encrypt(json.dumps(cameras, ensure_ascii=False).encode())
    Path(OUTPUT_ENC).write_bytes(encrypted)

    print("─" * 70)
    disabled_str = f"\033[91m{stats['disabled']}\033[0m" if stats["disabled"] else str(stats["disabled"])
    print(f"Количество камер: {stats['total']}, в сети: {stats['online']}, отключены: {disabled_str}")
    print(f"💾 Зашифровано и сохранено: {OUTPUT_ENC}")
    print(f"⚠️  Удалите исходный Excel-файл или убедитесь, что он не в репозитории!")


if __name__ == "__main__":
    main()
